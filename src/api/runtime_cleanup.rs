//! Restart cleanup never signals a PID until its complete identity is verified.
use super::{handlers::now_ms, runtime_service::RuntimeService};
#[cfg(target_os = "linux")]
use crate::process::ProcessIdentity;
use crate::{
    error::{Error, Result},
    state::SessionKey,
};

impl RuntimeService {
    pub(super) async fn cleanup_untracked(&self, uid: u32, key: &SessionKey) -> Result<()> {
        let owned_key = key.clone();
        let (record, manifest, prelaunch, intent) = self
            .state
            .with_store(move |store| {
                Ok((
                    store.session_process(uid, &owned_key)?,
                    store.session_resources(uid, &owned_key)?,
                    store.prelaunch(uid, &owned_key)?,
                    store.session_intent(uid, &owned_key)?,
                ))
            })
            .await?;
        match (record, manifest, prelaunch) {
            (None, None, Some(prelaunch)) => {
                let execution = &self.authority.execution;
                if prelaunch.operator_root != execution.operator_root
                    || prelaunch.cgroup_parent != execution.cgroup_parent
                {
                    return Err(Error::Path);
                }
                let cleanup_key = key.clone();
                let proof = tokio::task::spawn_blocking(move || {
                    crate::session::reconcile_prelaunch(&cleanup_key, &prelaunch)
                })
                .await
                .map_err(|_| Error::State)??;
                self.authority.restore_dynamic_owners(&intent.pins, None)?;
                let key = key.clone();
                self.state
                    .with_store(move |store| {
                        store.record_prelaunch_stopped(uid, &key, proof, now_ms()?)
                    })
                    .await
            }
            (Some(record), Some(manifest), None) => {
                let execution = &self.authority.execution;
                if manifest.jail_root
                    != execution
                        .operator_root
                        .join("firecracker")
                        .join(key.session.as_str())
                        .join("root")
                    || manifest.cgroup != execution.cgroup_parent.join(key.session.as_str())
                {
                    return Err(Error::Path);
                }
                #[cfg(target_os = "linux")]
                {
                    let cleanup_key = key.clone();
                    let recovery_intent = intent.clone();
                    let (record, manifest, process, exited) =
                        tokio::task::spawn_blocking(move || {
                            let exited = crate::process::prove_recorded_absent(&record)?;
                            let process = if exited {
                                None
                            } else {
                                Some(ProcessIdentity::reopen_verified(&record)?)
                            };
                            let manifest = crate::session::recover_legacy_manifest(
                                &manifest,
                                &recovery_intent,
                                process.as_ref(),
                            )?;
                            Ok::<_, Error>((record, manifest, process, exited))
                        })
                        .await
                        .map_err(|_| Error::State)??;
                    let persist_key = key.clone();
                    let durable_manifest = manifest.clone();
                    self.state
                        .with_store(move |store| {
                            store.record_recovered_cleanup_manifest(
                                uid,
                                &persist_key,
                                &durable_manifest,
                            )
                        })
                        .await?;
                    let proof = if exited {
                        crate::session::cleanup_after_recorded_exit(
                            &record,
                            &manifest,
                            &cleanup_key,
                        )?
                    } else {
                        let process = process.as_ref().ok_or(Error::State)?;
                        crate::session::stop_and_cleanup(process, &manifest, key).await?
                    };
                    self.authority.restore_dynamic_owners(&intent.pins, None)?;
                    let key = key.clone();
                    self.state
                        .with_store(move |store| {
                            store.record_session_stopped(uid, &key, proof, now_ms()?)
                        })
                        .await
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (record, manifest);
                    Err(Error::Config("recovery requires Linux"))
                }
            }
            (None, Some(manifest), None) => {
                let administrative_stop =
                    intent.state == sandboxd_protocol::SessionState::Terminating;
                let execution = &self.authority.execution;
                if manifest.sandbox_id != key.sandbox.as_str()
                    || manifest.session_id != key.session.as_str()
                    || manifest.jail_root
                        != execution
                            .operator_root
                            .join("firecracker")
                            .join(key.session.as_str())
                            .join("root")
                    || manifest.cgroup != execution.cgroup_parent.join(key.session.as_str())
                {
                    return Err(Error::Path);
                }
                let digest = intent.pins.firecracker_sha256.clone();
                let expected_uid = intent.uid;
                let expected_gid = intent.gid;
                let cgroup = manifest.cgroup.clone();
                let jail_root = manifest.jail_root.clone();
                let cgroup_identity = manifest.cgroup_identity;
                let jail_identity = manifest.assets.root_identity;
                let process = tokio::task::spawn_blocking(move || {
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::unix::fs::MetadataExt;
                        let cgroup_meta = std::fs::symlink_metadata(&cgroup)?;
                        if cgroup_meta.dev() != cgroup_identity.device
                            || cgroup_meta.ino() != cgroup_identity.inode
                        {
                            return Err(Error::Path);
                        }
                        verify_jail_or_absent(&jail_root, jail_identity)?;
                        let pids = crate::jailer::CgroupV2::processes_at(&cgroup)?;
                        if pids.is_empty() {
                            return Err(Error::Config(
                                "manifest cgroup is empty; launcher identity unavailable",
                            ));
                        }
                        if pids.len() > 1 {
                            return Err(Error::Config(
                                "manifest cgroup contains multiple processes",
                            ));
                        }
                        let process = ProcessIdentity::capture_from_cgroup(&cgroup, &digest)?;
                        if process.uids() != [expected_uid; 4]
                            || process.gids() != [expected_gid; 4]
                        {
                            return Err(Error::Path);
                        }
                        Ok(process)
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = (
                            cgroup,
                            jail_root,
                            cgroup_identity,
                            jail_identity,
                            digest,
                            expected_uid,
                            expected_gid,
                        );
                        Err(Error::Config("recovery requires Linux"))
                    }
                })
                .await
                .map_err(|_| Error::State)??;
                let persist_key = key.clone();
                self.state
                    .with_store(move |store| {
                        if administrative_stop {
                            store.record_vmm_process_for_cleanup(uid, &persist_key, &process)?;
                            Ok(())
                        } else {
                            store.record_vmm_process(uid, &persist_key, &process, now_ms()?)?;
                            store
                                .admit_runtime_loss(
                                    uid,
                                    &persist_key,
                                    sandboxd_protocol::EventKind::RecoveryFailed,
                                    now_ms()?,
                                )
                                .map(|_| ())
                        }
                    })
                    .await?;
                Box::pin(self.cleanup_untracked(uid, key)).await
            }
            _ => Err(Error::Config(
                "launch identity incomplete; quarantine required",
            )),
        }
    }
}

#[cfg(target_os = "linux")]
fn verify_jail_or_absent(
    path: &std::path::Path,
    expected: crate::session::AssetIdentity,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.dev() == expected.device
                && metadata.ino() == expected.inode =>
        {
            Ok(())
        }
        // A prior cleanup attempt may have removed the jail tree before the
        // daemon durably captured the VMM identity. Process, cgroup, digest,
        // UID and GID proofs remain mandatory before any signal is sent.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(Error::Path),
        Err(error) => Err(error.into()),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn manifest_only_recovery_accepts_absent_jail_but_rejects_replacement() {
        let directory = tempfile::tempdir().expect("fixture");
        let jail = directory.path().join("jail");
        std::fs::create_dir(&jail).expect("owned jail");
        let metadata = std::fs::symlink_metadata(&jail).expect("identity");
        let identity = crate::session::AssetIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        // Keep the original inode alive while replacing its pathname so a
        // filesystem cannot recycle the same device/inode pair for the test.
        let original = std::fs::File::open(&jail).expect("open original jail");
        verify_jail_or_absent(&jail, identity).expect("matching jail");
        std::fs::remove_dir(&jail).expect("remove jail");
        verify_jail_or_absent(&jail, identity).expect("already removed jail");
        std::fs::create_dir(&jail).expect("replacement jail");
        let replacement = std::fs::symlink_metadata(&jail).expect("replacement identity");
        assert_ne!(
            (replacement.dev(), replacement.ino()),
            (
                original.metadata().expect("original identity").dev(),
                identity.inode
            ),
            "replacement must have a distinct inode identity"
        );
        assert!(matches!(
            verify_jail_or_absent(&jail, identity),
            Err(Error::Path)
        ));
    }
}
