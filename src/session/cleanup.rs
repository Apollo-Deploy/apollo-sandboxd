//! Identity-checked teardown for one Firecracker session incarnation.
//!
//! Cleanup is deliberately conservative.  A resource that cannot be proved
//! to be the recorded object is left in place and the caller must reconcile it
//! later; allocation ownership is never released on a partial cleanup.
use super::LaunchManifest;
use crate::{
    error::{Error, Result},
    process::ProcessIdentity,
    state::{CleanupObservations, CleanupProof, SessionKey},
};
use std::{fs, os::unix::fs::MetadataExt, path::Path, time::Duration};

const PROCESS_WAIT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(20);

/// Terminates the exact pidfd-bound VMM, waits for kernel-observed exit, and
/// removes only the manifest's mounts, sockets, jail root, and cgroup.
pub async fn stop_and_cleanup(
    process: &ProcessIdentity,
    manifest: &LaunchManifest,
    key: &SessionKey,
) -> Result<CleanupProof> {
    super::legacy_cleanup::validate_ready(manifest)?;
    terminate_and_wait(&process).await?;
    let process_absent = process.has_exited()?;
    if !process_absent {
        return Err(Error::Config("VMM did not exit before cleanup"));
    }

    cleanup_resources(manifest, key, process_absent)
}

/// Cleans resources after daemon restart when the pidfd is gone. It proves
/// the exact recorded incarnation is absent and never signals a recyclable PID.
pub fn cleanup_after_recorded_exit(
    process: &crate::process::PersistedProcessIdentity,
    manifest: &LaunchManifest,
    key: &SessionKey,
) -> Result<CleanupProof> {
    super::legacy_cleanup::validate_ready(manifest)?;
    #[cfg(target_os = "linux")]
    if !crate::process::prove_recorded_absent(process)? {
        return Err(Error::Config("recorded VMM incarnation is still live"));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (process, manifest, key);
        Err(Error::Config("recorded process absence requires Linux"))
    }
    #[cfg(target_os = "linux")]
    cleanup_resources(manifest, key, true)
}

fn cleanup_resources(
    manifest: &LaunchManifest,
    key: &SessionKey,
    process_absent: bool,
) -> Result<CleanupProof> {
    super::legacy_cleanup::validate_ready(manifest)?;
    let tree = manifest.jail_tree.as_ref().ok_or(Error::Config(
        "jailer artifacts were not durably observed; quarantine required",
    ))?;
    // Removing the owned cgroup is the process-free barrier. Its identity and
    // membership must be proved before any mount, jail, socket, or stage is
    // dismantled. rmdir also fails if a process joins after the membership
    // read, so no resource teardown starts until the cgroup is absent.
    remove_cgroup(&manifest.cgroup, manifest.cgroup_identity)?;
    if !absent(&manifest.cgroup)? {
        return Err(Error::Config("owned cgroup remains after removal"));
    }

    super::assets::unmount_manifest_assets(&manifest.assets)?;
    super::jail_tree::remove(manifest, tree)?;
    super::cleanup_paths::remove_socket(
        &manifest.api_socket,
        manifest.api_socket_identity,
        &manifest.assets,
    )?;
    super::cleanup_paths::remove_socket(
        &manifest.vsock_socket,
        manifest.vsock_socket_identity,
        &manifest.assets,
    )?;
    let sockets_absent = absent(&manifest.api_socket)? && absent(&manifest.vsock_socket)?;

    let staged_jail_absent = if let Some(staged_jail) = &manifest.staged_jail {
        crate::jailer::remove_owned_manifest(staged_jail)?;
        true
    } else {
        false
    };
    super::cleanup_paths::remove_empty_directories(&manifest.assets)?;
    let jail_root_absent = absent(&manifest.jail_root)?;
    let cgroup_absent = absent(&manifest.cgroup)?;
    let session_dir = manifest.jail_root.parent().ok_or(Error::Path)?;
    let diagnostics_absent = absent(&session_dir.join("jailer.stderr"))?
        && absent(&manifest.jail_root.join("run/serial.log"))?;

    if !(sockets_absent
        && staged_jail_absent
        && jail_root_absent
        && cgroup_absent
        && diagnostics_absent)
    {
        return Err(Error::Config(
            "owned session resources remain after cleanup",
        ));
    }
    Ok(CleanupProof::new(
        key.clone(),
        CleanupObservations {
            process_absent,
            staged_jail_absent,
            cgroup_absent,
            jail_root_absent,
            sockets_absent,
            diagnostics_absent,
        },
    ))
}

pub(crate) async fn terminate_and_wait(process: &ProcessIdentity) -> Result<()> {
    if !process.has_exited()? {
        #[cfg(target_os = "linux")]
        process.send_signal(rustix::process::Signal::KILL)?;
    }
    let deadline = tokio::time::Instant::now() + PROCESS_WAIT;
    while !process.has_exited()? {
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Config("VMM exit timed out"));
        }
        tokio::time::sleep(POLL).await;
    }
    Ok(())
}

fn remove_cgroup(path: &Path, identity: crate::jailer::CgroupIdentity) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.dev() != identity.device || metadata.ino() != identity.inode || !metadata.is_dir() {
        return Err(Error::Path);
    }
    if !crate::jailer::CgroupV2::processes_at(path)?.is_empty() {
        return Err(Error::Config("owned cgroup still contains processes"));
    }
    fs::remove_dir(path)?;
    Ok(())
}

fn absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        os::unix::net::UnixListener,
    };

    fn owned_identity(path: &Path) -> super::super::AssetIdentity {
        let metadata = fs::symlink_metadata(path).expect("fixture identity");
        super::super::AssetIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn live_member_fixture() -> (tempfile::TempDir, LaunchManifest, SessionKey) {
        let directory = tempfile::tempdir().expect("temporary cleanup root");
        let operator = directory.path().canonicalize().unwrap();
        let session = operator.join("s");
        let root = session.join("root");
        fs::create_dir_all(root.join("dev/net")).expect("jail devices");
        fs::create_dir(root.join("run")).expect("run directory");

        let runtime = b"owned firecracker runtime";
        let digest = hex::encode(sha2::Sha256::digest(runtime));
        let runtime_path = root.join("firecracker");
        fs::write(&runtime_path, runtime).expect("runtime");
        fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o555))
            .expect("runtime mode");
        let diagnostics = session.join("jailer.stderr");
        fs::write(&diagnostics, b"jailer output").expect("diagnostics");
        fs::set_permissions(&diagnostics, fs::Permissions::from_mode(0o600))
            .expect("diagnostics mode");

        let api_socket = root.join("run/firecracker.socket");
        let api_listener = UnixListener::bind(&api_socket).expect("API socket");
        let api_socket_identity = owned_identity(&api_socket);
        let vsock_socket = root.join("run/vsock.socket");
        let vsock_listener = UnixListener::bind(&vsock_socket).expect("vsock socket");
        let vsock_socket_identity = owned_identity(&vsock_socket);

        let root_identity = owned_identity(&root);
        let session_identity = owned_identity(&session);
        let run_identity = owned_identity(&root.join("run"));
        let assets = super::super::AssetsManifest {
            root: root.clone(),
            root_identity,
            root_mount_id: None,
            mount_anchor_identity: None,
            mount_anchor_id: None,
            session_identity: Some(session_identity),
            run_identity: Some(run_identity),
            mount_namespace_identity: Some(root_identity),
            assets: Vec::new(),
        };
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let mut manifest = LaunchManifest {
            sandbox_id: "sandbox".into(),
            session_id: "session".into(),
            jail_root: root.clone(),
            cgroup: directory.path().join("cgroup/session"),
            api_socket,
            vsock_socket,
            api_socket_identity: Some(api_socket_identity),
            vsock_socket_identity: Some(vsock_socket_identity),
            jail_identity: crate::jailer::JailIdentity {
                device: root_identity.device,
                inode: root_identity.inode,
            },
            staged_jail: None,
            cgroup_identity: crate::jailer::CgroupIdentity {
                device: 0,
                inode: 0,
            },
            assets,
            jail_tree: None,
            network_identity: None,
            network_attachment: None,
            network_namespace: None,
        };
        manifest.jail_tree = Some(
            super::super::jail_tree::capture(&manifest, uid, gid, &digest)
                .expect("capture jail tree"),
        );

        let stage_parent = operator.join("i");
        let stage_root = stage_parent.join("session");
        fs::create_dir_all(&stage_root).expect("stage root");
        let staged_runtime = stage_root.join("firecracker");
        fs::write(&staged_runtime, runtime).expect("staged runtime");
        fs::set_permissions(&staged_runtime, fs::Permissions::from_mode(0o555))
            .expect("staged runtime mode");
        let ownership_manifest = stage_root.join("ownership.manifest");
        fs::write(
            &ownership_manifest,
            format!("session=session\nfirecracker_sha256={digest}\njailer_sha256={digest}\n"),
        )
        .expect("stage ownership manifest");
        fs::set_permissions(&ownership_manifest, fs::Permissions::from_mode(0o600))
            .expect("stage manifest mode");
        let stage_identity = |path: &Path| {
            let identity = owned_identity(path);
            crate::jailer::JailIdentity {
                device: identity.device,
                inode: identity.inode,
            }
        };
        manifest.staged_jail = Some(crate::jailer::JailStageManifest {
            root: stage_root.clone(),
            parent: stage_parent.clone(),
            firecracker: staged_runtime.clone(),
            ownership_manifest: ownership_manifest.clone(),
            root_identity: stage_identity(&stage_root),
            parent_identity: stage_identity(&stage_parent),
            firecracker_identity: stage_identity(&staged_runtime),
            ownership_manifest_identity: stage_identity(&ownership_manifest),
            firecracker_sha256: digest.clone(),
            jailer_sha256: digest,
        });

        let cgroup_parent = directory.path().join("cgroup");
        fs::create_dir_all(&cgroup_parent).expect("cgroup parent");
        let cgroup = cgroup_parent.join("session");
        fs::create_dir(&cgroup).expect("owned cgroup");
        fs::write(
            cgroup.join("cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .expect("foreign live member");
        let cgroup_identity = owned_identity(&cgroup);
        manifest.cgroup = cgroup;
        manifest.cgroup_identity = crate::jailer::CgroupIdentity {
            device: cgroup_identity.device,
            inode: cgroup_identity.inode,
        };

        let key = SessionKey {
            sandbox: "sandbox".parse().expect("sandbox id"),
            sandbox_generation: sandboxd_protocol::SandboxGeneration::new(1).unwrap(),
            session: "session".parse().expect("session id"),
            generation: sandboxd_protocol::SessionGeneration::new(1).unwrap(),
        };
        drop((api_listener, vsock_listener));
        (directory, manifest, key)
    }

    #[test]
    fn live_foreign_cgroup_member_preserves_owned_session_resources() {
        let (_directory, manifest, key) = live_member_fixture();
        let runtime = manifest.jail_root.join("firecracker");
        let diagnostics = manifest.jail_root.parent().unwrap().join("jailer.stderr");
        let stage = manifest.staged_jail.as_ref().unwrap();

        let result = cleanup_resources(&manifest, &key, true);

        assert!(matches!(
            result,
            Err(Error::Config("owned cgroup still contains processes"))
        ));
        assert!(manifest.cgroup.exists(), "populated cgroup remains");
        assert!(runtime.exists(), "jail runtime remains");
        assert!(diagnostics.exists(), "jail diagnostics remain");
        assert!(manifest.api_socket.exists(), "API socket remains");
        assert!(manifest.vsock_socket.exists(), "vsock socket remains");
        assert!(stage.firecracker.exists(), "staged runtime remains");
        assert!(stage.ownership_manifest.exists(), "stage token remains");
    }

    fn assets(root: &Path) -> super::super::AssetsManifest {
        let identity = |path: &Path| {
            let metadata = fs::symlink_metadata(path).expect("fixture identity");
            super::super::AssetIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        };
        super::super::AssetsManifest {
            root: root.to_path_buf(),
            root_identity: identity(root),
            root_mount_id: None,
            mount_anchor_identity: None,
            mount_anchor_id: None,
            session_identity: Some(identity(root.parent().expect("parent"))),
            run_identity: Some(identity(&root.join("run"))),
            mount_namespace_identity: None,
            assets: Vec::new(),
        }
    }

    #[test]
    fn socket_replacement_is_rejected_without_unlinking_foreign_object() {
        let directory = tempfile::tempdir().expect("temporary cleanup root");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical fixture")
            .join("root");
        let run = root.join("run");
        std::fs::create_dir_all(&run).expect("run directory");
        let path = run.join("firecracker.socket");
        let original = UnixListener::bind(&path).expect("original socket");
        let metadata = std::fs::symlink_metadata(&path).expect("original metadata");
        let identity = super::super::AssetIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        drop(original);
        std::fs::remove_file(&path).expect("remove original fixture");
        let replacement = UnixListener::bind(&path).expect("replacement socket");

        let result =
            crate::session::cleanup_paths::remove_socket(&path, Some(identity), &assets(&root));
        assert!(matches!(result, Err(Error::Path)));
        assert!(path.exists(), "foreign replacement must remain");
        drop(replacement);
    }

    #[test]
    fn matching_socket_identity_is_removed() {
        let directory = tempfile::tempdir().expect("temporary cleanup root");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical fixture")
            .join("root");
        let run = root.join("run");
        std::fs::create_dir_all(&run).expect("run directory");
        let path = run.join("vsock.socket");
        let socket = UnixListener::bind(&path).expect("socket");
        let metadata = std::fs::symlink_metadata(&path).expect("socket metadata");
        let identity = super::super::AssetIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        crate::session::cleanup_paths::remove_socket(&path, Some(identity), &assets(&root))
            .expect("owned socket removal");
        assert!(!path.exists());
        drop(socket);
    }
}
