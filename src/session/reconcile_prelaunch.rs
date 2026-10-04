//! Crash recovery for effects created before the durable launch manifest.
use crate::{
    error::{Error, Result},
    jailer::recover_stage_manifest,
    state::{PrelaunchIntent, SessionKey},
};
use std::{fs, os::unix::fs::MetadataExt};

pub struct PrelaunchCleanupProof {
    key: SessionKey,
    stage_absent: bool,
    assets_absent: bool,
    cgroup_absent: bool,
}

impl PrelaunchCleanupProof {
    pub(crate) fn complete(&self, key: &SessionKey) -> bool {
        self.key == *key && self.stage_absent && self.assets_absent && self.cgroup_absent
    }
}

/// Reconciles only a prelaunch record whose ownership observations are
/// sufficient. Missing mount/cgroup identities quarantine the record.
pub(crate) fn reconcile_prelaunch(
    key: &SessionKey,
    record: &PrelaunchIntent,
) -> Result<PrelaunchCleanupProof> {
    if record.sandbox != key.sandbox.as_str()
        || record.session != key.session.as_str()
        || record.sandbox_generation != key.sandbox_generation.get()
        || record.session_generation != key.generation.get()
    {
        return Err(Error::State);
    }
    let stage = match &record.staged_jail {
        Some(stage) => stage.clone(),
        None => match fs::symlink_metadata(&record.stage_root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return zero_effect(key, record);
            }
            Err(error) => return Err(error.into()),
            Ok(_) => recover_stage_manifest(
                &record.stage_root,
                &record.session,
                &record.firecracker_sha256,
                &record.jailer_sha256,
            )?,
        },
    };

    // An owned, empty cgroup is the process-free barrier for prelaunch
    // teardown. Missing ownership is acceptable only when the recorded path
    // is already absent; otherwise leave all assets and the staged jail intact.
    let cgroup_absent = match record.cgroup_identity {
        Some(identity) => {
            remove_cgroup(&record.cgroup, &record.cgroup_parent, identity)?;
            absent(&record.cgroup)?
        }
        None => absent(&record.cgroup)?,
    };
    if !cgroup_absent {
        return Err(Error::Config(
            "prelaunch cgroup identity is missing; quarantine required",
        ));
    }

    let assets_absent = match (&record.assets, &record.asset_setup) {
        (Some(_), Some(_)) => return Err(Error::State),
        (None, Some(setup)) => {
            if setup.root != record.jail_root {
                return Err(Error::Path);
            }
            super::asset_recovery::recover_setup(setup)?;
            absent(&record.jail_root)?
        }
        (Some(assets), None) => {
            if assets.root != record.jail_root || !(4..=24).contains(&assets.assets.len()) {
                return Err(Error::Path);
            }
            crate::session::assets::unmount_manifest_assets(assets)?;
            crate::session::cleanup_paths::remove_empty_directories(assets)?;
            assets.assets.iter().all(|asset| !asset.path.exists())
        }
        (None, None) => absent(&record.jail_root)?,
    };
    if !assets_absent {
        return Err(Error::Config(
            "prelaunch assets identity is missing; quarantine required",
        ));
    }
    crate::jailer::remove_owned_manifest(&stage)?;
    let cgroup_absent = absent(&record.cgroup)?;
    if !cgroup_absent {
        return Err(Error::Config("prelaunch cgroup remains after removal"));
    }
    Ok(PrelaunchCleanupProof {
        key: key.clone(),
        stage_absent: !record.stage_root.exists(),
        assets_absent,
        cgroup_absent,
    })
}

fn absent(path: &std::path::Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn zero_effect(key: &SessionKey, record: &PrelaunchIntent) -> Result<PrelaunchCleanupProof> {
    Ok(PrelaunchCleanupProof {
        key: key.clone(),
        stage_absent: true,
        assets_absent: absent(&record.jail_root)?,
        cgroup_absent: absent(&record.cgroup)?,
    })
}

fn remove_cgroup(
    path: &std::path::Path,
    parent: &std::path::Path,
    identity: crate::jailer::CgroupIdentity,
) -> Result<()> {
    if path.parent() != Some(parent) {
        return Err(Error::Path);
    }
    let parent_meta = fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir() || parent_meta.file_type().is_symlink() {
        return Err(Error::Path);
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.dev() != identity.device
        || meta.ino() != identity.inode
    {
        return Err(Error::Path);
    }
    if !crate::jailer::CgroupV2::processes_at(path)?.is_empty() {
        return Err(Error::Config("prelaunch cgroup still contains processes"));
    }
    fs::remove_dir(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn recovery_removes_a_staged_jail_created_before_its_manifest_was_committed() {
        let root = tempfile::tempdir().unwrap();
        let operator_root = root.path().canonicalize().unwrap().join("operator");
        let stage_root = operator_root.join(".inputs/ss");
        let jail_root = operator_root.join("firecracker/ss/root");
        let cgroup_parent = root.path().join("cgroup");
        std::fs::create_dir_all(&stage_root).unwrap();
        std::fs::set_permissions(&stage_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir_all(&cgroup_parent).unwrap();
        let executable = stage_root.join("firecracker");
        let contents = b"verified staged runtime";
        std::fs::write(&executable, contents).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o555)).unwrap();
        let digest = hex::encode(sha2::Sha256::digest(contents));
        std::fs::write(
            stage_root.join("ownership.manifest"),
            format!(
                "session=ss\nfirecracker_sha256={digest}\njailer_sha256={}\n",
                "b".repeat(64)
            ),
        )
        .unwrap();
        std::fs::set_permissions(
            stage_root.join("ownership.manifest"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let record = PrelaunchIntent {
            sandbox: "sb".into(),
            session: "ss".into(),
            sandbox_generation: 1,
            session_generation: 1,
            operator_root: operator_root.clone(),
            cgroup_parent: cgroup_parent.clone(),
            firecracker_sha256: digest,
            jailer_sha256: "b".repeat(64),
            stage_root: stage_root.clone(),
            jail_root,
            cgroup: cgroup_parent.join("ss"),
            staged_jail: None,
            assets: None,
            asset_setup: None,
            cgroup_identity: None,
        };
        let key = SessionKey {
            sandbox: "sb".parse().unwrap(),
            sandbox_generation: sandboxd_protocol::SandboxGeneration::new(1).unwrap(),
            session: "ss".parse().unwrap(),
            generation: sandboxd_protocol::SessionGeneration::new(1).unwrap(),
        };

        let proof = reconcile_prelaunch(&key, &record).expect("owned stage is reconciled");

        assert!(proof.complete(&key));
        assert!(!stage_root.exists(), "the owned external stage was removed");
    }

    #[test]
    fn live_foreign_cgroup_member_preserves_prelaunch_stage() {
        let root = tempfile::tempdir().expect("temporary recovery root");
        let operator_root = root.path().canonicalize().unwrap().join("operator");
        let stage_root = operator_root.join(".inputs/ss");
        let jail_root = operator_root.join("firecracker/ss/root");
        let cgroup_parent = root.path().join("cgroup");
        fs::create_dir_all(&stage_root).expect("stage root");
        fs::set_permissions(&stage_root, fs::Permissions::from_mode(0o700)).expect("stage mode");
        fs::create_dir_all(&cgroup_parent).expect("cgroup parent");

        let executable = stage_root.join("firecracker");
        let contents = b"verified staged runtime";
        fs::write(&executable, contents).expect("staged runtime");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o555)).expect("runtime mode");
        let digest = hex::encode(sha2::Sha256::digest(contents));
        let jailer_digest = "b".repeat(64);
        let ownership = stage_root.join("ownership.manifest");
        fs::write(
            &ownership,
            format!("session=ss\nfirecracker_sha256={digest}\njailer_sha256={jailer_digest}\n"),
        )
        .expect("ownership manifest");
        fs::set_permissions(&ownership, fs::Permissions::from_mode(0o600)).expect("manifest mode");

        let cgroup = cgroup_parent.join("ss");
        fs::create_dir(&cgroup).expect("owned cgroup");
        fs::write(
            cgroup.join("cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .expect("foreign live member");
        let metadata = fs::symlink_metadata(&cgroup).expect("cgroup identity");
        let record = PrelaunchIntent {
            sandbox: "sb".into(),
            session: "ss".into(),
            sandbox_generation: 1,
            session_generation: 1,
            operator_root: operator_root.clone(),
            cgroup_parent: cgroup_parent.clone(),
            firecracker_sha256: digest,
            jailer_sha256: jailer_digest,
            stage_root: stage_root.clone(),
            jail_root,
            cgroup: cgroup.clone(),
            staged_jail: None,
            assets: None,
            asset_setup: None,
            cgroup_identity: Some(crate::jailer::CgroupIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }),
        };
        let key = SessionKey {
            sandbox: "sb".parse().unwrap(),
            sandbox_generation: sandboxd_protocol::SandboxGeneration::new(1).unwrap(),
            session: "ss".parse().unwrap(),
            generation: sandboxd_protocol::SessionGeneration::new(1).unwrap(),
        };

        let result = reconcile_prelaunch(&key, &record);

        assert!(matches!(
            result,
            Err(Error::Config("prelaunch cgroup still contains processes"))
        ));
        assert!(cgroup.exists(), "populated cgroup remains");
        assert!(stage_root.exists(), "staged jail remains");
        assert!(executable.exists(), "staged runtime remains");
        assert!(ownership.exists(), "stage ownership token remains");
    }

    #[test]
    fn missing_observations_quarantine_without_path_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let operator_root = root.path().join("operator");
        let stage_root = operator_root.join(".inputs/ss");
        let jail_root = operator_root.join("firecracker/ss/root");
        let cgroup_parent = root.path().join("cgroup");
        std::fs::create_dir_all(&stage_root).unwrap();
        std::fs::create_dir_all(&jail_root).unwrap();
        std::fs::create_dir_all(&cgroup_parent).unwrap();
        let record = PrelaunchIntent {
            sandbox: "sb".into(),
            session: "ss".into(),
            sandbox_generation: 1,
            session_generation: 1,
            operator_root: operator_root.clone(),
            cgroup_parent: cgroup_parent.clone(),
            firecracker_sha256: "a".repeat(64),
            jailer_sha256: "b".repeat(64),
            stage_root,
            jail_root,
            cgroup: cgroup_parent.join("ss"),
            staged_jail: None,
            assets: None,
            asset_setup: None,
            cgroup_identity: None,
        };
        let key = SessionKey {
            sandbox: "sb".parse().unwrap(),
            sandbox_generation: sandboxd_protocol::SandboxGeneration::new(1).unwrap(),
            session: "ss".parse().unwrap(),
            generation: sandboxd_protocol::SessionGeneration::new(1).unwrap(),
        };
        assert!(reconcile_prelaunch(&key, &record).is_err());
    }

    #[test]
    fn zero_effect_proof_is_fenced_to_session_key() {
        let root = tempfile::tempdir().unwrap();
        let operator_root = root.path().join("operator");
        let cgroup_parent = root.path().join("cgroup");
        std::fs::create_dir_all(&operator_root).unwrap();
        std::fs::create_dir_all(&cgroup_parent).unwrap();
        let record = PrelaunchIntent {
            sandbox: "sb".into(),
            session: "ss".into(),
            sandbox_generation: 1,
            session_generation: 1,
            operator_root: operator_root.clone(),
            cgroup_parent: cgroup_parent.clone(),
            firecracker_sha256: "a".repeat(64),
            jailer_sha256: "b".repeat(64),
            stage_root: operator_root.join(".inputs/ss"),
            jail_root: operator_root.join("firecracker/ss/root"),
            cgroup: cgroup_parent.join("ss"),
            staged_jail: None,
            assets: None,
            asset_setup: None,
            cgroup_identity: None,
        };
        let key = SessionKey {
            sandbox: "sb".parse().unwrap(),
            sandbox_generation: sandboxd_protocol::SandboxGeneration::new(1).unwrap(),
            session: "ss".parse().unwrap(),
            generation: sandboxd_protocol::SessionGeneration::new(1).unwrap(),
        };
        let proof = reconcile_prelaunch(&key, &record).unwrap();
        assert!(proof.complete(&key));
        let wrong = SessionKey {
            sandbox: "sb".parse().unwrap(),
            sandbox_generation: sandboxd_protocol::SandboxGeneration::new(1).unwrap(),
            session: "other".parse().unwrap(),
            generation: sandboxd_protocol::SessionGeneration::new(1).unwrap(),
        };
        assert!(!proof.complete(&wrong));
    }
}
