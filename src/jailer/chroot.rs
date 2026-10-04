use super::cgroup::validate_component;
use crate::{
    error::{Error, Result},
    runtime::VerifiedRuntime,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use super::chroot_artifact::{checked_parent, copy_verified, validate_staged};
use super::chroot_cleanup::remove_owned_manifest;

#[derive(Clone, Debug)]
pub struct JailInputs {
    pub root: PathBuf,
    pub session_id: String,
    pub uid: u32,
    pub gid: u32,
}

/// Files staged into a unique jailer input directory. The manifest binds the
/// staged inode/digest to the verified runtime observation.
pub struct JailStage {
    root: PathBuf,
    chroot_base: PathBuf,
    firecracker: PathBuf,
    manifest: PathBuf,
    firecracker_sha256: String,
    jailer_sha256: String,
    device: u64,
    inode: u64,
    parent_device: u64,
    parent_inode: u64,
    firecracker_device: u64,
    firecracker_inode: u64,
    manifest_device: u64,
    manifest_inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailStageManifest {
    pub root: PathBuf,
    pub parent: PathBuf,
    pub firecracker: PathBuf,
    pub ownership_manifest: PathBuf,
    pub root_identity: JailIdentity,
    pub parent_identity: JailIdentity,
    pub firecracker_identity: JailIdentity,
    pub ownership_manifest_identity: JailIdentity,
    pub firecracker_sha256: String,
    pub jailer_sha256: String,
}

impl JailStage {
    pub fn prepare(inputs: &JailInputs, runtime: &VerifiedRuntime) -> Result<Self> {
        validate_component(&inputs.session_id)?;
        if inputs.uid < 100_000 || inputs.gid < 100_000 {
            return Err(Error::Config("jail identity outside configured pool"));
        }
        let parent = checked_parent(&inputs.root)?;
        let input_root = inputs.root.join(".inputs");
        if fs::symlink_metadata(&input_root).is_err() {
            fs::create_dir(&input_root)?;
            fs::set_permissions(&input_root, fs::Permissions::from_mode(0o700))?;
        } else {
            let meta = fs::symlink_metadata(&input_root)?;
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
            {
                return Err(Error::Path);
            }
        }
        let root = input_root.join(&inputs.session_id);
        if root.exists() {
            return Err(Error::Path);
        }
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let root_identity = fs::symlink_metadata(&root)?;
        let root_parent = fs::symlink_metadata(root.parent().ok_or(Error::Path)?)?;
        let firecracker = root.join("firecracker");
        copy_verified(
            &runtime.firecracker.file,
            &runtime.firecracker.sha256,
            &firecracker,
        )?;
        let manifest = root.join("ownership.manifest");
        let text = format!(
            "session={}\nuid={}\ngid={}\nfirecracker_sha256={}\njailer_sha256={}\n",
            inputs.session_id,
            inputs.uid,
            inputs.gid,
            runtime.firecracker.sha256,
            runtime.jailer.sha256
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&manifest)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        let firecracker_identity = fs::symlink_metadata(&firecracker)?;
        let manifest_identity = fs::symlink_metadata(&manifest)?;
        File::open(&root)?.sync_all()?;
        File::open(parent)?.sync_all()?;
        // Jailer appends executable basename and session ID itself:
        // <chroot-base>/<exec-name>/<id>/root.
        let chroot_base = inputs.root.clone();
        if fs::symlink_metadata(&chroot_base).is_err() {
            fs::create_dir(&chroot_base)?;
            fs::set_permissions(&chroot_base, fs::Permissions::from_mode(0o700))?;
        } else {
            let meta = fs::symlink_metadata(&chroot_base)?;
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
            {
                return Err(Error::Path);
            }
        }
        File::open(&inputs.root)?.sync_all()?;
        Ok(Self {
            root,
            chroot_base,
            firecracker,
            manifest,
            firecracker_sha256: runtime.firecracker.sha256.clone(),
            jailer_sha256: runtime.jailer.sha256.clone(),
            device: root_identity.dev(),
            inode: root_identity.ino(),
            parent_device: root_parent.dev(),
            parent_inode: root_parent.ino(),
            firecracker_device: firecracker_identity.dev(),
            firecracker_inode: firecracker_identity.ino(),
            manifest_device: manifest_identity.dev(),
            manifest_inode: manifest_identity.ino(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn chroot_base(&self) -> &Path {
        &self.chroot_base
    }
    pub fn firecracker(&self) -> &Path {
        &self.firecracker
    }
    pub fn ownership_manifest_path(&self) -> &Path {
        &self.manifest
    }

    pub fn identity(&self) -> JailIdentity {
        JailIdentity {
            device: self.device,
            inode: self.inode,
        }
    }

    pub fn stage_manifest(&self) -> JailStageManifest {
        JailStageManifest {
            root: self.root.clone(),
            parent: self
                .root
                .parent()
                .expect("staged root parent")
                .to_path_buf(),
            firecracker: self.firecracker.clone(),
            ownership_manifest: self.manifest.clone(),
            root_identity: JailIdentity {
                device: self.device,
                inode: self.inode,
            },
            parent_identity: JailIdentity {
                device: self.parent_device,
                inode: self.parent_inode,
            },
            firecracker_identity: JailIdentity {
                device: self.firecracker_device,
                inode: self.firecracker_inode,
            },
            ownership_manifest_identity: JailIdentity {
                device: self.manifest_device,
                inode: self.manifest_inode,
            },
            firecracker_sha256: self.firecracker_sha256.clone(),
            jailer_sha256: self.jailer_sha256.clone(),
        }
    }

    /// Revalidates the staged inputs immediately before invoking jailer.
    /// Neither executable is reopened from the operator catalog at launch.
    pub fn validate_artifacts(&self) -> Result<()> {
        validate_staged(&self.firecracker, &self.firecracker_sha256)
    }

    pub fn matches_runtime(&self, runtime: &VerifiedRuntime) -> bool {
        self.firecracker_sha256 == runtime.firecracker.sha256
            && self.jailer_sha256 == runtime.jailer.sha256
    }

    pub fn remove_owned(self) -> Result<()> {
        remove_owned_manifest(&self.stage_manifest())
    }
}
