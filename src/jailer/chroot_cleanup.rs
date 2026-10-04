//! Ownership-fenced staged runtime cleanup and crash discovery.
use super::cgroup::validate_component;
use super::chroot::{JailIdentity, JailStageManifest};
use super::chroot_artifact::validate_staged;
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
};

pub(crate) fn remove_owned_manifest(stage: &JailStageManifest) -> Result<()> {
    let meta = match fs::symlink_metadata(&stage.root) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !meta.is_dir()
        || (meta.uid() != 0 && meta.uid() != rustix::process::geteuid().as_raw())
        || meta.dev() != stage.root_identity.device
        || meta.ino() != stage.root_identity.inode
    {
        return Err(Error::Path);
    }
    let parent_meta = fs::symlink_metadata(&stage.parent)?;
    if !parent_meta.is_dir()
        || parent_meta.dev() != stage.parent_identity.device
        || parent_meta.ino() != stage.parent_identity.inode
    {
        return Err(Error::Path);
    }
    let root_dir = SecureDir::open(&stage.root)?;
    if let Some(manifest) = child_meta(&stage.ownership_manifest)? {
        if !manifest.is_file()
            || manifest.file_type().is_symlink()
            || manifest.dev() != stage.ownership_manifest_identity.device
            || manifest.ino() != stage.ownership_manifest_identity.inode
        {
            return Err(Error::Path);
        }
        let mut manifest_text = String::new();
        root_dir
            .open_file("ownership.manifest", false)?
            .take(4097)
            .read_to_string(&mut manifest_text)?;
        if manifest_text.len() > 4096
            || !manifest_text.contains(&format!(
                "firecracker_sha256={}\n",
                stage.firecracker_sha256
            ))
            || !manifest_text.contains(&format!("jailer_sha256={}\n", stage.jailer_sha256))
        {
            return Err(Error::Path);
        }
        remove_child(
            &root_dir,
            "ownership.manifest",
            stage.ownership_manifest_identity,
            rustix::fs::FileType::RegularFile,
        )?;
    }
    if let Some(binary) = child_meta(&stage.firecracker)? {
        if !binary.is_file()
            || binary.file_type().is_symlink()
            || binary.nlink() != 1
            || binary.dev() != stage.firecracker_identity.device
            || binary.ino() != stage.firecracker_identity.inode
        {
            return Err(Error::Path);
        }
        validate_staged(&stage.firecracker, &stage.firecracker_sha256)?;
        remove_child(
            &root_dir,
            "firecracker",
            stage.firecracker_identity,
            rustix::fs::FileType::RegularFile,
        )?;
    }
    drop(root_dir);
    let parent_dir = SecureDir::open(&stage.parent)?;
    remove_child(
        &parent_dir,
        stage
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::Path)?,
        stage.root_identity,
        rustix::fs::FileType::Directory,
    )?;
    Ok(())
}

fn child_meta(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn remove_child(
    dir: &SecureDir,
    name: &str,
    identity: JailIdentity,
    kind: rustix::fs::FileType,
) -> Result<()> {
    match dir.remove_if_identity(name, identity.device, identity.inode, kind) {
        Ok(()) => Ok(()),
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Reconstructs a staged identity after a crash before its callback was
/// committed. The ownership token and exact catalog digests are required.
pub(crate) fn recover_stage_manifest(
    root: &Path,
    session: &str,
    firecracker_sha256: &str,
    jailer_sha256: &str,
) -> Result<JailStageManifest> {
    validate_component(session)?;
    let expected_parent = root.parent().ok_or(Error::Path)?;
    let expected_root = expected_parent.join(session);
    if *root != expected_root {
        return Err(Error::Path);
    }
    let parent = expected_parent;
    let root_meta = fs::symlink_metadata(root)?;
    let parent_meta = fs::symlink_metadata(parent)?;
    if !root_meta.is_dir()
        || root_meta.file_type().is_symlink()
        || !parent_meta.is_dir()
        || parent_meta.file_type().is_symlink()
    {
        return Err(Error::Path);
    }
    let firecracker = root.join("firecracker");
    let ownership_manifest = root.join("ownership.manifest");
    let binary_meta = fs::symlink_metadata(&firecracker)?;
    let manifest_meta = fs::symlink_metadata(&ownership_manifest)?;
    if !binary_meta.is_file()
        || binary_meta.nlink() != 1
        || !manifest_meta.is_file()
        || manifest_meta.file_type().is_symlink()
    {
        return Err(Error::Path);
    }
    let mut token = String::new();
    File::open(&ownership_manifest)?
        .take(4097)
        .read_to_string(&mut token)?;
    if token.len() > 4096
        || !token.contains(&format!("session={session}\n"))
        || !token.contains(&format!("firecracker_sha256={firecracker_sha256}\n"))
        || !token.contains(&format!("jailer_sha256={jailer_sha256}\n"))
    {
        return Err(Error::Path);
    }
    validate_staged(&firecracker, firecracker_sha256)?;
    Ok(JailStageManifest {
        root: root.to_path_buf(),
        parent: parent.to_path_buf(),
        firecracker,
        ownership_manifest,
        root_identity: JailIdentity {
            device: root_meta.dev(),
            inode: root_meta.ino(),
        },
        parent_identity: JailIdentity {
            device: parent_meta.dev(),
            inode: parent_meta.ino(),
        },
        firecracker_identity: JailIdentity {
            device: binary_meta.dev(),
            inode: binary_meta.ino(),
        },
        ownership_manifest_identity: JailIdentity {
            device: manifest_meta.dev(),
            inode: manifest_meta.ino(),
        },
        firecracker_sha256: firecracker_sha256.to_owned(),
        jailer_sha256: jailer_sha256.to_owned(),
    })
}
