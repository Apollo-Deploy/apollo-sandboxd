//! Exact ownership checks used before accessing mounted session assets.
use super::AssetsManifest;
#[cfg(target_os = "linux")]
use super::asset_mount;
use crate::error::{Error, Result};
#[cfg(target_os = "linux")]
use crate::security::path::{SecureDir, device_id};
#[cfg(target_os = "linux")]
use rustix::fs::{FileType, Mode, OFlags};
#[cfg(target_os = "linux")]
use std::{os::fd::AsRawFd, path::Path};

#[cfg(target_os = "linux")]
pub(super) fn open_root(manifest: &AssetsManifest) -> Result<std::os::fd::OwnedFd> {
    if manifest.mount_namespace_identity != Some(asset_mount::current_namespace_identity()?) {
        return Err(Error::Path);
    }
    let session_path = manifest.root.parent().ok_or(Error::Path)?;
    let anchor_path = session_path.parent().ok_or(Error::Path)?;
    let anchor_identity = manifest.mount_anchor_identity.ok_or(Error::Path)?;
    let anchor_id = manifest.mount_anchor_id.ok_or(Error::Path)?;
    let root_id = manifest.root_mount_id.ok_or(Error::Path)?;

    let anchor = SecureDir::open(anchor_path)?;
    require_directory(&rustix::fs::fstat(anchor.as_fd())?, anchor_identity)?;
    let anchor_target = format!("/proc/self/fd/{}/.", anchor.as_fd().as_raw_fd());
    if asset_mount::observed_id(Path::new(&anchor_target))? != anchor_id {
        return Err(Error::Path);
    }
    asset_mount::require_private(anchor_id)?;

    let session_name = session_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::Path)?;
    let session = anchor.open_child(session_name)?;
    require_directory(
        &rustix::fs::fstat(session.as_fd())?,
        manifest.session_identity.ok_or(Error::Path)?,
    )?;
    let root = rustix::fs::openat(
        session.as_fd(),
        "root",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    require_directory(&rustix::fs::fstat(&root)?, manifest.root_identity)?;
    let root_target = format!("/proc/self/fd/{}/.", root.as_raw_fd());
    if asset_mount::observed_id(Path::new(&root_target))? != root_id {
        return Err(Error::Path);
    }
    asset_mount::require_private(root_id)?;
    Ok(root)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn open_root(_manifest: &AssetsManifest) -> Result<std::os::fd::OwnedFd> {
    Err(Error::Config("asset verification requires Linux"))
}

#[cfg(target_os = "linux")]
fn require_directory(stat: &rustix::fs::Stat, expected: super::AssetIdentity) -> Result<()> {
    if device_id(stat.st_dev) != expected.device
        || stat.st_ino != expected.inode
        || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
    {
        return Err(Error::Path);
    }
    Ok(())
}
