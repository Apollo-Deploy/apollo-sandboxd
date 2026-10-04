//! Recovery of asset setup interrupted before a complete assets manifest was saved.
use super::asset_setup::AssetSetupEntry;
use super::{AssetIdentity, AssetSetup, asset_mount};
use crate::{
    error::{Error, Result},
    security::path::{SecureDir, device_id},
};
use rustix::fs::{self, AtFlags, FileType};
use std::{
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

/// Removes only the session tree described by its durable progress record.
/// A bind whose mount ID was not recorded is recognized by its source inode
/// and by its difference from the recorded root mount.
pub(crate) fn recover_setup(setup: &AssetSetup) -> Result<()> {
    setup.validate(&setup.root)?;
    if setup.mount_namespace_identity != asset_mount::current_namespace_identity()? {
        return Err(Error::Path);
    }
    let session_path = setup.root.parent().ok_or(Error::Path)?;
    let anchor_path = session_path.parent().ok_or(Error::Path)?;
    let anchor = SecureDir::open(anchor_path)?;
    check_identity(&fs::fstat(anchor.as_fd())?, setup.anchor_identity)?;
    if asset_mount::observed_id(anchor_path)? != setup.anchor_mount_id {
        return Err(Error::Path);
    }
    asset_mount::require_private(setup.anchor_mount_id)?;

    let session_name = session_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::Path)?;
    let session = match anchor.open_child(session_name) {
        Ok(session) => session,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let session_stat = fs::fstat(session.as_fd())?;
    verify_directory(&session_stat, setup.session_identity)?;
    let root = match session.open_child("root") {
        Ok(root) => Some(root),
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => None,
        Err(error) => return Err(error),
    };
    let Some(root) = root else {
        if !session.is_empty()? {
            return Err(Error::Path);
        }
        remove_directory(&anchor, session_name, setup.session_identity)?;
        return Ok(());
    };
    let root_stat = fs::fstat(root.as_fd())?;
    verify_directory(&root_stat, setup.root_identity)?;

    let root_path = setup.root.as_path();
    let observed_root_mount = asset_mount::observed_id(root_path)?;
    let root_parent_mount = setup.root_parent_mount_id.unwrap_or(setup.anchor_mount_id);
    if root_parent_mount != setup.anchor_mount_id {
        return Err(Error::Path);
    }
    let root_mount_id = setup.root_mount_id;
    let root_is_mounted = match root_mount_id {
        Some(expected) if observed_root_mount == expected => {
            asset_mount::require_private(expected)?;
            true
        }
        Some(_) if observed_root_mount == root_parent_mount => false,
        Some(_) => return Err(Error::Path),
        None if observed_root_mount == root_parent_mount => false,
        None => {
            asset_mount::require_private(observed_root_mount)?;
            true
        }
    };

    if root_is_mounted {
        if let Some(root_mount_id) = root_mount_id {
            for asset in setup.assets.iter().rev() {
                recover_asset(&root, asset, root_mount_id)?;
            }
        } else {
            ensure_assets_absent(&root, setup)?;
        }
    } else {
        // The root bind is detached only after all asset mounts and their
        // placeholders are removed, so remaining progress here is ambiguous.
        ensure_assets_absent(&root, setup)?;
    }

    remove_run(&root, setup.run_identity)?;
    if root_is_mounted {
        let target = fd_path(root.as_fd().as_raw_fd(), ".");
        if asset_mount::observed_id(&target)? != observed_root_mount {
            return Err(Error::Path);
        }
        asset_mount::unmount(&target)?;
    }
    remove_directory(&session, "root", setup.root_identity)?;
    if !session.is_empty()? {
        return Err(Error::Path);
    }
    let session_identity = setup.session_identity.or(Some(identity(&session_stat)));
    remove_directory(&anchor, session_name, session_identity)?;
    Ok(())
}

fn recover_asset(root: &SecureDir, asset: &AssetSetupEntry, root_mount_id: u64) -> Result<()> {
    let name = asset
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::Path)?;
    let stat = match root.stat(name) {
        Ok(stat) => stat,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
        Err(error) => return Err(error),
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(Error::Path);
    }
    let target = fd_path(root.as_fd().as_raw_fd(), name);
    let observed_mount = asset_mount::observed_id(&target)?;
    if observed_mount != root_mount_id {
        let observed_identity = AssetIdentity {
            device: device_id(stat.st_dev),
            inode: stat.st_ino,
        };
        if observed_identity != asset.source_identity
            || asset
                .mount_id
                .is_some_and(|expected| expected != observed_mount)
        {
            return Err(Error::Path);
        }
        asset_mount::require_private(observed_mount)?;
        asset_mount::unmount(&target)?;
    }

    let placeholder = root.stat(name)?;
    let observed = AssetIdentity {
        device: device_id(placeholder.st_dev),
        inode: placeholder.st_ino,
    };
    if FileType::from_raw_mode(placeholder.st_mode) != FileType::RegularFile
        || placeholder.st_nlink != 1
        || placeholder.st_size != 0
        || placeholder.st_uid != rustix::process::geteuid().as_raw()
        || placeholder.st_mode & 0o777 != 0o600
        || asset
            .placeholder_identity
            .is_some_and(|expected| expected != observed)
    {
        return Err(Error::Path);
    }
    fs::unlinkat(root.as_fd(), name, AtFlags::empty())?;
    fs::fsync(root.as_fd())?;
    Ok(())
}

fn remove_run(root: &SecureDir, expected: Option<AssetIdentity>) -> Result<()> {
    let stat = match root.stat("run") {
        Ok(stat) => stat,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let run = root.open_child("run")?;
    verify_directory(&fs::fstat(run.as_fd())?, expected)?;
    if !run.is_empty()? {
        return Err(Error::Path);
    }
    let actual = expected.or(Some(identity(&stat)));
    remove_directory(root, "run", actual)
}

fn path_exists(root: &SecureDir, path: &Path) -> Result<bool> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::Path)?;
    match root.stat(name) {
        Ok(_) => Ok(true),
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => Ok(false),
        Err(error) => Err(error),
    }
}

fn ensure_assets_absent(root: &SecureDir, setup: &AssetSetup) -> Result<()> {
    for asset in &setup.assets {
        if path_exists(root, &asset.path)? {
            return Err(Error::Path);
        }
    }
    Ok(())
}

fn remove_directory(parent: &SecureDir, name: &str, expected: Option<AssetIdentity>) -> Result<()> {
    let stat = parent.stat(name)?;
    verify_directory(&stat, expected)?;
    let actual = expected.unwrap_or_else(|| identity(&stat));
    parent.remove_if_identity(name, actual.device, actual.inode, FileType::Directory)
}

fn verify_directory(stat: &fs::Stat, expected: Option<AssetIdentity>) -> Result<()> {
    let actual = identity(stat);
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o777 != 0o700
        || expected.is_some_and(|expected| expected != actual)
    {
        return Err(Error::Path);
    }
    Ok(())
}

fn check_identity(stat: &fs::Stat, expected: AssetIdentity) -> Result<()> {
    if identity(stat) != expected {
        return Err(Error::Path);
    }
    Ok(())
}

fn identity(stat: &fs::Stat) -> AssetIdentity {
    AssetIdentity {
        device: device_id(stat.st_dev),
        inode: stat.st_ino,
    }
}

fn fd_path(fd: i32, name: &str) -> PathBuf {
    Path::new(&format!("/proc/self/fd/{fd}/{name}")).to_path_buf()
}

#[cfg(all(test, target_os = "linux"))]
#[path = "asset_recovery_tests.rs"]
mod tests;
