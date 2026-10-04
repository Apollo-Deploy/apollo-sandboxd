//! Teardown below pinned session, root and run directory identities.
use super::{AssetIdentity, AssetsManifest};
use crate::{
    error::{Error, Result},
    security::path::{SecureDir, device_id},
};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use std::{
    os::fd::{AsFd, OwnedFd},
    path::Path,
};

fn session(assets: &AssetsManifest) -> Result<Option<SecureDir>> {
    let parent = match SecureDir::open(assets.root.parent().ok_or(Error::Path)?) {
        Ok(parent) => parent,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let stat = fs::fstat(parent.as_fd())?;
    matches_identity(
        &stat,
        assets.session_identity.ok_or(Error::Path)?,
        FileType::Directory,
    )?;
    Ok(Some(parent))
}

fn matches_identity(stat: &fs::Stat, identity: AssetIdentity, kind: FileType) -> Result<()> {
    if device_id(stat.st_dev) != identity.device
        || stat.st_ino != identity.inode
        || FileType::from_raw_mode(stat.st_mode) != kind
    {
        return Err(Error::Path);
    }
    Ok(())
}

fn open_directory(parent: impl AsFd, name: &str, expected: AssetIdentity) -> Result<OwnedFd> {
    let fd = fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    matches_identity(&fs::fstat(&fd)?, expected, FileType::Directory)?;
    Ok(fd)
}

pub(super) fn remove_socket(
    path: &Path,
    expected: Option<AssetIdentity>,
    assets: &AssetsManifest,
) -> Result<()> {
    if path.parent() != Some(assets.root.join("run").as_path()) {
        return Err(Error::Path);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::Path)?;
    if !matches!(name, "firecracker.socket" | "vsock.socket") {
        return Err(Error::Path);
    }
    let Some(parent) = session(assets)? else {
        return Ok(());
    };
    let root = match open_directory(parent.as_fd(), "root", assets.root_identity) {
        Ok(root) => root,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let run = match open_directory(&root, "run", assets.run_identity.ok_or(Error::Path)?) {
        Ok(run) => run,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let stat = match fs::statat(&run, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    matches_identity(&stat, expected.ok_or(Error::Path)?, FileType::Socket)?;
    fs::unlinkat(&run, name, AtFlags::empty())?;
    fs::fsync(&run)?;
    Ok(())
}

pub(super) fn remove_empty_directories(assets: &AssetsManifest) -> Result<()> {
    let Some(parent) = session(assets)? else {
        return Ok(());
    };
    match open_directory(parent.as_fd(), "root", assets.root_identity) {
        Ok(root) => {
            match fs::statat(&root, "run", AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => {
                    matches_identity(
                        &stat,
                        assets.run_identity.ok_or(Error::Path)?,
                        FileType::Directory,
                    )?;
                    fs::unlinkat(&root, "run", AtFlags::REMOVEDIR)?;
                    fs::fsync(&root)?;
                }
                Err(rustix::io::Errno::NOENT) => (),
                Err(error) => return Err(error.into()),
            }
            parent.remove_if_identity(
                "root",
                assets.root_identity.device,
                assets.root_identity.inode,
                FileType::Directory,
            )?;
        }
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
        Err(error) => return Err(error),
    }
    let path = assets.root.parent().ok_or(Error::Path)?;
    let outer = SecureDir::open(path.parent().ok_or(Error::Path)?)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::Path)?;
    let expected = assets.session_identity.ok_or(Error::Path)?;
    outer.remove_if_identity(name, expected.device, expected.inode, FileType::Directory)
}
