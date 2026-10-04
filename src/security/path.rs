use crate::error::{Error, Result};
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags};
use std::{
    fs::File,
    os::fd::{AsFd, OwnedFd},
    path::{Component, Path},
};

/// Descriptor-relative file access under an ownership-validated directory chain.
pub struct SecureDir {
    fd: OwnedFd,
}

/// rustix uses a signed device type on macOS and u64 on Linux. Keep the
/// persisted identity representation consistent across the supported builds.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn device_id(value: rustix::fs::Dev) -> u64 {
    value as u64
}
impl SecureDir {
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(Error::Path);
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut fd = fs::open("/", flags, Mode::empty())?;
        check_directory(&fd, false)?;
        for component in path.components() {
            match component {
                Component::RootDir => (),
                Component::Normal(name) => {
                    fd = fs::openat(&fd, name, flags, Mode::empty())?;
                    check_directory(&fd, true)?;
                }
                _ => return Err(Error::Path),
            }
        }
        Ok(Self { fd })
    }
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }
    pub fn open_child(&self, name: &str) -> Result<Self> {
        check_name(name)?;
        let fd = fs::openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        check_directory(&fd, false)?;
        Ok(Self { fd })
    }
    pub fn create_private_directory(&self, name: &str) -> Result<Self> {
        check_name(name)?;
        fs::mkdirat(&self.fd, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
        fs::fsync(&self.fd)?;
        self.open_child(name)
    }
    /// Creates a private child, or reopens an existing child without changing
    /// its permissions. A pre-existing foreign or exposed object is rejected.
    pub fn ensure_private_directory(&self, name: &str) -> Result<Self> {
        let child = match self.create_private_directory(name) {
            Ok(child) => child,
            Err(Error::Kernel(rustix::io::Errno::EXIST)) => self.open_child(name)?,
            Err(error) => return Err(error),
        };
        let stat = fs::fstat(child.as_fd())?;
        if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o777 != 0o700 {
            return Err(Error::Path);
        }
        Ok(child)
    }
    pub fn is_empty(&self) -> Result<bool> {
        let mut entries = fs::Dir::read_from(&self.fd)?;
        for entry in &mut entries {
            let entry = entry?;
            if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub fn open_file(&self, name: &str, writable: bool) -> Result<File> {
        check_name(name)?;
        let access = if writable {
            OFlags::RDWR
        } else {
            OFlags::RDONLY
        };
        let fd = fs::openat(
            &self.fd,
            name,
            access | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        check_regular(&fd)?;
        Ok(File::from(fd))
    }
    /// Opens an operator-owned descriptor without imposing regular-file
    /// semantics. Used for kernel descriptor types such as nsfs; the caller
    /// must validate the returned descriptor type before use.
    pub fn open_handle(&self, name: &str) -> Result<File> {
        check_name(name)?;
        let fd = fs::openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(File::from(fd))
    }
    pub fn create_file(&self, name: &str) -> Result<File> {
        check_name(name)?;
        let fd = fs::openat(
            &self.fd,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        check_regular(&fd)?;
        fs::fsync(&self.fd)?;
        Ok(File::from(fd))
    }
    pub fn open_or_create_private(&self, name: &str) -> Result<File> {
        match self.create_file(name) {
            Ok(file) => Ok(file),
            Err(Error::Kernel(rustix::io::Errno::EXIST)) => {
                let file = self.open_file(name, true)?;
                let stat = fs::fstat(&file)?;
                if stat.st_mode & 0o077 != 0 || stat.st_uid != rustix::process::geteuid().as_raw() {
                    return Err(Error::Path);
                }
                Ok(file)
            }
            Err(error) => Err(error),
        }
    }
    pub fn lock(&self, name: &str) -> Result<File> {
        let file = self.open_or_create_private(name)?;
        fs::flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::Locked)?;
        Ok(file)
    }
    pub fn stat(&self, name: &str) -> Result<fs::Stat> {
        check_name(name)?;
        Ok(fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW)?)
    }
    pub fn remove_if_identity(
        &self,
        name: &str,
        dev: u64,
        ino: u64,
        file_type: FileType,
    ) -> Result<()> {
        let stat = self.stat(name)?;
        if device_id(stat.st_dev) != dev
            || stat.st_ino != ino
            || FileType::from_raw_mode(stat.st_mode) != file_type
        {
            return Err(Error::Path);
        }
        // Parent is not writable by untrusted principals; the daemon holds its exclusive lock.
        let flags = if file_type == FileType::Directory {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        fs::unlinkat(&self.fd, name, flags)?;
        fs::fsync(&self.fd)?;
        Ok(())
    }
}
fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.contains(['/', '\0'])
    {
        return Err(Error::Path);
    }
    Ok(())
}
fn check_directory(fd: &OwnedFd, allow_sticky: bool) -> Result<()> {
    let stat = fs::fstat(fd)?;
    let uid = rustix::process::geteuid().as_raw();
    // Root-owned sticky ancestors permit pinned private subdirectories (e.g. /tmp).
    let sticky = allow_sticky && stat.st_uid == 0 && stat.st_mode & 0o1000 != 0;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != 0 && stat.st_uid != uid)
        || (stat.st_mode & 0o022 != 0 && !sticky)
    {
        return Err(Error::Path);
    }
    Ok(())
}
fn check_regular(fd: &OwnedFd) -> Result<()> {
    let stat = fs::fstat(fd)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || (stat.st_uid != 0 && stat.st_uid != rustix::process::geteuid().as_raw())
        || stat.st_mode & 0o022 != 0
    {
        return Err(Error::Path);
    }
    Ok(())
}
