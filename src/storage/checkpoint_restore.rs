//! Restore replaces only the recorded state inode; a durable prepared identity closes the rename crash window.
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
    storage::{CheckpointCatalog, DriveIdentity},
};
use rustix::fs::{Mode, OFlags};
use sandboxd_protocol::{CheckpointId, OperationId, VolumeId};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

pub(crate) fn open_drive(root: &Path, volume: &VolumeId, expected: DriveIdentity) -> Result<File> {
    let directory = SecureDir::open(root)?;
    let file = open(&directory, &name(volume))?;
    if super::checkpoint::identity(&file)? != expected {
        return Err(Error::Path);
    }
    Ok(file)
}
fn name(volume: &VolumeId) -> String {
    format!("volume-{}.ext4", volume.as_str())
}
fn temporary(operation: &OperationId) -> String {
    format!(
        ".restore-{}",
        hex::encode(Sha256::digest(operation.as_str().as_bytes()))
    )
}
fn open(directory: &SecureDir, name: &str) -> Result<File> {
    Ok(File::from(rustix::fs::openat(
        directory.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?))
}
impl CheckpointCatalog {
    pub(crate) fn restore(
        &self,
        id: &CheckpointId,
        root: &Path,
        volume: &VolumeId,
        old: DriveIdentity,
        operation: &OperationId,
        prepared: Option<DriveIdentity>,
        record: impl FnOnce(DriveIdentity) -> Result<()>,
    ) -> Result<DriveIdentity> {
        let directory = SecureDir::open(root)?;
        let stat = rustix::fs::fstat(directory.as_fd())?;
        if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
            return Err(Error::Path);
        }
        let target = name(volume);
        let temporary = temporary(operation);
        let current = open(&directory, &target)?;
        let current_identity = super::checkpoint::identity(&current)?;
        if let Some(prepared) = prepared {
            if current_identity == prepared {
                self.verify_restored(id, &current)?;
                rustix::fs::fsync(directory.as_fd())?;
                return Ok(prepared);
            }
        }
        if current_identity != old {
            return Err(Error::Path);
        }
        let staged = match open(&directory, &temporary) {
            Ok(file) => Some(file),
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => None,
            Err(error) => return Err(error),
        };
        let replacement = if let Some(file) = staged {
            let prepared = prepared.ok_or(Error::State)?;
            if super::checkpoint::identity(&file)? != prepared {
                return Err(Error::Path);
            }
            self.verify_restored(id, &file)?;
            prepared
        } else {
            let mut source = self.verify_file(id)?;
            let manifest = self.inspect(id)?;
            if manifest.bytes != old.size {
                return Err(Error::State);
            }
            #[cfg(target_os = "linux")]
            let mut file = File::from(rustix::fs::openat(
                directory.as_fd(),
                ".",
                OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?);
            #[cfg(not(target_os = "linux"))]
            let mut file = directory.create_file(&temporary)?;
            // This staging inode is private and unpublished until its identity commits.
            let result = (|| {
                let mut buffer = vec![0u8; 1 << 20];
                let mut length = 0u64;
                loop {
                    let n = source.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    if buffer[..n].iter().all(|b| *b == 0) {
                        file.seek(SeekFrom::Current(n as i64))?;
                    } else {
                        file.write_all(&buffer[..n])?;
                    }
                    length = length.checked_add(n as u64).ok_or(Error::State)?;
                    if length > old.size {
                        return Err(Error::State);
                    }
                }
                if length != old.size {
                    return Err(Error::State);
                }
                file.set_len(length)?;
                rustix::fs::fchown(
                    &file,
                    Some(rustix::process::Uid::from_raw(old.uid)),
                    Some(rustix::process::Gid::from_raw(old.gid)),
                )?;
                file.sync_all()?;
                self.verify_restored(id, &file)?;
                let stat = rustix::fs::fstat(&file)?;
                let identity = DriveIdentity {
                    device: crate::security::path::device_id(stat.st_dev),
                    inode: stat.st_ino,
                    size: stat.st_size as u64,
                    uid: stat.st_uid,
                    gid: stat.st_gid,
                };
                rustix::fs::fsync(directory.as_fd())?;
                record(identity)?;
                #[cfg(target_os = "linux")]
                {
                    use std::os::fd::AsRawFd;
                    let source = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
                    rustix::fs::linkat(
                        rustix::fs::CWD,
                        &source,
                        directory.as_fd(),
                        &temporary,
                        rustix::fs::AtFlags::SYMLINK_FOLLOW,
                    )?;
                }
                rustix::fs::fsync(directory.as_fd())?;
                Ok(identity)
            })();
            // On failure preserve the inode: the durable callback may have committed before its reply was lost.
            result?
        };
        if super::checkpoint::identity(&open(&directory, &target)?)? != old {
            return Err(Error::Path);
        }
        rustix::fs::renameat(directory.as_fd(), &temporary, directory.as_fd(), &target)?;
        rustix::fs::fsync(directory.as_fd())?;
        let file = open(&directory, &target)?;
        if super::checkpoint::identity(&file)? != replacement {
            return Err(Error::Path);
        }
        self.verify_restored(id, &file)?;
        Ok(replacement)
    }
    fn verify_restored(&self, id: &CheckpointId, file: &File) -> Result<()> {
        let manifest = self.inspect(id)?;
        if file.metadata()?.len() != manifest.bytes {
            return Err(Error::State);
        }
        super::checkpoint::verify_digest(file, &manifest)
    }
}
