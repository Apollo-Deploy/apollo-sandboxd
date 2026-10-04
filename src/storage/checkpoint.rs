//! Filesystem checkpoints published atomically in an owned private directory.
//! The caller commits its intent and quiesces the guest before copying a drive.
use crate::{
    error::{Error, Result},
    security::path::{SecureDir, device_id},
    storage::DriveIdentity,
};
use rustix::fs::{FileType, RenameFlags};
use sandboxd_protocol::{CheckpointId, codec};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::FileExt,
    path::PathBuf,
};

#[path = "checkpoint_create.rs"]
mod create;
pub use create::CheckpointStage;

const MAX_BYTES: u64 = 64 << 30;
const DATA: &str = "drive.img";
const MANIFEST: &str = "manifest.cbor";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointManifest {
    pub version: u16,
    pub id: CheckpointId,
    pub sandbox: String,
    pub sandbox_generation: u64,
    pub source: DriveIdentity,
    pub artifact: DriveIdentity,
    pub bytes: u64,
    pub sha256: String,
}

pub struct CheckpointCatalog {
    root: SecureDir,
    _lock: File,
}
impl CheckpointCatalog {
    pub fn open(root: PathBuf) -> Result<Self> {
        let parent = SecureDir::open(root.parent().ok_or(Error::Path)?)?;
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::Path)?;
        let root = match parent.create_private_directory(name) {
            Ok(root) => root,
            Err(Error::Kernel(rustix::io::Errno::EXIST)) => parent.open_child(name)?,
            Err(error) => return Err(error),
        };
        private_directory(&root)?;
        let lock = root.lock("catalog.lock")?;
        Ok(Self { root, _lock: lock })
    }

    pub fn inspect(&self, id: &CheckpointId) -> Result<CheckpointManifest> {
        let directory = self.root.open_child(id.as_str())?;
        private_directory(&directory)?;
        read_manifest(&directory, id).map_err(|error| match error {
            Error::Kernel(rustix::io::Errno::NOENT) => Error::State,
            error => error,
        })
    }

    pub fn verify_file(&self, id: &CheckpointId) -> Result<File> {
        let directory = self.root.open_child(id.as_str())?;
        private_directory(&directory)?;
        let manifest = read_manifest(&directory, id)?;
        let file = directory
            .open_file(DATA, false)
            .map_err(|error| match error {
                Error::Kernel(rustix::io::Errno::NOENT) => Error::State,
                error => error,
            })?;
        if identity(&file)? != manifest.artifact {
            return Err(Error::Path);
        }
        verify_digest(&file, &manifest)?;
        // Recovery may observe a rename whose original directory fsync never completed.
        rustix::fs::fsync(directory.as_fd())?;
        rustix::fs::fsync(self.root.as_fd())?;
        Ok(file)
    }

    pub fn delete(&self, id: &CheckpointId) -> Result<()> {
        let tombstone = format!(".deleted-{}", id.as_str());
        let directory = match self.root.open_child(id.as_str()) {
            Ok(directory) => {
                // Validate the complete artifact before making deletion visible.
                self.verify_file(id)?;
                rustix::fs::renameat_with(
                    self.root.as_fd(),
                    id.as_str(),
                    self.root.as_fd(),
                    &tombstone,
                    RenameFlags::NOREPLACE,
                )?;
                rustix::fs::fsync(self.root.as_fd())?;
                directory
            }
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => {
                match self.root.open_child(&tombstone) {
                    Ok(directory) => directory,
                    Err(Error::Kernel(rustix::io::Errno::NOENT)) => {
                        rustix::fs::fsync(self.root.as_fd())?;
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        private_directory(&directory)?;
        let stat = rustix::fs::fstat(directory.as_fd())?;
        match read_manifest(&directory, id) {
            Ok(manifest) => {
                match directory.open_file(DATA, false) {
                    Ok(file) => {
                        if identity(&file)? != manifest.artifact {
                            return Err(Error::Path);
                        }
                        verify_digest(&file, &manifest)?;
                        directory.remove_if_identity(
                            DATA,
                            manifest.artifact.device,
                            manifest.artifact.inode,
                            FileType::RegularFile,
                        )?;
                    }
                    Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
                    Err(error) => return Err(error),
                }
                let file = directory.open_file(MANIFEST, false)?;
                let identity = identity(&file)?;
                directory.remove_if_identity(
                    MANIFEST,
                    identity.device,
                    identity.inode,
                    FileType::RegularFile,
                )?;
            }
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
            Err(error) => return Err(error),
        }
        self.root.remove_if_identity(
            &tombstone,
            device_id(stat.st_dev),
            stat.st_ino,
            FileType::Directory,
        )
    }
}

fn private_directory(directory: &SecureDir) -> Result<()> {
    let stat = rustix::fs::fstat(directory.as_fd())?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err(Error::Path);
    }
    Ok(())
}
pub(super) fn identity(file: &File) -> Result<DriveIdentity> {
    let stat = rustix::fs::fstat(file)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_size < 0
        || stat.st_nlink != 1
    {
        return Err(Error::Path);
    }
    Ok(DriveIdentity {
        device: device_id(stat.st_dev),
        inode: stat.st_ino,
        size: stat.st_size as u64,
        uid: stat.st_uid,
        gid: stat.st_gid,
    })
}
fn check_source(file: &File, expected: DriveIdentity) -> Result<()> {
    if identity(file)? != expected {
        return Err(Error::Path);
    }
    Ok(())
}
fn read_manifest(directory: &SecureDir, id: &CheckpointId) -> Result<CheckpointManifest> {
    let file = directory.open_file(MANIFEST, false)?;
    if file.metadata()?.len() > 4096 {
        return Err(Error::State);
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(Error::State);
    }
    let manifest: CheckpointManifest = codec::decode_body(&bytes)?;
    if manifest.version != 1
        || &manifest.id != id
        || manifest.sandbox_generation == 0
        || manifest.bytes > MAX_BYTES
        || manifest.bytes != manifest.artifact.size
        || manifest.sha256.len() != 64
        || !manifest
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || manifest.artifact.uid != rustix::process::geteuid().as_raw()
    {
        return Err(Error::State);
    }
    Ok(manifest)
}
pub(super) fn verify_digest(file: &File, manifest: &CheckpointManifest) -> Result<()> {
    let mut digest = Sha256::new();
    let mut offset = 0u64;
    let mut buffer = vec![0u8; 1 << 20];
    while offset < manifest.bytes {
        let length = buffer.len().min((manifest.bytes - offset) as usize);
        let count = file.read_at(&mut buffer[..length], offset)?;
        if count == 0 {
            return Err(Error::Path);
        }
        digest.update(&buffer[..count]);
        offset += count as u64;
    }
    if hex::encode(digest.finalize()) != manifest.sha256 {
        return Err(Error::State);
    }
    Ok(())
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
