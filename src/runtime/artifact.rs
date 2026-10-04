use crate::{
    error::{Error, Result},
    security::path::{SecureDir, device_id},
};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::{fs::File, os::unix::fs::FileExt, path::Path};

const MAX_ARTIFACT_BYTES: u64 = 4 << 30;

/// Holds the verified inode open. Execution must use this handle, not reopen an unchecked path.
pub struct VerifiedArtifact {
    pub file: File,
    pub sha256: String,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    executable: bool,
}

impl VerifiedArtifact {
    /// Duplicate the pinned descriptor without reopening its operator path.
    /// Runtime workers use this to move a short lived launch snapshot out of
    /// the startup catalog before awaiting boot I/O.
    pub fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            sha256: self.sha256.clone(),
            device: self.device,
            inode: self.inode,
            size: self.size,
            executable: self.executable,
        })
    }

    /// Re-checks the open inode and digest before handing it to an executor.
    /// The path is deliberately not reopened, so a replacement pathname cannot
    /// redirect execution to a different file.
    pub fn revalidate(&mut self) -> Result<()> {
        let before = rustix::fs::fstat(&self.file)?;
        if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
            || before.st_nlink != 1
            || device_id(before.st_dev) != self.device
            || before.st_ino != self.inode
            || before.st_size as u64 != self.size
            || before.st_size <= 0
            || before.st_size as u64 > MAX_ARTIFACT_BYTES
            || before.st_uid != 0
            || before.st_mode & 0o222 != 0
            || (self.executable && before.st_mode & 0o111 == 0)
        {
            return Err(Error::Artifact("verified artifact identity changed"));
        }
        let mut hash = Sha256::new();
        let mut buffer = [0; 65_536];
        let mut offset = 0;
        loop {
            let count = self.file.read_at(&mut buffer, offset)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            offset += count as u64;
        }
        let after = rustix::fs::fstat(&self.file)?;
        if rustix::fs::FileType::from_raw_mode(after.st_mode) != rustix::fs::FileType::RegularFile
            || after.st_nlink != 1
            || after.st_uid != 0
            || after.st_mode & 0o222 != 0
            || (self.executable && after.st_mode & 0o111 == 0)
            || after.st_dev != before.st_dev
            || after.st_ino != before.st_ino
            || after.st_size != before.st_size
            || after.st_mtime != before.st_mtime
            || after.st_ctime != before.st_ctime
            || hex::encode(hash.finalize()) != self.sha256
        {
            return Err(Error::Artifact("verified artifact digest changed"));
        }
        Ok(())
    }

    /// Duplicates the pinned descriptor for a child setup operation.
    pub fn try_clone(&self) -> Result<File> {
        Ok(self.file.try_clone()?)
    }

    /// Returns the procfs handle path used only for an immediate version check.
    /// Production launchers should use a copied, verified jail input and invoke
    /// `revalidate` immediately before the external effect.
    #[cfg(target_os = "linux")]
    pub fn proc_fd_path(&self) -> String {
        format!("/proc/self/fd/{}", self.file.as_raw_fd())
    }
}
pub fn verify(path: &Path, expected: &str, executable: bool) -> Result<VerifiedArtifact> {
    let parent = SecureDir::open(path.parent().ok_or(Error::Path)?)?;
    let file = parent.open_file(
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or(Error::Path)?,
        false,
    )?;
    let before = rustix::fs::fstat(&file)?;
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        || before.st_nlink != 1
        || before.st_uid != 0
        || before.st_mode & 0o222 != 0
        || (executable && before.st_mode & 0o111 == 0)
        || before.st_size <= 0
        || before.st_size as u64 > MAX_ARTIFACT_BYTES
    {
        return Err(Error::Artifact(
            "artifact must be root-owned, immutable to ordinary writers, and have correct permissions",
        ));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65_536];
    let mut offset = 0;
    loop {
        let count = file.read_at(&mut buffer, offset)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    let after = rustix::fs::fstat(&file)?;
    if before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_ctime != after.st_ctime
        || before.st_ino != after.st_ino
        || before.st_dev != after.st_dev
    {
        return Err(Error::Artifact("artifact changed during verification"));
    }
    let sha256 = hex::encode(hash.finalize());
    if expected.len() != 64 || sha256 != expected {
        return Err(Error::Artifact("artifact digest mismatch"));
    }
    Ok(VerifiedArtifact {
        file,
        sha256,
        device: device_id(before.st_dev),
        inode: before.st_ino,
        size: before.st_size as u64,
        executable,
    })
}
