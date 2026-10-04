//! Ownership records are committed before ciphertext writes or publication.
use super::{ArtifactContext, ArtifactKind, SnapshotManifest};
use crate::{
    error::{Error, Result},
    security::path::{SecureDir, device_id},
};
use rustix::fs::FileType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::FileExt,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedArtifact {
    pub device: u64,
    pub inode: u64,
    pub plain_bytes: u64,
    pub plain_sha256: String,
    pub cipher_bytes: u64,
    pub cipher_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotArtifacts {
    pub version: u16,
    pub context: ArtifactContext,
    pub stage_name: String,
    pub directory: DirectoryIdentity,
    pub memory: Option<EncryptedArtifact>,
    pub state: Option<EncryptedArtifact>,
    pub manifest: Option<EncryptedArtifact>,
}
impl SnapshotArtifacts {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.context.kind != ArtifactKind::Manifest
            || !self
                .stage_name
                .starts_with(&format!(".snapshot-{}-", self.context.snapshot))
            || self.stage_name.len() > 180
            || self.stage_name.contains(['/', '\0'])
        {
            return Err(Error::State);
        }
        for (kind, item) in [
            (ArtifactKind::Memory, &self.memory),
            (ArtifactKind::State, &self.state),
            (ArtifactKind::Manifest, &self.manifest),
        ] {
            if let Some(item) = item {
                let limit = match kind {
                    ArtifactKind::Memory => 1 << 40,
                    ArtifactKind::State => 64 << 20,
                    ArtifactKind::Manifest => 256 << 10,
                };
                if item.plain_bytes == 0
                    || item.plain_bytes > limit
                    || item.cipher_bytes != cipher_size(item.plain_bytes)?
                    || !valid_digest(&item.plain_sha256)
                    || item
                        .cipher_sha256
                        .as_ref()
                        .is_some_and(|s| !valid_digest(s))
                {
                    return Err(Error::State);
                }
            }
        }
        Ok(())
    }
    pub fn matches(&self, manifest: &SnapshotManifest) -> bool {
        self.context.snapshot == manifest.id
            && self.context.sandbox == manifest.sandbox
            && self.context.sandbox_generation == manifest.sandbox_generation
            && self.context.session == manifest.session
            && self.context.session_generation == manifest.session_generation
    }
}
pub(super) fn cipher_size(size: u64) -> Result<u64> {
    size.checked_add(
        size.div_ceil(65536)
            .checked_add(1)
            .and_then(|n| n.checked_mul(16))
            .ok_or(Error::State)?,
    )
    .and_then(|n| n.checked_add(36))
    .ok_or(Error::State)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn directory_identity(directory: &SecureDir) -> Result<DirectoryIdentity> {
    let stat = rustix::fs::fstat(directory.as_fd())?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o777 != 0o700 {
        return Err(Error::Path);
    }
    Ok(DirectoryIdentity {
        device: device_id(stat.st_dev),
        inode: stat.st_ino,
    })
}
pub(super) fn file_identity(
    file: &File,
    plain_bytes: u64,
    plain_sha256: String,
) -> Result<EncryptedArtifact> {
    let stat = rustix::fs::fstat(file)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o777 != 0o600
    {
        return Err(Error::Path);
    }
    Ok(EncryptedArtifact {
        device: device_id(stat.st_dev),
        inode: stat.st_ino,
        plain_bytes,
        plain_sha256,
        cipher_bytes: cipher_size(plain_bytes)?,
        cipher_sha256: None,
    })
}
pub(super) fn verify_cipher(file: &mut File, expected: &EncryptedArtifact) -> Result<()> {
    verify_inode(file, expected)?;
    if file.metadata()?.len() != expected.cipher_bytes
        || expected.cipher_sha256.as_deref() != Some(&digest(file, expected.cipher_bytes)?)
    {
        return Err(Error::State);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}
pub(super) fn verify_inode(file: &File, expected: &EncryptedArtifact) -> Result<()> {
    let current = file_identity(file, expected.plain_bytes, expected.plain_sha256.clone())?;
    if current.device != expected.device || current.inode != expected.inode {
        return Err(Error::Path);
    }
    Ok(())
}
pub(super) fn digest(file: &File, size: u64) -> Result<String> {
    if file.metadata()?.len() != size {
        return Err(Error::State);
    }
    let mut reader = PositionalReader { file, offset: 0 };
    let mut buffer = vec![0; 65536];
    let mut hash = Sha256::new();
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    if reader.offset != size {
        return Err(Error::State);
    }
    Ok(hex::encode(hash.finalize()))
}
pub(super) struct PositionalReader<'a> {
    pub file: &'a File,
    pub offset: u64,
}
impl Read for PositionalReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.file.read_at(buffer, self.offset)?;
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| std::io::Error::other("snapshot input overflow"))?;
        Ok(count)
    }
}
