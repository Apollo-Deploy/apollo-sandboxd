//! Snapshot keys never occur in manifests, Debug output, or durable receipts.
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use std::{io::Read, os::unix::fs::MetadataExt, path::Path};
use zeroize::Zeroizing;

pub struct SnapshotKey(Zeroizing<[u8; 32]>);
impl SnapshotKey {
    pub(super) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
    #[cfg(test)]
    pub(super) fn fixture(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// A generic provider may fetch keys from another local source without
/// snapshot storage acquiring a dependency on that provider's implementation.
pub trait KeyProvider: Send + Sync {
    fn key(&self) -> Result<SnapshotKey>;
}

pub struct LocalKey {
    key: SnapshotKey,
}
impl LocalKey {
    /// Keys must be installed explicitly, separately from snapshot storage.
    /// An absent, empty or truncated key is never silently regenerated.
    pub fn open(path: &Path) -> Result<Self> {
        let parent = SecureDir::open(path.parent().ok_or(Error::Path)?)?;
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(Error::Path)?;
        let mut file = parent.open_file(name, false)?;
        let metadata = file.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() != 32
        {
            return Err(Error::Config(
                "snapshot key must be an owned private 32-byte file",
            ));
        }
        let mut bytes = Zeroizing::new([0; 32]);
        file.read_exact(&mut *bytes)?;
        Ok(Self {
            key: SnapshotKey(bytes),
        })
    }
}
impl KeyProvider for LocalKey {
    fn key(&self) -> Result<SnapshotKey> {
        Ok(SnapshotKey(Zeroizing::new(*self.key.bytes())))
    }
}
