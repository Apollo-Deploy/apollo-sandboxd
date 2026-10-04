//! Ciphertext-only owned local storage. The Store supplies trusted identities.
use super::{ArtifactKind, KeyProvider, SnapshotArtifacts, SnapshotManifest, artifact::*};
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use std::{fs::File, path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

pub struct SnapshotCatalog {
    pub(super) root: SecureDir,
    pub(super) keys: Arc<dyn KeyProvider>,
    _lock: File,
}
pub struct VerifiedSnapshot {
    pub manifest: SnapshotManifest,
    pub memory: File,
    pub state: File,
}
impl SnapshotCatalog {
    pub fn open(path: PathBuf, keys: Arc<dyn KeyProvider>) -> Result<Self> {
        #[cfg(target_os = "linux")]
        super::validate_memory_policy()?;
        // Fail before READY if the key source is unavailable.
        keys.key()?;
        let parent = SecureDir::open(path.parent().ok_or(Error::Path)?)?;
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(Error::Path)?;
        let root = match parent.create_private_directory(name) {
            Ok(root) => root,
            Err(Error::Kernel(rustix::io::Errno::EXIST)) => parent.open_child(name)?,
            Err(error) => return Err(error),
        };
        directory_identity(&root)?;
        let lock = root.lock("catalog.lock")?;
        Ok(Self {
            root,
            keys,
            _lock: lock,
        })
    }
    pub(super) fn owned_directory(
        &self,
        record: &SnapshotArtifacts,
        name: &str,
    ) -> Result<SecureDir> {
        record.validate()?;
        let directory = self.root.open_child(name)?;
        if directory_identity(&directory)? != record.directory {
            return Err(Error::Path);
        }
        Ok(directory)
    }
    pub fn verify(&self, record: &SnapshotArtifacts) -> Result<SnapshotManifest> {
        let directory = self.owned_directory(record, record.context.snapshot.as_str())?;
        self.verify_directory(&directory, record)
    }
    pub(super) fn verify_directory(
        &self,
        directory: &SecureDir,
        record: &SnapshotArtifacts,
    ) -> Result<SnapshotManifest> {
        record.validate()?;
        let expected = record.manifest.as_ref().ok_or(Error::State)?;
        let mut file = directory.open_file("manifest.enc", false)?;
        verify_cipher(&mut file, expected)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(expected.plain_bytes as usize));
        let digest = super::encryption::decrypt_stream(
            &mut file,
            &mut *bytes,
            &self.keys.key()?,
            &record.context,
            expected.plain_bytes,
        )?;
        if digest != expected.plain_sha256 || bytes.len() as u64 != expected.plain_bytes {
            return Err(Error::State);
        }
        let manifest: SnapshotManifest = sandboxd_protocol::codec::decode_body(&bytes)?;
        manifest.validate()?;
        if !record.matches(&manifest) {
            return Err(Error::State);
        }
        for (name, artifact, bytes, digest) in [
            (
                "memory.enc",
                &record.memory,
                manifest.memory_bytes,
                &manifest.memory_sha256,
            ),
            (
                "state.enc",
                &record.state,
                manifest.state_bytes,
                &manifest.state_sha256,
            ),
        ] {
            let expected = artifact.as_ref().ok_or(Error::State)?;
            if expected.plain_bytes != bytes || &expected.plain_sha256 != digest {
                return Err(Error::State);
            }
            verify_cipher(&mut directory.open_file(name, false)?, expected)?;
        }
        // Recovery may see the rename immediately before its directory fsync.
        rustix::fs::fsync(directory.as_fd())?;
        rustix::fs::fsync(self.root.as_fd())?;
        Ok(manifest)
    }
    /// Resume a durable completed-encryption intent whose rename was uncertain.
    /// False means encryption did not finish; delete only its journaled objects.
    pub fn recover_publish(&self, record: &SnapshotArtifacts) -> Result<bool> {
        match self.owned_directory(record, record.context.snapshot.as_str()) {
            Ok(directory) => {
                self.verify_directory(&directory, record)?;
                return Ok(true);
            }
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
            Err(error) => return Err(error),
        }
        if [&record.memory, &record.state, &record.manifest]
            .iter()
            .any(|i| i.as_ref().is_none_or(|i| i.cipher_sha256.is_none()))
        {
            return Ok(false);
        }
        let directory = self.owned_directory(record, &record.stage_name)?;
        self.verify_directory(&directory, record)?;
        rustix::fs::renameat_with(
            self.root.as_fd(),
            &record.stage_name,
            self.root.as_fd(),
            record.context.snapshot.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        rustix::fs::fsync(self.root.as_fd())?;
        Ok(true)
    }
    /// Admission must reserve memory for both artifacts before calling this.
    pub fn decrypt(&self, record: &SnapshotArtifacts) -> Result<VerifiedSnapshot> {
        super::validate_memory_policy()?;
        let manifest = self.verify(record)?;
        let directory = self.owned_directory(record, record.context.snapshot.as_str())?;
        let load = |name: &str, kind, expected: &super::EncryptedArtifact| -> Result<File> {
            let mut file = directory.open_file(name, false)?;
            verify_cipher(&mut file, expected)?;
            let mut context = record.context.clone();
            context.kind = kind;
            super::decrypt(
                file,
                &self.keys.key()?,
                &context,
                expected.plain_bytes,
                &expected.plain_sha256,
            )
        };
        let memory = load(
            "memory.enc",
            ArtifactKind::Memory,
            record.memory.as_ref().ok_or(Error::State)?,
        )?;
        let state = load(
            "state.enc",
            ArtifactKind::State,
            record.state.as_ref().ok_or(Error::State)?,
        )?;
        Ok(VerifiedSnapshot {
            manifest,
            memory,
            state,
        })
    }
}
