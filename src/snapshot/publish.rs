//! Durable identity callbacks precede every ciphertext file write.
use super::{
    ArtifactContext, ArtifactKind, EncryptedArtifact, SnapshotArtifacts, SnapshotCatalog,
    SnapshotManifest, artifact::*,
};
use crate::error::{Error, Result};
use rustix::fs::RenameFlags;
use std::{fs::File, io::Write};
use zeroize::Zeroizing;

impl SnapshotCatalog {
    pub fn publish(
        &self,
        manifest: &SnapshotManifest,
        memory: &File,
        state: &File,
        mut persist: impl FnMut(&SnapshotArtifacts) -> Result<()>,
    ) -> Result<SnapshotArtifacts> {
        super::validate_memory_policy()?;
        manifest.validate()?;
        anonymous_input(memory, manifest.memory_bytes)?;
        anonymous_input(state, manifest.state_bytes)?;
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(|_| Error::State)?;
        let stage_name = format!(".snapshot-{}-{}", manifest.id, hex::encode(random));
        let directory = self.root.create_private_directory(&stage_name)?;
        let mut record = SnapshotArtifacts {
            version: 1,
            context: ArtifactContext {
                snapshot: manifest.id.clone(),
                sandbox: manifest.sandbox.clone(),
                sandbox_generation: manifest.sandbox_generation,
                session: manifest.session.clone(),
                session_generation: manifest.session_generation,
                kind: ArtifactKind::Manifest,
            },
            stage_name,
            directory: directory_identity(&directory)?,
            memory: None,
            state: None,
            manifest: None,
        };
        // A crash before this callback can leave only an empty private directory.
        persist(&record)?;
        let key = self.keys.key()?;
        let mut finalized = manifest.clone();
        for (name, input, kind, size) in [
            (
                "memory.enc",
                memory,
                ArtifactKind::Memory,
                manifest.memory_bytes,
            ),
            (
                "state.enc",
                state,
                ArtifactKind::State,
                manifest.state_bytes,
            ),
        ] {
            let mut output = directory.create_file(name)?;
            let identity = file_identity(&output, size, "0".repeat(64))?;
            *slot(&mut record, kind) = Some(identity);
            persist(&record)?;
            let mut context = record.context.clone();
            context.kind = kind;
            let digest = super::encrypt(
                PositionalReader {
                    file: input,
                    offset: 0,
                },
                &mut output,
                &key,
                &context,
                size,
            )?;
            output.flush()?;
            output.sync_all()?;
            let item = slot(&mut record, kind).as_mut().ok_or(Error::State)?;
            item.plain_sha256 = digest.clone();
            item.cipher_sha256 = Some(super::artifact::digest(&output, item.cipher_bytes)?);
            match kind {
                ArtifactKind::Memory => finalized.memory_sha256 = digest,
                ArtifactKind::State => finalized.state_sha256 = digest,
                _ => return Err(Error::State),
            }
            persist(&record)?;
        }
        finalized.validate()?;
        let bytes = Zeroizing::new(sandboxd_protocol::codec::encode_body(&finalized)?);
        let mut output = directory.create_file("manifest.enc")?;
        record.manifest = Some(file_identity(&output, bytes.len() as u64, "0".repeat(64))?);
        persist(&record)?;
        let digest = super::encrypt(
            bytes.as_slice(),
            &mut output,
            &key,
            &record.context,
            bytes.len() as u64,
        )?;
        output.flush()?;
        output.sync_all()?;
        let item = record.manifest.as_mut().ok_or(Error::State)?;
        item.plain_sha256 = digest;
        item.cipher_sha256 = Some(super::artifact::digest(&output, item.cipher_bytes)?);
        persist(&record)?;
        rustix::fs::fsync(directory.as_fd())?;
        rustix::fs::renameat_with(
            self.root.as_fd(),
            &record.stage_name,
            self.root.as_fd(),
            manifest.id.as_str(),
            RenameFlags::NOREPLACE,
        )?;
        rustix::fs::fsync(self.root.as_fd())?;
        Ok(record)
    }
}
fn slot(record: &mut SnapshotArtifacts, kind: ArtifactKind) -> &mut Option<EncryptedArtifact> {
    match kind {
        ArtifactKind::Memory => &mut record.memory,
        ArtifactKind::State => &mut record.state,
        ArtifactKind::Manifest => &mut record.manifest,
    }
}
#[cfg(target_os = "linux")]
fn anonymous_input(file: &File, expected: u64) -> Result<()> {
    let stat = rustix::fs::fstat(file)?;
    if stat.st_nlink != 0
        || stat.st_size < 0
        || stat.st_size as u64 != expected
        || rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || rustix::fs::fstatfs(file)?.f_type != 0x01021994
    {
        return Err(Error::Path);
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn anonymous_input(_file: &File, _expected: u64) -> Result<()> {
    Err(sandboxd_protocol::ApiError::new(
        sandboxd_protocol::ErrorCode::UnsupportedHost,
        "snapshot capture requires Linux anonymous RAM files",
    )
    .into())
}
