//! Fixed-size authenticated records, including an authenticated end marker.
//! Decryption publishes only a completely verified, sealed anonymous file.
use super::SnapshotKey;
use crate::error::{Error, Result};
use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use sandboxd_protocol::{
    ApiError, ErrorCode, SandboxGeneration, SandboxId, SessionGeneration, SessionId, SnapshotId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ASDSNP01";
const CHUNK: usize = 64 * 1024;
const HEADER: usize = 36;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Memory,
    State,
    Manifest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactContext {
    pub snapshot: SnapshotId,
    pub sandbox: SandboxId,
    pub sandbox_generation: SandboxGeneration,
    pub session: SessionId,
    pub session_generation: SessionGeneration,
    pub kind: ArtifactKind,
}
impl ArtifactContext {
    fn validate_size(&self, size: u64) -> Result<()> {
        let maximum = match self.kind {
            ArtifactKind::Memory => 1 << 40,
            ArtifactKind::State => 64 << 20,
            ArtifactKind::Manifest => 256 << 10,
        };
        if size > maximum {
            return Err(integrity());
        }
        Ok(())
    }
}

fn integrity() -> Error {
    ApiError::new(
        ErrorCode::SnapshotIntegrityFailed,
        "snapshot artifact authentication or framing failed",
    )
    .into()
}
fn aad(header: &[u8; HEADER], context: &ArtifactContext) -> Result<Vec<u8>> {
    let mut bytes = b"apollo-sandboxd.snapshot.v1\0".to_vec();
    bytes.extend_from_slice(header);
    let identity = serde_json::to_vec(context).map_err(|_| integrity())?;
    // Typed identifiers make this finite independently of any file length.
    if identity.len() > 1024 {
        return Err(integrity());
    }
    bytes.extend_from_slice(&(identity.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&identity);
    Ok(bytes)
}
fn record_aad(base: &[u8], sequence: u64, final_record: bool) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(base.len() + 9);
    bytes.extend_from_slice(base);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.push(u8::from(final_record));
    bytes
}
fn nonce(header: &[u8; HEADER], sequence: u64) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..16].copy_from_slice(&header[20..]);
    nonce[16..].copy_from_slice(&sequence.to_le_bytes());
    nonce
}
fn no_trailing_bytes(input: &mut impl Read) -> Result<()> {
    let mut byte = [0];
    loop {
        match input.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(integrity()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(integrity()),
        }
    }
}

/// The caller writes ciphertext into a private temporary object and publishes
/// it atomically only after success. Plaintext input must not reside on disk.
/// Returns the plaintext digest for the separately authenticated manifest.
pub fn encrypt(
    mut input: impl Read,
    mut output: impl Write,
    key: &SnapshotKey,
    context: &ArtifactContext,
    size: u64,
) -> Result<String> {
    context.validate_size(size)?;
    let cipher = XChaCha20Poly1305::new(key.bytes().into());
    let mut header = [0; HEADER];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&(CHUNK as u32).to_le_bytes());
    header[12..20].copy_from_slice(&size.to_le_bytes());
    getrandom::getrandom(&mut header[20..]).map_err(|_| integrity())?;
    let base = aad(&header, context)?;
    output.write_all(&header)?;
    let mut buffer = Zeroizing::new(vec![0; CHUNK]);
    let mut remaining = size;
    let mut sequence = 0;
    let mut digest = Sha256::new();
    while remaining != 0 {
        let count = remaining.min(CHUNK as u64) as usize;
        input.read_exact(&mut buffer[..count])?;
        digest.update(&buffer[..count]);
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce(&header, sequence)),
                &record_aad(&base, sequence, false),
                &mut buffer[..count],
            )
            .map_err(|_| integrity())?;
        output.write_all(&buffer[..count])?;
        output.write_all(&tag)?;
        remaining -= count as u64;
        sequence += 1;
    }
    no_trailing_bytes(&mut input)?;
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce(&header, sequence)),
            &record_aad(&base, sequence, true),
            &mut [],
        )
        .map_err(|_| integrity())?;
    output.write_all(&tag)?;
    Ok(hex::encode(digest.finalize()))
}

// Never expose this stream writer publicly: late authentication failure may
// have written a prefix. Production decryption keeps it anonymous and closes
// it on every error, before Firecracker can obtain it.
pub(super) fn decrypt_stream(
    mut input: impl Read,
    mut output: impl Write,
    key: &SnapshotKey,
    context: &ArtifactContext,
    expected_size: u64,
) -> Result<String> {
    context.validate_size(expected_size)?;
    let mut header = [0; HEADER];
    input.read_exact(&mut header).map_err(|_| integrity())?;
    if &header[..8] != MAGIC
        || header[8..12] != (CHUNK as u32).to_le_bytes()
        || header[12..20] != expected_size.to_le_bytes()
    {
        return Err(integrity());
    }
    let base = aad(&header, context)?;
    let cipher = XChaCha20Poly1305::new(key.bytes().into());
    let mut buffer = Zeroizing::new(vec![0; CHUNK]);
    let mut digest = Sha256::new();
    let mut remaining = expected_size;
    let mut sequence = 0;
    let mut tag = [0; 16];
    while remaining != 0 {
        let count = remaining.min(CHUNK as u64) as usize;
        input
            .read_exact(&mut buffer[..count])
            .map_err(|_| integrity())?;
        input.read_exact(&mut tag).map_err(|_| integrity())?;
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce(&header, sequence)),
                &record_aad(&base, sequence, false),
                &mut buffer[..count],
                Tag::from_slice(&tag),
            )
            .map_err(|_| integrity())?;
        digest.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
        remaining -= count as u64;
        sequence += 1;
    }
    input.read_exact(&mut tag).map_err(|_| integrity())?;
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&nonce(&header, sequence)),
            &record_aad(&base, sequence, true),
            &mut [],
            Tag::from_slice(&tag),
        )
        .map_err(|_| integrity())?;
    no_trailing_bytes(&mut input)?;
    Ok(hex::encode(digest.finalize()))
}

/// The caller must reserve host memory for expected_size before decrypting.
/// A verified anonymous file is sealed against changes before being returned.
#[cfg(target_os = "linux")]
pub fn decrypt(
    input: impl Read,
    key: &SnapshotKey,
    context: &ArtifactContext,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<std::fs::File> {
    use rustix::fs::{MemfdFlags, SealFlags};
    use std::io::{Seek, SeekFrom};
    context.validate_size(expected_size)?;
    let fd = rustix::fs::memfd_create(
        "sandboxd-verified-snapshot",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?;
    let mut file = std::fs::File::from(fd);
    if decrypt_stream(input, &mut file, key, context, expected_size)? != expected_sha256 {
        return Err(integrity());
    }
    rustix::fs::fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}
#[cfg(not(target_os = "linux"))]
pub fn decrypt(
    _input: impl Read,
    _key: &SnapshotKey,
    _context: &ArtifactContext,
    _expected_size: u64,
    _expected_sha256: &str,
) -> Result<std::fs::File> {
    Err(ApiError::new(
        ErrorCode::UnsupportedHost,
        "verified snapshot loading requires Linux anonymous sealed files",
    )
    .into())
}
