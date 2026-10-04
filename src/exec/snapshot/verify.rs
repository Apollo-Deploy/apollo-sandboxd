use super::{MANIFEST, MAX_MANIFEST_BYTES, OutputSnapshotRecord, ownership};
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use sandboxd_protocol::codec;
use sha2::{Digest, Sha256};
use std::io::Read;

pub(crate) fn verify(record: &OutputSnapshotRecord) -> Result<()> {
    if record.digest == [0; 32] || record.manifest_inode == 0 {
        return Err(Error::State);
    }
    let (_, root) = ownership::open_root(record)?.ok_or(Error::State)?;
    ownership::validate_tree(record, &root, true)?;
    let manifest = root.open_file(MANIFEST, false)?;
    if manifest.metadata()?.len() > MAX_MANIFEST_BYTES {
        return Err(Error::State);
    }
    let mut bytes = Vec::new();
    manifest
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::State);
    }
    let stored: OutputSnapshotRecord = codec::decode_body(&bytes)?;
    if stored != *record || digest(record, &root)? != record.digest {
        return Err(Error::State);
    }
    Ok(())
}

pub(super) fn digest(record: &OutputSnapshotRecord, root: &SecureDir) -> Result<[u8; 32]> {
    ownership::validate_tree(record, root, true)?;
    let mut files: Vec<_> = record.files.iter().collect();
    files.sort_by(|a, b| a.relative.cmp(&b.relative));
    let mut hash = Sha256::new();
    hash.update(b"apollo-output-snapshot-v1\0");
    let mut total = 0u64;
    for ledger in files {
        total = total.checked_add(ledger.bytes).ok_or(Error::State)?;
        if total > record.bytes {
            return Err(Error::State);
        }
        let (directory, name) = ownership::file_parts(&ledger.relative)?;
        let owner = record
            .directories
            .iter()
            .find(|dir| dir.relative == directory)
            .ok_or(Error::State)?;
        let child = ownership::open_child(root, owner)?;
        let input = child.open_file(name, false)?;
        ownership::check_file(&input, ledger, true)?;
        hash.update((ledger.relative.len() as u64).to_le_bytes());
        hash.update(ledger.relative.as_bytes());
        hash.update(ledger.bytes.to_le_bytes());
        let mut bounded = input.take(ledger.bytes.checked_add(1).ok_or(Error::State)?);
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 << 10];
        loop {
            let count = bounded.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied += count as u64;
            if copied > ledger.bytes {
                return Err(Error::State);
            }
            hash.update(&buffer[..count]);
        }
        if copied != ledger.bytes {
            return Err(Error::State);
        }
    }
    if total != record.bytes {
        return Err(Error::State);
    }
    Ok(hash.finalize().into())
}
