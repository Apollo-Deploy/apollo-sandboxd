//! CLI transfers retain at most one 64 KiB data chunk in memory.
use super::super::Target;
use apollo_sandboxd::error::{Error, Result};
use sandboxd_protocol::{GuestReply, OperationId, files::FileRequest};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const MAX_TRANSFER: u64 = 256 * 1024 * 1024;

fn chunk_operation(
    target: &Target,
    offset: u64,
    final_chunk: bool,
    chunk_index: u64,
) -> Result<(OperationId, u64)> {
    let sequence = target
        .operation_sequence
        .checked_add(chunk_index)
        .ok_or(Error::Config("file transfer operation sequence overflow"))?;
    let encoded = sandboxd_protocol::codec::encode_body(&(
        "file_chunk",
        &target.operation,
        offset,
        final_chunk,
    ))?;
    let operation = OperationId::with_sequence(
        sequence,
        format!("file-{}", &hex::encode(Sha256::digest(encoded))[..24]),
    )
    .map_err(|_| Error::State)?;
    Ok((operation, sequence))
}

pub async fn upload(
    socket: &Path,
    target: &Target,
    path: &str,
    input: &mut impl Read,
) -> Result<()> {
    let mut chunk = vec![0; sandboxd_protocol::MAX_DATA_BYTES];
    let mut offset = 0u64;
    let mut digest = Sha256::new();
    let mut chunk_index = 0u64;
    loop {
        let count = input.read(&mut chunk)?;
        let end = offset
            .checked_add(count as u64)
            .filter(|end| *end <= MAX_TRANSFER)
            .ok_or(Error::Config("file transfer limit"))?;
        digest.update(&chunk[..count]);
        let final_chunk = count == 0;
        let hash = final_chunk.then(|| digest.clone().finalize().into());
        let (operation, sequence) = chunk_operation(target, offset, final_chunk, chunk_index)?;
        super::files::call(
            socket,
            target,
            operation,
            sequence,
            FileRequest::Write {
                transfer_id: target.operation.to_string(),
                path: path.into(),
                offset,
                data: chunk[..count].to_vec(),
                final_chunk,
                sha256: hash,
                atomic_replace: true,
            },
        )
        .await?;
        offset = end;
        chunk_index = chunk_index.checked_add(1).ok_or(Error::State)?;
        if final_chunk {
            return Ok(());
        }
    }
}

pub async fn download(
    socket: &Path,
    target: &Target,
    path: &str,
    mut offset: u64,
    output: &mut impl Write,
) -> Result<()> {
    let first = offset;
    let mut chunk_index = 0u64;
    loop {
        let remaining = MAX_TRANSFER
            .checked_sub(offset - first)
            .ok_or(Error::Config("file transfer limit"))?;
        // The extra EOF probe accepts an exactly-at-limit file, but no extra byte.
        let limit = remaining
            .min(sandboxd_protocol::MAX_DATA_BYTES as u64)
            .max(1) as u32;
        let (operation, sequence) = chunk_operation(target, offset, false, chunk_index)?;
        let reply = super::files::call(
            socket,
            target,
            operation,
            sequence,
            FileRequest::Read {
                path: path.into(),
                offset,
                limit,
            },
        )
        .await?;
        let GuestReply::File {
            data,
            offset: observed,
            eof,
            ..
        } = reply
        else {
            return Err(Error::State);
        };
        if observed != offset || data.len() > limit as usize || data.len() as u64 > remaining {
            return Err(Error::Config("file response exceeded transfer bounds"));
        }
        output.write_all(&data)?;
        offset = offset.checked_add(data.len() as u64).ok_or(Error::State)?;
        chunk_index = chunk_index.checked_add(1).ok_or(Error::State)?;
        if eof {
            return Ok(());
        }
        if data.is_empty() {
            return Err(Error::Config("file transfer made no progress"));
        }
    }
}

pub async fn download_atomic(
    socket: &Path,
    target: &Target,
    path: &str,
    destination: &Path,
) -> Result<()> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::State)?;
    let temporary = parent.join(format!(".sandboxctl-{}", hex::encode(nonce)));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = async {
        download(socket, target, path, 0, &mut output).await?;
        output.sync_all()?;
        fs::rename(&temporary, destination)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
