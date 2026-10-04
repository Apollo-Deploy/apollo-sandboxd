use super::model::OciDescriptor;
use crate::security::path::SecureDir;
use sha2::{Digest, Sha256};
use std::{
    fmt::Display,
    fs,
    io::{self, Read, Write},
    path::Path,
};

pub(super) fn read_layout_blob(
    layout: &Path,
    descriptor: &OciDescriptor,
    max: u64,
) -> io::Result<Vec<u8>> {
    let digest = descriptor
        .digest
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("unsupported OCI digest"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
        || descriptor.size > max
    {
        return Err(invalid("invalid OCI descriptor"));
    }
    let path = layout.join("blobs/sha256").join(digest);
    read_verified(&path, &descriptor.digest, descriptor.size, max)
}

pub(super) fn open_layout_blob(
    layout: &Path,
    descriptor: &OciDescriptor,
    max: u64,
) -> io::Result<fs::File> {
    let value = descriptor
        .digest
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("OCI digest"))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
        || descriptor.size > max
    {
        return Err(invalid("invalid OCI descriptor"));
    }
    let file = open_file(&layout.join("blobs/sha256").join(value))?;
    if file.metadata()?.len() != descriptor.size {
        return Err(invalid("OCI descriptor size mismatch"));
    }
    Ok(file)
}

fn open_file(path: &Path) -> io::Result<fs::File> {
    let parent =
        SecureDir::open(path.parent().ok_or_else(|| invalid("OCI parent"))?).map_err(invalid)?;
    parent
        .open_file(
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| invalid("OCI name"))?,
            false,
        )
        .map_err(invalid)
}

pub(super) fn write_verified(path: &Path, mut bytes: &[u8], digest: &str) -> io::Result<()> {
    let size = bytes.len() as u64;
    store_verified_stream(path, &mut bytes, digest, size, size)
}

/// Stream a layer with constant working memory. A concurrent publication never
/// replaces the winner; it is independently verified before accepting a hit.
pub(super) fn store_verified_stream(
    path: &Path,
    source: &mut impl Read,
    digest: &str,
    size: u64,
    max: u64,
) -> io::Result<()> {
    if size > max {
        return Err(invalid("OCI object exceeds limit"));
    }
    let publication = super::content_publish::Publication::create(path)?;
    let mut file = publication.file.try_clone()?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| invalid("OCI size overflow"))?;
        if total > size || total > max {
            return Err(invalid("OCI object exceeds limit"));
        }
        hash.update(&buffer[..count]);
        file.write_all(&buffer[..count])?;
    }
    if total != size || format!("sha256:{:x}", hash.finalize()) != digest {
        return Err(invalid("OCI digest mismatch"));
    }
    verify_file(publication.publish()?, digest, size)
}

pub(super) fn verify_file(mut file: fs::File, digest: &str, expected_size: u64) -> io::Result<()> {
    if file.metadata()?.len() != expected_size {
        return Err(invalid("OCI size mismatch"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| invalid("OCI size overflow"))?;
        if total > expected_size {
            return Err(invalid("OCI size mismatch"));
        }
        hash.update(&buffer[..count]);
    }
    if total != expected_size || format!("sha256:{:x}", hash.finalize()) != digest {
        return Err(invalid("OCI digest mismatch"));
    }
    Ok(())
}

pub(super) fn verify_blob(path: &Path, digest: &str, expected_size: u64) -> io::Result<()> {
    verify_file(open_file(path)?, digest, expected_size)
}

pub(super) fn read_bounded_file(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let file = open_file(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > max {
        return Err(invalid("bounded OCI file size mismatch"));
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(max) as usize);
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(invalid("OCI object exceeds limit"));
    }
    Ok(bytes)
}

pub(super) fn read_verified(
    path: &Path,
    digest: &str,
    expected_size: u64,
    max: u64,
) -> io::Result<Vec<u8>> {
    if expected_size > max {
        return Err(invalid("OCI object exceeds limit"));
    }
    let mut file = open_file(path)?;
    let metadata = file.metadata()?;
    if metadata.len() != expected_size {
        return Err(invalid("OCI object metadata mismatch"));
    }
    let mut hash = Sha256::new();
    let mut bytes = Vec::with_capacity(expected_size.min(max) as usize);
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| invalid("OCI size overflow"))?;
        if total > expected_size || total > max {
            return Err(invalid("OCI object exceeds limit"));
        }
        hash.update(&buffer[..count]);
        bytes.extend_from_slice(&buffer[..count]);
    }
    if total != expected_size || format!("sha256:{:x}", hash.finalize()) != digest {
        return Err(invalid("OCI digest mismatch"));
    }
    Ok(bytes)
}

fn invalid(value: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, value.to_string())
}
