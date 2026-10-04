//! Raw tar validation performed before the `tar` crate expands extension data.
use super::layers::LayerLimits;
use flate2::read::GzDecoder;
use std::{
    fs,
    io::{self, Read},
    path::Path,
};
use tar::{Archive, EntryType};

const MAX_EXTENSION_BYTES: u64 = 64 * 1024;
const MAX_TOTAL_EXTENSION_BYTES: u64 = 1024 * 1024;

pub(super) fn open_reader(source: &Path, gzip: bool) -> io::Result<Box<dyn Read>> {
    let file = fs::File::open(source)?;
    if gzip {
        Ok(Box::new(GzDecoder::new(file)))
    } else {
        Ok(Box::new(file))
    }
}

/// Raw mode prevents PAX and GNU long-name records from being read into an
/// unbounded `Vec` before their declared sizes have been checked.
pub(super) fn validate(source: &Path, gzip: bool, limits: LayerLimits) -> io::Result<()> {
    let mut archive = Archive::new(open_reader(source, gzip)?);
    let mut entries = 0u64;
    let mut extension_bytes = 0u64;
    let mut regular_bytes = 0u64;
    for item in archive.entries()?.raw(true) {
        let mut entry = item?;
        entries = entries.checked_add(1).ok_or_else(limit_error)?;
        if entries > limits.max_entries {
            return Err(limit_error());
        }
        let size = entry.size();
        let kind = entry.header().entry_type();
        if is_extension(kind) {
            extension_bytes = extension_bytes.checked_add(size).ok_or_else(limit_error)?;
            if size > MAX_EXTENSION_BYTES || extension_bytes > MAX_TOTAL_EXTENSION_BYTES {
                return Err(limit_error());
            }
            if matches!(kind, EntryType::XHeader | EntryType::XGlobalHeader) {
                let mut data = Vec::with_capacity(size as usize);
                entry.read_to_end(&mut data)?;
                validate_pax(&data)?;
                continue;
            }
        } else if kind == EntryType::Regular {
            regular_bytes = regular_bytes.checked_add(size).ok_or_else(limit_error)?;
            if size > limits.max_file_bytes || regular_bytes > limits.max_uncompressed_bytes {
                return Err(limit_error());
            }
        } else if kind == EntryType::GNUSparse {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sparse OCI entry rejected",
            ));
        }
        io::copy(&mut entry, &mut io::sink())?;
    }
    Ok(())
}

fn is_extension(kind: EntryType) -> bool {
    matches!(
        kind,
        EntryType::XHeader
            | EntryType::XGlobalHeader
            | EntryType::GNULongName
            | EntryType::GNULongLink
    )
}

fn validate_pax(data: &[u8]) -> io::Result<()> {
    for extension in tar::PaxExtensions::new(data) {
        let extension = extension?;
        let key = extension.key().map_err(|_| invalid_error())?;
        if key == "size" || key.starts_with("GNU.sparse.") {
            return Err(invalid_error());
        }
    }
    Ok(())
}

fn limit_error() -> io::Error {
    io::Error::new(io::ErrorKind::FileTooLarge, "OCI layer limit exceeded")
}

fn invalid_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unsafe OCI PAX extension")
}
