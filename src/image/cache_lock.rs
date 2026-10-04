//! Serializes cache mutations across daemon tasks and process restarts.
use crate::security::path::SecureDir;
use rustix::fs::FlockOperation;
use std::{fs::File, io, path::Path};

pub(super) fn acquire(root: &Path) -> io::Result<File> {
    let directory = SecureDir::open(root).map_err(error)?;
    let file = directory
        .open_or_create_private("cache.lock")
        .map_err(error)?;
    rustix::fs::flock(&file, FlockOperation::LockExclusive)?;
    Ok(file)
}

fn error(value: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, value.to_string())
}
