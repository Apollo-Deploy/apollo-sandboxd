//! Verification of pinned runtime copies and their operator directories.
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
const MAX_RUNTIME_BYTES: u64 = 4 << 30;

pub(super) fn checked_parent(root: &Path) -> Result<&Path> {
    if !root.is_absolute()
        || root
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Path);
    }
    let parent = root.parent().ok_or(Error::Path)?;
    validate_existing_chain(parent)?;
    if fs::symlink_metadata(root).is_ok() {
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(Error::Path);
        }
    } else {
        fs::create_dir(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    Ok(root)
}

fn validate_existing_chain(path: &Path) -> Result<()> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            current.push(name);
            let meta = fs::symlink_metadata(&current)?;
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
            {
                return Err(Error::Path);
            }
        }
    }
    Ok(())
}

pub(super) fn copy_verified(source: &File, expected: &str, target: &Path) -> Result<()> {
    let source_meta = source.metadata()?;
    if !source_meta.is_file()
        || source_meta.nlink() != 1
        || source_meta.len() == 0
        || source_meta.len() > MAX_RUNTIME_BYTES
        || source_meta.uid() != 0
        || source_meta.mode() & 0o222 != 0
    {
        return Err(Error::Artifact("runtime artifact cannot be staged"));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o555)
        .open(target)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65_536];
    let mut offset = 0;
    loop {
        let count = source.read_at(&mut buf, offset)?;
        if count == 0 {
            break;
        }
        hash.update(&buf[..count]);
        output.write_all(&buf[..count])?;
        offset += count as u64;
    }
    output.sync_all()?;
    if hex::encode(hash.finalize()) != expected {
        return Err(Error::Artifact("staged runtime digest mismatch"));
    }
    let target_meta = target.metadata()?;
    if !target_meta.is_file() || target_meta.nlink() != 1 || target_meta.mode() & 0o222 != 0 {
        return Err(Error::Path);
    }
    Ok(())
}

pub(super) fn validate_staged(path: &Path, expected: &str) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.nlink() != 1
        || (meta.uid() != 0 && meta.uid() != rustix::process::geteuid().as_raw())
        || meta.mode() & 0o222 != 0
        || meta.mode() & 0o111 == 0
        || meta.len() == 0
        || meta.len() > MAX_RUNTIME_BYTES
    {
        return Err(Error::Path);
    }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    if hex::encode(hash.finalize()) != expected {
        return Err(Error::Artifact("staged runtime identity changed"));
    }
    Ok(())
}
