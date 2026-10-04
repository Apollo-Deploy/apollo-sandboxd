use super::{MANIFEST, MAX_EXECS, OutputSnapshotRecord, SnapshotDirectory, SnapshotFile};
use crate::{
    error::{Error, Result},
    security::path::{SecureDir, device_id},
};
use std::{collections::BTreeSet, fs::File, os::unix::fs::MetadataExt};

pub(super) fn file_parts(relative: &str) -> Result<(&str, &str)> {
    let (directory, name) = relative.split_once('/').ok_or(Error::Path)?;
    sandboxd_protocol::ExecId::new(directory).map_err(|_| Error::Path)?;
    if !matches!(name, "exec.manifest" | "journal.sqlite3" | "exit.cbor") {
        return Err(Error::Path);
    }
    Ok((directory, name))
}

pub(super) fn open_root(record: &OutputSnapshotRecord) -> Result<Option<(SecureDir, SecureDir)>> {
    if !record.root.is_absolute()
        || record.root.file_name().and_then(|v| v.to_str()) != Some(record.id.as_str())
        || record.id.is_empty()
        || record.id.len() > 128
        || !record
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || record.directories.len() > MAX_EXECS
        || record.files.len() > MAX_EXECS * 3
        || record.execs.len() > MAX_EXECS
    {
        return Err(Error::Path);
    }
    let mut names = BTreeSet::new();
    for directory in &record.directories {
        sandboxd_protocol::ExecId::new(directory.relative.as_str()).map_err(|_| Error::Path)?;
        if !names.insert(&directory.relative) {
            return Err(Error::State);
        }
    }
    let mut files = BTreeSet::new();
    for file in &record.files {
        let (directory, _) = file_parts(&file.relative)?;
        if !names.iter().any(|name| name.as_str() == directory) || !files.insert(&file.relative) {
            return Err(Error::State);
        }
    }
    let parent = match SecureDir::open(record.root.parent().ok_or(Error::Path)?) {
        Ok(parent) => parent,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let root = match parent.open_child(&record.id) {
        Ok(root) => root,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let stat = rustix::fs::fstat(root.as_fd())?;
    if device_id(stat.st_dev) != record.root_device
        || stat.st_ino != record.root_inode
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o077 != 0
    {
        return Err(Error::Path);
    }
    Ok(Some((parent, root)))
}
pub(super) fn open_child(root: &SecureDir, directory: &SnapshotDirectory) -> Result<SecureDir> {
    let child = root.open_child(&directory.relative)?;
    let stat = rustix::fs::fstat(child.as_fd())?;
    if device_id(stat.st_dev) != directory.device
        || stat.st_ino != directory.inode
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o077 != 0
    {
        return Err(Error::Path);
    }
    Ok(child)
}
pub(super) fn check_file(file: &File, ledger: &SnapshotFile, complete: bool) -> Result<()> {
    let stat = file.metadata()?;
    if !stat.is_file()
        || stat.dev() != ledger.device
        || stat.ino() != ledger.inode
        || stat.uid() != rustix::process::geteuid().as_raw()
        || stat.mode() & 0o077 != 0
        || (complete && stat.len() != ledger.bytes)
    {
        return Err(Error::Path);
    }
    Ok(())
}

// Reject unknown objects before cleanup touches anything. Partial publication and
// interrupted deletion may omit ledger entries, but can never introduce new ones.
pub(super) fn validate_tree(
    record: &OutputSnapshotRecord,
    root: &SecureDir,
    complete: bool,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for entry in rustix::fs::Dir::read_from(root.as_fd())? {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        let name = std::str::from_utf8(bytes).map_err(|_| Error::Path)?;
        seen.insert(name.to_owned());
        if name == MANIFEST {
            let file = root.open_file(name, false)?;
            let meta = file.metadata()?;
            if record.manifest_inode == 0
                || meta.dev() != record.manifest_device
                || meta.ino() != record.manifest_inode
            {
                return Err(Error::Path);
            }
            continue;
        }
        let directory = record
            .directories
            .iter()
            .find(|dir| dir.relative == name)
            .ok_or(Error::Path)?;
        let child = open_child(root, directory)?;
        let mut child_seen = BTreeSet::new();
        for entry in rustix::fs::Dir::read_from(child.as_fd())? {
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            let leaf = std::str::from_utf8(bytes).map_err(|_| Error::Path)?;
            let relative = format!("{name}/{leaf}");
            let ledger = record
                .files
                .iter()
                .find(|file| file.relative == relative)
                .ok_or(Error::Path)?;
            check_file(&child.open_file(leaf, false)?, ledger, complete)?;
            child_seen.insert(relative);
        }
        if complete
            && record.files.iter().any(|file| {
                file.relative.starts_with(&format!("{name}/"))
                    && !child_seen.contains(&file.relative)
            })
        {
            return Err(Error::State);
        }
    }
    if complete
        && (!seen.contains(MANIFEST)
            || record
                .directories
                .iter()
                .any(|dir| !seen.contains(&dir.relative)))
    {
        return Err(Error::State);
    }
    Ok(())
}
