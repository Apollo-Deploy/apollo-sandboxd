use crate::error::{Error, Result};
use crate::security::path::SecureDir;
use sandboxd_protocol::{ExecId, codec};
use serde::{Deserialize, Serialize};
mod delete;
mod ownership;
mod verify;

pub(crate) use delete::delete;
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
pub(crate) use verify::verify;

const MANIFEST: &str = "output.snapshot";
const MAX_EXECS: usize = 256;
const MAX_MANIFEST_BYTES: u64 = 1 << 20;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSnapshotRecord {
    pub id: String,
    pub root: PathBuf,
    pub bytes: u64,
    pub digest: [u8; 32],
    pub root_device: u64,
    pub root_inode: u64,
    pub manifest_device: u64,
    pub manifest_inode: u64,
    pub directories: Vec<SnapshotDirectory>,
    pub files: Vec<SnapshotFile>,
    pub execs: Vec<OutputSnapshotExec>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFile {
    pub relative: String,
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDirectory {
    pub relative: String,
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSnapshotExec {
    pub exec: ExecId,
    pub max_bytes: u64,
    pub high_watermark: u64,
    pub exit: Option<(Option<i32>, Option<u8>, bool)>,
    pub bytes: u64,
}
pub type SnapshotOutput = OutputSnapshotRecord;

fn persist_capture(
    persist: &mut dyn FnMut(&OutputSnapshotRecord) -> Result<()>,
    record: &OutputSnapshotRecord,
) -> Result<()> {
    match persist(record) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = delete(record);
            Err(error)
        }
    }
}

pub(crate) fn capture(
    snapshot_root: &Path,
    id: &str,
    max_bytes: u64,
    persist: &mut dyn FnMut(&OutputSnapshotRecord) -> Result<()>,
    inventory: &[super::bridge::SnapshotExec],
) -> Result<OutputSnapshotRecord> {
    if !snapshot_root.is_absolute()
        || id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || max_bytes == 0
        || inventory.len() > MAX_EXECS
    {
        return Err(Error::Config("invalid output snapshot bounds"));
    }
    let snapshot_parent_path = snapshot_root.parent().ok_or(Error::Path)?;
    let snapshot_name = snapshot_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::Path)?;
    let snapshot_parent = SecureDir::open(snapshot_parent_path)?;
    let parent = match snapshot_parent.open_child(snapshot_name) {
        Ok(existing) => existing,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => {
            snapshot_parent.create_private_directory(snapshot_name)?
        }
        Err(error) => return Err(error),
    };
    let root_dir = parent
        .create_private_directory(id)
        .map_err(|_| Error::Config("output snapshot already exists"))?;
    let root = snapshot_root.join(id);
    let root_stat = rustix::fs::fstat(root_dir.as_fd())?;
    let mut total = 0u64;
    let mut execs = Vec::with_capacity(inventory.len());
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut record = OutputSnapshotRecord {
        id: id.to_owned(),
        root: root.clone(),
        bytes: 0,
        digest: [0; 32],
        root_device: root_stat.st_dev as u64,
        root_inode: root_stat.st_ino,
        manifest_device: 0,
        manifest_inode: 0,
        directories: Vec::new(),
        files: Vec::new(),
        execs: Vec::new(),
    };
    // Establish durable ownership of the root before creating any child.
    persist_capture(persist, &record)?;
    let mut manifest_file = root_dir.create_file(MANIFEST)?;
    let manifest_meta = manifest_file.metadata()?;
    record.manifest_device = manifest_meta.dev();
    record.manifest_inode = manifest_meta.ino();
    persist_capture(persist, &record)?;
    for item in inventory {
        let target_dir = root_dir.create_private_directory(item.exec.as_str())?;
        let target = root.join(item.exec.as_str());
        let target_meta = rustix::fs::fstat(target_dir.as_fd())?;
        directories.push(SnapshotDirectory {
            relative: item.exec.as_str().to_owned(),
            device: crate::security::path::device_id(target_meta.st_dev),
            inode: target_meta.st_ino,
        });
        record.directories = directories.clone();
        persist_capture(persist, &record)?;
        execs.push(OutputSnapshotExec {
            exec: item.exec.clone(),
            max_bytes: item.max_bytes,
            high_watermark: item.high_watermark,
            exit: item.exit,
            bytes: 0,
        });
        record.execs = execs.clone();
        persist_capture(persist, &record)?;
        let source_dir = SecureDir::open(&item.source)?;
        for name in ["exec.manifest", "journal.sqlite3", "exit.cbor"] {
            let mut source_file = match source_dir.open_file(name, false) {
                Ok(file) => file,
                Err(Error::Kernel(rustix::io::Errno::NOENT)) if name == "exit.cbor" => {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let meta = source_file.metadata()?;
            if !meta.file_type().is_file()
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.mode() & 0o077 != 0
            {
                return Err(Error::Path);
            }
            total = total.checked_add(meta.len()).ok_or(Error::State)?;
            if total > max_bytes {
                return Err(Error::Config("output snapshot quota exceeded"));
            }
            if name == "exec.manifest" {
                if meta.len() > MAX_MANIFEST_BYTES {
                    return Err(Error::State);
                }
                let mut manifest_bytes = Vec::new();
                (&source_file)
                    .take(MAX_MANIFEST_BYTES + 1)
                    .read_to_end(&mut manifest_bytes)?;
                if manifest_bytes.len() as u64 != meta.len() {
                    return Err(Error::State);
                }
                let manifest: super::router::ExecManifest = codec::decode_body(&manifest_bytes)?;
                if manifest.exec != item.exec {
                    return Err(Error::Path);
                }
            }
            let target_path = target.join(name);
            let mut target_file = target_dir.create_file(name)?;
            let target_meta = target_file.metadata()?;
            let ledger = SnapshotFile {
                relative: target_path
                    .strip_prefix(&root)
                    .map_err(|_| Error::Path)?
                    .to_string_lossy()
                    .into_owned(),
                device: target_meta.dev(),
                inode: target_meta.ino(),
                bytes: meta.len(),
            };
            files.push(ledger.clone());
            record.files = files.clone();
            record.bytes = total;
            persist_capture(persist, &record)?;
            if name == "exec.manifest" {
                source_file.seek(SeekFrom::Start(0))?;
            }
            let mut input = source_file;
            copy_exact(&mut input, &mut target_file, meta.len())?;
            target_file.sync_all()?;
        }
        let index = execs.len() - 1;
        execs[index].bytes = files
            .iter()
            .filter(|file| {
                file.relative
                    .starts_with(&format!("{}/", item.exec.as_str()))
            })
            .map(|file| file.bytes)
            .sum();
        record.execs = execs.clone();
        persist_capture(persist, &record)?;
    }
    let digest = verify::digest(&record, &root_dir)?;
    record.bytes = total;
    record.digest = digest;
    record.execs = execs;
    let bytes = codec::encode_body(&record)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::State);
    }
    manifest_file.write_all(&bytes)?;
    manifest_file.sync_all()?;
    rustix::fs::fsync(root_dir.as_fd())?;
    persist_capture(persist, &record)?;
    Ok(record)
}

#[cfg(test)]
pub(crate) fn restore(record: &OutputSnapshotRecord, root: &Path) -> Result<()> {
    restore_journaled(record, root, &mut |_| Ok(()))
}

pub(crate) fn restore_journaled(
    record: &OutputSnapshotRecord,
    new_output_root: &Path,
    persist: &mut dyn FnMut(&OutputSnapshotRecord) -> Result<()>,
) -> Result<()> {
    if !new_output_root.is_absolute() {
        return Err(Error::Path);
    }
    verify(record)?;
    let inventory: Vec<_> = record
        .execs
        .iter()
        .map(|item| super::bridge::SnapshotExec {
            exec: item.exec.clone(),
            source: record.root.join(item.exec.as_str()),
            high_watermark: item.high_watermark,
            exit: item.exit,
            max_bytes: item.max_bytes,
        })
        .collect();
    let parent = new_output_root.parent().ok_or(Error::Path)?;
    let name = new_output_root
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or(Error::Path)?;
    // The same pre-write inode ledger is required for the fresh session copy.
    let restored = capture(parent, name, record.bytes.max(1), persist, &inventory)?;
    if restored.digest != record.digest {
        return Err(Error::State);
    }
    Ok(())
}

fn copy_exact(input: &mut fs::File, output: &mut fs::File, expected: u64) -> Result<()> {
    let mut limited = input.take(expected.saturating_add(1));
    let copied = std::io::copy(&mut limited, output)?;
    if copied != expected {
        return Err(Error::State);
    }
    let mut byte = [0u8; 1];
    if input.read(&mut byte)? != 0 {
        return Err(Error::State);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
