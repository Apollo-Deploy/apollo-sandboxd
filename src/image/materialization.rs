//! Durable staging, publication, and recovery for extracted OCI roots.
use crate::security::path::{SecureDir, device_id};
use rustix::fs::{self as unix_fs, FileType, RenameFlags};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[path = "materialization_format.rs"]
mod format;
use format::{
    commit_bytes, digest_value, identity_bytes, intent_bytes, invalid, parse_commit,
    parse_identity, parse_intent, valid_transaction_name,
};

const TRANSACTION_PREFIX: &str = ".txn-";
const MARKER_LIMIT: u64 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Identity {
    pub(super) device: u64,
    pub(super) inode: u64,
}

impl Identity {
    pub(super) fn from_stat(stat: &unix_fs::Stat) -> Self {
        Self {
            device: device_id(stat.st_dev),
            inode: stat.st_ino,
        }
    }
}

pub(super) struct MaterializingRoot {
    rootfs_path: PathBuf,
    rootfs: SecureDir,
    transaction_name: String,
    transaction: SecureDir,
    identity: Identity,
    digest: String,
}

impl MaterializingRoot {
    pub(super) fn create(rootfs_path: &Path, digest: &str) -> io::Result<Self> {
        let value = digest_value(digest)?;
        let rootfs = SecureDir::open(rootfs_path).map_err(to_io)?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| invalid("OCI stage nonce unavailable"))?;
        let nonce = hex::encode(nonce);
        let transaction_name = format!("{TRANSACTION_PREFIX}{nonce}");
        let transaction = rootfs
            .create_private_directory(&transaction_name)
            .map_err(to_io)?;
        let identity = Identity::from_stat(&unix_fs::fstat(transaction.as_fd())?);
        let mut result = Self {
            rootfs_path: rootfs_path.to_path_buf(),
            rootfs,
            transaction_name,
            transaction,
            identity,
            digest: format!("sha256:{value}"),
        };
        result.initialize(&nonce)?;
        Ok(result)
    }

    fn initialize(&mut self, nonce: &str) -> io::Result<()> {
        self.transaction
            .create_private_directory("payload")
            .map_err(to_io)?;
        let mut intent = self.transaction.create_file("intent").map_err(to_io)?;
        intent.write_all(intent_bytes(nonce, &self.digest).as_bytes())?;
        intent.sync_all()?;
        unix_fs::fsync(self.transaction.as_fd())?;
        unix_fs::fsync(self.rootfs.as_fd())?;
        Ok(())
    }

    pub(super) fn path(&self) -> PathBuf {
        self.rootfs_path
            .join(&self.transaction_name)
            .join("payload")
    }

    /// Durably publishes the prepared directory without replacing a digest path.
    pub(super) fn publish(&self, digest_name: &str) -> io::Result<PublishResult> {
        let payload = self.transaction.open_child("payload").map_err(to_io)?;
        let payload_identity = Identity::from_stat(&unix_fs::fstat(payload.as_fd())?);
        write_marker(
            &self.transaction,
            "prepared",
            identity_bytes(&self.digest, payload_identity).as_bytes(),
        )?;
        let result = unix_fs::renameat_with(
            self.transaction.as_fd(),
            "payload",
            self.rootfs.as_fd(),
            digest_name,
            RenameFlags::NOREPLACE,
        );
        match result {
            Ok(()) => {
                unix_fs::fsync(self.transaction.as_fd())?;
                unix_fs::fsync(self.rootfs.as_fd())?;
                Ok(PublishResult::Installed(payload_identity))
            }
            Err(rustix::io::Errno::EXIST) => Ok(PublishResult::AlreadyExists),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn commit(&self, digest_name: &str, identity: Identity) -> io::Result<()> {
        publish_commit(&self.rootfs_path, &self.digest, digest_name, identity)
    }

    fn cleanup(&self) -> io::Result<()> {
        remove_owned_tree(&self.rootfs, &self.transaction_name, self.identity)
    }
}

impl Drop for MaterializingRoot {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub(super) enum PublishResult {
    Installed(Identity),
    AlreadyExists,
}

/// Reconcile only transaction directories with the exact private name and intent format.
/// Callers must hold the cache's global lock for the full recovery pass.
pub(super) fn recover(
    rootfs_path: &Path,
    manifests_path: &Path,
    max_manifest_bytes: u64,
) -> io::Result<()> {
    let rootfs = SecureDir::open(rootfs_path).map_err(to_io)?;
    let mut entries = unix_fs::Dir::read_from(rootfs.as_fd())?;
    let mut names = Vec::new();
    for entry in &mut entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = match name.to_str() {
            Ok(name) => name.to_owned(),
            Err(_) => continue,
        };
        if name.starts_with(TRANSACTION_PREFIX) {
            if !valid_transaction_name(&name) {
                return Err(invalid("invalid OCI materialization transaction name"));
            }
            names.push(name);
        }
    }
    drop(entries);

    for name in names {
        recover_one(
            &rootfs,
            rootfs_path,
            manifests_path,
            &name,
            max_manifest_bytes,
        )?;
    }
    Ok(())
}

pub(super) fn verify_committed_root(
    rootfs_path: &Path,
    digest: &str,
    root_path: &Path,
) -> io::Result<Identity> {
    let digest_name = digest_value(digest)?;
    let rootfs = SecureDir::open(rootfs_path).map_err(to_io)?;
    let identity = directory_identity(&rootfs, &digest_name)?
        .ok_or_else(|| invalid("committed OCI rootfs is missing"))?;
    let commit = read_commit(&rootfs_path.join(".commits"), &digest_name)?
        .ok_or_else(|| invalid("OCI rootfs has no durable commit record"))?;
    if commit != identity {
        return Err(invalid("OCI rootfs commit identity mismatch"));
    }
    super::rootfs::verify_extracted_root(root_path)?;
    Ok(identity)
}

pub(super) fn ensure_no_orphan_commit(rootfs_path: &Path, digest: &str) -> io::Result<()> {
    let digest_name = digest_value(digest)?;
    if read_commit(&rootfs_path.join(".commits"), &digest_name)?.is_some() {
        return Err(invalid("OCI commit record has no rootfs"));
    }
    Ok(())
}

pub(super) fn directory_identity(parent: &SecureDir, name: &str) -> io::Result<Option<Identity>> {
    match parent.stat(name) {
        Ok(stat) => {
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
                return Err(invalid("OCI digest path is not a directory"));
            }
            Ok(Some(Identity::from_stat(&stat)))
        }
        Err(crate::error::Error::Kernel(rustix::io::Errno::NOENT)) => Ok(None),
        Err(error) => Err(to_io(error)),
    }
}

fn recover_one(
    rootfs: &SecureDir,
    rootfs_path: &Path,
    manifests_path: &Path,
    transaction_name: &str,
    max_manifest_bytes: u64,
) -> io::Result<()> {
    let transaction = rootfs.open_child(transaction_name).map_err(to_io)?;
    let stat = unix_fs::fstat(transaction.as_fd())?;
    if stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o777 != 0o700
        || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
    {
        return Err(invalid("OCI transaction ownership/type mismatch"));
    }
    let transaction_identity = Identity::from_stat(&stat);
    match read_marker(&transaction, "intent")? {
        None => {
            cleanup_unmarked(rootfs, transaction_name, transaction_identity, &transaction)?;
            return Ok(());
        }
        Some(bytes) => {
            let (nonce, digest) = parse_intent(&bytes)?;
            if transaction_name != format!("{TRANSACTION_PREFIX}{nonce}") {
                return Err(invalid("OCI transaction nonce mismatch"));
            }
            let digest_name = digest_value(&digest)?;
            let prepared = read_marker(&transaction, "prepared")?
                .map(|bytes| parse_identity(&bytes, &digest))
                .transpose()?;
            let committed = read_commit(&rootfs_path.join(".commits"), &digest_name)?;
            let final_identity = directory_identity(rootfs, &digest_name)?;
            let manifest_valid =
                manifest_matches(manifests_path, &digest_name, &digest, max_manifest_bytes);

            if let Some(commit) = committed {
                if final_identity != Some(commit) || !manifest_valid {
                    return Err(invalid("durable OCI commit is inconsistent"));
                }
                super::rootfs::verify_extracted_root(&rootfs_path.join(&digest_name))?;
                unix_fs::fsync(rootfs.as_fd())?;
                remove_owned_tree(rootfs, transaction_name, transaction_identity)?;
                return Ok(());
            }

            if let Some(identity) = final_identity {
                if prepared == Some(identity) {
                    if manifest_valid {
                        super::rootfs::verify_extracted_root(&rootfs_path.join(&digest_name))?;
                        publish_commit(rootfs_path, &digest, &digest_name, identity)?;
                    } else {
                        remove_published_root(rootfs, &digest_name, identity)?;
                    }
                }
            }
            remove_owned_tree(rootfs, transaction_name, transaction_identity)
        }
    }
}

fn cleanup_unmarked(
    rootfs: &SecureDir,
    transaction_name: &str,
    identity: Identity,
    transaction: &SecureDir,
) -> io::Result<()> {
    let mut entries = unix_fs::Dir::read_from(transaction.as_fd())?;
    let mut payload_empty = true;
    for entry in &mut entries {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_bytes() == b"intent" {
            let Some(bytes) = read_marker(transaction, "intent")? else {
                return Err(invalid("OCI transaction intent disappeared"));
            };
            let expected = valid_intent_prefix(&bytes, transaction_name)?;
            if !expected {
                return Err(invalid("unrecognized OCI transaction intent"));
            }
        } else if name.to_bytes() == b"payload" {
            let payload = transaction.open_child("payload").map_err(to_io)?;
            let mut children = unix_fs::Dir::read_from(payload.as_fd())?;
            payload_empty = true;
            for child in &mut children {
                let child = child?;
                if !matches!(child.file_name().to_bytes(), b"." | b"..") {
                    payload_empty = false;
                    break;
                }
            }
            if !payload_empty {
                return Err(invalid("unmarked OCI transaction contains staged data"));
            }
        } else if !matches!(name.to_bytes(), b"." | b"..") {
            return Err(invalid("unrecognized unmarked OCI transaction entry"));
        }
    }
    if !payload_empty {
        return Err(invalid("unmarked OCI transaction is not empty"));
    }
    remove_owned_tree(rootfs, transaction_name, identity)
}

fn valid_intent_prefix(bytes: &[u8], transaction_name: &str) -> io::Result<bool> {
    let Some(nonce) = transaction_name.strip_prefix(TRANSACTION_PREFIX) else {
        return Ok(false);
    };
    let prefix = format!("APOLLO-OCI-INTENT-1\n{nonce}\nsha256:");
    Ok(prefix.as_bytes().starts_with(bytes) || bytes.starts_with(prefix.as_bytes()))
}

fn publish_commit(
    rootfs_path: &Path,
    digest: &str,
    digest_name: &str,
    identity: Identity,
) -> io::Result<()> {
    let commit_dir = rootfs_path.join(".commits");
    let bytes = commit_bytes(digest, identity);
    let record_digest = format!("sha256:{:x}", Sha256::digest(bytes.as_bytes()));
    super::content::write_verified(
        &commit_dir.join(format!("{digest_name}.commit")),
        bytes.as_bytes(),
        &record_digest,
    )?;
    match read_commit(&commit_dir, digest_name)? {
        Some(actual) if actual == identity => Ok(()),
        _ => Err(invalid("OCI commit record publication mismatch")),
    }
}

fn read_commit(commit_dir: &Path, digest_name: &str) -> io::Result<Option<Identity>> {
    let directory = match SecureDir::open(commit_dir) {
        Ok(value) => value,
        Err(crate::error::Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(None),
        Err(error) => return Err(to_io(error)),
    };
    let name = format!("{digest_name}.commit");
    let Some(bytes) = read_marker(&directory, &name)? else {
        return Ok(None);
    };
    let digest = format!("sha256:{digest_name}");
    parse_commit(&bytes, &digest).map(Some)
}

fn manifest_matches(path: &Path, digest_name: &str, digest: &str, max: u64) -> bool {
    let manifest = path.join(digest_name);
    match super::content::read_bounded_file(&manifest, max) {
        Ok(bytes) => format!("sha256:{:x}", Sha256::digest(bytes)) == digest,
        Err(_) => false,
    }
}

fn remove_published_root(rootfs: &SecureDir, name: &str, expected: Identity) -> io::Result<()> {
    super::materialization_fs::remove_directory_tree(rootfs, name, expected)
}

fn remove_owned_tree(parent: &SecureDir, name: &str, expected: Identity) -> io::Result<()> {
    super::materialization_fs::remove_directory_tree(parent, name, expected)
}

fn write_marker(directory: &SecureDir, name: &str, contents: &[u8]) -> io::Result<()> {
    let mut file = directory.create_file(name).map_err(to_io)?;
    file.write_all(contents)?;
    file.sync_all()?;
    unix_fs::fsync(directory.as_fd())?;
    Ok(())
}

fn read_marker(directory: &SecureDir, name: &str) -> io::Result<Option<Vec<u8>>> {
    let file = match directory.open_file(name, false) {
        Ok(value) => value,
        Err(crate::error::Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(None),
        Err(error) => return Err(to_io(error)),
    };
    let stat = unix_fs::fstat(&file)?;
    if stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o777 != 0o600
        || stat.st_nlink != 1
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_size < 0
        || stat.st_size as u64 > MARKER_LIMIT
    {
        return Err(invalid("OCI transaction marker ownership/type mismatch"));
    }
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    file.take(MARKER_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MARKER_LIMIT {
        return Err(invalid("OCI transaction marker exceeds limit"));
    }
    Ok(Some(bytes))
}

pub(super) fn to_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
