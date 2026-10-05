//! Verified content-addressed export storage, quota accounting, and crash recovery.
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::{fd::OwnedFd, unix::fs::MetadataExt},
    path::Path,
};

const BUFFER_BYTES: usize = 64 * 1024;

pub(crate) fn load_filesystem_export(
    state: &Path,
    uid: u32,
    sha256: &str,
    expected_len: u64,
    max_bytes: u64,
) -> Result<OwnedFd> {
    if sha256.len() != 64
        || !sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || expected_len == 0
        || expected_len > max_bytes
    {
        return Err(Error::Path);
    }
    let directory = export_dir(state, uid)?;
    let file = directory.open_file(&blob_name(sha256), false)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o400
        || metadata.len() != expected_len
        || expected_len > max_bytes
    {
        return Err(Error::Path);
    }
    let mut source = file;
    source.seek(SeekFrom::Start(0))?;
    let fd = memfd_create(
        "apollo-oci-layer",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?;
    let mut staged = File::from(fd);
    let mut copied = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; BUFFER_BYTES];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied = copied.checked_add(count as u64).ok_or(Error::Path)?;
        if copied > expected_len {
            return Err(Error::Path);
        }
        staged.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
    }
    if copied != expected_len || hex::encode(hash.finalize()) != sha256 {
        return Err(Error::Path);
    }
    staged.flush()?;
    staged.seek(SeekFrom::Start(0))?;
    fcntl_add_seals(
        &staged,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    Ok(staged.into())
}

pub(super) fn export_root(state: &Path) -> Result<SecureDir> {
    SecureDir::open(state)?.ensure_private_directory("filesystem-exports")
}
pub(super) fn export_dir(state: &Path, uid: u32) -> Result<SecureDir> {
    export_root(state)?.open_child(&uid.to_string())
}
pub(super) fn blob_name(sha256: &str) -> String {
    format!("{sha256}.layer")
}

pub(super) fn verify_blob(
    mut file: File,
    sha256: &str,
    expected_len: u64,
    max_bytes: u64,
) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o400
        || metadata.len() != expected_len
        || expected_len > max_bytes
    {
        return Err(Error::Path);
    }
    let source = &mut file;
    let mut digest = Sha256::new();
    let mut len = 0u64;
    let mut buf = [0; BUFFER_BYTES];
    loop {
        let count = source.read(&mut buf)?;
        if count == 0 {
            break;
        }
        len = len.checked_add(count as u64).ok_or(Error::Path)?;
        if len > max_bytes {
            return Err(Error::Path);
        }
        digest.update(&buf[..count]);
    }
    if len != expected_len || hex::encode(digest.finalize()) != sha256 {
        return Err(Error::Path);
    }
    Ok(())
}

pub(super) fn stored_usage(root_path: &Path) -> Result<u64> {
    let mut usage = 0u64;
    for item in fs::read_dir(root_path)? {
        let entry = item?;
        if entry.file_name() == "publish.lock" {
            continue;
        }
        let dir_meta = fs::symlink_metadata(entry.path())?;
        if !dir_meta.is_dir()
            || dir_meta.uid() != rustix::process::geteuid().as_raw()
            || dir_meta.mode() & 0o777 != 0o700
        {
            return Err(Error::Path);
        }
        for file in fs::read_dir(entry.path())? {
            let file = file?;
            let name = file.file_name();
            if name == "publish.lock" {
                continue;
            }
            let metadata = fs::symlink_metadata(file.path())?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(Error::Path);
            }
            if name.to_str().is_some_and(|n| n.starts_with(".stage-")) {
                if !matches!(metadata.mode() & 0o777, 0o600 | 0o400) {
                    return Err(Error::Path);
                }
                usage = usage.checked_add(metadata.len()).ok_or(Error::Path)?;
            } else {
                if metadata.mode() & 0o777 != 0o400
                    || !name.to_str().is_some_and(|n| n.ends_with(".layer"))
                {
                    return Err(Error::Path);
                }
                usage = usage.checked_add(metadata.len()).ok_or(Error::Path)?;
            }
        }
    }
    Ok(usage)
}

pub(super) fn recover_stages_root(path: &Path) -> Result<()> {
    for user_dir in fs::read_dir(path)? {
        let user_dir = user_dir?;
        if user_dir.file_name() == "publish.lock" {
            continue;
        }
        let metadata = fs::symlink_metadata(user_dir.path())?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(Error::Path);
        }
        let directory = SecureDir::open(&user_dir.path())?;
        for item in fs::read_dir(user_dir.path())? {
            let entry = item?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Err(Error::Path);
            };
            if !name.starts_with(".stage-") {
                continue;
            }
            let stage = directory.open_file(&name, false)?;
            if let Err(error) =
                rustix::fs::flock(&stage, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            {
                if error == rustix::io::Errno::WOULDBLOCK {
                    continue;
                }
                return Err(error.into());
            }
            let meta = stage.metadata()?;
            if meta.nlink() != 1
                || meta.uid() != rustix::process::geteuid().as_raw()
                || !matches!(meta.mode() & 0o777, 0o600 | 0o400)
                || meta.len() > sandboxd_protocol::MAX_FILESYSTEM_EXPORT_BYTES
            {
                return Err(Error::Path);
            }
            drop(stage);
            rustix::fs::unlinkat(
                directory.as_fd(),
                name.as_str(),
                rustix::fs::AtFlags::empty(),
            )?;
        }
    }
    Ok(())
}
