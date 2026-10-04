//! Bounded chunk writes; the final offset defines the complete file length.
use super::{io_error, ok_result};
use guest_protocol::GuestMessage;
use sha2::{Digest, Sha256};
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

pub(super) fn write_file(
    transfer_id: &str,
    path: &str,
    offset: u64,
    data: &[u8],
    final_chunk: bool,
    expected: Option<[u8; 32]>,
    atomic_replace: bool,
) -> Result<GuestMessage, String> {
    let destination = Path::new(path);
    let actual_path = if atomic_replace {
        let mut name = destination
            .file_name()
            .ok_or("destination has no file name")?
            .to_os_string();
        name.push(format!(".sandboxd-{transfer_id}"));
        destination.with_file_name(name)
    } else {
        destination.to_path_buf()
    };
    let end = offset
        .checked_add(u64::try_from(data.len()).map_err(|_| "write size overflow")?)
        .ok_or("write offset overflow")?;
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&actual_path)
        .map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file() {
        return Err("write target is not a regular file".into());
    }
    file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
    file.write_all(data).map_err(io_error)?;
    if final_chunk {
        file.set_len(end).map_err(io_error)?;
    }
    file.sync_all().map_err(io_error)?;
    if final_chunk {
        if let Some(expected) = expected {
            file.seek(SeekFrom::Start(0)).map_err(io_error)?;
            let mut digest = Sha256::new();
            let mut chunk = [0; 65536];
            loop {
                let n = file.read(&mut chunk).map_err(io_error)?;
                if n == 0 {
                    break;
                }
                digest.update(&chunk[..n]);
            }
            if digest.finalize().as_slice() != expected {
                return Err("file digest mismatch".into());
            }
        }
        if atomic_replace {
            fs::rename(&actual_path, destination).map_err(io_error)?;
        }
    }
    // Durability includes a newly created temporary file and the final rename.
    let parent = actual_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(io_error)?;
    ok_result()
}
