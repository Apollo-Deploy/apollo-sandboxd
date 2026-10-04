use guest_protocol::{DirectoryEntry, FileKind, FileMetadata, FileRequest, GuestMessage};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::time::UNIX_EPOCH;

#[path = "file_write.rs"]
mod write;

pub fn handle(request: FileRequest) -> Result<GuestMessage, String> {
    request.validate().map_err(str::to_owned)?;
    match request {
        FileRequest::Stat {
            path,
            follow_symlink,
        } => {
            let file_metadata = if follow_symlink {
                fs::metadata(path)
            } else {
                fs::symlink_metadata(path)
            }
            .map_err(io_error)?;
            Ok(GuestMessage::FileResult {
                data: Vec::new(),
                offset: 0,
                eof: true,
                metadata: Some(metadata(&file_metadata)),
                entries: Vec::new(),
                link_target: None,
            })
        }
        FileRequest::List {
            path,
            cursor,
            limit,
        } => list(&path, cursor.as_deref(), limit),
        FileRequest::Read {
            path,
            offset,
            limit,
        } => read_file(&path, offset, limit),
        FileRequest::Write {
            transfer_id,
            path,
            offset,
            data,
            final_chunk,
            sha256,
            atomic_replace,
        } => write::write_file(
            &transfer_id,
            &path,
            offset,
            &data,
            final_chunk,
            sha256,
            atomic_replace,
        ),
        FileRequest::Mkdir {
            path,
            mode,
            parents,
        } => {
            if parents {
                fs::create_dir_all(&path)
            } else {
                fs::create_dir(&path)
            }
            .map_err(io_error)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).map_err(io_error)?;
            ok_result()
        }
        FileRequest::Remove { path, recursive } => {
            let kind = fs::symlink_metadata(&path).map_err(io_error)?;
            let result = if kind.is_dir() {
                if recursive {
                    fs::remove_dir_all(&path)
                } else {
                    fs::remove_dir(&path)
                }
            } else {
                fs::remove_file(&path)
            };
            result.map_err(io_error)?;
            ok_result()
        }
        FileRequest::Rename {
            source,
            destination,
        } => {
            fs::rename(source, destination).map_err(io_error)?;
            ok_result()
        }
        FileRequest::Chmod { path, mode } => {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_error)?;
            ok_result()
        }
        FileRequest::Chown { path, uid, gid } => {
            chown(&path, uid, gid)?;
            ok_result()
        }
        FileRequest::Symlink { target, path } => {
            std::os::unix::fs::symlink(target, path).map_err(io_error)?;
            ok_result()
        }
        FileRequest::Readlink { path } => {
            let target = fs::read_link(path)
                .map_err(io_error)?
                .to_string_lossy()
                .into_owned();
            Ok(GuestMessage::FileResult {
                data: Vec::new(),
                offset: 0,
                eof: true,
                metadata: None,
                entries: Vec::new(),
                link_target: Some(target),
            })
        }
    }
}

fn list(path: &str, cursor: Option<&str>, limit: u16) -> Result<GuestMessage, String> {
    // Keep only the next page plus one lookahead entry. A directory with
    // millions of names must not allocate millions of entries in the agent.
    let mut entries = BTreeMap::new();
    let bound = usize::from(limit) + 1;
    for entry in fs::read_dir(path).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "directory name is not UTF-8")?;
        if cursor.is_some_and(|cursor| name.as_str() <= cursor) {
            continue;
        }
        entries.insert(name, entry);
        if entries.len() > bound {
            entries.pop_last();
        }
    }
    let more = entries.len() > usize::from(limit);
    if more {
        entries.pop_last();
    }
    let page = entries
        .into_iter()
        .map(|(name, entry)| {
            let meta = fs::symlink_metadata(entry.path()).map_err(io_error)?;
            Ok(DirectoryEntry {
                name,
                metadata: metadata(&meta),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let next = if more {
        page.last().map(|entry| entry.name.clone())
    } else {
        None
    };
    Ok(GuestMessage::FileResult {
        data: Vec::new(),
        offset: 0,
        eof: next.is_none(),
        metadata: None,
        entries: page,
        link_target: next,
    })
}

fn read_file(path: &str, offset: u64, limit: u32) -> Result<GuestMessage, String> {
    let mut file = File::open(path).map_err(io_error)?;
    file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
    let mut data = vec![0; usize::try_from(limit).map_err(|_| "read limit")?];
    let count = file.read(&mut data).map_err(io_error)?;
    data.truncate(count);
    Ok(GuestMessage::FileResult {
        data,
        offset,
        eof: count < usize::try_from(limit).map_err(|_| "read limit")?,
        metadata: None,
        entries: Vec::new(),
        link_target: None,
    })
}

fn metadata(value: &fs::Metadata) -> FileMetadata {
    let kind = if value.file_type().is_file() {
        FileKind::Regular
    } else if value.file_type().is_dir() {
        FileKind::Directory
    } else if value.file_type().is_symlink() {
        FileKind::Symlink
    } else {
        FileKind::Other
    };
    let modified_unix_ms = value
        .modified()
        .ok()
        .and_then(|v| v.duration_since(UNIX_EPOCH).ok())
        .and_then(|v| u64::try_from(v.as_millis()).ok());
    FileMetadata {
        kind,
        size: value.len(),
        mode: value.mode(),
        uid: value.uid(),
        gid: value.gid(),
        modified_unix_ms,
    }
}

fn ok_result() -> Result<GuestMessage, String> {
    Ok(GuestMessage::FileResult {
        data: Vec::new(),
        offset: 0,
        eof: true,
        metadata: None,
        entries: Vec::new(),
        link_target: None,
    })
}
fn io_error(error: std::io::Error) -> String {
    format!("guest file operation failed: {error}")
}

#[cfg(target_os = "linux")]
fn chown(path: &str, uid: u32, gid: u32) -> Result<(), String> {
    nix::unistd::chown(
        Path::new(path),
        Some(nix::unistd::Uid::from_raw(uid)),
        Some(nix::unistd::Gid::from_raw(gid)),
    )
    .map_err(|e| e.to_string())
}
#[cfg(not(target_os = "linux"))]
fn chown(_path: &str, _uid: u32, _gid: u32) -> Result<(), String> {
    Err("chown is unsupported on this guest target".into())
}

use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
#[path = "file_tests.rs"]
mod tests;
