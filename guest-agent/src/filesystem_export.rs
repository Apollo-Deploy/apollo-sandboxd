//! Creates and serves a bounded OCI-compatible tar layer from overlay upper.
//! The spool is stored beside `upper` through the trusted state directory FD,
//! outside the guest-visible merged root and never addressed by customer path.
use sandboxd_protocol::OperationId;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
};

const MAX_XATTRS: usize = 64;
const MAX_XATTR_BYTES: usize = 256 * 1024;
#[path = "filesystem_export_spool.rs"]
mod spool;
pub use spool::{read, retire};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub sha256: String,
    pub byte_len: u64,
    pub entry_count: u32,
}

struct Budget {
    max_bytes: u64,
    max_entries: u32,
    expanded_bytes: u64,
    entry_count: u32,
    hardlinks: BTreeMap<(u64, u64), PathBuf>,
}

struct BoundedWriter<W> {
    inner: W,
    max_bytes: u64,
    written: u64,
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .ok_or_else(limit)?;
        if next > self.max_bytes {
            return Err(limit());
        }
        let count = self.inner.write(bytes)?;
        self.written += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn create(
    state: &File,
    operation: &OperationId,
    max_bytes: u64,
    max_entries: u32,
) -> Result<Receipt, String> {
    create_selected(state, operation, None, max_bytes, max_entries)
}

pub(crate) fn create_selected(
    state: &File,
    operation: &OperationId,
    selected: Option<&File>,
    max_bytes: u64,
    max_entries: u32,
) -> Result<Receipt, String> {
    if max_bytes == 0 || max_entries == 0 {
        return Err("filesystem export bounds".into());
    }
    let upper = selected.map_or_else(
        || spool::state_path(state, "upper"),
        |file| {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
        },
    );
    let upper_meta = if selected.is_some() {
        fs::metadata(&upper)
    } else {
        fs::symlink_metadata(&upper)
    }
    .map_err(io_code)?;
    if !upper_meta.is_dir()
        || (selected.is_none() && (upper_meta.uid() != 0 || upper_meta.mode() & 0o022 != 0))
    {
        return Err("trusted upper directory rejected".into());
    }
    #[cfg(target_os = "linux")]
    if let Some(file) = selected {
        use std::os::fd::AsRawFd;
        #[allow(unsafe_code)]
        if unsafe { nix::libc::syncfs(file.as_raw_fd()) } != 0 {
            return Err("sync selected volume failed".into());
        }
    }
    let spool = spool::Spool::new(state, operation).map_err(io_code)?;
    let mut budget = Budget {
        max_bytes,
        max_entries,
        expanded_bytes: 0,
        entry_count: 0,
        hardlinks: BTreeMap::new(),
    };
    let writer = BoundedWriter {
        inner: spool.file.try_clone().map_err(io_code)?,
        max_bytes,
        written: 0,
    };
    let mut archive = tar::Builder::new(writer);
    archive.mode(tar::HeaderMode::Complete);
    walk(
        &mut archive,
        &upper,
        Path::new(""),
        &mut budget,
        upper_meta.dev(),
        selected
            .map_or_else(|| mount_id(&upper), |file| selected_mount_id(file))
            .map_err(io_code)?,
    )
    .map_err(io_code)?;
    let writer = archive.into_inner().map_err(io_code)?;
    writer.inner.sync_all().map_err(io_code)?;
    let byte_len = writer.inner.metadata().map_err(io_code)?.len();
    drop(writer);
    let mut reader = spool.file.try_clone().map_err(io_code)?;
    reader.seek(SeekFrom::Start(0)).map_err(io_code)?;
    let mut digest = Sha256::new();
    let mut buf = [0; 64 * 1024];
    loop {
        let count = reader.read(&mut buf).map_err(io_code)?;
        if count == 0 {
            break;
        }
        digest.update(&buf[..count]);
    }
    spool.publish().map_err(io_code)?;
    Ok(Receipt {
        sha256: hex::encode(digest.finalize()),
        byte_len,
        entry_count: budget.entry_count,
    })
}

fn walk(
    archive: &mut tar::Builder<BoundedWriter<File>>,
    dir: &Path,
    relative: &Path,
    budget: &mut Budget,
    device: u64,
    source_mount: u64,
) -> io::Result<()> {
    // Bound allocation before sorting; tar accounting happens later.
    let mut children = Vec::new();
    let remaining = budget.max_entries.saturating_sub(budget.entry_count) as usize;
    for child in fs::read_dir(dir)? {
        if children.len() >= remaining {
            return Err(limit());
        }
        children.push(child?);
    }
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let name = child.file_name();
        if name.as_bytes().contains(&b'/')
            || name.as_bytes().contains(&0)
            || name == "."
            || name == ".."
        {
            return Err(path_error());
        }
        if name.as_bytes().starts_with(b".wh.") {
            return Err(path_error());
        }
        let path = child.path();
        let rel = relative.join(&name);
        let metadata = fs::symlink_metadata(&path)?;
        // Never archive a nested mount, including a bind of the same disk.
        if metadata.dev() != device || mount_id(&path)? != source_mount {
            continue;
        }
        if metadata.file_type().is_char_device() && metadata.rdev() == 0 {
            let whiteout = rel
                .parent()
                .unwrap_or(Path::new(""))
                .join(format!(".wh.{}", name.to_string_lossy()));
            append_empty(archive, &whiteout, &metadata, budget)?;
            continue;
        }
        if metadata.is_dir() {
            let opaque = overlay_attr(&path, "opaque")?.is_some_and(|value| value == b"y");
            append_entry(
                archive,
                &path,
                &rel,
                EntrySpec {
                    metadata: &metadata,
                    kind: tar::EntryType::Directory,
                    size: 0,
                    link: None,
                },
                budget,
            )?;
            if opaque {
                let marker = rel.join(".wh..wh..opq");
                append_empty(archive, &marker, &metadata, budget)?;
            }
            walk(archive, &path, &rel, budget, device, source_mount)?;
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            append_entry(
                archive,
                &path,
                &rel,
                EntrySpec {
                    metadata: &metadata,
                    kind: tar::EntryType::Symlink,
                    size: 0,
                    link: Some(target),
                },
                budget,
            )?;
        } else if metadata.is_file() {
            let marker = overlay_attr(&path, "whiteout")?.is_some_and(|value| value == b"y");
            if marker {
                let whiteout = rel
                    .parent()
                    .unwrap_or(Path::new(""))
                    .join(format!(".wh.{}", name.to_string_lossy()));
                append_empty(archive, &whiteout, &metadata, budget)?;
                continue;
            }
            let key = (metadata.dev(), metadata.ino());
            if metadata.nlink() > 1
                && let Some(target) = budget.hardlinks.get(&key)
            {
                append_entry(
                    archive,
                    &path,
                    &rel,
                    EntrySpec {
                        metadata: &metadata,
                        kind: tar::EntryType::Link,
                        size: 0,
                        link: Some(target.clone()),
                    },
                    budget,
                )?;
            } else {
                if metadata.nlink() > 1 {
                    budget.hardlinks.insert(key, rel.clone());
                }
                let size = metadata.len();
                budget.expanded_bytes =
                    budget.expanded_bytes.checked_add(size).ok_or_else(limit)?;
                if budget.expanded_bytes > budget.max_bytes {
                    return Err(limit());
                }
                let mut input = File::open(&path)?;
                let mut header = header(&metadata, tar::EntryType::Regular, size)?;
                append_xattrs(archive, &path)?;
                account(budget)?;
                archive.append_data(&mut header, &rel, &mut input)?;
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported special file in overlay upper",
            ));
        }
    }
    Ok(())
}

fn overlay_attr(path: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
    for prefix in ["trusted.overlay.", "user.overlay."] {
        if let Some(value) = xattr::get(path, format!("{prefix}{name}"))? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn append_empty(
    archive: &mut tar::Builder<BoundedWriter<File>>,
    path: &Path,
    metadata: &fs::Metadata,
    budget: &mut Budget,
) -> io::Result<()> {
    account(budget)?;
    let mut header = header(metadata, tar::EntryType::Regular, 0)?;
    archive.append_data(&mut header, path, io::empty())
}

fn append_entry(
    archive: &mut tar::Builder<BoundedWriter<File>>,
    source: &Path,
    path: &Path,
    entry: EntrySpec<'_>,
    budget: &mut Budget,
) -> io::Result<()> {
    append_xattrs(archive, source)?;
    account(budget)?;
    let mut header = header(entry.metadata, entry.kind, entry.size)?;
    match entry.link {
        Some(target) => archive.append_link(&mut header, path, target),
        None => archive.append_data(&mut header, path, io::empty()),
    }
}

struct EntrySpec<'a> {
    metadata: &'a fs::Metadata,
    kind: tar::EntryType,
    size: u64,
    link: Option<PathBuf>,
}

fn header(metadata: &fs::Metadata, kind: tar::EntryType, size: u64) -> io::Result<tar::Header> {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(kind);
    header.set_size(size);
    header.set_mode(metadata.mode() & 0o7777);
    header.set_uid(u64::from(metadata.uid()));
    header.set_gid(u64::from(metadata.gid()));
    header.set_mtime(metadata.mtime().max(0) as u64);
    header.set_cksum();
    Ok(header)
}

fn append_xattrs(archive: &mut tar::Builder<BoundedWriter<File>>, path: &Path) -> io::Result<()> {
    let attrs = xattr::list(path)?
        .filter_map(|name| {
            let name = name.to_string_lossy().into_owned();
            if (name.starts_with("user.") && !name.starts_with("user.overlay."))
                || name == "security.capability"
            {
                Some(name)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if attrs.len() > MAX_XATTRS {
        return Err(path_error());
    }
    let mut total = 0usize;
    let mut values = Vec::with_capacity(attrs.len());
    for name in attrs {
        if name.is_empty() || name.len() > 255 {
            return Err(path_error());
        }
        let value = xattr::get(path, &name)?.ok_or_else(path_error)?;
        total = total.checked_add(value.len()).ok_or_else(limit)?;
        if value.len() > 64 * 1024 || total > MAX_XATTR_BYTES {
            return Err(limit());
        }
        values.push((format!("SCHILY.xattr.{name}"), value));
    }
    let refs = values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect::<Vec<_>>();
    archive.append_pax_extensions(refs)
}

fn account(budget: &mut Budget) -> io::Result<()> {
    budget.entry_count = budget.entry_count.checked_add(1).ok_or_else(limit)?;
    if budget.entry_count > budget.max_entries {
        return Err(limit());
    }
    Ok(())
}

fn io_code(error: io::Error) -> String {
    format!("filesystem export failed: {error}")
}
fn path_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unsafe filesystem export path")
}
fn limit() -> io::Error {
    io::Error::new(io::ErrorKind::FileTooLarge, "filesystem export limit")
}

#[cfg(all(test, target_os = "linux"))]
#[path = "filesystem_export_tests.rs"]
mod tests;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn mount_id(path: &Path) -> io::Result<u64> {
    use std::{
        ffi::CString,
        os::fd::{AsRawFd, FromRawFd},
    };
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| path_error())?;
    let fd = unsafe {
        nix::libc::open(
            path.as_ptr(),
            nix::libc::O_PATH | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    // Opening /proc/self/fd/N with O_NOFOLLOW selects the proc symlink itself;
    // source directories instead use their supplied descriptor's fdinfo.
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    info.lines()
        .find_map(|line| {
            line.strip_prefix("mnt_id:")
                .and_then(|value| value.trim().parse().ok())
        })
        .ok_or_else(path_error)
}
#[cfg(not(target_os = "linux"))]
fn mount_id(path: &Path) -> io::Result<u64> {
    Ok(fs::metadata(path)?.dev())
}

#[cfg(target_os = "linux")]
fn selected_mount_id(file: &File) -> io::Result<u64> {
    use std::os::fd::AsRawFd;
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    info.lines()
        .find_map(|line| {
            line.strip_prefix("mnt_id:")
                .and_then(|value| value.trim().parse().ok())
        })
        .ok_or_else(path_error)
}
#[cfg(not(target_os = "linux"))]
fn selected_mount_id(file: &File) -> io::Result<u64> {
    Ok(file.metadata()?.dev())
}
