use rustix::fs::{self as unix_fs, AtFlags, Gid, Mode, OFlags, Uid};
use std::os::fd::OwnedFd;
use std::{
    fs,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
};
use tar::{Archive, EntryType};

use super::layer_scan;

#[derive(Clone, Copy)]
pub struct LayerLimits {
    pub max_entries: u64,
    pub max_uncompressed_bytes: u64,
    pub max_file_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LayerUsage {
    pub entries: u64,
    pub bytes: u64,
}

pub fn apply_layer(
    source: &Path,
    root: &Path,
    gzip: bool,
    limits: LayerLimits,
) -> io::Result<LayerUsage> {
    layer_scan::validate(source, gzip, limits)?;
    let whiteouts = collect_whiteouts(source, gzip, limits.max_entries)?;
    for (directory, target) in &whiteouts {
        if *target {
            remove_children(root, &root.join(directory))?;
        } else {
            let path = root.join(directory);
            // A guest-absolute symlink is valid image data, but a whiteout
            // must never traverse it to delete an unrelated host object.
            reject_symlink_components(root, path.parent().ok_or_else(path_error)?)?;
            remove_owned(&path)?;
        }
    }
    let reader = layer_scan::open_reader(source, gzip)?;
    apply_entries(Archive::new(reader), root, limits)
}

fn collect_whiteouts(
    source: &Path,
    gzip: bool,
    max_entries: u64,
) -> io::Result<Vec<(PathBuf, bool)>> {
    let reader = layer_scan::open_reader(source, gzip)?;
    let mut archive = Archive::new(reader);
    let mut result = Vec::new();
    let mut entries = 0u64;
    for item in archive.entries()? {
        let entry = item?;
        entries = entries.checked_add(1).ok_or_else(limit_error)?;
        if entries > max_entries {
            return Err(limit_error());
        }
        let relative = entry.path()?.into_owned();
        validate_relative(&relative)?;
        let name = relative.file_name().ok_or_else(path_error)?;
        if name == ".wh..wh..opq" {
            result.push((
                relative
                    .parent()
                    .unwrap_or_else(|| Path::new(""))
                    .to_path_buf(),
                true,
            ));
        } else if let Some(target) = name.to_str().and_then(|v| v.strip_prefix(".wh.")) {
            if target.is_empty() || matches!(target, "." | "..") {
                return Err(path_error());
            }
            let mut path = relative
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf();
            path.push(target);
            validate_relative(&path)?;
            result.push((path, false));
        }
    }
    Ok(result)
}

fn apply_entries<R: Read>(
    mut archive: Archive<R>,
    root: &Path,
    limits: LayerLimits,
) -> io::Result<LayerUsage> {
    let mut entries = 0u64;
    let mut bytes = 0u64;
    for item in archive.entries()? {
        let mut entry = item?;
        entries = entries.checked_add(1).ok_or_else(limit_error)?;
        if entries > limits.max_entries {
            return Err(limit_error());
        }
        let relative = entry.path()?.into_owned();
        validate_relative(&relative)?;
        let name = relative.file_name().ok_or_else(path_error)?;
        if name.to_str().is_some_and(|value| value.starts_with(".wh.")) {
            continue;
        }
        let target = root.join(&relative);
        ensure_parent(root, &target)?;
        let (xattrs, xattr_bytes) = read_xattrs(&mut entry)?;
        bytes = bytes.checked_add(xattr_bytes).ok_or_else(limit_error)?;
        if bytes > limits.max_uncompressed_bytes {
            return Err(limit_error());
        }
        let kind = entry.header().entry_type();
        match kind {
            EntryType::Directory => {
                ensure_directory(&target)?;
                chmod_from_tar(&entry, &target)?;
                apply_owner(&entry, &target)?;
                apply_xattrs(&target, &xattrs)?;
            }
            EntryType::Regular => {
                let size = entry.size();
                let next = bytes.checked_add(size).ok_or_else(limit_error)?;
                if size > limits.max_file_bytes || next > limits.max_uncompressed_bytes {
                    return Err(limit_error());
                }
                let temporary = temporary_path(&target);
                let mut output = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)?;
                io::copy(&mut entry, &mut output)?;
                output.sync_all()?;
                chmod_from_tar(&entry, &temporary)?;
                replace_owned(&temporary, &target)?;
                apply_owner(&entry, &target)?;
                apply_xattrs(&target, &xattrs)?;
                bytes = next;
            }
            EntryType::Symlink => {
                if !xattrs.is_empty() {
                    return Err(path_error());
                }
                let link = entry.link_name()?.ok_or_else(path_error)?;
                validate_symlink_target(&relative, &link)?;
                remove_owned(&target)?;
                std::os::unix::fs::symlink(link, &target)?;
                apply_xattrs(&target, &xattrs)?;
            }
            EntryType::Link => {
                let link = entry.link_name()?.ok_or_else(path_error)?;
                validate_relative(&link)?;
                let source = root.join(link);
                reject_symlink_components(root, &source)?;
                if !source.is_file() {
                    return Err(path_error());
                }
                remove_owned(&target)?;
                fs::hard_link(source, &target)?;
                apply_owner(&entry, &target)?;
                apply_xattrs(&target, &xattrs)?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "device or special tar entry rejected",
                ));
            }
        }
    }
    Ok(LayerUsage { entries, bytes })
}

fn validate_relative(path: &Path) -> io::Result<()> {
    if path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(path_error());
    }
    Ok(())
}

fn validate_symlink_target(link_path: &Path, target: &Path) -> io::Result<()> {
    if target.is_absolute() {
        return Ok(()); // absolute links are guest paths and are never host-followed
    }
    let mut depth = 0i32;
    for component in link_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .components()
    {
        if matches!(component, Component::Normal(_)) {
            depth += 1;
        }
    }
    for component in target.components() {
        match component {
            Component::ParentDir => depth -= 1,
            Component::Normal(_) => depth += 1,
            Component::CurDir => (),
            _ => return Err(path_error()),
        }
        if depth < 0 {
            return Err(path_error());
        }
    }
    Ok(())
}

fn ensure_parent(root: &Path, target: &Path) -> io::Result<()> {
    let parent = target.parent().ok_or_else(path_error)?;
    let relative = parent.strip_prefix(root).map_err(|_| path_error())?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory: OwnedFd =
        unix_fs::open(root, flags, Mode::empty()).map_err(io::Error::from)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(path_error());
        };
        let next = match unix_fs::openat(&directory, name, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => {
                unix_fs::mkdirat(&directory, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
                    .map_err(io::Error::from)?;
                unix_fs::openat(&directory, name, flags, Mode::empty()).map_err(io::Error::from)?
            }
            Err(error) => return Err(io::Error::from(error)),
        };
        directory = next;
    }
    Ok(())
}

fn reject_symlink_components(root: &Path, path: &Path) -> io::Result<()> {
    let relative = path.strip_prefix(root).map_err(|_| path_error())?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(path_error());
        }
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(path_error()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(path),
        Err(error) => Err(error),
    }
}

fn remove_children(root: &Path, path: &Path) -> io::Result<()> {
    reject_symlink_components(root, path)?;
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        remove_owned(&entry?.path())?;
    }
    Ok(())
}

fn remove_owned(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || metadata.is_file() {
        fs::remove_file(path)
    } else if metadata.is_dir() {
        fs::remove_dir_all(path)
    } else {
        Err(path_error())
    }
}

fn replace_owned(source: &Path, target: &Path) -> io::Result<()> {
    remove_owned(target)?;
    fs::rename(source, target)
}

fn temporary_path(target: &Path) -> PathBuf {
    let mut value = target.as_os_str().to_os_string();
    value.push(format!(".tmp-{}", std::process::id()));
    PathBuf::from(value)
}

fn chmod_from_tar<R: Read>(entry: &tar::Entry<'_, R>, target: &Path) -> io::Result<()> {
    let mode = entry.header().mode()? as u32 & 0o7777;
    fs::set_permissions(target, fs::Permissions::from_mode(mode))
}

fn apply_owner<R: Read>(entry: &tar::Entry<'_, R>, target: &Path) -> io::Result<()> {
    let uid = entry.header().uid()?;
    let gid = entry.header().gid()?;
    if uid > u32::MAX as u64 || gid > u32::MAX as u64 {
        return Err(path_error());
    }
    if rustix::process::geteuid().as_raw() != 0 {
        // Unprivileged imports cannot preserve arbitrary numeric owners.
        return Ok(());
    }
    unix_fs::chownat(
        rustix::fs::CWD,
        target,
        Some(Uid::from_raw(uid as u32)),
        Some(Gid::from_raw(gid as u32)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)
}

fn read_xattrs<R: Read>(
    entry: &mut tar::Entry<'_, R>,
) -> io::Result<(Vec<(String, Vec<u8>)>, u64)> {
    let mut result = Vec::new();
    let mut total = 0u64;
    if let Some(extensions) = entry.pax_extensions()? {
        for extension in extensions {
            let extension = extension?;
            if let Some(name) = extension
                .key()
                .ok()
                .and_then(|key| key.strip_prefix("SCHILY.xattr."))
            {
                let value = extension.value_bytes();
                if !allowed_xattr(name) || value.len() > 64 * 1024 || result.len() >= 64 {
                    return Err(path_error());
                }
                total = total
                    .checked_add(value.len() as u64)
                    .ok_or_else(limit_error)?;
                if total > 256 * 1024 {
                    return Err(limit_error());
                }
                result.push((name.to_owned(), value.to_vec()));
            }
        }
    }
    Ok((result, total))
}

fn allowed_xattr(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && (name.starts_with("user.") || name == "security.capability")
}

fn apply_xattrs(path: &Path, values: &[(String, Vec<u8>)]) -> io::Result<()> {
    for (name, value) in values {
        xattr::set(path, name, value)?;
    }
    Ok(())
}

fn limit_error() -> io::Error {
    io::Error::new(io::ErrorKind::FileTooLarge, "OCI layer limit exceeded")
}
fn path_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unsafe OCI layer path")
}
