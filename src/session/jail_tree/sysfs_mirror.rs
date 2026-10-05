//! Bounded capture and removal support for jailer-created ARM sysfs mirrors.
use super::{JailEntry, PinnedDir, capture_entry, is_noent, kind, reject_sysfs_unknown};
use crate::error::{Error, Result};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const MAX_CACHE_INDEXES: u8 = 8;

pub(super) fn allowed_sysfs_entry(path: &Path) -> bool {
    let Some(path) = path.to_str() else {
        return false;
    };
    let parts = path.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["root", "sys"]
        | ["root", "sys", "devices"]
        | ["root", "sys", "devices", "system"]
        | ["root", "sys", "devices", "system", "cpu"]
        | ["root", "sys", "devices", "system", "cpu", "cpu0"]
        | ["root", "sys", "devices", "system", "cpu", "cpu0", "cache"]
        | ["root", "sys", "devices", "system", "cpu", "cpu0", "regs"]
        | [
            "root",
            "sys",
            "devices",
            "system",
            "cpu",
            "cpu0",
            "regs",
            "identification",
        ] => true,
        [
            "root",
            "sys",
            "devices",
            "system",
            "cpu",
            "cpu0",
            "cache",
            index,
        ] if cache_index(index).is_some() => true,
        [
            "root",
            "sys",
            "devices",
            "system",
            "cpu",
            "cpu0",
            "cache",
            index,
            file,
        ] if cache_index(index).is_some()
            && matches!(
                *file,
                "level"
                    | "type"
                    | "shared_cpu_map"
                    | "coherency_line_size"
                    | "size"
                    | "number_of_sets"
            ) =>
        {
            true
        }
        [
            "root",
            "sys",
            "devices",
            "system",
            "cpu",
            "cpu0",
            "regs",
            "identification",
            "midr_el1",
        ] => true,
        _ => false,
    }
}

fn cache_index(name: &str) -> Option<u8> {
    let index = name.strip_prefix("index")?.parse::<u8>().ok()?;
    (index < MAX_CACHE_INDEXES).then_some(index)
}

pub(super) fn capture(
    jail_root: &Path,
    uid: u32,
    gid: u32,
    entries: &mut Vec<JailEntry>,
) -> Result<()> {
    const PREFIX: &str = "root/sys/devices/system/cpu/cpu0";
    let sys = jail_root.join("sys");
    let Some(root_sys) = capture_sys_dir(&sys, "root/sys", uid, gid, true)? else {
        return Ok(());
    };
    entries.push(root_sys);
    reject_sysfs_unknown(&sys, &["devices"])?;
    let mut parent = sys;
    for component in ["devices", "system", "cpu", "cpu0"] {
        parent.push(component);
        let relative =
            Path::new("root").join(parent.strip_prefix(jail_root).map_err(|_| Error::Path)?);
        let entry = capture_sys_dir(
            &parent,
            relative.to_str().ok_or(Error::Path)?,
            uid,
            gid,
            false,
        )?
        .ok_or(Error::Path)?;
        entries.push(entry);
        let allowed = match component {
            "devices" => &["system"][..],
            "system" => &["cpu"][..],
            "cpu" => &["cpu0"][..],
            "cpu0" => &["cache", "regs"][..],
            _ => return Err(Error::Path),
        };
        reject_sysfs_unknown(&parent, allowed)?;
    }

    let cache = parent.join("cache");
    if let Some(entry) = capture_sys_dir(&cache, &format!("{PREFIX}/cache"), uid, gid, true)? {
        entries.push(entry);
        let index_names: Vec<String> = (0..MAX_CACHE_INDEXES)
            .map(|index| format!("index{index}"))
            .collect();
        let index_refs: Vec<&str> = index_names.iter().map(String::as_str).collect();
        reject_sysfs_unknown(&cache, &index_refs)?;
        for index in 0..MAX_CACHE_INDEXES {
            let name = format!("index{index}");
            let directory = cache.join(&name);
            let relative = format!("{PREFIX}/cache/{name}");
            let Some(entry) = capture_sys_dir(&directory, &relative, uid, gid, true)? else {
                continue;
            };
            entries.push(entry);
            const CACHE_FILES: &[&str] = &[
                "level",
                "type",
                "shared_cpu_map",
                "coherency_line_size",
                "size",
                "number_of_sets",
            ];
            reject_sysfs_unknown(&directory, CACHE_FILES)?;
            for file in CACHE_FILES {
                if let Some(entry) = capture_sys_file(
                    &directory.join(file),
                    &format!("{relative}/{file}"),
                    uid,
                    gid,
                )? {
                    entries.push(entry);
                }
            }
        }
    }

    let regs = parent.join("regs");
    if let Some(entry) = capture_sys_dir(&regs, &format!("{PREFIX}/regs"), uid, gid, true)? {
        entries.push(entry);
        reject_sysfs_unknown(&regs, &["identification"])?;
        let identification = regs.join("identification");
        if let Some(entry) = capture_sys_dir(
            &identification,
            &format!("{PREFIX}/regs/identification"),
            uid,
            gid,
            true,
        )? {
            entries.push(entry);
            reject_sysfs_unknown(&identification, &["midr_el1"])?;
            if let Some(entry) = capture_sys_file(
                &identification.join("midr_el1"),
                &format!("{PREFIX}/regs/identification/midr_el1"),
                uid,
                gid,
            )? {
                entries.push(entry);
            }
        }
    }
    Ok(())
}

fn capture_sys_dir(
    path: &Path,
    relative: &str,
    uid: u32,
    gid: u32,
    optional: bool,
) -> Result<Option<JailEntry>> {
    let entry = capture_entry(path, relative.into(), uid, gid, optional)?;
    if let Some(entry) = &entry {
        if kind(entry.mode) != rustix::fs::FileType::Directory {
            return Err(Error::Path);
        }
    }
    Ok(entry)
}

fn capture_sys_file(path: &Path, relative: &str, uid: u32, gid: u32) -> Result<Option<JailEntry>> {
    let entry = capture_entry(path, relative.into(), uid, gid, true)?;
    if let Some(entry) = &entry {
        if kind(entry.mode) != rustix::fs::FileType::RegularFile {
            return Err(Error::Path);
        }
    }
    Ok(entry)
}

pub(super) fn open_directories(
    entries: &[JailEntry],
    root: Option<&PinnedDir>,
) -> Result<BTreeMap<PathBuf, PinnedDir>> {
    let mut directories = BTreeMap::new();
    let mut sys_entries = entries
        .iter()
        .filter(|entry| entry.relative.starts_with("root/sys"))
        .collect::<Vec<_>>();
    sys_entries.sort_by_key(|entry| entry.relative.components().count());
    for entry in sys_entries {
        if kind(entry.mode) != rustix::fs::FileType::Directory {
            continue;
        }
        let Some(root) = root else {
            continue;
        };
        let parent = entry.relative.parent().ok_or(Error::Path)?;
        let parent_fd = if parent == Path::new("root") {
            Some(root.as_fd())
        } else {
            directories.get(parent).map(PinnedDir::as_fd)
        };
        let Some(parent_fd) = parent_fd else {
            continue;
        };
        let name = entry
            .relative
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::Path)?;
        let directory = match PinnedDir::open(parent_fd, name, entry) {
            Ok(directory) => Some(directory),
            Err(error) if is_noent(&error) => None,
            Err(error) => return Err(error),
        };
        if let Some(directory) = directory {
            directories.insert(entry.relative.clone(), directory);
        }
    }
    Ok(directories)
}
