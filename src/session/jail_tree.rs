//! Descriptor-pinned inventory of jailer-created files and device nodes.
use super::LaunchManifest;
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
};

const MAX_ENTRIES: usize = 96;
const MAX_PID_BYTES: u64 = 32;
const MAX_RUNTIME_BYTES: u64 = 4 << 30;

mod sysfs_mirror;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailTreeManifest {
    pub uid: u32,
    pub gid: u32,
    pub entries: Vec<JailEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailEntry {
    pub relative: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub links: u64,
}

pub fn capture(
    manifest: &LaunchManifest,
    uid: u32,
    gid: u32,
    expected_fc_sha256: &str,
) -> Result<JailTreeManifest> {
    let session = manifest.jail_root.parent().ok_or(Error::Path)?;
    let session_meta = fs::symlink_metadata(session)?;
    let root_meta = fs::symlink_metadata(&manifest.jail_root)?;
    let expected_session = manifest.assets.session_identity.ok_or(Error::Path)?;
    if session_meta.dev() != expected_session.device
        || session_meta.ino() != expected_session.inode
        || root_meta.dev() != manifest.assets.root_identity.device
        || root_meta.ino() != manifest.assets.root_identity.inode
        || !root_meta.is_dir()
    {
        return Err(Error::Path);
    }
    let mut entries = Vec::new();
    if capture_entry(&session.join("root"), "root".into(), uid, gid, false)?.is_none() {
        return Err(Error::Path);
    }
    for relative in [
        "root/dev",
        "root/firecracker",
        "root/firecracker.pid",
        "root/dev/kvm",
        "root/dev/net",
        "root/dev/net/tun",
        "root/dev/urandom",
        "root/dev/userfaultfd",
        "root/run/serial.log",
        "jailer.stderr",
    ] {
        let path = session.join(relative);
        let optional = matches!(
            relative,
            "root/firecracker.pid"
                | "root/dev/kvm"
                | "root/dev/net"
                | "root/dev/net/tun"
                | "root/dev/urandom"
                | "root/dev/userfaultfd"
                | "root/run/serial.log"
                | "jailer.stderr"
        );
        let Some(entry) = capture_entry(&path, relative.into(), uid, gid, optional)? else {
            continue;
        };
        expected_kind(relative, &entry)?;
        if relative == "root/firecracker" {
            verify_firecracker(&path, &entry, expected_fc_sha256, uid, gid)?;
        }
        entries.push(entry);
    }
    sysfs_mirror::capture(&manifest.jail_root, uid, gid, &mut entries)?;
    if entries.len() > MAX_ENTRIES {
        return Err(Error::Path);
    }
    reject_unknown(
        session,
        "root/dev",
        &["kvm", "net", "urandom", "userfaultfd"],
    )?;
    reject_unknown(session, "root/dev/net", &["tun"])?;
    reject_unknown(
        session,
        "root/run",
        &["serial.log", "firecracker.socket", "vsock.socket"],
    )?;
    if let Some(pid) = entry_for(&entries, "root/firecracker.pid") {
        let mut bytes = Vec::new();
        fs::File::open(session.join(&pid.relative))?
            .take(MAX_PID_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_PID_BYTES || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(Error::Path);
        }
    }
    Ok(JailTreeManifest { uid, gid, entries })
}

pub fn remove(manifest: &LaunchManifest, tree: &JailTreeManifest) -> Result<()> {
    if tree.uid == 0 || tree.gid == 0 || tree.entries.len() > MAX_ENTRIES {
        return Err(Error::Path);
    }
    let session = manifest.jail_root.parent().ok_or(Error::Path)?;
    let session_dir = match SecureDir::open(session) {
        Ok(dir) => dir,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let session_stat = rustix::fs::fstat(session_dir.as_fd())?;
    let expected_session = manifest.assets.session_identity.ok_or(Error::Path)?;
    if crate::security::path::device_id(session_stat.st_dev) != expected_session.device
        || session_stat.st_ino != expected_session.inode
    {
        return Err(Error::Path);
    }
    let root_stat = match rustix::fs::statat(
        session_dir.as_fd(),
        "root",
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(stat) => Some(stat),
        Err(rustix::io::Errno::NOENT) => None,
        Err(error) => return Err(error.into()),
    };
    let root = match root_stat {
        Some(stat) => {
            if crate::security::path::device_id(stat.st_dev) != manifest.assets.root_identity.device
                || stat.st_ino != manifest.assets.root_identity.inode
                || rustix::fs::FileType::from_raw_mode(stat.st_mode)
                    != rustix::fs::FileType::Directory
            {
                return Err(Error::Path);
            }
            Some(PinnedDir::open_identity(
                session_dir.as_fd(),
                "root",
                manifest.assets.root_identity,
            )?)
        }
        None => None,
    };
    let dev = match (&root, entry_for(&tree.entries, "root/dev")) {
        (Some(root), Some(entry)) => optional_open(PinnedDir::open(root.as_fd(), "dev", entry))?,
        _ => None,
    };
    let net = match (&dev, entry_for(&tree.entries, "root/dev/net")) {
        (Some(dev), Some(entry)) => optional_open(PinnedDir::open(dev.as_fd(), "net", entry))?,
        _ => None,
    };
    let run = match (&root, manifest.assets.run_identity) {
        (Some(root), Some(expected)) => {
            optional_open(PinnedDir::open_identity(root.as_fd(), "run", expected))?
        }
        _ => None,
    };
    let sys_directories = sysfs_mirror::open_directories(&tree.entries, root.as_ref())?;
    for entry in tree.entries.iter().rev() {
        if !allowed_entry(&entry.relative) {
            return Err(Error::Path);
        }
        let parent = entry.relative.parent().ok_or(Error::Path)?;
        let target = if parent.as_os_str().is_empty() {
            Some(session_dir.as_fd())
        } else if parent == Path::new("root") {
            root.as_ref().map(PinnedDir::as_fd)
        } else if parent == Path::new("root/dev") {
            dev.as_ref().map(PinnedDir::as_fd)
        } else if parent == Path::new("root/dev/net") {
            net.as_ref().map(PinnedDir::as_fd)
        } else if parent == Path::new("root/run") {
            run.as_ref().map(PinnedDir::as_fd)
        } else if parent.starts_with("root/sys") {
            sys_directories.get(parent).map(PinnedDir::as_fd)
        } else {
            return Err(Error::Path);
        };
        if let Some(target) = target {
            let name = entry
                .relative
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or(Error::Path)?;
            remove_checked_fd(target, name, entry)?;
        }
    }
    Ok(())
}

fn is_noent(error: &Error) -> bool {
    matches!(error, Error::Kernel(rustix::io::Errno::NOENT))
}

fn optional_open(result: Result<PinnedDir>) -> Result<Option<PinnedDir>> {
    match result {
        Ok(dir) => Ok(Some(dir)),
        Err(error) if is_noent(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn allowed_entry(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some(
            "root/dev"
                | "root/firecracker"
                | "root/firecracker.pid"
                | "root/dev/kvm"
                | "root/dev/net"
                | "root/dev/net/tun"
                | "root/dev/urandom"
                | "root/dev/userfaultfd"
                | "root/run/serial.log"
                | "jailer.stderr"
        )
    ) || sysfs_mirror::allowed_sysfs_entry(path)
}

fn remove_checked_fd(dir: BorrowedFd<'_>, name: &str, entry: &JailEntry) -> Result<()> {
    let stat = match rustix::fs::statat(dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if stat.st_ino != entry.inode
        || crate::security::path::device_id(stat.st_dev) != entry.device
        || stat.st_uid != entry.uid
        || stat.st_gid != entry.gid
        || (kind(stat.st_mode as u32) != rustix::fs::FileType::Directory
            && u64::from(stat.st_nlink) != entry.links)
        || stat.st_rdev as u64 != entry.rdev
        || kind(stat.st_mode as u32) != kind(entry.mode)
    {
        return Err(Error::Path);
    }
    let flags = if kind(entry.mode) == rustix::fs::FileType::Directory {
        rustix::fs::AtFlags::REMOVEDIR
    } else {
        rustix::fs::AtFlags::empty()
    };
    match rustix::fs::unlinkat(dir, name, flags) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {
            let _ = rustix::fs::fsync(dir);
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

struct PinnedDir {
    fd: OwnedFd,
}

impl PinnedDir {
    fn open(parent: BorrowedFd<'_>, name: &str, expected: &JailEntry) -> Result<Self> {
        let fd = rustix::fs::openat(
            parent,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let observed = rustix::fs::fstat(&fd)?;
        if !same_entry(&observed, expected) {
            return Err(Error::Path);
        }
        Ok(Self { fd })
    }

    fn open_identity(
        parent: BorrowedFd<'_>,
        name: &str,
        expected: crate::session::AssetIdentity,
    ) -> Result<Self> {
        let fd = rustix::fs::openat(
            parent,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let observed = rustix::fs::fstat(&fd)?;
        if crate::security::path::device_id(observed.st_dev) != expected.device
            || observed.st_ino != expected.inode
            || rustix::fs::FileType::from_raw_mode(observed.st_mode)
                != rustix::fs::FileType::Directory
        {
            return Err(Error::Path);
        }
        Ok(Self { fd })
    }

    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn same_entry(stat: &rustix::fs::Stat, entry: &JailEntry) -> bool {
    crate::security::path::device_id(stat.st_dev) == entry.device
        && stat.st_ino == entry.inode
        && stat.st_uid == entry.uid
        && stat.st_gid == entry.gid
        && (kind(stat.st_mode.into()) == rustix::fs::FileType::Directory
            || stat.st_nlink as u64 == entry.links)
        && stat.st_rdev as u64 == entry.rdev
        && kind(stat.st_mode.into()) == kind(entry.mode)
}

fn capture_entry(
    path: &Path,
    relative: PathBuf,
    uid: u32,
    gid: u32,
    optional: bool,
) -> Result<Option<JailEntry>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if meta.file_type().is_symlink()
        || (!meta.is_dir() && meta.nlink() != 1)
        || !owner_allowed(&meta, uid, gid)
    {
        return Err(Error::Path);
    }
    if !meta.is_dir() && !meta.is_file() && !meta.file_type().is_char_device() {
        return Err(Error::Path);
    }
    Ok(Some(JailEntry {
        relative,
        device: meta.dev(),
        inode: meta.ino(),
        mode: meta.mode(),
        uid: meta.uid(),
        gid: meta.gid(),
        rdev: meta.rdev(),
        links: meta.nlink(),
    }))
}

fn reject_unknown(session: &Path, relative: &str, allowed: &[&str]) -> Result<()> {
    let path = session.join(relative);
    let Ok(entries) = fs::read_dir(path) else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if !allowed.iter().any(|allowed| name == *allowed) {
            return Err(Error::Path);
        }
    }
    Ok(())
}

fn reject_sysfs_unknown(directory: &Path, allowed: &[&str]) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if !allowed.iter().any(|allowed| name == *allowed) {
            return Err(Error::Path);
        }
    }
    Ok(())
}

fn verify_firecracker(
    path: &Path,
    entry: &JailEntry,
    expected: &str,
    uid: u32,
    gid: u32,
) -> Result<()> {
    if (entry.uid != 0 || entry.gid != 0) && (entry.uid != uid || entry.gid != gid)
        || entry.mode & 0o111 == 0
    {
        return Err(Error::Path);
    }
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let count = std::io::Read::read(&mut file, &mut bytes)?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or(Error::Path)?;
        if total > MAX_RUNTIME_BYTES {
            return Err(Error::Path);
        }
        hash.update(&bytes[..count]);
    }
    if hex::encode(hash.finalize()) != expected {
        return Err(Error::Artifact("jailer Firecracker digest mismatch"));
    }
    Ok(())
}

fn expected_kind(relative: &str, entry: &JailEntry) -> Result<()> {
    let kind = kind(entry.mode);
    let valid = match relative {
        "root/dev" | "root/dev/net" => kind == rustix::fs::FileType::Directory,
        "root/firecracker" | "root/firecracker.pid" | "root/run/serial.log" | "jailer.stderr" => {
            kind == rustix::fs::FileType::RegularFile
        }
        "root/dev/kvm" | "root/dev/net/tun" | "root/dev/urandom" | "root/dev/userfaultfd" => {
            kind == rustix::fs::FileType::CharacterDevice
        }
        _ => false,
    };
    if valid { Ok(()) } else { Err(Error::Path) }
}

fn owner_allowed(meta: &fs::Metadata, uid: u32, gid: u32) -> bool {
    (meta.uid() == 0 && meta.gid() == 0) || (meta.uid() == uid && meta.gid() == gid)
}
#[cfg(target_os = "linux")]
fn kind(mode: u32) -> rustix::fs::FileType {
    rustix::fs::FileType::from_raw_mode(mode)
}

#[cfg(not(target_os = "linux"))]
fn kind(mode: u32) -> rustix::fs::FileType {
    rustix::fs::FileType::from_raw_mode(mode as u16)
}
fn entry_for<'a>(entries: &'a [JailEntry], relative: &str) -> Option<&'a JailEntry> {
    entries
        .iter()
        .find(|entry| entry.relative == Path::new(relative))
}
