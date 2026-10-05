//! Private descriptor-only ext4 backing creation. The host never mounts images.
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
    state::DynamicVolumeRecord,
};
#[cfg(target_os = "linux")]
use sandboxd_protocol::{VolumeBacking, VolumeCommand, VolumeInfo};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
use std::{fs::File, os::unix::fs::MetadataExt};

pub(crate) fn directory(root: &std::path::Path) -> Result<SecureDir> {
    SecureDir::open(root)?.ensure_private_directory("dynamic-volumes")
}
pub(crate) fn path(root: &std::path::Path, id: &str) -> std::path::PathBuf {
    root.join("dynamic-volumes").join(format!("{id}.img"))
}
pub(crate) fn verify_identity(file: &File, record: &DynamicVolumeRecord) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.dev() != record.device
        || m.ino() != record.inode
        || m.len() != record.info.size_bytes
    {
        return Err(Error::Artifact("dynamic backing identity changed"));
    }
    Ok(())
}
/// Root-owned private parent plus exact durable identity gates the VMM-owned
/// inode. Ordinary catalog admission remains daemon-owned.
pub(crate) fn open_pinned(
    root: &std::path::Path,
    record: &DynamicVolumeRecord,
    writable: bool,
    session_owners: &[(u32, u32)],
) -> Result<File> {
    if !record.info.backing.validate() {
        return Err(Error::State);
    }
    let dir = directory(root)?;
    let file = File::from(rustix::fs::openat(
        dir.as_fd(),
        format!("{}.img", record.info.backing.id),
        (if writable {
            rustix::fs::OFlags::RDWR
        } else {
            rustix::fs::OFlags::RDONLY
        }) | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?);
    verify_identity(&file, record)?;
    let metadata = file.metadata()?;
    let daemon_owner = metadata.uid() == rustix::process::geteuid().as_raw();
    let session_owner =
        record.info.writable && session_owners.contains(&(metadata.uid(), metadata.gid()));
    let mode = if record.info.writable { 0o644 } else { 0o444 };
    if (!daemon_owner && !session_owner) || metadata.mode() & 0o7777 != mode {
        return Err(Error::Path);
    }
    Ok(file)
}
#[cfg(target_os = "linux")]
fn digest(file: &File, size: u64) -> Result<String> {
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    let mut offset = 0;
    while offset < size {
        let n = ((size - offset) as usize).min(bytes.len());
        file.read_exact_at(&mut bytes[..n], offset)?;
        hash.update(&bytes[..n]);
        offset += n as u64;
    }
    Ok(hex::encode(hash.finalize()))
}
#[cfg(target_os = "linux")]
fn validate_ext4(file: &File, size: u64) -> Result<()> {
    let mut sb = [0u8; 1024];
    file.read_exact_at(&mut sb, 1024)?;
    let u16at = |n| u16::from_le_bytes([sb[n], sb[n + 1]]);
    let u32at = |n| u32::from_le_bytes(sb[n..n + 4].try_into().unwrap());
    let incompat = u32at(96);
    let blocks = u64::from(u32at(4))
        | if incompat & 0x80 != 0 {
            u64::from(u32at(336)) << 32
        } else {
            0
        };
    let shift = u32at(24);
    // Reject dirty/journal-device filesystems, unsupported block sizes, and a
    // superblock claiming bytes outside the exact sealed image.
    if u16at(56) != 0xef53
        || u16at(58) & 1 == 0
        || incompat & 0x0c != 0
        || shift > 2
        || blocks == 0
        || blocks
            .checked_mul(1024u64 << shift)
            .is_none_or(|n| n > size)
    {
        return Err(Error::Artifact("invalid clean bounded ext4 image"));
    }
    Ok(())
}
#[cfg(target_os = "linux")]
pub(crate) fn create(
    root: &std::path::Path,
    uid: u32,
    id: String,
    command: &VolumeCommand,
    input: Option<File>,
    prepared_hash: Option<String>,
    mut formatter: crate::runtime::VerifiedArtifact,
    prepared: Option<DynamicVolumeRecord>,
    persist: impl FnOnce(&DynamicVolumeRecord) -> Result<()>,
) -> Result<DynamicVolumeRecord> {
    use std::{os::fd::AsRawFd, os::unix::fs::FileExt};
    let dir = directory(root)?;
    let name = format!("{id}.img");
    match dir.open_file(&name, false) {
        Ok(file) => {
            let mut record = prepared.ok_or(Error::State)?;
            verify_identity(&file, &record)?;
            if digest(&file, record.info.size_bytes)? != record.info.initial_sha256 {
                return Err(Error::Artifact("unpublished backing contents changed"));
            }
            record.published = true;
            return Ok(record);
        }
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(Error::Kernel(e)) if e == rustix::io::Errno::NOENT => {}
        Err(e) => return Err(e),
    }
    let size = command.size_bytes();
    let file = File::from(rustix::fs::openat(
        dir.as_fd(),
        ".",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?);
    rustix::fs::ftruncate(&file, size)?;
    match command {
        VolumeCommand::Allocate { .. } => {
            formatter.revalidate()?;
            super::drive::run_formatter(formatter.file.as_raw_fd(), file.as_raw_fd())?;
        }
        VolumeCommand::Import { .. } | VolumeCommand::ImportPrepared { .. } => {
            let sha256 = match command {
                VolumeCommand::Import { sha256, .. } => sha256.as_str(),
                VolumeCommand::ImportPrepared { .. } => {
                    prepared_hash.as_deref().ok_or(Error::State)?
                }
                _ => return Err(Error::State),
            };
            let input = input.ok_or(Error::Path)?;
            let flags = rustix::fs::fcntl_getfl(&input)?;
            let sealed = if matches!(command, VolumeCommand::Import { .. }) {
                rustix::fs::fcntl_get_seals(&input)?.contains(
                    rustix::fs::SealFlags::WRITE
                        | rustix::fs::SealFlags::GROW
                        | rustix::fs::SealFlags::SHRINK
                        | rustix::fs::SealFlags::SEAL,
                )
            } else {
                true
            };
            if flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
                || !sealed
                || !input.metadata()?.is_file()
                || input.metadata()?.len() != size
            {
                return Err(Error::Path);
            }
            let mut bytes = [0u8; 65536];
            let mut offset = 0;
            while offset < size {
                let n = ((size - offset) as usize).min(bytes.len());
                input.read_exact_at(&mut bytes[..n], offset)?;
                file.write_all_at(&bytes[..n], offset)?;
                offset += n as u64;
            }
            if digest(&file, size)? != sha256 {
                return Err(Error::Artifact("volume import digest mismatch"));
            }
        }
    }
    validate_ext4(&file, size)?;
    rustix::fs::fchmod(
        &file,
        rustix::fs::Mode::from_raw_mode(if command.writable() { 0o644 } else { 0o444 }),
    )?;
    file.sync_all()?;
    let m = file.metadata()?;
    let mut record = DynamicVolumeRecord {
        owner_uid: uid,
        info: VolumeInfo {
            backing: VolumeBacking { id, generation: 1 },
            size_bytes: size,
            writable: command.writable(),
            initial_sha256: digest(&file, size)?,
        },
        device: m.dev(),
        inode: m.ino(),
        published: false,
    };
    persist(&record)?;
    let source = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
    rustix::fs::linkat(
        rustix::fs::CWD,
        &source,
        dir.as_fd(),
        &name,
        rustix::fs::AtFlags::SYMLINK_FOLLOW,
    )?;
    rustix::fs::fsync(dir.as_fd())?;
    verify_identity(&dir.open_file(&name, false)?, &record)?;
    record.published = true;
    Ok(record)
}

pub(crate) fn release(root: &std::path::Path, record: &DynamicVolumeRecord) -> Result<()> {
    let dir = directory(root)?;
    let name = format!("{}.img", record.info.backing.id);
    match dir.open_file(&name, false) {
        Ok(file) => {
            verify_identity(&file, record)?;
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| Error::Locked)?;
            dir.remove_if_identity(
                &name,
                record.device,
                record.inode,
                rustix::fs::FileType::RegularFile,
            )?;
        }
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => {}
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // ENOENT is reconciled only after a durable owner-bound release intent;
    // the API never calls this function without that admission.
    rustix::fs::fsync(dir.as_fd())?;
    Ok(())
}
