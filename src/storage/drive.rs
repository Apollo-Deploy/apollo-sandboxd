//! Fixed-size ext4 block-drive creation and identity-pinned reopening.
//!
//! The host never mounts these files.  A drive is created anonymously, formatted
//! through a verified formatter descriptor, and published with a no-replace
//! hard-link only after its contents and identity are durable.

use crate::{
    error::{Error, Result},
    runtime::VerifiedArtifact,
    security::path::{SecureDir, device_id},
};
use sandboxd_protocol::VolumeId;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::{
    os::fd::AsRawFd,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MIN_DRIVE_BYTES: u64 = 1 << 20;
const SECTOR_BYTES: u64 = 4096;
const MIN_ASSIGNED_ID: u32 = 100_000;
#[cfg(target_os = "linux")]
const FORMAT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveOwner {
    pub uid: u32,
    pub gid: u32,
}

impl DriveOwner {
    pub fn new(uid: u32, gid: u32) -> Result<Self> {
        if uid < MIN_ASSIGNED_ID || gid < MIN_ASSIGNED_ID || uid == u32::MAX || gid == u32::MAX {
            return Err(Error::Config(
                "drive owner is outside the trusted allocator range",
            ));
        }
        Ok(Self { uid, gid })
    }
}

pub struct PinnedDrive {
    pub file: File,
    pub volume: VolumeId,
    pub identity: DriveIdentity,
}

pub struct DriveFactory {
    directory: SecureDir,
    #[cfg(target_os = "linux")]
    formatter: VerifiedArtifact,
    max_size: u64,
}

impl DriveFactory {
    pub fn new(directory: SecureDir, formatter: VerifiedArtifact, max_size: u64) -> Result<Self> {
        validate_size(max_size)?;
        #[cfg(not(target_os = "linux"))]
        let _ = formatter;
        Ok(Self {
            directory,
            #[cfg(target_os = "linux")]
            formatter,
            max_size,
        })
    }

    #[cfg(target_os = "linux")]
    /// The caller must durably record its create intent before invoking this
    /// method. This operation only publishes after formatting and fsync.
    pub fn create(
        &mut self,
        volume: &VolumeId,
        size: u64,
        owner: DriveOwner,
    ) -> Result<PinnedDrive> {
        self.create_journaled(volume, size, owner, |_| Ok(()))
    }

    /// Records the prepared inode before publishing it. The callback must
    /// commit durably; a callback failure leaves no named drive behind.
    #[cfg(target_os = "linux")]
    pub fn create_journaled(
        &mut self,
        volume: &VolumeId,
        size: u64,
        owner: DriveOwner,
        persist: impl FnOnce(DriveIdentity) -> Result<()>,
    ) -> Result<PinnedDrive> {
        validate_size(size)?;
        if size > self.max_size {
            return Err(Error::Config("drive exceeds configured maximum"));
        }
        let name = drive_name(volume);
        let file = anonymous_file(&self.directory)?;
        rustix::fs::ftruncate(&file, size)?;
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))?;
        let target_fd = file.as_raw_fd();
        self.formatter.revalidate()?;
        let formatter_fd = self.formatter.file.as_raw_fd();
        run_formatter(formatter_fd, target_fd)?;
        file.sync_all()?;
        rustix::fs::fchown(
            &file,
            Some(rustix::process::Uid::from_raw(owner.uid)),
            Some(rustix::process::Gid::from_raw(owner.gid)),
        )?;
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))?;
        file.sync_all()?;
        let prepared = identity(&file, size, owner, false)?;
        persist(prepared)?;
        let target = format!("/proc/{}/fd/{}", std::process::id(), target_fd);
        rustix::fs::linkat(
            rustix::fs::CWD,
            &target,
            self.directory.as_fd(),
            &name,
            rustix::fs::AtFlags::SYMLINK_FOLLOW,
        )?;
        rustix::fs::fsync(self.directory.as_fd())?;
        let identity = identity(&file, size, owner, true)?;
        if identity != prepared {
            return Err(Error::Path);
        }
        // An O_TMPFILE descriptor still refers to its anonymous dentry even
        // after linkat publishes the inode. Linux cannot bind-mount that
        // dentry through procfs. Reopen the published name descriptor-relatively
        // and verify the exact inode before returning a mountable handle.
        let published = self.reopen(volume, identity)?;
        drop(file);
        Ok(published)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create(
        &mut self,
        _volume: &VolumeId,
        _size: u64,
        _owner: DriveOwner,
    ) -> Result<PinnedDrive> {
        Err(Error::Config("fixed ext4 drives require Linux"))
    }

    pub fn reopen(&self, volume: &VolumeId, expected: DriveIdentity) -> Result<PinnedDrive> {
        validate_size(expected.size)?;
        if expected.size > self.max_size {
            return Err(Error::Config("drive exceeds configured maximum"));
        }
        let file = open_owned_file(
            &self.directory,
            &drive_name(volume),
            expected.uid,
            expected.gid,
        )?;
        let owner = DriveOwner::new(expected.uid, expected.gid)?;
        let actual = identity(&file, expected.size, owner, true)?;
        if actual != expected {
            return Err(Error::Path);
        }
        Ok(PinnedDrive {
            file,
            volume: volume.clone(),
            identity: actual,
        })
    }

    /// The caller must persist the complete old/new owner transition before
    /// invoking this method. Either owner is accepted after a crash, but the
    /// device, inode and length must still match the original drive.
    pub fn reassign(
        &self,
        volume: &VolumeId,
        expected: DriveIdentity,
        target: DriveOwner,
    ) -> Result<PinnedDrive> {
        validate_size(expected.size)?;
        DriveOwner::new(expected.uid, expected.gid)?;
        DriveOwner::new(target.uid, target.gid)?;
        let file = File::from(rustix::fs::openat(
            self.directory.as_fd(),
            drive_name(volume),
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )?);
        let stat = rustix::fs::fstat(&file)?;
        let current = DriveOwner {
            uid: stat.st_uid,
            gid: stat.st_gid,
        };
        if current != target
            && current
                != (DriveOwner {
                    uid: expected.uid,
                    gid: expected.gid,
                })
        {
            return Err(Error::Path);
        }
        let observed = identity(&file, expected.size, current, true)?;
        if observed.device != expected.device
            || observed.inode != expected.inode
            || expected.size > self.max_size
            || stat.st_mode & 0o777 != 0o600
        {
            return Err(Error::Path);
        }
        DriveOwner::new(target.uid, target.gid)?;
        rustix::fs::fchown(
            &file,
            Some(rustix::process::Uid::from_raw(target.uid)),
            Some(rustix::process::Gid::from_raw(target.gid)),
        )?;
        file.sync_all()?;
        let identity = identity(&file, expected.size, target, true)?;
        Ok(PinnedDrive {
            file,
            volume: volume.clone(),
            identity,
        })
    }
}

fn validate_size(size: u64) -> Result<()> {
    if !(MIN_DRIVE_BYTES..=1 << 40).contains(&size) || !size.is_multiple_of(SECTOR_BYTES) {
        return Err(Error::Config("invalid fixed drive size"));
    }
    Ok(())
}

fn drive_name(volume: &VolumeId) -> String {
    format!("volume-{}.ext4", volume.as_str())
}

fn open_owned_file(directory: &SecureDir, name: &str, uid: u32, gid: u32) -> Result<File> {
    let fd = rustix::fs::openat(
        directory.as_fd(),
        name,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(fd);
    let stat = rustix::fs::fstat(&file)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_uid != uid
        || stat.st_gid != gid
        || stat.st_mode & 0o077 != 0
    {
        return Err(Error::Path);
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn anonymous_file(directory: &SecureDir) -> Result<File> {
    let fd = rustix::fs::openat(
        directory.as_fd(),
        ".",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;
    Ok(File::from(fd))
}

#[cfg(target_os = "linux")]
pub(crate) fn run_formatter(formatter_fd: i32, target_fd: i32) -> Result<()> {
    let formatter = format!("/proc/self/fd/{formatter_fd}");
    let target = format!("/proc/{}/fd/{target_fd}", std::process::id());
    let mut child = Command::new(formatter)
        .env_clear()
        .args(["-t", "ext4", "-F", &target])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::Artifact("trusted formatter could not start"))?;
    let deadline = Instant::now() + FORMAT_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(Error::Artifact("trusted formatter failed")),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Artifact("trusted formatter timed out"));
            }
            Err(_) => return Err(Error::Artifact("trusted formatter status failed")),
        }
    }
}

fn identity(
    file: &File,
    expected_size: u64,
    owner: DriveOwner,
    published: bool,
) -> Result<DriveIdentity> {
    let stat = rustix::fs::fstat(file)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || (published && stat.st_nlink != 1)
        || (!published && stat.st_nlink != 0)
        || stat.st_size < 0
        || stat.st_size as u64 != expected_size
        || stat.st_uid != owner.uid
        || stat.st_gid != owner.gid
    {
        return Err(Error::Path);
    }
    Ok(DriveIdentity {
        device: device_id(stat.st_dev),
        inode: stat.st_ino,
        size: stat.st_size as u64,
        uid: stat.st_uid,
        gid: stat.st_gid,
    })
}

#[cfg(test)]
#[path = "drive_tests.rs"]
mod tests;
