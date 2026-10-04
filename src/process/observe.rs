use crate::{error::Error, error::Result};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

const MAX_PROC_BYTES: usize = 64 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 1 << 30;

#[derive(PartialEq)]
pub(super) struct Observed {
    pub(super) pid: u32,
    pub(super) boot_id: String,
    pub(super) start_time_ticks: u64,
    pub(super) uids: [u32; 4],
    pub(super) gids: [u32; 4],
    pub(super) executable_device: u64,
    pub(super) executable_inode: u64,
    pub(super) executable_sha256: String,
    pub(super) cgroup_sha256: String,
}

pub(super) fn read_proc(pid: u32) -> Result<Observed> {
    let root = PathBuf::from("/proc").join(pid.to_string());
    let proc_dir = File::from(rustix::fs::open(
        &root,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let boot_id = bounded_text(PathBuf::from("/proc/sys/kernel/random/boot_id"), 128)?;
    let boot_id = boot_id.trim().to_owned();
    if boot_id.len() != 36 || !boot_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(Error::Config("invalid host boot ID"));
    }
    let stat = bounded_at(&proc_dir, "stat", MAX_PROC_BYTES)?;
    let after_name = stat
        .rfind(')')
        .ok_or(Error::Config("invalid process stat"))?
        + 1;
    let fields: Vec<&str> = stat[after_name..].split_whitespace().collect();
    if fields.first() == Some(&"Z") || fields.first() == Some(&"X") {
        return Err(Error::Config("managed process is a zombie or dead task"));
    }
    let start_time_ticks = fields
        .get(19)
        .ok_or(Error::Config("process stat missing start time"))?
        .parse()
        .map_err(|_| Error::Config("invalid process start time"))?;
    let status = bounded_at(&proc_dir, "status", MAX_PROC_BYTES)?;
    let uids = status_ids(&status, "Uid:")?;
    let gids = status_ids(&status, "Gid:")?;
    let exe = File::from(rustix::fs::openat(
        &proc_dir,
        "exe",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let exe_stat = rustix::fs::fstat(&exe)?;
    if rustix::fs::FileType::from_raw_mode(exe_stat.st_mode) != rustix::fs::FileType::RegularFile
        || exe_stat.st_nlink != 1
        || exe_stat.st_size < 0
        || exe_stat.st_size as u64 > MAX_EXECUTABLE_BYTES
    {
        return Err(Error::Config("managed executable exceeds size limit"));
    }
    let executable_sha256 = digest_file(exe)?;
    let cgroup_sha256 = digest_bytes(bounded_at(&proc_dir, "cgroup", MAX_PROC_BYTES)?.as_bytes());
    Ok(Observed {
        pid,
        boot_id,
        start_time_ticks,
        uids,
        gids,
        executable_device: exe_stat.st_dev as u64,
        executable_inode: exe_stat.st_ino,
        executable_sha256,
        cgroup_sha256,
    })
}

pub(super) fn matches_record(
    observed: &Observed,
    record: &super::PersistedProcessIdentity,
) -> bool {
    observed.pid == record.pid
        && observed.boot_id == record.boot_id
        && observed.start_time_ticks == record.start_time_ticks
        && observed.uids == record.uids
        && observed.gids == record.gids
        && observed.executable_device == record.executable_device
        && observed.executable_inode == record.executable_inode
        && observed.executable_sha256 == record.executable_sha256
        && observed.cgroup_sha256 == record.cgroup_sha256
}

fn bounded_at(dir: &File, name: &str, limit: usize) -> Result<String> {
    let mut file = File::from(rustix::fs::openat(
        dir,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    bounded_read(&mut file, limit)
}

fn bounded_text(path: PathBuf, limit: usize) -> Result<String> {
    bounded_read(&mut File::open(path)?, limit)
}

fn bounded_read(file: &mut File, limit: usize) -> Result<String> {
    let mut bytes = Vec::with_capacity(limit.min(4096));
    file.by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Config("proc record exceeds size limit"));
    }
    String::from_utf8(bytes).map_err(|_| Error::Config("proc record is not UTF-8"))
}

fn status_ids(status: &str, key: &str) -> Result<[u32; 4]> {
    let line = status
        .lines()
        .find(|line| line.starts_with(key))
        .ok_or(Error::Config("process credentials missing"))?;
    let values: Vec<u32> = line
        .split_whitespace()
        .skip(1)
        .map(|value| {
            value
                .parse()
                .map_err(|_| Error::Config("process credentials malformed"))
        })
        .collect::<Result<Vec<_>>>()?;
    values
        .try_into()
        .map_err(|_| Error::Config("process credentials incomplete"))
}

fn digest_file(mut file: File) -> Result<String> {
    let before = rustix::fs::fstat(&file)?;
    let mut hash = Sha256::new();
    let mut buf = [0; 65_536];
    file.seek(SeekFrom::Start(0))?;
    loop {
        let count = file.read(&mut buf)?;
        if count == 0 {
            break;
        }
        hash.update(&buf[..count]);
    }
    let after = rustix::fs::fstat(&file)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_ctime != after.st_ctime
    {
        return Err(Error::Config("managed executable changed during hashing"));
    }
    Ok(hex::encode(hash.finalize()))
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hex::encode(hash.finalize())
}

pub(super) fn pidfd_exited(pidfd: &std::os::fd::OwnedFd) -> Result<bool> {
    let pollfd = rustix::event::PollFd::new(
        pidfd,
        rustix::event::PollFlags::IN
            | rustix::event::PollFlags::HUP
            | rustix::event::PollFlags::ERR
            | rustix::event::PollFlags::NVAL,
    );
    let mut fds = [pollfd];
    rustix::event::poll(
        &mut fds,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )?;
    Ok(fds[0].revents().intersects(
        rustix::event::PollFlags::IN
            | rustix::event::PollFlags::HUP
            | rustix::event::PollFlags::ERR
            | rustix::event::PollFlags::NVAL,
    ))
}
