use crate::{error::Error, error::Result};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use super::observe::{Observed, matches_record, pidfd_exited, read_proc};

#[derive(Debug)]
pub struct ProcessIdentity {
    pid: u32,
    boot_id: String,
    start_time_ticks: u64,
    uids: [u32; 4],
    gids: [u32; 4],
    executable_device: u64,
    executable_inode: u64,
    executable_sha256: String,
    cgroup_sha256: String,
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
}

/// Durable identity fields. The pidfd itself is intentionally excluded: it is
/// a live kernel handle and cannot survive daemon restart or host reboot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PersistedProcessIdentity {
    pub pid: u32,
    pub boot_id: String,
    pub start_time_ticks: u64,
    pub uids: [u32; 4],
    pub gids: [u32; 4],
    pub executable_device: u64,
    pub executable_inode: u64,
    pub executable_sha256: String,
    pub cgroup_sha256: String,
}

impl ProcessIdentity {
    /// Captures the sole verified executable in an already-owned cgroup.
    /// Recovery uses this after a daemon crash between jailer spawn and the
    /// normal process observation callback; no PID or filename is trusted.
    #[cfg(target_os = "linux")]
    pub(crate) fn capture_from_cgroup(cgroup: &std::path::Path, digest: &str) -> Result<Self> {
        let mut found = None;
        for pid in crate::jailer::CgroupV2::processes_at(cgroup)? {
            let candidate = Self::capture(pid)?;
            if candidate.executable_sha256() == digest {
                if found.is_some() {
                    return Err(Error::Config("multiple matching VMM processes in cgroup"));
                }
                found = Some(candidate);
            }
        }
        found.ok_or(Error::Config("verified VMM is absent from owned cgroup"))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn capture_from_cgroup(_cgroup: &std::path::Path, _digest: &str) -> Result<Self> {
        Err(Error::Config("strong process identity requires Linux"))
    }

    /// Capture a live process and retain its pidfd before returning.
    #[cfg(target_os = "linux")]
    pub fn capture(pid: u32) -> Result<Self> {
        let raw = i32::try_from(pid).map_err(|_| Error::Config("process PID out of range"))?;
        let pid_value = rustix::process::Pid::from_raw(raw)
            .ok_or(Error::Config("process PID must be nonzero"))?;
        let before = read_proc(pid)?;
        let pidfd = rustix::process::pidfd_open(pid_value, rustix::process::PidfdFlags::empty())?;
        if pidfd_exited(&pidfd)? {
            return Err(Error::Config(
                "managed process exited during identity capture",
            ));
        }
        let after = read_proc(pid)?;
        if pidfd_exited(&pidfd)? || before != after {
            return Err(Error::Config(
                "managed process changed during identity capture",
            ));
        }
        Ok(Self::from_observed(after, pidfd))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn capture(_pid: u32) -> Result<Self> {
        Err(Error::Config("strong process identity requires Linux"))
    }

    /// Re-read all recyclable identity fields. Callers must fail closed on error.
    #[cfg(target_os = "linux")]
    pub fn verify(&self) -> Result<()> {
        if pidfd_exited(&self.pidfd)? {
            return Err(Error::Config("managed process is no longer live"));
        }
        let observed = read_proc(self.pid)?;
        if pidfd_exited(&self.pidfd)? || !matches_record(&observed, &self.persisted()) {
            return Err(Error::Config("managed process identity changed"));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn verify(&self) -> Result<()> {
        Err(Error::Config("strong process identity requires Linux"))
    }

    #[cfg(target_os = "linux")]
    pub fn send_signal(&self, signal: rustix::process::Signal) -> Result<()> {
        self.verify()?;
        rustix::process::pidfd_send_signal(&self.pidfd, signal)?;
        Ok(())
    }

    /// Reports kernel-observed process exit without re-reading or trusting a PID.
    #[cfg(target_os = "linux")]
    pub fn has_exited(&self) -> Result<bool> {
        pidfd_exited(&self.pidfd)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn has_exited(&self) -> Result<bool> {
        Err(Error::Config("strong process identity requires Linux"))
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn start_time_ticks(&self) -> u64 {
        self.start_time_ticks
    }
    pub fn uid(&self) -> u32 {
        self.uids[0]
    }
    pub fn gid(&self) -> u32 {
        self.gids[0]
    }
    pub fn uids(&self) -> [u32; 4] {
        self.uids
    }
    pub fn gids(&self) -> [u32; 4] {
        self.gids
    }
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }
    pub fn cgroup_sha256(&self) -> &str {
        &self.cgroup_sha256
    }

    pub fn persisted(&self) -> PersistedProcessIdentity {
        PersistedProcessIdentity {
            pid: self.pid,
            boot_id: self.boot_id.clone(),
            start_time_ticks: self.start_time_ticks,
            uids: self.uids,
            gids: self.gids,
            executable_device: self.executable_device,
            executable_inode: self.executable_inode,
            executable_sha256: self.executable_sha256.clone(),
            cgroup_sha256: self.cgroup_sha256.clone(),
        }
    }

    /// Re-adopt only when the complete durable identity still matches.
    #[cfg(target_os = "linux")]
    pub fn reopen_verified(record: &PersistedProcessIdentity) -> Result<Self> {
        let before = read_proc(record.pid)?;
        if !matches_record(&before, record) {
            return Err(Error::Config("persisted process identity mismatch"));
        }
        let raw =
            i32::try_from(record.pid).map_err(|_| Error::Config("process PID out of range"))?;
        let pid = rustix::process::Pid::from_raw(raw)
            .ok_or(Error::Config("process PID must be nonzero"))?;
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
        if pidfd_exited(&pidfd)? {
            return Err(Error::Config("persisted process exited during recovery"));
        }
        let after = read_proc(record.pid)?;
        if pidfd_exited(&pidfd)? || before != after || !matches_record(&after, record) {
            return Err(Error::Config("process changed during identity recovery"));
        }
        Ok(Self::from_observed(after, pidfd))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn reopen_verified(_record: &PersistedProcessIdentity) -> Result<Self> {
        Err(Error::Config("strong process identity requires Linux"))
    }

    #[cfg(target_os = "linux")]
    fn from_observed(observed: Observed, pidfd: std::os::fd::OwnedFd) -> Self {
        Self {
            pid: observed.pid,
            boot_id: observed.boot_id,
            start_time_ticks: observed.start_time_ticks,
            uids: observed.uids,
            gids: observed.gids,
            executable_device: observed.executable_device,
            executable_inode: observed.executable_inode,
            executable_sha256: observed.executable_sha256,
            cgroup_sha256: observed.cgroup_sha256,
            pidfd,
        }
    }
}

/// Proves the recorded process incarnation is no longer present without
/// opening or signalling a recyclable PID. A PID reuse is treated as absence
/// of the recorded identity and is never acted upon.
#[cfg(target_os = "linux")]
pub(crate) fn prove_recorded_absent(record: &PersistedProcessIdentity) -> Result<bool> {
    match read_proc(record.pid) {
        // An identity-policy change (UID, cgroup or executable) does not
        // prove death. Only a different kernel process incarnation does.
        Ok(observed) => Ok(observed.boot_id != record.boot_id
            || observed.start_time_ticks != record.start_time_ticks),
        Err(crate::error::Error::Kernel(rustix::io::Errno::NOENT)) => exited_or_missing(record.pid),
        Err(crate::error::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            exited_or_missing(record.pid)
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn exited_or_missing(pid: u32) -> Result<bool> {
    let pid = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or(Error::Config("process PID must be nonzero"))?;
    match rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
        Ok(pidfd) => pidfd_exited(&pidfd),
        Err(rustix::io::Errno::SRCH) => Ok(true),
        Err(error) => Err(error.into()),
    }
}
