//! Bounded kernel diagnostics; no VM, namespace, cgroup or file is created.
use super::Report;
use crate::error::{Error, Result};
use rustix::fs::{Mode, OFlags};
use std::{fs::File, io::Read, path::Path};

pub(super) fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut bytes = Vec::new();
    File::from(fd).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Config("host diagnostic size limit"));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(super) fn kvm_api_version() -> Result<i32> {
    use std::os::fd::AsRawFd;
    let fd = rustix::fs::open(
        "/dev/kvm",
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&fd)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::CharacterDevice {
        return Err(Error::Path);
    }
    // KVM_GET_API_VERSION is Linux _IO(0xae, 0x00): no pointer, no VM creation.
    // The validated character-device descriptor stays owned throughout ioctl.
    let version = unsafe { nix::libc::ioctl(fd.as_raw_fd(), 0xae00, 0) };
    if version < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(version)
}
#[cfg(not(target_os = "linux"))]
pub(super) fn kvm_api_version() -> Result<i32> {
    Err(sandboxd_protocol::ApiError::new(
        sandboxd_protocol::ErrorCode::UnsupportedHost,
        "KVM requires Linux",
    )
    .into())
}

pub(super) fn inspect(report: &mut Report) {
    let release = bounded_read(Path::new("/proc/sys/kernel/osrelease"), 256)
        .ok()
        .and_then(|v| String::from_utf8(v).ok());
    report.add(
        "upstream_tested_host_kernel",
        release.as_deref().is_some_and(tested_kernel_branch),
        format!(
            "{}; Firecracker 1.17 tested branches: 5.10, 6.1, 6.18",
            release.as_deref().unwrap_or("unavailable").trim()
        ),
    );
    let cpu = bounded_read(Path::new("/proc/cpuinfo"), 8 << 20)
        .ok()
        .and_then(|v| String::from_utf8(v).ok());
    let (virtualization, hypervisor) = cpu.as_deref().map(cpu_flags).unwrap_or_default();
    report.add(
        "cpu_virtualization",
        cfg!(target_arch = "aarch64") || virtualization,
        "x86_64 requires vmx/svm flags; aarch64 availability is checked through KVM",
    );
    report.add(
        "supported_host_environment",
        cpu.is_some() && !hypervisor,
        if hypervisor {
            "hypervisor flag present; nested KVM is outside the supported production host scope"
        } else {
            "no x86 hypervisor flag observed; physical-host provenance still needs qualification"
        },
    );
    let memory = bounded_read(Path::new("/proc/meminfo"), 128 << 10)
        .ok()
        .and_then(|v| available_memory(&v));
    report.add(
        "available_memory",
        memory.is_some_and(|bytes| bytes >= 64 << 20),
        format!(
            "MemAvailable bytes: {}; configured ceilings still govern admission",
            memory.map_or_else(|| "unavailable".into(), |v| v.to_string())
        ),
    );
    inspect_systemd(report);
}

pub(super) fn tested_kernel_branch(release: &str) -> bool {
    // Upstream v1.17.0 README test matrix; other branches may run but are unqualified.
    let mut fields = release.trim().split('.');
    matches!(
        (fields.next(), fields.next()),
        (Some("5"), Some("10")) | (Some("6"), Some("1" | "18"))
    )
}
pub(super) fn cpu_flags(cpu: &str) -> (bool, bool) {
    let flags = cpu
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim() == "flags")
        .flat_map(|(_, value)| value.split_whitespace())
        .collect::<Vec<_>>();
    (
        flags.iter().any(|flag| matches!(*flag, "vmx" | "svm")),
        flags.contains(&"hypervisor"),
    )
}
pub(super) fn available_memory(bytes: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut values = text
        .lines()
        .filter_map(|line| line.strip_prefix("MemAvailable:"));
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let mut fields = value.split_whitespace();
    let kib = fields.next()?.parse::<u64>().ok()?;
    if fields.next()? != "kB" || fields.next().is_some() {
        return None;
    }
    kib.checked_mul(1024)
}

fn inspect_systemd(report: &mut Report) {
    for path in [
        "/etc/systemd/system/apollo-sandboxd.service",
        "/usr/lib/systemd/system/apollo-sandboxd.service",
    ] {
        let path = Path::new(path);
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                let unit = (|| -> Result<String> {
                    let parent =
                        crate::security::path::SecureDir::open(path.parent().ok_or(Error::Path)?)?;
                    let name = path
                        .file_name()
                        .and_then(|v| v.to_str())
                        .ok_or(Error::Path)?;
                    let file = parent.open_file(name, false)?;
                    let mut bytes = Vec::new();
                    file.take(65537).read_to_end(&mut bytes)?;
                    if bytes.len() > 65536 {
                        return Err(Error::Path);
                    }
                    String::from_utf8(bytes).map_err(|_| Error::Path)
                })();
                let passed = unit
                    .as_ref()
                    .is_ok_and(|text| required_unit_directives(text));
                report.add("installed_systemd_unit", passed,
                    "read-only unit checks: safe file, VMM preservation, no-new-privileges, no core dumps; live service hardening requires qualification");
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => {
                report.add("installed_systemd_unit", false, "unit inaccessible");
                return;
            }
        }
    }
    report.add(
        "installed_systemd_unit",
        true,
        "unit not installed; systemd qualification remains separate",
    );
}

pub(super) fn required_unit_directives(text: &str) -> bool {
    let mut service = false;
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            service = line == "[Service]";
            continue;
        }
        if service && !line.starts_with(['#', ';']) {
            if let Some((name, value)) = line.split_once('=') {
                values.insert(name.trim(), value.trim());
            }
        }
    }
    [
        ("KillMode", "process"),
        ("NoNewPrivileges", "yes"),
        ("LimitCORE", "0"),
    ]
    .iter()
    .all(|(name, value)| values.get(name) == Some(value))
}
