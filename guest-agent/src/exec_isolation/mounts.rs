//! Private per-execution proc, sys, dev and run mounts.
use nix::libc;
use nix::mount::{MsFlags, mount};
use std::fs;

pub(super) fn isolate_mounts() -> Result<(), String> {
    // Replace guest-global sysfs, cgroupfs, devtmpfs and /run with private
    // mounts before customer code can inspect paths or raw guest devices.
    mount_tmpfs("/sys", true)?;
    mount_tmpfs("/dev", false)?;
    mount_tmpfs("/run", false)?;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        // subset=pid omits global proc controls such as sysrq-trigger,
        // kcore and keys while retaining the execution's task tree.
        Some("hidepid=2,subset=pid"),
    )
    .map_err(|e| format!("mount private execution proc: {e}"))?;
    mount_safe_devices()?;
    make_read_only("/sys")?;
    // `subset=pid` intentionally omits procfs' global `/sys` subtree. In
    // particular, do not fail setup by trying to bind-remount `/proc/sys`:
    // global sysctls are absent from the customer PID namespace already.
    Ok(())
}

/// Restrict the execution's overlay root in its private mount namespace.
/// Clone child mounts with a recursive bind, then remount only the root.
/// This preserves private proc/dev/run and separately authorized writable
/// mounts; remounting the shared guest overlay would affect other execs.
pub(super) fn make_root_read_only() -> Result<(), String> {
    mount(
        Some("/"),
        "/",
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| format!("bind private execution root: {e}"))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .map_err(|e| format!("make private execution root read-only: {e}"))
}

fn mount_tmpfs(path: &str, read_only: bool) -> Result<(), String> {
    let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
    if path != "/dev" {
        flags |= MsFlags::MS_NODEV;
    }
    mount(
        Some("tmpfs"),
        path,
        Some("tmpfs"),
        flags,
        Some("mode=755,size=16m"),
    )
    .map_err(|e| format!("mount private tmpfs at {path}: {e}"))?;
    if read_only {
        make_read_only(path)?;
    }
    Ok(())
}

fn make_read_only(path: &str) -> Result<(), String> {
    mount(
        Some(path),
        path,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| format!("bind private read-only mount {path}: {e}"))?;
    mount(
        Some(path),
        path,
        None::<&str>,
        MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV
            | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| format!("remount {path} read-only: {e}"))
}

#[allow(unsafe_code)]
fn mount_safe_devices() -> Result<(), String> {
    fs::create_dir_all("/dev/pts").map_err(|e| format!("create private devpts: {e}"))?;
    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    )
    .map_err(|e| format!("mount private devpts: {e}"))?;
    for (name, major, minor) in [
        ("null", 1, 3),
        ("zero", 1, 5),
        ("full", 1, 7),
        ("random", 1, 8),
        ("urandom", 1, 9),
        ("tty", 5, 0),
    ] {
        let path = format!("/dev/{name}");
        let cpath = std::ffi::CString::new(path.clone()).map_err(|_| "invalid safe device path")?;
        let mode = libc::S_IFCHR | 0o666;
        // SAFETY: path is NUL terminated; mknod receives a valid character
        // device mode and Linux device-number encoding.
        let result = unsafe { libc::mknod(cpath.as_ptr(), mode, libc::makedev(major, minor)) };
        if result < 0 {
            return Err(format!(
                "create safe device {path}: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    std::os::unix::fs::symlink("pts/ptmx", "/dev/ptmx")
        .map_err(|e| format!("create private ptmx link: {e}"))?;
    let _ = std::os::unix::fs::symlink("/proc/self/fd", "/dev/fd");
    let _ = std::os::unix::fs::symlink("/proc/self/fd/0", "/dev/stdin");
    let _ = std::os::unix::fs::symlink("/proc/self/fd/1", "/dev/stdout");
    let _ = std::os::unix::fs::symlink("/proc/self/fd/2", "/dev/stderr");
    Ok(())
}
