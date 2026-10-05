//! Trusted trampoline for cgroup-bounded, per-execution PID namespaces.
use guest_protocol::ExecutionSpec;
use nix::libc;
use nix::mount::{MsFlags, mount};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};
use std::time::Duration;

mod ephemeral_mounts;
mod mounts;
mod security;

const MAX_SPEC_BYTES: usize = sandboxd_protocol::MAX_FRAME_BYTES;
const INTERNAL_LAUNCHER: &str = "--apollo-internal-exec-launcher";
const INTERNAL_INIT: &str = "--apollo-internal-exec-init";

/// Handles private internal modes before public supervisor argument parsing.
pub(crate) fn dispatch() -> bool {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(mode) = args.next() else {
        return false;
    };
    let Some(fd) = args.next() else { return false };
    let Some(executable_fd) = args.next() else {
        return false;
    };
    if args.next().is_some() {
        return false;
    }
    let Some(mode) = mode.to_str() else {
        return false;
    };
    let Some(fd) = fd.to_str().and_then(|value| value.parse::<RawFd>().ok()) else {
        return false;
    };
    let Some(executable_fd) = executable_fd
        .to_str()
        .and_then(|value| value.parse::<RawFd>().ok())
    else {
        return false;
    };
    let result = match mode {
        INTERNAL_LAUNCHER => run_launcher(fd, executable_fd),
        INTERNAL_INIT => run_init(fd, executable_fd),
        _ => return false,
    };
    if let Err(error) = result {
        eprintln!("trusted execution setup failed: {error}");
        std::process::exit(125);
    }
    true
}

/// Prevent the trusted supervisor's bootstrap authority descriptors from
/// surviving into a customer launcher. They remain open in the supervisor;
/// this only sets close-on-exec on the inherited descriptor table entries.
pub(crate) fn close_bootstrap_descriptors<I>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let mut name: Option<String> = None;
    for arg in args {
        let Some(value) = arg.to_str() else { continue };
        if let Some(previous) = name.take()
            && (previous == "--state-fd" || previous == "--network-tool-fd")
        {
            let fd = value
                .parse::<RawFd>()
                .map_err(|_| format!("{previous} is not a descriptor"))?;
            set_cloexec(fd, true)?;
        }
        name = Some(value.to_owned());
    }
    Ok(())
}

#[allow(unsafe_code)]
pub(crate) fn configure_launcher(
    command: &mut Command,
    spec: &ExecutionSpec,
    executable_fd: RawFd,
) -> Result<(UnixStream, UnixStream, Vec<u8>, Vec<File>), String> {
    let (parent, child) =
        UnixStream::pair().map_err(|e| format!("create execution spec channel: {e}"))?;
    let child_fd = child.as_raw_fd();
    set_cloexec(child_fd, false)?;
    command
        .arg(INTERNAL_LAUNCHER)
        .arg(child_fd.to_string())
        .arg(executable_fd.to_string())
        .env_clear();

    let volumes = crate::volumes::execution(&spec.mounts)?;
    let mapping: Vec<_> = volumes
        .iter()
        .map(|(id, file, readonly)| (id.clone(), file.as_raw_fd(), *readonly))
        .collect();
    let inherited: Vec<_> = mapping.iter().map(|(_, fd, _)| *fd).collect();
    // Only these trusted held volume descriptors survive into the launcher.
    unsafe {
        command.pre_exec(move || {
            for fd in &inherited {
                if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&(spec, &mapping), &mut bytes)
        .map_err(|e| format!("encode execution spec: {e}"))?;
    if bytes.len() > MAX_SPEC_BYTES {
        return Err("execution spec exceeds trusted launcher limit".into());
    }
    Ok((
        parent,
        child,
        bytes,
        volumes.into_iter().map(|(_, file, _)| file).collect(),
    ))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(crate) fn install_placement_hook(
    command: &mut Command,
    child_socket_fd: RawFd,
    placement: &File,
) {
    use std::os::unix::process::CommandExt;
    let placement_fd = placement.as_raw_fd();
    // SAFETY: this pre_exec closure uses only fcntl/getpid/write and a stack
    // buffer. The cgroup file is opened by the trusted parent before fork.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(child_socket_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut buffer = [0u8; 16];
            let mut value = libc::getpid() as u32;
            let mut cursor = buffer.len();
            loop {
                cursor -= 1;
                buffer[cursor] = b'0' + (value % 10) as u8;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            let count = libc::write(
                placement_fd,
                buffer[cursor..].as_ptr().cast(),
                buffer.len() - cursor,
            );
            if count != (buffer.len() - cursor) as isize {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[allow(unsafe_code)]
pub(crate) fn set_cloexec(fd: RawFd, value: bool) -> Result<(), String> {
    // SAFETY: fcntl only inspects/updates flags for the supplied open descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(format!(
            "get execution channel flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    let next = if value {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
        return Err(format!(
            "set execution channel flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn read_spec(
    fd: RawFd,
) -> Result<
    (
        ExecutionSpec,
        Vec<(sandboxd_protocol::VolumeId, RawFd, bool)>,
    ),
    String,
> {
    // SAFETY: the only call sites receive the inherited, live UnixStream file
    // descriptor encoded by this private trampoline's command line.
    let mut file = unsafe { UnixStream::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    Read::take(&mut file, (MAX_SPEC_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read trusted execution spec: {e}"))?;
    if bytes.is_empty() || bytes.len() > MAX_SPEC_BYTES {
        return Err("trusted execution spec length is invalid".into());
    }
    let (spec, volumes): (
        ExecutionSpec,
        Vec<(sandboxd_protocol::VolumeId, RawFd, bool)>,
    ) = ciborium::de::from_reader(bytes.as_slice())
        .map_err(|e| format!("decode trusted execution spec: {e}"))?;
    spec.validate().map_err(str::to_owned)?;
    if volumes.len() > 16 || volumes.iter().any(|(_, fd, _)| *fd < 3) {
        return Err("invalid trusted volume descriptors".into());
    }
    Ok((spec, volumes))
}

#[allow(unsafe_code)]
fn run_launcher(fd: RawFd, executable_fd: RawFd) -> Result<(), String> {
    let (spec, volumes) = read_spec(fd)?;
    nix::sched::unshare(
        nix::sched::CloneFlags::CLONE_NEWPID
            | nix::sched::CloneFlags::CLONE_NEWNS
            | nix::sched::CloneFlags::CLONE_NEWCGROUP,
    )
    .map_err(|e| format!("create execution namespaces: {e}"))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| format!("make execution mounts private: {e}"))?;

    let (mut sender, child_socket) =
        UnixStream::pair().map_err(|e| format!("create PID1 spec channel: {e}"))?;
    let child_fd = child_socket.as_raw_fd();
    set_cloexec(child_fd, false)?;
    let mut init = Command::new(format!("/proc/self/fd/{executable_fd}"));
    init.arg(INTERNAL_INIT)
        .arg(child_fd.to_string())
        .arg(executable_fd.to_string());
    unsafe {
        init.pre_exec(move || {
            if libc::fcntl(child_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = init
        .spawn()
        .map_err(|e| format!("start trusted PID1: {e}"))?;
    drop(child_socket);
    ciborium::ser::into_writer(&(&spec, &volumes), &mut sender)
        .map_err(|e| format!("send execution spec to PID1: {e}"))?;
    sender
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("close PID1 spec channel: {e}"))?;
    let status = child
        .wait()
        .map_err(|e| format!("wait for trusted PID1: {e}"))?;
    forward_status(status)
}

#[allow(unsafe_code)]
fn run_init(fd: RawFd, executable_fd: RawFd) -> Result<(), String> {
    let (spec, volumes) = read_spec(fd)?;
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
        .map_err(|e| format!("create private execution mount namespace: {e}"))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| format!("make PID1 mounts private: {e}"))?;
    let volume_files: Vec<_> = volumes
        .into_iter()
        .map(|(id, fd, readonly)| {
            // SAFETY: inherited descriptors are produced only by the supervisor.
            (id, unsafe { File::from_raw_fd(fd) }, readonly)
        })
        .collect();
    mounts::isolate_mounts()?;
    ephemeral_mounts::install(&spec.mounts, &volume_files)?;
    drop(volume_files);
    if spec.readonly_root {
        mounts::make_root_read_only()?;
    }
    // A same-UID or root customer process must not ptrace or inspect the
    // trusted PID-namespace init which owns the cgroup-facing outer lifetime.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } < 0 {
        return Err(format!(
            "make trusted PID1 non-dumpable: {}",
            std::io::Error::last_os_error()
        ));
    }
    set_cloexec(executable_fd, true)
        .map_err(|e| format!("close trusted executable authority: {e}"))?;

    // Rust Command::uid clears supplementary groups. Apply the complete
    // identity explicitly in the child before the customer security boundary.
    let groups: Vec<libc::gid_t> = spec.supplementary_groups.clone();
    let uid = spec.uid;
    let gid = spec.gid;
    let mut command = Command::new(&spec.argv[0]);
    command
        .args(&spec.argv[1..])
        .current_dir(&spec.cwd)
        .env_clear()
        .envs(&spec.environment);
    for (key, value) in &spec.secret_environment {
        command.env(key, &value.0);
    }
    command.stdin(std::process::Stdio::inherit());
    command.stdout(std::process::Stdio::inherit());
    command.stderr(std::process::Stdio::inherit());
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            security::install_customer_boundary()
        });
    }
    let status = command
        .status()
        .map_err(|e| format!("start customer command: {e}"))?;
    let code = status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        128 + status.signal().unwrap_or(0)
    });

    // Namespace PID1 is the trusted reaper. Kill and reap double-forked or
    // session-detached descendants before its namespace can outlive the exec.
    let _ = kill(Pid::from_raw(-1), Signal::SIGKILL);
    reap_namespace_descendants()?;
    std::process::exit(code.clamp(0, 255));
}

fn forward_status(status: ExitStatus) -> Result<(), String> {
    if let Some(code) = status.code() {
        std::process::exit(code.clamp(0, 255));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::ExitStatusExt;
        let signal = status.signal().unwrap_or(libc::SIGKILL);
        let _ = kill(
            Pid::from_raw(std::process::id() as i32),
            Signal::try_from(signal).unwrap_or(Signal::SIGKILL),
        );
    }
    Err("trusted PID1 was terminated by signal".into())
}

fn reap_namespace_descendants() -> Result<(), String> {
    for _ in 0..500 {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => std::thread::sleep(Duration::from_millis(10)),
            Ok(WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _)) => {}
            Err(nix::errno::Errno::ECHILD) => return Ok(()),
            Ok(_) => {}
            Err(error) => return Err(format!("reap execution descendants: {error}")),
        }
    }
    Err("execution namespace did not become empty".into())
}
