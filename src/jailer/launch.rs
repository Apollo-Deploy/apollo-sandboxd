use super::{CgroupLimits, JailStage, VmmResourceLimits};
use crate::{
    error::{Error, Result},
    runtime::VerifiedRuntime,
};
use sandboxd_protocol::{NetworkMode, Resources};
use std::fs::File;
use std::{
    fs::OpenOptions,
    os::unix::fs::OpenOptionsExt,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
};

#[derive(Debug)]
pub struct JailerLaunchSpec {
    pub sandbox_id: String,
    pub session_id: String,
    pub jailer_root: PathBuf,
    pub cgroup_parent: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub cid: u32,
    pub resources: Resources,
    pub network: NetworkMode,
    pub network_namespace: Option<PathBuf>,
    pub network_namespace_file: Option<File>,
    /// Path as seen after the jailer chroot, e.g. `/run/firecracker.socket`.
    pub api_socket: PathBuf,
}

pub struct JailerLaunch {
    pub command: Command,
    pub stage: JailStage,
    pub cgroup: super::CgroupV2,
    pub api_socket_host: PathBuf,
    pub network_namespace_file: Option<File>,
}

/// Constructs the only supported VMM launch path. This function does not
/// spawn: callers must persist the session intent before calling it, and must
/// retain `stage` and `cgroup` until process identity is recorded.
#[allow(unsafe_code)] // pre_exec performs only the inherited file-size limit syscall.
pub fn build_jailer_command(
    spec: &mut JailerLaunchSpec,
    runtime: &VerifiedRuntime,
    stage: JailStage,
    cgroup: super::CgroupV2,
) -> Result<JailerLaunch> {
    if spec.sandbox_id.is_empty()
        || spec.session_id.is_empty()
        || spec.cid < 3
        || spec.uid < 100_000
        || spec.gid < 100_000
    {
        return Err(Error::Config("invalid jailer identity"));
    }
    if spec.sandbox_id.contains(['/', '\\', '\0'])
        || spec.session_id.contains(['/', '\\', '\0'])
        || spec.jailer_root != stage.chroot_base()
        || spec.cgroup_parent != cgroup.path().parent().ok_or(Error::Path)?
    {
        return Err(Error::Path);
    }
    if matches!(spec.network, NetworkMode::ExternalAttachment(_))
        && spec.network_namespace.is_none()
    {
        return Err(Error::Config("external network namespace is not verified"));
    }
    if spec.network_namespace.is_some() != spec.network_namespace_file.is_some() {
        return Err(Error::Config("network namespace descriptor is not pinned"));
    }
    if matches!(spec.network, NetworkMode::None) && spec.network_namespace.is_some() {
        return Err(Error::Config(
            "network namespace supplied for network mode none",
        ));
    }
    if !stage.matches_runtime(runtime) {
        return Err(Error::Artifact(
            "staged runtime profile does not match launch profile",
        ));
    }
    let limits = CgroupLimits::from_resources(&spec.resources)?;
    let resource_limits = VmmResourceLimits::from_resources(&spec.resources)?;
    if cgroup.path().as_os_str().is_empty() || limits.memory_max == 0 {
        return Err(Error::Config("invalid cgroup preparation"));
    }
    stage.validate_artifacts()?;
    let mut command = Command::new(jailer_program(runtime)?);
    command.args([
        "--id",
        &spec.session_id,
        "--exec-file",
        stage.firecracker().to_str().ok_or(Error::Path)?,
    ]);
    if let Some(namespace) = &spec.network_namespace {
        if !namespace.is_absolute()
            || namespace
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(Error::Path);
        }
        let fd = spec
            .network_namespace_file
            .as_ref()
            .ok_or(Error::Config("network namespace descriptor is not pinned"))?;
        use std::os::fd::AsRawFd;
        let _ = namespace;
        let daemon_pid = rustix::process::getpid().as_raw_pid();
        command.args(["--netns", &namespace_fd_path(daemon_pid, fd.as_raw_fd())]);
    }
    command.args([
        "--uid",
        &spec.uid.to_string(),
        "--gid",
        &spec.gid.to_string(),
        "--cgroup-version",
        "2",
        "--new-pid-ns",
    ]);
    command.args([
        "--parent-cgroup",
        cgroup.parent_argument(),
        "--chroot-base-dir",
        stage.chroot_base().to_str().ok_or(Error::Path)?,
    ]);
    command.args([
        "--resource-limit",
        &format!("fsize={}", resource_limits.file_size_bytes),
        "--resource-limit",
        &format!("no-file={}", resource_limits.open_files),
    ]);
    if !spec.api_socket.is_absolute()
        || spec
            .api_socket
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(Error::Path);
    }
    command.args([
        "--",
        "--api-sock",
        spec.api_socket.to_str().ok_or(Error::Path)?,
    ]);
    let relative = spec.api_socket.strip_prefix("/").map_err(|_| Error::Path)?;
    if relative.as_os_str().is_empty()
        || relative.as_os_str().len() > 128
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Error::Path);
    }
    let api_socket_host = stage
        .chroot_base()
        .join("firecracker")
        .join(&spec.session_id)
        .join("root")
        .join(relative);
    let diagnostics = spec
        .jailer_root
        .join("firecracker")
        .join(&spec.session_id)
        .join("jailer.stderr");
    let diagnostics_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&diagnostics)?;
    let diagnostics_stdout = OpenOptions::new().append(true).open(&diagnostics)?;
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(diagnostics_stdout))
        .stderr(Stdio::from(diagnostics_file));
    let stderr_limit = resource_limits.file_size_bytes;
    // The jailer's `--resource-limit` flags configure Firecracker. Apply the
    // same file bound to the jailer process itself so its stderr is bounded too.
    unsafe {
        command.pre_exec(move || {
            rustix::process::setrlimit(
                rustix::process::Resource::Fsize,
                rustix::process::Rlimit {
                    current: Some(stderr_limit),
                    maximum: Some(stderr_limit),
                },
            )
            .map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    // No --no-seccomp and no host-network fallback are intentionally present.
    Ok(JailerLaunch {
        command,
        stage,
        cgroup,
        api_socket_host,
        network_namespace_file: spec.network_namespace_file.take(),
    })
}

fn namespace_fd_path(pid: i32, fd: i32) -> String {
    format!("/proc/{pid}/fd/{fd}")
}

#[cfg(test)]
mod tests {
    use super::namespace_fd_path;

    #[test]
    fn namespace_join_uses_daemon_descriptor_not_child_self() {
        assert_eq!(namespace_fd_path(4242, 17), "/proc/4242/fd/17");
        assert!(!namespace_fd_path(4242, 17).contains("/proc/self/"));
    }
}

#[cfg(target_os = "linux")]
fn jailer_program(runtime: &VerifiedRuntime) -> Result<String> {
    // The retained verified descriptor is resolved by execve before its
    // close-on-exec flag takes effect. This avoids reopening a mutable path.
    Ok(runtime.jailer.proc_fd_path())
}

#[cfg(not(target_os = "linux"))]
fn jailer_program(_runtime: &VerifiedRuntime) -> Result<String> {
    Err(Error::Config("jailer execution requires Linux"))
}
