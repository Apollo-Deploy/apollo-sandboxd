//! Trusted initramfs PID1 bootstrap. It mounts the guest root and executes the
//! supervisor through an fd opened before any customer filesystem is visible.

#[cfg(target_os = "linux")]
mod linux {
    use nix::mount::{MsFlags, mount};
    use nix::unistd::{chdir, chroot, fexecve, getpid};
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    const BASE: &str = "/mnt/base";
    const STATE: &str = "/mnt/state";
    const NEW_ROOT: &str = "/mnt/root";
    const TRUSTED_AGENT: &str = "/run/initramfs/staticagent/apollo-sandbox-guest";
    const TRUSTED_NETWORK_TOOL: &str = "/run/initramfs/statictool/network-tool";

    pub fn run() -> Result<(), String> {
        if getpid().as_raw() != 1 {
            return Err("guest bootstrap must run as PID 1".into());
        }
        mount_pseudo_filesystems()?;
        let cmdline = fs::read_to_string("/proc/cmdline")
            .map_err(|e| format!("read kernel command line: {e}"))?;
        let identity = identity_args(&cmdline)?;
        let agent = open_trusted_agent()?;
        let network_tool = open_optional_trusted_network_tool()?;
        let state_fd = mount_guest_root()?;
        clear_close_on_exec(&state_fd)?;
        if let Some(tool) = &network_tool {
            clear_close_on_exec(tool)?;
        }
        switch_root()?;
        exec_agent(agent, identity, state_fd, network_tool)
    }

    fn mount_pseudo_filesystems() -> Result<(), String> {
        for path in ["/proc", "/sys", "/dev"] {
            ensure_mount_dir(path)?;
        }
        mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount initramfs proc: {e}"))?;
        mount(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount initramfs sysfs: {e}"))?;
        mount(
            Some("devtmpfs"),
            "/dev",
            Some("devtmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount initramfs devtmpfs: {e}"))
    }

    fn identity_args(cmdline: &str) -> Result<Vec<CString>, String> {
        let mut values = Vec::with_capacity(12);
        for name in [
            "sandbox",
            "sandbox-generation",
            "session",
            "session-generation",
            "boot-nonce",
            "vsock-cid",
        ] {
            let prefix = format!("sandboxd.{name}=");
            let value = cmdline
                .split_whitespace()
                .find_map(|part| part.strip_prefix(&prefix))
                .ok_or_else(|| format!("missing trusted kernel argument {prefix}"))?;
            if value.is_empty() || value.contains(['\0', ' ', '\t']) {
                return Err(format!("invalid kernel argument {prefix}"));
            }
            values.push(CString::new(format!("--{name}")).map_err(|_| "invalid argument")?);
            values.push(CString::new(value).map_err(|_| "invalid argument")?);
        }
        Ok(values)
    }

    fn open_trusted_agent() -> Result<File, String> {
        let metadata = fs::symlink_metadata(TRUSTED_AGENT)
            .map_err(|e| format!("trusted supervisor missing: {e}"))?;
        if !metadata.file_type().is_file() || metadata.uid() != 0 || metadata.gid() != 0 {
            return Err("trusted supervisor must be a root-owned regular file".into());
        }
        if metadata.mode() & 0o022 != 0 {
            return Err("trusted supervisor is writable by group or other".into());
        }
        OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(TRUSTED_AGENT)
            .map_err(|e| format!("open trusted supervisor: {e}"))
    }

    fn open_optional_trusted_network_tool() -> Result<Option<File>, String> {
        match fs::symlink_metadata(TRUSTED_NETWORK_TOOL) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("inspect trusted network tool: {error}")),
            Ok(metadata) => {
                if !metadata.file_type().is_file()
                    || metadata.uid() != 0
                    || metadata.gid() != 0
                    || metadata.mode() & 0o022 != 0
                {
                    return Err(
                        "trusted network tool must be a root-owned non-writable regular file"
                            .into(),
                    );
                }
                OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(TRUSTED_NETWORK_TOOL)
                    .map(Some)
                    .map_err(|e| format!("open trusted network tool: {e}"))
            }
        }
    }

    fn mount_guest_root() -> Result<File, String> {
        for path in ["/mnt", BASE, STATE, NEW_ROOT] {
            ensure_mount_dir(path)?;
        }
        mount(
            Some("/dev/vda"),
            BASE,
            Some("ext4"),
            MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| format!("mount immutable base /dev/vda: {e}"))?;
        mount(
            Some("/dev/vdb"),
            STATE,
            Some("ext4"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount writable state /dev/vdb: {e}"))?;
        let state_fd = OpenOptions::new()
            .read(true)
            .open(STATE)
            .map_err(|e| format!("open trusted state mount: {e}"))?;
        // These directories belong to the mounted state filesystem, so they
        // must be created after the /dev/vdb mount is in place.
        ensure_mount_dir("/mnt/state/upper")?;
        ensure_mount_dir("/mnt/state/work")?;
        let options = format!("lowerdir={BASE},upperdir={STATE}/upper,workdir={STATE}/work");
        mount(
            Some("overlay"),
            NEW_ROOT,
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        )
        .map_err(|e| format!("mount overlay root: {e}"))?;
        for path in [
            "/mnt/root/proc",
            "/mnt/root/sys",
            "/mnt/root/dev",
            "/mnt/root/run",
        ] {
            ensure_mount_dir(path)?;
        }
        mount(
            Some("proc"),
            "/mnt/root/proc",
            Some("proc"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount guest proc: {e}"))?;
        mount(
            Some("sysfs"),
            "/mnt/root/sys",
            Some("sysfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount guest sysfs: {e}"))?;
        mount(
            Some("devtmpfs"),
            "/mnt/root/dev",
            Some("devtmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount guest devtmpfs: {e}"))?;
        // devtmpfs replaces /dev; its child mountpoints must be made afterward.
        ensure_mount_dir("/mnt/root/dev/pts")?;
        mount(
            Some("devpts"),
            "/mnt/root/dev/pts",
            Some("devpts"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount guest devpts: {e}"))?;
        mount(
            Some("tmpfs"),
            "/mnt/root/run",
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount guest run tmpfs: {e}"))?;
        Ok(state_fd)
    }

    fn ensure_mount_dir(path: &str) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err(format!("refusing symlink mount target {path}"))
            }
            Ok(metadata) if metadata.is_dir() => Ok(()),
            Ok(_) => Err(format!("mount target {path} is not a directory")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|e| format!("create mount target {path}: {e}"))
            }
            Err(error) => Err(format!("inspect mount target {path}: {error}")),
        }
    }

    fn switch_root() -> Result<(), String> {
        // Follow switch_root ordering: make the new root the cwd before moving
        // the mount, then chroot through the cwd rather than resolving "/"
        // against the still-active initramfs root.
        chdir(NEW_ROOT).map_err(|e| format!("chdir prepared guest root: {e}"))?;
        mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
            .map_err(|e| format!("move guest root over initramfs root: {e}"))?;
        chroot(".").map_err(|e| format!("chroot guest root: {e}"))?;
        chdir("/").map_err(|e| format!("chdir guest root: {e}"))
    }

    fn clear_close_on_exec(file: &File) -> Result<(), String> {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        let flags =
            fcntl(file, FcntlArg::F_GETFD).map_err(|e| format!("get state fd flags: {e}"))?;
        fcntl(
            file,
            FcntlArg::F_SETFD(FdFlag::from_bits_truncate(flags).difference(FdFlag::FD_CLOEXEC)),
        )
        .map_err(|e| format!("retain state fd: {e}"))?;
        Ok(())
    }

    fn exec_agent(
        agent: File,
        mut identity: Vec<CString>,
        state: File,
        network_tool: Option<File>,
    ) -> Result<(), String> {
        let fd = state.as_raw_fd();
        identity.push(CString::new("--state-fd").map_err(|_| "invalid state argument")?);
        identity.push(CString::new(fd.to_string()).map_err(|_| "invalid state fd")?);
        if let Some(tool) = network_tool {
            identity.push(
                CString::new("--network-tool-fd").map_err(|_| "invalid network tool argument")?,
            );
            identity.push(
                CString::new(tool.as_raw_fd().to_string())
                    .map_err(|_| "invalid network tool fd")?,
            );
            std::mem::forget(tool);
        }
        let arg0 = CString::new("/run/apollo-sandbox-guest").map_err(|_| "invalid argv[0]")?;
        let mut args = vec![arg0];
        args.extend(identity);
        let path_env = CString::new("PATH=/usr/bin:/bin").map_err(|_| "invalid PATH")?;
        match fexecve(agent, &args, &[path_env]) {
            Ok(never) => match never {},
            Err(error) => Err(format!("exec trusted supervisor: {error}")),
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), String> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), String> {
    Err("guest bootstrap requires Linux".into())
}
