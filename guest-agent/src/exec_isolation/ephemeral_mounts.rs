//! Descriptor-contained mount targets prepared before any customer process starts.
use guest_protocol::ExecutionMount;
use nix::{
    libc,
    mount::{MsFlags, mount},
};
use std::{
    ffi::CString,
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
};

pub(super) fn install(
    mounts: &[ExecutionMount],
    files: &[(sandboxd_protocol::VolumeId, File, bool)],
) -> Result<(), String> {
    let mut ordered: Vec<_> = mounts.iter().collect();
    // Parents must exist before nested mounts of any kind. Otherwise a later
    // tmpfs could silently hide a disk or a secret already installed below it.
    ordered.sort_by_key(|mount| {
        let target = match mount {
            ExecutionMount::Volume { target, .. }
            | ExecutionMount::Tmpfs { target, .. }
            | ExecutionMount::Secret { target, .. } => target,
        };
        (target.matches('/').count(), target.as_str())
    });
    for spec in ordered {
        spec.validate().map_err(str::to_owned)?;
        let (target, size_bytes, readonly) = match spec {
            ExecutionMount::Tmpfs {
                target,
                size_bytes,
                readonly,
            } => (target, size_bytes, readonly),
            ExecutionMount::Volume { .. } => {
                install_volumes(std::slice::from_ref(spec), files)?;
                continue;
            }
            ExecutionMount::Secret {
                target,
                value,
                uid,
                gid,
                mode,
            } => {
                install_secret(target, &value.0, *uid, *gid, *mode)?;
                continue;
            }
        };
        let directory = target_directory(target)?;
        let fd_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
        let options = format!("mode=1777,size={size_bytes}");
        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
        if *readonly {
            flags |= MsFlags::MS_RDONLY;
        }
        mount(
            Some("tmpfs"),
            fd_path.as_str(),
            Some("tmpfs"),
            flags,
            Some(options.as_str()),
        )
        .map_err(|e| format!("install private execution tmpfs: {e}"))?;
    }
    Ok(())
}

#[allow(unsafe_code)]
fn target_directory(target: &str) -> Result<File, String> {
    let mut directory = File::open("/").map_err(|e| format!("open execution root: {e}"))?;
    for component in target.split('/').skip(1).filter(|part| !part.is_empty()) {
        let name = CString::new(component).map_err(|_| "invalid mount component")?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // Every lookup is relative to a held directory descriptor. Symlinks
        // cannot redirect either creation or the final mount out of the root.
        let mut fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            let created = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o755) };
            if created < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(format!(
                    "create mount target: {}",
                    std::io::Error::last_os_error()
                ));
            }
            fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        }
        if fd < 0 {
            return Err(format!(
                "open mount target: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: openat returned a new owned descriptor; it is closed when
        // the directory is replaced or the completed target is dropped.
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

// The backing memfd is anonymous RAM. Its bind mount is private to this
// execution namespace and is readonly, nosuid, nodev and noexec before UID drop.
#[allow(unsafe_code)]
fn install_secret(target: &str, value: &[u8], uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    use std::io::Write;
    let (parent, name) = target.rsplit_once('/').ok_or("invalid secret target")?;
    let parent = target_directory(if parent.is_empty() { "/" } else { parent })?;
    let name = CString::new(name).map_err(|_| "invalid secret filename")?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err("open secret target failed".into());
    }
    let target_file = unsafe { File::from_raw_fd(fd) };
    if !target_file
        .metadata()
        .map_err(|_| "stat secret target failed")?
        .is_file()
    {
        return Err("secret target is not regular".into());
    }
    let memfd = unsafe {
        libc::memfd_create(
            c"execution-secret".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if memfd < 0 {
        return Err("allocate secret backing failed".into());
    }
    let mut backing = unsafe { File::from_raw_fd(memfd) };
    backing
        .write_all(value)
        .map_err(|_| "write secret backing failed")?;
    if unsafe { libc::fchown(memfd, uid, gid) } != 0 || unsafe { libc::fchmod(memfd, mode) } != 0 {
        return Err("secret ownership failed".into());
    }
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(memfd, libc::F_ADD_SEALS, seals) } != 0 {
        return Err("seal secret backing failed".into());
    }
    let source = format!("/proc/self/fd/{memfd}");
    let dest = format!("/proc/self/fd/{}", target_file.as_raw_fd());
    mount(
        Some(source.as_str()),
        dest.as_str(),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|_| "bind secret backing failed")?;
    mount(
        None::<&str>,
        dest.as_str(),
        None::<&str>,
        MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV
            | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|_| "protect secret mount failed")?;
    Ok(())
}

/// Bind only supervisor-pinned disks; declarations carry no source path.
pub(super) fn install_volumes(
    mounts: &[ExecutionMount],
    files: &[(sandboxd_protocol::VolumeId, File, bool)],
) -> Result<(), String> {
    for spec in mounts {
        if let ExecutionMount::Volume {
            volume_id,
            target,
            readonly,
        } = spec
        {
            let (_, source, policy_readonly) = files
                .iter()
                .find(|(id, _, _)| id == volume_id)
                .ok_or("unconfigured execution volume")?;
            if *policy_readonly && !readonly {
                return Err("volume readonly policy rejected".into());
            }
            let directory = target_directory(target)?;
            let source = format!("/proc/self/fd/{}", source.as_raw_fd());
            let target = format!("/proc/self/fd/{}", directory.as_raw_fd());
            mount(
                Some(source.as_str()),
                target.as_str(),
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|_| "bind execution volume failed")?;
            let mut flags =
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
            if *readonly || *policy_readonly {
                flags |= MsFlags::MS_RDONLY;
            }
            mount(
                None::<&str>,
                target.as_str(),
                None::<&str>,
                flags,
                None::<&str>,
            )
            .map_err(|_| "protect execution volume failed")?;
        }
    }
    Ok(())
}
