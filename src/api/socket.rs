use super::socket_namespace::{DIRECTORY, Identity, Namespace, STAGED_SOCKET};
use crate::{
    config::Daemon,
    error::{Error, Result},
    security::path::SecureDir,
};
use rustix::fs::{self, AtFlags, FileType, Mode, RenameFlags};
use std::{
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    time::timeout,
};

pub struct Socket {
    pub listener: UnixListener,
    directory: SecureDir,
    namespace: Namespace,
    name: String,
    identity: Identity,
    published: bool,
    _lock: File,
}
impl Socket {
    pub async fn bind(config: &Daemon) -> Result<Self> {
        let parent_path = config.socket.parent().ok_or(Error::Path)?;
        let directory = SecureDir::open(parent_path)?;
        super::socket_namespace::preflight(&directory)?;
        let name = config
            .socket
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(Error::Path)?
            .to_owned();
        let lock = directory.lock("socket.lock")?;
        let mut namespace = Namespace::open(&directory, &name)?;
        let endpoint = pinned_path(&directory, parent_path, &name);
        match directory.stat(&name) {
            Ok(stat) => {
                let identity = checked_socket(&stat)?;
                if !namespace.owns_published(identity) {
                    return Err(Error::Path);
                }
                stale(&endpoint).await?;
                directory.remove_if_identity(
                    &name,
                    identity.dev,
                    identity.ino,
                    FileType::Socket,
                )?;
            }
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
            Err(error) => return Err(error),
        }
        let stage_path = pinned_path(
            &namespace.directory,
            &parent_path.join(DIRECTORY),
            STAGED_SOCKET,
        );
        match namespace.directory.stat(STAGED_SOCKET) {
            Ok(stat) => {
                let identity = checked_socket(&stat)?;
                if namespace
                    .staged_identity()
                    .is_some_and(|expected| expected != identity)
                {
                    return Err(Error::Path);
                }
                // Even before a socket identity is recorded, the persisted private
                // namespace proves this internal bind belongs to this endpoint.
                stale(&stage_path).await?;
                namespace.directory.remove_if_identity(
                    STAGED_SOCKET,
                    identity.dev,
                    identity.ino,
                    FileType::Socket,
                )?;
            }
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
            Err(error) => return Err(error),
        }
        namespace.clear()?;
        let listener = UnixListener::bind(&stage_path)?;
        let identity = checked_socket(&namespace.directory.stat(STAGED_SOCKET)?)?;
        // RAII covers ordinary setup failures. SIGKILL recovery uses the durable
        // namespace and prepared identity, including the rename/commit window.
        let mut socket = Self {
            listener,
            directory,
            namespace,
            name,
            identity,
            published: false,
            _lock: lock,
        };
        fs::chownat(
            socket.namespace.directory.as_fd(),
            STAGED_SOCKET,
            None,
            Some(rustix::process::Gid::from_raw(config.socket_group)),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        fs::chmodat(
            socket.namespace.directory.as_fd(),
            STAGED_SOCKET,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP,
            AtFlags::empty(),
        )?;
        socket.namespace.prepare(identity)?;
        fs::renameat_with(
            socket.namespace.directory.as_fd(),
            STAGED_SOCKET,
            socket.directory.as_fd(),
            &socket.name,
            RenameFlags::NOREPLACE,
        )?;
        socket.published = true;
        fs::fsync(socket.namespace.directory.as_fd())?;
        fs::fsync(socket.directory.as_fd())?;
        socket.namespace.published(identity)?;
        Ok(socket)
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let (directory, name) = if self.published {
            (&self.directory, self.name.as_str())
        } else {
            (&self.namespace.directory, STAGED_SOCKET)
        };
        match directory.remove_if_identity(
            name,
            self.identity.dev,
            self.identity.ino,
            FileType::Socket,
        ) {
            Ok(()) | Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
            Err(_) => eprintln!("socket cleanup rejected: ownership could not be proven"),
        }
    }
}
fn checked_socket(stat: &fs::Stat) -> Result<Identity> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
    {
        return Err(Error::Path);
    }
    Ok(Identity::of(stat))
}
async fn stale(path: &Path) -> Result<()> {
    match timeout(Duration::from_secs(1), UnixStream::connect(path)).await {
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => Ok(()),
        _ => Err(Error::Locked),
    }
}
fn pinned_path(directory: &SecureDir, absolute_parent: &Path, name: &str) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let _ = absolute_parent;
        PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            directory.as_fd().as_raw_fd(),
            name
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = directory;
        absolute_parent.join(name)
    }
}

#[cfg(test)]
#[path = "socket_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "socket_attack_tests.rs"]
mod attack_tests;
