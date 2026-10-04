use crate::error::{Error, Result};
#[cfg(target_os = "linux")]
use crate::security::path::SecureDir;
#[cfg(target_os = "linux")]
use crate::session::LaunchManifest;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestEndpoint {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    #[cfg(target_os = "linux")]
    session_parent: Option<Box<LaunchManifest>>,
}
impl GuestEndpoint {
    pub fn observed(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        validate_parent(&path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_socket() {
            return Err(Error::Path);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                #[cfg(target_os = "linux")]
                session_parent: None,
            })
        }
        #[cfg(not(unix))]
        {
            Err(Error::Config("vsock Unix transport requires Unix"))
        }
    }

    /// Observe a jailer-created endpoint while preserving the staged-root proof.
    /// The jailer owns `root/run` after setup, so ordinary daemon-owned directory
    /// validation cannot be reused for this path.
    #[cfg(target_os = "linux")]
    pub fn observed_for_session(
        path: impl Into<PathBuf>,
        manifest: &LaunchManifest,
        uid: u32,
        gid: u32,
    ) -> Result<Self> {
        use rustix::fs::{self, AtFlags, FileType, OFlags};
        let path = path.into();
        if manifest.assets.root != manifest.jail_root || path != manifest.vsock_socket {
            return Err(Error::Path);
        }
        let relative = path
            .strip_prefix(&manifest.jail_root)
            .map_err(|_| Error::Path)?;
        let mut components = relative.components();
        if components.next() != Some(Component::Normal("run".as_ref())) {
            return Err(Error::Path);
        }
        let leaf = match (components.next(), components.next()) {
            (Some(Component::Normal(name)), None) => name,
            _ => return Err(Error::Path),
        };

        // All ancestors are daemon-owned and are opened through SecureDir. The
        // final jail root may be jailer-owned, but its identity is pinned to the
        // durable staged-assets manifest.
        let jail_parent = manifest.jail_root.parent().ok_or(Error::Path)?;
        let trusted_parent = SecureDir::open(jail_parent)?;
        let root_fd = fs::openat(
            trusted_parent.as_fd(),
            manifest.jail_root.file_name().ok_or(Error::Path)?,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let root_stat = fs::fstat(&root_fd)?;
        if FileType::from_raw_mode(root_stat.st_mode) != FileType::Directory
            || crate::security::path::device_id(root_stat.st_dev)
                != manifest.assets.root_identity.device
            || root_stat.st_ino != manifest.assets.root_identity.inode
        {
            return Err(Error::Path);
        }
        let run_fd = fs::openat(
            &root_fd,
            "run",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let run_stat = fs::fstat(&run_fd)?;
        if FileType::from_raw_mode(run_stat.st_mode) != FileType::Directory
            || run_stat.st_uid != uid
            || run_stat.st_gid != gid
            || run_stat.st_mode & 0o777 != 0o700
        {
            return Err(Error::Path);
        }
        let socket = fs::statat(&run_fd, leaf, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(socket.st_mode) != FileType::Socket
            || socket.st_uid != uid
            || socket.st_gid != gid
        {
            return Err(Error::Path);
        }
        if let Some(expected) = manifest.vsock_socket_identity {
            let device = crate::security::path::device_id(socket.st_dev);
            if device != expected.device || socket.st_ino != expected.inode {
                return Err(Error::Config("guest endpoint identity changed"));
            }
        }
        Ok(Self {
            path,
            device: crate::security::path::device_id(socket.st_dev),
            inode: socket.st_ino,
            uid: socket.st_uid,
            gid: socket.st_gid,
            session_parent: Some(Box::new(manifest.clone())),
        })
    }

    pub(super) fn verify(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(manifest) = &self.session_parent {
            let current = Self::observed_for_session(&self.path, manifest, self.uid, self.gid)?;
            if current.device != self.device || current.inode != self.inode {
                return Err(Error::Config("guest endpoint identity changed"));
            }
            return Ok(());
        }
        validate_parent(&self.path)?;
        let current = std::fs::symlink_metadata(&self.path)?;
        if !current.file_type().is_socket() {
            return Err(Error::Path);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if current.dev() != self.device
                || current.ino() != self.inode
                || current.uid() != self.uid
                || current.gid() != self.gid
            {
                return Err(Error::Config("guest endpoint identity changed"));
            }
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn validate_parent(path: &Path) -> Result<()> {
    SecureDir::open(path.parent().ok_or(Error::Path)?).map(|_| ())
}
#[cfg(not(target_os = "linux"))]
fn validate_parent(path: &Path) -> Result<()> {
    if path.parent().is_some() {
        Ok(())
    } else {
        Err(Error::Path)
    }
}
