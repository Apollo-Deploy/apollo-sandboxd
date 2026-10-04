//! Descriptor-relative, no-replace publication of verified OCI content.
use crate::security::path::SecureDir;
#[cfg(not(target_os = "linux"))]
use crate::security::path::device_id;
use std::{fs::File, io, path::Path};

pub(super) struct Publication {
    directory: SecureDir,
    name: String,
    pub(super) file: File,
    #[cfg(not(target_os = "linux"))]
    temporary: (String, u64, u64),
}

impl Publication {
    pub(super) fn create(path: &Path) -> io::Result<Self> {
        let directory = SecureDir::open(path.parent().ok_or_else(invalid)?).map_err(error)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(invalid)?
            .to_owned();
        // Validate the destination component before any filesystem effect.
        match directory.stat(&name) {
            Ok(_) | Err(crate::error::Error::Kernel(rustix::io::Errno::NOENT)) => (),
            Err(e) => return Err(error(e)),
        }
        #[cfg(target_os = "linux")]
        let file = File::from(rustix::fs::openat(
            directory.as_fd(),
            ".",
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )?);
        #[cfg(not(target_os = "linux"))]
        let (file, temporary) = {
            let suffix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(error)?
                .as_nanos();
            let name = format!(".tmp-{}-{suffix}", std::process::id());
            let file = directory.create_file(&name).map_err(error)?;
            let identity = rustix::fs::fstat(&file)?;
            (file, (name, device_id(identity.st_dev), identity.st_ino))
        };
        Ok(Self {
            directory,
            name,
            file,
            #[cfg(not(target_os = "linux"))]
            temporary,
        })
    }

    /// Publishes the pinned inode or returns the independently opened winner.
    /// Linux uses O_TMPFILE, so interruption never leaves a download pathname.
    pub(super) fn publish(&self) -> io::Result<File> {
        self.file.sync_all()?;
        #[cfg(target_os = "linux")]
        let result = {
            use std::os::fd::AsRawFd;
            let source = format!("/proc/self/fd/{}", self.file.as_raw_fd());
            rustix::fs::linkat(
                rustix::fs::CWD,
                &source,
                self.directory.as_fd(),
                &self.name,
                rustix::fs::AtFlags::SYMLINK_FOLLOW,
            )
        };
        #[cfg(not(target_os = "linux"))]
        let result = rustix::fs::renameat_with(
            self.directory.as_fd(),
            &self.temporary.0,
            self.directory.as_fd(),
            &self.name,
            rustix::fs::RenameFlags::NOREPLACE,
        );
        match result {
            Ok(()) => rustix::fs::fsync(self.directory.as_fd())?,
            Err(rustix::io::Errno::EXIST) => (),
            Err(e) => return Err(e.into()),
        }
        self.directory.open_file(&self.name, false).map_err(error)
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for Publication {
    fn drop(&mut self) {
        let (name, device, inode) = &self.temporary;
        // Never unlink a replacement or foreign object if the name changed.
        let _ = self.directory.remove_if_identity(
            name,
            *device,
            *inode,
            rustix::fs::FileType::RegularFile,
        );
    }
}

fn invalid() -> io::Error {
    error("invalid OCI publication path")
}
fn error(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
