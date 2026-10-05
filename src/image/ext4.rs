//! Host-side preparation executes only the operator-verified formatter.
use crate::{
    error::{Error, Result},
    runtime::VerifiedArtifact,
};
#[cfg(target_os = "linux")]
use crate::{runtime::verify, security::path::SecureDir};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedExt4 {
    pub sha256: String,
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
}

/// Converts an Artifactd-verified prepared rootfs received over SCM_RIGHTS.
/// The caller verifies the owning Artifactd endpoint before this function is
/// reached; this boundary independently rejects writable or non-directory FDs.
#[cfg(target_os = "linux")]
pub fn build_read_only_ext4_from_fd(
    formatter: &mut VerifiedArtifact,
    source: &std::fs::File,
    expected_owner_uid: u32,
    destination: &std::path::Path,
    bytes: u64,
    before_publish: &mut dyn FnMut(&PreparedExt4) -> Result<()>,
) -> Result<VerifiedArtifact> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use sha2::{Digest, Sha256};
    use std::{
        os::{fd::AsRawFd, unix::fs::FileExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    if !(1 << 20..=4 << 30).contains(&bytes) || !bytes.is_multiple_of(4096) {
        return Err(Error::Config("invalid prepared ext4 size"));
    }
    let source_stat = rustix::fs::fstat(source)?;
    let source_flags = rustix::fs::fcntl_getfl(source)?;
    if FileType::from_raw_mode(source_stat.st_mode) != FileType::Directory
        || source_stat.st_uid != expected_owner_uid
        || source_stat.st_mode & 0o222 != 0
        || source_flags & OFlags::ACCMODE != OFlags::RDONLY
    {
        return Err(Error::Path);
    }
    let parent = SecureDir::open(destination.parent().ok_or(Error::Path)?)?;
    let name = destination
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or(Error::Path)?;
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(Error::Path);
    }
    let output = std::fs::File::from(rustix::fs::openat(
        parent.as_fd(),
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    output.set_len(bytes)?;
    formatter.revalidate()?;
    let target = format!("/proc/{}/fd/{}", std::process::id(), output.as_raw_fd());
    let tree = format!("/proc/{}/fd/{}", std::process::id(), source.as_raw_fd());
    let mut child = Command::new(formatter.proc_fd_path())
        .env_clear()
        .args(["-t", "ext4", "-F", "-d", &tree, &target])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::Artifact("trusted rootfs formatter failed to start"))?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => return Err(Error::Artifact("trusted rootfs formatter failed")),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Artifact(
                    "trusted rootfs formatter timed out or could not be observed",
                ));
            }
        }
    }
    if output.metadata()?.len() != bytes {
        return Err(Error::Artifact("formatter resized prepared image"));
    }
    output.sync_all()?;
    rustix::fs::fchmod(&output, Mode::from_raw_mode(0o444))?;
    output.sync_all()?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65_536];
    let mut offset = 0;
    loop {
        let count = output.read_at(&mut buffer, offset)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    let digest = hex::encode(hash.finalize());
    let metadata = rustix::fs::fstat(&output)?;
    before_publish(&PreparedExt4 {
        sha256: digest.clone(),
        device: crate::security::path::device_id(metadata.st_dev),
        inode: metadata.st_ino,
        bytes,
    })?;
    rustix::fs::linkat(
        rustix::fs::CWD,
        format!("/proc/{}/fd/{}", std::process::id(), output.as_raw_fd()),
        parent.as_fd(),
        name,
        AtFlags::SYMLINK_FOLLOW,
    )?;
    rustix::fs::fsync(parent.as_fd())?;
    verify(destination, &digest, false)
}
