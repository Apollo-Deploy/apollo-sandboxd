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

#[cfg(target_os = "linux")]
pub fn build_read_only_ext4(
    formatter: &mut VerifiedArtifact,
    source_root: &std::path::Path,
    destination: &std::path::Path,
    bytes: u64,
    before_publish: &mut dyn FnMut(&PreparedExt4) -> Result<()>,
) -> Result<VerifiedArtifact> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use sha2::{Digest, Sha256};
    use std::{
        fs::File,
        os::{fd::AsRawFd, unix::fs::FileExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    if !(1 << 20..=4 << 30).contains(&bytes) || !bytes.is_multiple_of(4096) {
        return Err(Error::Config("invalid prepared ext4 size"));
    }
    super::rootfs::verify_extracted_root(source_root)?;
    let source = SecureDir::open(source_root)?;
    let parent = SecureDir::open(destination.parent().ok_or(Error::Path)?)?;
    let name = destination
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or(Error::Path)?;
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(Error::Path);
    }
    let output = File::from(rustix::fs::openat(
        parent.as_fd(),
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    output.set_len(bytes)?;
    formatter.revalidate()?;
    let target = format!("/proc/{}/fd/{}", std::process::id(), output.as_raw_fd());
    let tree = format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        source.as_fd().as_raw_fd()
    );
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
    // O_TMPFILE has no pathname to remove on failure. NOREPLACE linkat leaves
    // an existing artifact intact and the parent fsync makes publication durable.
    rustix::fs::linkat(
        rustix::fs::CWD,
        &target,
        parent.as_fd(),
        name,
        AtFlags::SYMLINK_FOLLOW,
    )?;
    rustix::fs::fsync(parent.as_fd())?;
    verify(destination, &digest, false)
}

#[cfg(not(target_os = "linux"))]
pub fn build_read_only_ext4(
    _formatter: &mut VerifiedArtifact,
    _source_root: &std::path::Path,
    _destination: &std::path::Path,
    _bytes: u64,
    _before_publish: &mut dyn FnMut(&PreparedExt4) -> Result<()>,
) -> Result<VerifiedArtifact> {
    Err(Error::Config("rootfs image preparation requires Linux"))
}
