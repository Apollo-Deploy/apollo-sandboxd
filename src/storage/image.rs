use crate::{
    error::{Error, Result},
    security::path::{SecureDir, device_id},
};
use sandboxd_protocol::{ApiError, ErrorCode, ImageDigest};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};
#[cfg(target_os = "linux")]
use std::{io::Write, os::fd::AsRawFd};

#[derive(Clone, Copy)]
pub struct ImageLimits {
    pub max_image_bytes: u64,
    pub max_cache_bytes: u64,
    pub max_images: u32,
}

/// A pinned immutable content inode. Raw ext4 input is never mounted or
/// extracted by the host; its digest identifies bytes, not trusted guest code.
pub struct VerifiedImage {
    pub file: File,
    pub digest: ImageDigest,
    pub bytes: u64,
    pub device: u64,
    pub inode: u64,
}

pub struct ImageCache {
    directory: SecureDir,
    limits: ImageLimits,
    _lock: File,
}

impl ImageCache {
    pub fn open(path: &Path, limits: ImageLimits) -> Result<Self> {
        if limits.max_image_bytes < 2048
            || limits.max_image_bytes > 1 << 40
            || limits.max_cache_bytes < limits.max_image_bytes
            || limits.max_cache_bytes > 1 << 44
            || limits.max_images == 0
            || limits.max_images > 100_000
        {
            return Err(Error::Config("invalid image cache bounds"));
        }
        let directory = SecureDir::open(path)?;
        let stat = rustix::fs::fstat(directory.as_fd())?;
        if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
            return Err(Error::Path);
        }
        let lock = directory.lock("image-cache.lock")?;
        Ok(Self {
            directory,
            limits,
            _lock: lock,
        })
    }

    pub fn inspect(&self, digest: &ImageDigest) -> Result<VerifiedImage> {
        let file = self
            .directory
            .open_file(image_name(digest), false)
            .map_err(|error| match error {
                Error::Kernel(rustix::io::Errno::NOENT) => {
                    ApiError::new(ErrorCode::ImageNotFound, "image is not cached").into()
                }
                other => other,
            })?;
        verify_image(file, digest, self.limits.max_image_bytes)
    }

    /// Import one stream using a bounded buffer and an anonymous temporary
    /// inode. An interrupted import leaves no pathname to recover or clean.
    /// Publishing never replaces a cached inode and fsyncs data before its name.
    #[cfg(target_os = "linux")]
    pub fn import_raw(
        &mut self,
        mut source: impl Read,
        digest: &ImageDigest,
    ) -> Result<VerifiedImage> {
        match self.inspect(digest) {
            Ok(image) => return Ok(image),
            Err(Error::Api(error)) if error.code == ErrorCode::ImageNotFound => (),
            Err(error) => return Err(error),
        }
        let (count, used) = self.usage()?;
        if count >= self.limits.max_images {
            return Err(quota());
        }
        let remaining = self
            .limits
            .max_cache_bytes
            .checked_sub(used)
            .ok_or_else(quota)?;
        let limit = remaining.min(self.limits.max_image_bytes);
        let fd = rustix::fs::openat(
            self.directory.as_fd(),
            ".",
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )?;
        let mut file = File::from(fd);
        let mut bytes = 0u64;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65_536];
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            bytes = bytes.checked_add(count as u64).ok_or_else(quota)?;
            if bytes > limit {
                return Err(quota());
            }
            hash.update(&buffer[..count]);
            file.write_all(&buffer[..count])?;
        }
        if hex::encode(hash.finalize()) != digest.as_str()[7..] {
            return Err(
                ApiError::new(ErrorCode::ImageDigestMismatch, "raw image digest mismatch").into(),
            );
        }
        file.seek(SeekFrom::Start(0))?;
        check_ext4(&mut file, bytes)?;
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o444))?;
        file.sync_all()?;
        // Procfs resolves the pinned anonymous inode without the extra
        // CAP_DAC_READ_SEARCH requirement of AT_EMPTY_PATH.
        let descriptor = format!("/proc/self/fd/{}", file.as_raw_fd());
        rustix::fs::linkat(
            rustix::fs::CWD,
            &descriptor,
            self.directory.as_fd(),
            image_name(digest),
            rustix::fs::AtFlags::SYMLINK_FOLLOW,
        )?;
        rustix::fs::fsync(self.directory.as_fd())?;
        // Reopen read-only so the returned handle cannot accidentally modify
        // an immutable shared base even though the import descriptor was RW.
        self.inspect(digest)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn import_raw(
        &mut self,
        _source: impl Read,
        _digest: &ImageDigest,
    ) -> Result<VerifiedImage> {
        Err(ApiError::new(
            ErrorCode::UnsupportedHost,
            "raw image import requires Linux",
        )
        .into())
    }

    #[cfg(target_os = "linux")]
    fn usage(&self) -> Result<(u32, u64)> {
        let mut count = 0u32;
        let mut bytes = 0u64;
        let mut entries = rustix::fs::Dir::read_from(self.directory.as_fd())?;
        for entry in &mut entries {
            let entry = entry?;
            let raw = entry.file_name().to_bytes();
            if matches!(raw, b"." | b".." | b"image-cache.lock") {
                continue;
            }
            let name = std::str::from_utf8(raw).map_err(|_| Error::Path)?;
            let digest = ImageDigest::new(format!("sha256:{name}")).map_err(|_| Error::Path)?;
            let file = self.directory.open_file(image_name(&digest), false)?;
            let stat = rustix::fs::fstat(&file)?;
            if stat.st_mode & 0o222 != 0 || stat.st_size <= 0 {
                return Err(Error::Path);
            }
            count = count.checked_add(1).ok_or_else(quota)?;
            bytes = bytes.checked_add(stat.st_size as u64).ok_or_else(quota)?;
            if count > self.limits.max_images || bytes > self.limits.max_cache_bytes {
                return Err(quota());
            }
        }
        Ok((count, bytes))
    }
}

fn image_name(digest: &ImageDigest) -> &str {
    &digest.as_str()[7..]
}
#[cfg(target_os = "linux")]
fn quota() -> Error {
    ApiError::new(ErrorCode::QuotaExceeded, "image cache quota exceeded").into()
}

fn verify_image(mut file: File, digest: &ImageDigest, max: u64) -> Result<VerifiedImage> {
    let before = rustix::fs::fstat(&file)?;
    if before.st_mode & 0o222 != 0 || before.st_size < 2048 || before.st_size as u64 > max {
        return Err(Error::Path);
    }
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes.checked_add(count as u64).ok_or(Error::State)?;
        if bytes > max {
            return Err(Error::Path);
        }
        hash.update(&buffer[..count]);
    }
    let after = rustix::fs::fstat(&file)?;
    if bytes != before.st_size as u64
        || after.st_size != before.st_size
        || after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_mtime != before.st_mtime
        || after.st_ctime != before.st_ctime
        || after.st_mode != before.st_mode
        || after.st_nlink != 1
        || after.st_uid != before.st_uid
        || hex::encode(hash.finalize()) != image_name(digest)
    {
        return Err(ApiError::new(
            ErrorCode::ImageDigestMismatch,
            "cached image integrity failed",
        )
        .into());
    }
    check_ext4(&mut file, bytes)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(VerifiedImage {
        file,
        digest: digest.clone(),
        bytes,
        device: device_id(after.st_dev),
        inode: after.st_ino,
    })
}

/// This checks the declared raw format without invoking a host filesystem
/// parser. The guest kernel remains responsible for mounting hostile content.
fn check_ext4(file: &mut File, bytes: u64) -> Result<()> {
    if bytes < 2048 {
        return Err(Error::Artifact("raw ext4 image is truncated"));
    }
    file.seek(SeekFrom::Start(1080))?;
    let mut magic = [0u8; 2];
    file.read_exact(&mut magic)?;
    if magic != [0x53, 0xef] {
        return Err(Error::Artifact("raw image does not declare ext4"));
    }
    Ok(())
}
