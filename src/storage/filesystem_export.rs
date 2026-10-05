//! Bounded, durable OCI layer staging and content-addressed publication.
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub(crate) const MAX_PERSISTED_EXPORT_BYTES: u64 = 8 << 30;

pub(crate) struct FilesystemExportStager {
    root: SecureDir,
    root_path: PathBuf,
    directory: SecureDir,
    temp_name: String,
    file: File,
    max_bytes: u64,
    byte_len: u64,
    digest: Sha256,
}

impl FilesystemExportStager {
    pub(crate) fn new(state: &Path, uid: u32, max_bytes: u64) -> Result<Self> {
        if max_bytes == 0 || max_bytes > sandboxd_protocol::MAX_FILESYSTEM_EXPORT_BYTES {
            return Err(Error::Path);
        }
        let root = export_root(state)?;
        let root_path = state.join("filesystem-exports");
        let lock = root.open_or_create_private("publish.lock")?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
        recover_stages_root(&root_path)?;
        let reserved = stored_usage(&root_path)?;
        if reserved.checked_add(max_bytes).ok_or(Error::Path)? > MAX_PERSISTED_EXPORT_BYTES {
            return Err(Error::Path);
        }
        let directory = root.ensure_private_directory(&uid.to_string())?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::State)?;
        let temp_name = format!(".stage-{}-{}", std::process::id(), hex::encode(nonce));
        let file = directory.create_file(&temp_name)?;
        file.set_len(max_bytes)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)?;
        Ok(Self {
            root,
            root_path,
            directory,
            temp_name,
            file,
            max_bytes,
            byte_len: 0,
            digest: Sha256::new(),
        })
    }

    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<()> {
        self.byte_len = self
            .byte_len
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Path)?;
        if self.byte_len > self.max_bytes {
            return Err(Error::Path);
        }
        self.file.write_all(bytes)?;
        self.digest.update(bytes);
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        expected_len: u64,
        expected_sha256: &str,
    ) -> Result<(String, u64)> {
        if self.byte_len == 0 || self.byte_len != expected_len {
            return Err(Error::Path);
        }
        let sha256 = hex::encode(std::mem::take(&mut self.digest).finalize());
        if sha256 != expected_sha256 {
            return Err(Error::Path);
        }
        self.file.set_len(expected_len)?;
        self.file
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        self.file.sync_all()?;
        // Flock serializes quota checks and publication across daemon processes.
        let lock = self.root.open_or_create_private("publish.lock")?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
        recover_stages_root(&self.root_path)?;
        let name = blob_name(&sha256);
        if let Ok(existing) = self.directory.open_file(&name, false) {
            verify_blob(existing, &sha256, expected_len, self.max_bytes)?;
            rustix::fs::unlinkat(
                self.directory.as_fd(),
                &self.temp_name,
                rustix::fs::AtFlags::empty(),
            )?;
            rustix::fs::fsync(self.directory.as_fd())?;
            return Ok((sha256, expected_len));
        }
        // The stage was pre-sized to reserve its full requested maximum when
        // admitted. `finish` truncates it before taking this lock, so the
        // current usage already includes its actual final size.
        if stored_usage(&self.root_path)? > MAX_PERSISTED_EXPORT_BYTES {
            return Err(Error::Path);
        }
        rustix::fs::renameat_with(
            self.directory.as_fd(),
            &self.temp_name,
            self.directory.as_fd(),
            &name,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        rustix::fs::fsync(self.directory.as_fd())?;
        let published = self.directory.open_file(&name, false)?;
        verify_blob(published, &sha256, expected_len, self.max_bytes)?;
        Ok((sha256, expected_len))
    }
}

impl Drop for FilesystemExportStager {
    fn drop(&mut self) {
        let _ = rustix::fs::unlinkat(
            self.directory.as_fd(),
            &self.temp_name,
            rustix::fs::AtFlags::empty(),
        );
    }
}

use super::filesystem_export_store::{
    blob_name, export_root, recover_stages_root, stored_usage, verify_blob,
};

#[cfg(test)]
mod tests {
    use super::super::filesystem_export_store::{export_dir, load_filesystem_export as load};
    use super::*;
    use rustix::fs::SealFlags;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn published_layer_reopens_with_verified_sealed_descriptor() {
        let state = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let bytes = b"durable OCI layer";
        let sha = hex::encode(Sha256::digest(bytes));
        let mut stage = FilesystemExportStager::new(state.path(), uid, 1024).unwrap();
        stage.append(bytes).unwrap();
        let (published_sha, published_len) = stage.finish(bytes.len() as u64, &sha).unwrap();
        assert_eq!(published_sha, sha);
        let fd = load(state.path(), uid, &sha, published_len, 1024).unwrap();
        let seals = rustix::fs::fcntl_get_seals(&fd).unwrap();
        assert!(
            seals
                .contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL)
        );

        let directory = export_dir(state.path(), uid).unwrap();
        let blob = directory.open_file(&blob_name(&sha), false).unwrap();
        let metadata = blob.metadata().unwrap();
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o777, 0o400);
    }

    #[test]
    fn stale_stage_is_recovered_but_live_stage_is_reserved() {
        let state = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let root = export_root(state.path()).unwrap();
        let user = root
            .ensure_private_directory(&rustix::process::geteuid().as_raw().to_string())
            .unwrap();
        let mut stale = user.create_file(".stage-dead").unwrap();
        stale.write_all(b"orphan").unwrap();
        drop(stale);
        recover_stages_root(&state.path().join("filesystem-exports")).unwrap();
        assert!(user.open_file(".stage-dead", false).is_err());

        let active =
            FilesystemExportStager::new(state.path(), rustix::process::geteuid().as_raw(), 1024)
                .unwrap();
        assert!(stored_usage(&state.path().join("filesystem-exports")).unwrap() == 1024);
        drop(active);
        assert_eq!(
            stored_usage(&state.path().join("filesystem-exports")).unwrap(),
            0
        );
    }

    #[test]
    fn existing_content_addressed_file_is_rehashed_before_reuse() {
        let state = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let bytes = b"blob";
        let sha = hex::encode(Sha256::digest(bytes));
        let mut stage = FilesystemExportStager::new(state.path(), uid, 1024).unwrap();
        stage.append(bytes).unwrap();
        stage.finish(bytes.len() as u64, &sha).unwrap();
        let path = state
            .path()
            .join("filesystem-exports")
            .join(uid.to_string())
            .join(blob_name(&sha));
        let mut second = FilesystemExportStager::new(state.path(), uid, 1024).unwrap();
        second.append(bytes).unwrap();
        std::fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"tampered").unwrap();
        std::fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(second.finish(bytes.len() as u64, &sha).is_err());
    }
}
