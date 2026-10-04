//! Each named staging resource is journaled before publication; bulk data uses anonymous Linux inodes.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointStage {
    pub name: String,
    pub device: u64,
    pub inode: u64,
    pub data: Option<DriveIdentity>,
    pub manifest: Option<DriveIdentity>,
}
impl CheckpointCatalog {
    pub fn create_from_file(
        &self,
        id: CheckpointId,
        sandbox: String,
        generation: u64,
        source: &File,
        expected: DriveIdentity,
    ) -> Result<CheckpointManifest> {
        self.create_journaled(id, sandbox, generation, source, expected, |_| Ok(()))
    }
    pub(crate) fn create_journaled(
        &self,
        id: CheckpointId,
        sandbox: String,
        generation: u64,
        source: &File,
        expected: DriveIdentity,
        mut record: impl FnMut(&CheckpointStage) -> Result<()>,
    ) -> Result<CheckpointManifest> {
        if sandbox.is_empty() || sandbox.len() > 64 || generation == 0 || expected.size > MAX_BYTES
        {
            return Err(Error::Config("invalid checkpoint identity or size"));
        }
        check_source(source, expected)?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::State)?;
        let temporary = format!(".checkpoint-{}", hex::encode(nonce));
        let directory = self.root.create_private_directory(&temporary)?;
        let stat = rustix::fs::fstat(directory.as_fd())?;
        let mut stage = CheckpointStage {
            name: temporary.clone(),
            device: device_id(stat.st_dev),
            inode: stat.st_ino,
            data: None,
            manifest: None,
        };
        if let Err(error) = record(&stage) {
            let _ = self.root.remove_if_identity(
                &stage.name,
                stage.device,
                stage.inode,
                FileType::Directory,
            );
            return Err(error);
        }
        let result = (|| {
            let mut target = staging_file(&directory, DATA)?;
            let mut hash = Sha256::new();
            let mut offset = 0u64;
            let mut buffer = vec![0u8; 1 << 20];
            while offset < expected.size {
                let length = buffer.len().min((expected.size - offset) as usize);
                let count = source.read_at(&mut buffer[..length], offset)?;
                if count == 0 {
                    return Err(Error::Path);
                }
                if buffer[..count].iter().all(|b| *b == 0) {
                    target.seek(SeekFrom::Current(count as i64))?;
                } else {
                    target.write_all(&buffer[..count])?;
                }
                hash.update(&buffer[..count]);
                offset = offset.checked_add(count as u64).ok_or(Error::State)?;
            }
            check_source(source, expected)?;
            target.set_len(offset)?;
            target.sync_all()?;
            let artifact = staging_identity(&target)?;
            stage.data = Some(artifact);
            record(&stage)?;
            publish(&directory, DATA, &target)?;
            let manifest = CheckpointManifest {
                version: 1,
                id: id.clone(),
                sandbox,
                sandbox_generation: generation,
                source: expected,
                artifact,
                bytes: offset,
                sha256: hex::encode(hash.finalize()),
            };
            let mut file = staging_file(&directory, MANIFEST)?;
            file.write_all(&codec::encode_body(&manifest)?)?;
            file.sync_all()?;
            stage.manifest = Some(staging_identity(&file)?);
            record(&stage)?;
            publish(&directory, MANIFEST, &file)?;
            rustix::fs::fsync(directory.as_fd())?;
            rustix::fs::renameat_with(
                self.root.as_fd(),
                &temporary,
                self.root.as_fd(),
                id.as_str(),
                RenameFlags::NOREPLACE,
            )?;
            rustix::fs::fsync(self.root.as_fd())?;
            Ok(manifest)
        })();
        if result.is_err() {
            let _ = self.cleanup_stage(&stage);
        }
        result
    }
    pub(crate) fn cleanup_stage(&self, stage: &CheckpointStage) -> Result<()> {
        if !stage.name.starts_with(".checkpoint-") || stage.name.len() != 44 {
            return Err(Error::State);
        }
        let directory = match self.root.open_child(&stage.name) {
            Ok(directory) => directory,
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
            Err(error) => return Err(error),
        };
        private_directory(&directory)?;
        let stat = rustix::fs::fstat(directory.as_fd())?;
        if device_id(stat.st_dev) != stage.device || stat.st_ino != stage.inode {
            return Err(Error::Path);
        }
        for (name, expected) in [(MANIFEST, stage.manifest), (DATA, stage.data)] {
            if let Some(expected) = expected {
                match directory.remove_if_identity(
                    name,
                    expected.device,
                    expected.inode,
                    FileType::RegularFile,
                ) {
                    Ok(()) | Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
                    Err(error) => return Err(error),
                }
            }
        }
        self.root
            .remove_if_identity(&stage.name, stage.device, stage.inode, FileType::Directory)
    }
}
fn staging_file(directory: &SecureDir, name: &str) -> Result<File> {
    #[cfg(target_os = "linux")]
    {
        let _ = name;
        Ok(File::from(rustix::fs::openat(
            directory.as_fd(),
            ".",
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        directory.create_file(name)
    }
}
fn staging_identity(file: &File) -> Result<DriveIdentity> {
    let stat = rustix::fs::fstat(file)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_size < 0
        || stat.st_nlink > 1
    {
        return Err(Error::Path);
    }
    Ok(DriveIdentity {
        device: device_id(stat.st_dev),
        inode: stat.st_ino,
        size: stat.st_size as u64,
        uid: stat.st_uid,
        gid: stat.st_gid,
    })
}
fn publish(directory: &SecureDir, name: &str, file: &File) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let source = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
        rustix::fs::linkat(
            rustix::fs::CWD,
            &source,
            directory.as_fd(),
            name,
            rustix::fs::AtFlags::SYMLINK_FOLLOW,
        )?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (directory, name, file);
    }
    Ok(())
}
