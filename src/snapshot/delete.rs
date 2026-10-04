//! Resumable deletion requires persisted inode identities, including on retry.
use super::{SnapshotArtifacts, SnapshotCatalog, artifact::*};
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use rustix::fs::{FileType, RenameFlags};

impl SnapshotCatalog {
    pub fn delete(&self, record: &SnapshotArtifacts) -> Result<()> {
        record.validate()?;
        let tombstone = format!(".deleted-{}", record.context.snapshot);
        let mut candidate = None;
        for name in [
            record.context.snapshot.as_str(),
            record.stage_name.as_str(),
            tombstone.as_str(),
        ] {
            match self.owned_directory(record, name) {
                Ok(directory) => {
                    if candidate.is_some() {
                        return Err(Error::Path);
                    }
                    candidate = Some((name, directory));
                }
                Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
                Err(error) => return Err(error),
            }
        }
        let Some((name, directory)) = candidate else {
            rustix::fs::fsync(self.root.as_fd())?;
            return Ok(());
        };
        // Validate every remaining object before removing any one of them.
        validate_entries(&directory, record)?;
        if name != tombstone {
            rustix::fs::renameat_with(
                self.root.as_fd(),
                name,
                self.root.as_fd(),
                &tombstone,
                RenameFlags::NOREPLACE,
            )?;
            rustix::fs::fsync(self.root.as_fd())?;
        }
        for (name, item) in [
            ("memory.enc", &record.memory),
            ("state.enc", &record.state),
            ("manifest.enc", &record.manifest),
        ] {
            if let Some(item) = item {
                match directory.open_file(name, false) {
                    Ok(file) => {
                        verify_inode(&file, item)?;
                        if file.metadata()?.len() > item.cipher_bytes {
                            return Err(Error::Path);
                        }
                        directory.remove_if_identity(
                            name,
                            item.device,
                            item.inode,
                            FileType::RegularFile,
                        )?;
                    }
                    Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
                    Err(error) => return Err(error),
                }
            }
        }
        if !directory.is_empty()? {
            return Err(Error::Path);
        }
        self.root.remove_if_identity(
            &tombstone,
            record.directory.device,
            record.directory.inode,
            FileType::Directory,
        )
    }
}
fn validate_entries(directory: &SecureDir, record: &SnapshotArtifacts) -> Result<()> {
    for entry in rustix::fs::Dir::read_from(directory.as_fd())? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        let expected = match name {
            b"." | b".." => continue,
            b"memory.enc" => &record.memory,
            b"state.enc" => &record.state,
            b"manifest.enc" => &record.manifest,
            _ => return Err(Error::Path),
        };
        let expected = expected.as_ref().ok_or(Error::Path)?;
        let name = std::str::from_utf8(name).map_err(|_| Error::Path)?;
        let file = directory.open_file(name, false)?;
        verify_inode(&file, expected)?;
        if file.metadata()?.len() > expected.cipher_bytes {
            return Err(Error::Path);
        }
    }
    Ok(())
}
