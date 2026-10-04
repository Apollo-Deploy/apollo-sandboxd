use super::{MANIFEST, OutputSnapshotRecord, ownership};
use crate::error::{Error, Result};
use rustix::fs::FileType;

fn absent_ok(result: Result<()>) -> Result<()> {
    match result {
        Ok(()) | Err(Error::Kernel(rustix::io::Errno::NOENT)) => Ok(()),
        Err(error) => Err(error),
    }
}

// Cleanup relies exclusively on the durable inode ledger, never mutable bytes.
// Missing owned objects are expected after a crash during a previous cleanup.
pub(crate) fn delete(record: &OutputSnapshotRecord) -> Result<()> {
    let Some((parent, root)) = ownership::open_root(record)? else {
        return Ok(());
    };
    ownership::validate_tree(record, &root, false)?;
    for directory in record.directories.iter().rev() {
        let child = match ownership::open_child(&root, directory) {
            Ok(child) => child,
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => continue,
            Err(error) => return Err(error),
        };
        for file in record.files.iter().rev() {
            let (name, leaf) = ownership::file_parts(&file.relative)?;
            if name == directory.relative {
                absent_ok(child.remove_if_identity(
                    leaf,
                    file.device,
                    file.inode,
                    FileType::RegularFile,
                ))?;
            }
        }
        absent_ok(root.remove_if_identity(
            &directory.relative,
            directory.device,
            directory.inode,
            FileType::Directory,
        ))?;
    }
    if record.manifest_inode != 0 {
        absent_ok(root.remove_if_identity(
            MANIFEST,
            record.manifest_device,
            record.manifest_inode,
            FileType::RegularFile,
        ))?;
    }
    absent_ok(parent.remove_if_identity(
        &record.id,
        record.root_device,
        record.root_inode,
        FileType::Directory,
    ))
}
