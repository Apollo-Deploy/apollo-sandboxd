//! Validation of an OCI extracted root.  The importer never walks through a
//! symlink and never accepts special files; this check is repeated before a
//! prepared image is handed to the runtime authority.
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::{fs, io, path::Path};

/// Flush the verified staged tree before its directory entry is published.
pub(super) fn sync_extracted_root(root: &Path) -> io::Result<()> {
    sync_directory(root, 0)
}

fn sync_directory(path: &Path, depth: u16) -> io::Result<()> {
    if depth > 128 {
        return Err(unsafe_root());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            sync_directory(&child, depth + 1)?;
        } else if metadata.is_file() {
            fs::File::open(&child)?.sync_all()?;
        } else {
            return Err(unsafe_root());
        }
    }
    fs::File::open(path)?.sync_all()
}

pub fn verify_extracted_root(root: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(unsafe_root());
    }
    let mut count = 0;
    visit(root, 0, &mut count)
}

fn visit(path: &Path, depth: u16, count: &mut u64) -> io::Result<()> {
    if depth > 128 {
        return Err(unsafe_root());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        *count = count.checked_add(1).ok_or_else(unsafe_root)?;
        if *count > 1_000_000 {
            return Err(unsafe_root());
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            // A link target is guest data. Never traverse it on the host.
            // Guest-absolute and relative parent links are valid OCI entries.
            let target = fs::read_link(entry.path())?;
            if target.as_os_str().len() > 4096 {
                return Err(unsafe_root());
            }
            continue;
        }
        if metadata.file_type().is_block_device()
            || metadata.file_type().is_char_device()
            || metadata.file_type().is_fifo()
            || metadata.file_type().is_socket()
        {
            return Err(unsafe_root());
        }
        if metadata.is_dir() {
            visit(&entry.path(), depth + 1, count)?;
        } else if !metadata.is_file() {
            return Err(unsafe_root());
        }
    }
    Ok(())
}

fn unsafe_root() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "OCI root contains unsafe entry")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_targets_are_preserved_without_following_host_paths() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("root");
        fs::create_dir(&root).expect("root");
        fs::write(root.join("bin"), b"guest").expect("file");
        std::os::unix::fs::symlink("bin", root.join("safe")).expect("safe link");
        verify_extracted_root(&root).expect("relative link");
        fs::remove_file(root.join("safe")).expect("remove");
        std::os::unix::fs::symlink("../../etc", root.join("escape")).expect("escape link");
        verify_extracted_root(&root).expect("link is never followed");
        assert_eq!(
            fs::read_link(root.join("escape")).expect("target"),
            Path::new("../../etc")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_fifo_without_opening_or_executing_it() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("root");
        fs::create_dir(&root).expect("root");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &root.join("device"),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .expect("fifo");
        assert!(verify_extracted_root(&root).is_err());
    }
}
