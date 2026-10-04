use super::materialization::{Identity, to_io};
use crate::security::path::{SecureDir, device_id};
use rustix::fs::{self as unix_fs, AtFlags, FileType, Mode, OFlags};
use std::{
    ffi::OsString,
    io,
    os::{fd::AsFd, unix::ffi::OsStringExt},
};

pub(super) fn remove_directory_tree(
    parent: &SecureDir,
    name: &str,
    expected: Identity,
) -> io::Result<()> {
    let stat = match parent.stat(name) {
        Ok(value) => value,
        Err(crate::error::Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
        Err(error) => return Err(to_io(error)),
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || Identity::from_stat(&stat) != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OCI cleanup identity mismatch",
        ));
    }
    let directory = open_directory(parent.as_fd(), name)?;
    if Identity::from_stat(&unix_fs::fstat(&directory)?) != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OCI cleanup descriptor identity mismatch",
        ));
    }
    clear_directory(&directory)?;
    unix_fs::unlinkat(parent.as_fd(), name, AtFlags::REMOVEDIR)?;
    unix_fs::fsync(parent.as_fd())?;
    Ok(())
}

fn clear_directory(directory: &impl AsFd) -> io::Result<()> {
    let mut entries = unix_fs::Dir::read_from(directory.as_fd())?;
    let mut names = Vec::<OsString>::new();
    for entry in &mut entries {
        let entry = entry?;
        let name = entry.file_name();
        if !matches!(name.to_bytes(), b"." | b"..") {
            names.push(OsString::from_vec(name.to_bytes().to_vec()));
        }
    }
    drop(entries);
    for name in names {
        let stat = unix_fs::statat(directory.as_fd(), &name, AtFlags::SYMLINK_NOFOLLOW)?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let child = open_directory(directory.as_fd(), &name)?;
                let opened = unix_fs::fstat(&child)?;
                if Identity::from_stat(&opened) != Identity::from_stat(&stat) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "OCI cleanup child changed",
                    ));
                }
                if device_id(opened.st_dev) != device_id(unix_fs::fstat(directory.as_fd())?.st_dev)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "OCI cleanup crossed a filesystem",
                    ));
                }
                clear_directory(&child)?;
                unix_fs::unlinkat(directory.as_fd(), &name, AtFlags::REMOVEDIR)?;
            }
            _ => unix_fs::unlinkat(directory.as_fd(), &name, AtFlags::empty())?,
        }
    }
    unix_fs::fsync(directory.as_fd())?;
    Ok(())
}

fn open_directory(
    parent: impl AsFd,
    name: impl rustix::path::Arg,
) -> io::Result<std::os::fd::OwnedFd> {
    Ok(unix_fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}
