use crate::{
    error::{Error, Result},
    security::path::{SecureDir, device_id},
};
use rustix::fs::{self, FileType, XattrFlags};
use serde::{Deserialize, Serialize};
use std::io::Read;

pub(super) const DIRECTORY: &str = ".sandboxd-socket-stage";
pub(super) const STAGED_SOCKET: &str = "s";
const ATTRIBUTE: &str = "user.apollo_sandboxd.socket_owner";

/// Read-only feature probe. Startup must still persist its actual ownership
/// record successfully: this cannot promise free space or storage durability.
pub(super) fn preflight(directory: &SecureDir) -> Result<()> {
    let stat = fs::fstat(directory.as_fd())?;
    if stat.st_mode & 0o022 != 0 || stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(Error::Path);
    }
    if fs::fstatvfs(directory.as_fd())?
        .f_flag
        .contains(fs::StatVfsMountFlags::RDONLY)
    {
        return Err(Error::Config("socket filesystem is read-only"));
    }
    match fs::fgetxattr(directory.as_fd(), ATTRIBUTE, &mut [0u8; 0][..]) {
        Ok(_) => Ok(()),
        Err(error) if attribute_absent(error) => Ok(()),
        Err(_) => Err(Error::Config(
            "socket filesystem requires user xattr support",
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub dev: u64,
    pub ino: u64,
}
impl Identity {
    pub fn of(stat: &fs::Stat) -> Self {
        Self {
            dev: device_id(stat.st_dev),
            ino: stat.st_ino,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    version: u16,
    endpoint: String,
    directory: Identity,
    published: Option<Identity>,
    staged: Option<Identity>,
}

/// A private, inode-pinned namespace is claimed durably before bind. Its small
/// ownership record is replaced atomically as an xattr, never truncated in place.
pub(super) struct Namespace {
    pub directory: SecureDir,
    owner: Ownership,
}
impl Namespace {
    pub fn open(parent: &SecureDir, endpoint: &str) -> Result<Self> {
        let directory = match parent.create_private_directory(DIRECTORY) {
            Ok(dir) => dir,
            Err(Error::Kernel(rustix::io::Errno::EXIST)) => parent.open_child(DIRECTORY)?,
            Err(error) => return Err(error),
        };
        let stat = fs::fstat(directory.as_fd())?;
        if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
            return Err(Error::Path);
        }
        let mut bytes = [0u8; 4096];
        let owner = match fs::fgetxattr(directory.as_fd(), ATTRIBUTE, &mut bytes[..]) {
            Ok(size) => sandboxd_protocol::codec::decode_body::<Ownership>(&bytes[..size])?,
            Err(error) if attribute_absent(error) => {
                // An interrupted mkdir is safe to adopt only while empty. A
                // preexisting populated directory without proof is never cleaned.
                if !directory.is_empty()? {
                    return Err(Error::Path);
                }
                let owner = Ownership {
                    version: 1,
                    endpoint: endpoint.to_owned(),
                    directory: Identity::of(&stat),
                    published: legacy_identity(parent, endpoint)?,
                    staged: None,
                };
                fs::fsetxattr(
                    directory.as_fd(),
                    ATTRIBUTE,
                    &sandboxd_protocol::codec::encode_body(&owner)?,
                    XattrFlags::CREATE,
                )?;
                fs::fsync(directory.as_fd())?;
                fs::fsync(parent.as_fd())?;
                owner
            }
            Err(error) => return Err(error.into()),
        };
        if owner.version != 1
            || owner.endpoint != endpoint
            || owner.directory != Identity::of(&stat)
        {
            return Err(Error::Path);
        }
        Ok(Self { directory, owner })
    }
    pub fn owns_published(&self, identity: Identity) -> bool {
        // A crash after rename but before the final record update leaves the
        // prepared identity in staged. Both locations are covered by that intent.
        self.owner.published == Some(identity) || self.owner.staged == Some(identity)
    }
    pub fn staged_identity(&self) -> Option<Identity> {
        self.owner.staged
    }
    pub fn clear(&mut self) -> Result<()> {
        self.owner.published = None;
        self.owner.staged = None;
        self.persist()
    }
    pub fn prepare(&mut self, identity: Identity) -> Result<()> {
        self.owner.staged = Some(identity);
        self.persist()
    }
    pub fn published(&mut self, identity: Identity) -> Result<()> {
        self.owner.published = Some(identity);
        self.owner.staged = None;
        self.persist()
    }
    fn persist(&self) -> Result<()> {
        let bytes = sandboxd_protocol::codec::encode_body(&self.owner)?;
        if bytes.len() > 4096 {
            return Err(Error::State);
        }
        fs::fsetxattr(
            self.directory.as_fd(),
            ATTRIBUTE,
            &bytes,
            XattrFlags::REPLACE,
        )?;
        fs::fsync(self.directory.as_fd())?;
        Ok(())
    }
}

fn legacy_identity(parent: &SecureDir, endpoint: &str) -> Result<Option<Identity>> {
    let legacy = match parent.open_file("socket-owner.cbor", false) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(4097).read_to_end(&mut bytes)?;
            if bytes.len() > 4096 {
                return Err(Error::Path);
            }
            Some(sandboxd_protocol::codec::decode_body::<Identity>(&bytes)?)
        }
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => None,
        Err(error) => return Err(error),
    };
    match parent.stat(endpoint) {
        Ok(stat)
            if FileType::from_raw_mode(stat.st_mode) == FileType::Socket
                && stat.st_uid == rustix::process::geteuid().as_raw()
                && stat.st_nlink == 1
                && legacy == Some(Identity::of(&stat)) =>
        {
            Ok(legacy)
        }
        Ok(_) => Err(Error::Path),
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => Ok(None),
        Err(error) => Err(error),
    }
}
fn attribute_absent(error: rustix::io::Errno) -> bool {
    #[cfg(target_os = "linux")]
    {
        error == rustix::io::Errno::NODATA
    }
    #[cfg(not(target_os = "linux"))]
    {
        error == rustix::io::Errno::NOATTR
    }
}
