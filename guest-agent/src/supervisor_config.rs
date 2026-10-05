//! Trusted command-line identity and inherited descriptor admission.
use super::Error;
use guest_protocol::{BootNonce, SessionIdentity};
use sandboxd_protocol::{SandboxGeneration, SandboxId, SessionGeneration, SessionId};
use std::{
    collections::HashMap, ffi::OsString, fs::File, os::unix::fs::MetadataExt, path::PathBuf,
};

pub struct Config {
    pub identity: SessionIdentity,
    pub state: Option<File>,
    pub network_tool: Option<File>,
}

impl Config {
    pub fn from_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Self, Error> {
        let mut values = HashMap::new();
        let mut iterator = args.into_iter();
        let _program = iterator.next();
        while let Some(arg) = iterator.next() {
            let key = arg
                .to_str()
                .ok_or_else(|| Error::Config("argument is not UTF-8".into()))?;
            let key = key
                .strip_prefix("--")
                .ok_or_else(|| Error::Config("arguments must use --key value".into()))?;
            let value = iterator
                .next()
                .ok_or_else(|| Error::Config(format!("missing value for --{key}")))?;
            let value = value
                .into_string()
                .map_err(|_| Error::Config(format!("value for --{key} is not UTF-8")))?;
            if values.insert(key.to_owned(), value).is_some() {
                return Err(Error::Config(format!("duplicate --{key}")));
            }
        }
        let required = |name: &str| {
            values
                .get(name)
                .cloned()
                .ok_or_else(|| Error::Config(format!("missing --{name}")))
        };
        let nonce = required("boot-nonce")?;
        let nonce =
            hex::decode(nonce).map_err(|_| Error::Config("boot nonce must be hex".into()))?;
        let boot_nonce: [u8; 32] = nonce
            .try_into()
            .map_err(|_| Error::Config("boot nonce must contain 32 bytes".into()))?;
        let identity = SessionIdentity {
            sandbox: SandboxId::new(required("sandbox")?)
                .map_err(|_| Error::Config("invalid sandbox ID".into()))?,
            sandbox_generation: parse_generation(&required("sandbox-generation")?)?,
            session: SessionId::new(required("session")?)
                .map_err(|_| Error::Config("invalid session ID".into()))?,
            session_generation: parse_session_generation(&required("session-generation")?)?,
            boot_nonce: BootNonce(boot_nonce),
            vsock_cid: parse_u32(&required("vsock-cid")?)?,
            protocol_version: guest_protocol::GUEST_PROTOCOL_VERSION,
        };
        identity
            .authenticate(&identity)
            .map_err(|_| Error::Config("invalid guest identity".into()))?;
        let state = values
            .get("state-fd")
            .map(|value| {
                let fd: i32 = value
                    .parse()
                    .map_err(|_| Error::Config("state fd is invalid".into()))?;
                if fd < 0 {
                    return Err(Error::Config("state fd is negative".into()));
                }
                let path = PathBuf::from(format!("/proc/self/fd/{fd}"));
                let file = File::open(path)?;
                let meta = file.metadata()?;
                if !meta.is_dir() || meta.uid() != 0 {
                    return Err(Error::Config(
                        "state fd is not a root-owned directory".into(),
                    ));
                }
                #[cfg(target_os = "linux")]
                {
                    let fs_type = nix::sys::statfs::fstatfs(&file)
                        .map_err(|e| Error::Config(format!("inspect state filesystem: {e}")))?;
                    if fs_type.filesystem_type() != nix::sys::statfs::EXT4_SUPER_MAGIC {
                        return Err(Error::Config("state fd is not ext4".into()));
                    }
                }
                Ok(file)
            })
            .transpose()?;
        let network_tool = values
            .get("network-tool-fd")
            .map(|value| {
                let fd: i32 = value
                    .parse()
                    .map_err(|_| Error::Config("network tool fd is invalid".into()))?;
                if fd < 0 {
                    return Err(Error::Config("network tool fd is negative".into()));
                }
                let file = File::open(format!("/proc/self/fd/{fd}"))?;
                let meta = file.metadata()?;
                if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                    return Err(Error::Config(
                        "network tool fd is not a trusted regular file".into(),
                    ));
                }
                Ok(file)
            })
            .transpose()?;
        Ok(Self {
            identity,
            state,
            network_tool,
        })
    }
}

fn parse_u32(value: &str) -> Result<u32, Error> {
    value
        .parse()
        .map_err(|_| Error::Config("numeric identity value is invalid".into()))
}
fn parse_generation(value: &str) -> Result<sandboxd_protocol::SandboxGeneration, Error> {
    SandboxGeneration::new(
        value
            .parse()
            .map_err(|_| Error::Config("generation is invalid".into()))?,
    )
    .map_err(|e| Error::Config(e.into()))
}

fn parse_session_generation(value: &str) -> Result<SessionGeneration, Error> {
    SessionGeneration::new(
        value
            .parse()
            .map_err(|_| Error::Config("generation is invalid".into()))?,
    )
    .map_err(|e| Error::Config(e.into()))
}
