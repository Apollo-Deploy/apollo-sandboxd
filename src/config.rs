pub use crate::config_execution::{ArtifactdSettings, BaseImage, Execution};
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use sandboxd_protocol::Architecture;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub snapshots: Option<crate::snapshot::SnapshotSettings>,
    #[serde(default)]
    pub checkpoints: CheckpointLimits,
    pub daemon: Daemon,
    pub security: Security,
    pub state: State,
    pub runtimes: Vec<RuntimeProfile>,
    pub kernels: Vec<KernelProfile>,
    pub identities: IdentityPools,
    pub quotas: Quotas,
    pub leases: LeaseConfig,
    #[serde(default)]
    pub execution: Option<Execution>,
    #[serde(default)]
    pub volume_catalog: VolumeCatalog,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeCatalog {
    pub max_total_bytes: u64,
    #[serde(default)]
    pub entries: Vec<VolumeCatalogEntry>,
}

impl Default for VolumeCatalog {
    fn default() -> Self {
        Self {
            max_total_bytes: 0,
            entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeCatalogEntry {
    pub key: String,
    pub path: PathBuf,
    pub max_bytes: u64,
    /// Writable entries require an exclusive nonblocking lock for each boot.
    pub writable: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Daemon {
    pub socket: PathBuf,
    pub socket_group: u32,
    pub max_connections: u16,
    pub request_timeout_seconds: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Security {
    pub allowed_uids: Vec<u32>,
    pub allowed_gids: Vec<u32>,
    pub allowed_pids: Vec<u32>,
}
impl Security {
    /// Untrusted API clients must not share the service's filesystem authority.
    /// Host root remains trusted and can administer a root-owned daemon.
    pub fn validate_daemon_identity(&self, daemon_uid: u32) -> Result<()> {
        if daemon_uid != 0
            && (self.allowed_uids.is_empty() || self.allowed_uids.contains(&daemon_uid))
        {
            return Err(Error::Config(
                "non-root daemon requires distinct explicit client UIDs",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub directory: PathBuf,
    pub event_retention: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProfile {
    pub name: String,
    pub version: String,
    pub architecture: Architecture,
    pub firecracker: PathBuf,
    pub firecracker_sha256: String,
    pub jailer: PathBuf,
    pub jailer_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelProfile {
    pub name: String,
    pub architecture: Architecture,
    pub kernel: PathBuf,
    pub kernel_sha256: String,
    pub initramfs: PathBuf,
    pub initramfs_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPools {
    pub uid_first: u32,
    pub uid_last: u32,
    pub gid_first: u32,
    pub gid_last: u32,
    pub cid_first: u32,
    pub cid_last: u32,
}
impl IdentityPools {
    pub fn validate(&self) -> Result<()> {
        let p = self;
        if p.uid_first < 100_000
            || p.gid_first < 100_000
            || p.uid_last < p.uid_first
            || p.gid_last < p.gid_first
            || p.cid_first < 3
            || p.cid_last < p.cid_first
            || p.cid_last == u32::MAX
            || p.uid_last == u32::MAX
            || p.gid_last == u32::MAX
        {
            return Err(Error::Config("invalid identity pool"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quotas {
    pub max_active_sandboxes: u32,
    pub max_booting_sandboxes: u32,
    pub max_sandbox_identities: u32,
    pub max_operation_receipts: u32,
    pub max_vcpus: u8,
    pub max_memory_mib: u32,
    pub max_state_disk_mib: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseConfig {
    pub max_seconds: u32,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let config = Self::read(path)?;
        config.validate()?;
        Ok(config)
    }

    #[doc(hidden)]
    pub fn load_for_cleanup(path: &Path) -> Result<Self> {
        let config = Self::read(path)?;
        config.validate_for_cleanup()?;
        Ok(config)
    }

    fn read(path: &Path) -> Result<Self> {
        let parent = path.parent().ok_or(Error::Path)?;
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(Error::Path)?;
        let directory = SecureDir::open(parent)?;
        let file = directory.open_file(name, false)?;
        let mut bytes = Vec::new();
        file.take(131_073).read_to_end(&mut bytes)?;
        if bytes.len() > 131_072 {
            return Err(Error::Config("configuration size limit"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Error::Config("configuration encoding"))?;
        toml::from_str(text).map_err(|_| Error::Config("invalid configuration schema"))
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_inner(false)
    }

    pub(crate) fn validate_for_cleanup(&self) -> Result<()> {
        self.validate_inner(true)
    }

    fn validate_inner(&self, cleanup: bool) -> Result<()> {
        if let Some(snapshots) = &self.snapshots {
            snapshots.validate()?;
        }
        self.checkpoints.validate()?;
        if let Some(execution) = &self.execution {
            if cleanup {
                execution.validate_for_cleanup()?;
            } else {
                execution.validate()?;
            }
        }
        if !self.daemon.socket.is_absolute()
            || !self.state.directory.is_absolute()
            || self.daemon.socket.parent().is_none()
            || self.daemon.socket.as_os_str().len() > 100
            || self.daemon.max_connections == 0
            || self.daemon.max_connections > 64
            || self.daemon.request_timeout_seconds == 0
            || self.daemon.request_timeout_seconds > 30
            || self.state.event_retention == 0
            || self.state.event_retention > 1_000_000
            || self.quotas.max_active_sandboxes == 0
            || self.quotas.max_active_sandboxes > 100_000
            || self.quotas.max_booting_sandboxes == 0
            || self.quotas.max_booting_sandboxes > self.quotas.max_active_sandboxes
            || self.quotas.max_sandbox_identities == 0
            || self.quotas.max_sandbox_identities > 1_000_000
            || self.quotas.max_operation_receipts == 0
            || self.quotas.max_operation_receipts > 10_000_000
            || self.quotas.max_vcpus == 0
            || self.quotas.max_vcpus > 32
            || self.quotas.max_memory_mib < 64
            || self.quotas.max_memory_mib > 1_048_576
            || self.quotas.max_state_disk_mib == 0
            || self.quotas.max_state_disk_mib > 1_048_576
            || self.leases.max_seconds == 0
            || self.leases.max_seconds > 86_400
        {
            return Err(Error::Config("invalid or unbounded daemon limits"));
        }
        if self.security.allowed_uids.len() > 256
            || self.security.allowed_gids.len() > 256
            || self.security.allowed_pids.len() > 256
            || (self.security.allowed_uids.is_empty() && self.security.allowed_gids.is_empty())
        {
            return Err(Error::Config("caller allowlist missing or oversized"));
        }
        self.identities.validate()?;
        self.volume_catalog.validate()?;
        if self.runtimes.is_empty()
            || self.runtimes.len() > 32
            || self.kernels.is_empty()
            || self.kernels.len() > 32
        {
            return Err(Error::Config("trusted runtime/kernel catalogs required"));
        }
        let mut names = BTreeSet::new();
        for profile in &self.runtimes {
            if sandboxd_protocol::SandboxId::new(&profile.name).is_err()
                || !names.insert(&profile.name)
                || profile.version != "1.17.0"
            {
                return Err(Error::Config("invalid or unsupported runtime profile"));
            }
            validate_artifact(&profile.firecracker, &profile.firecracker_sha256)?;
            validate_artifact(&profile.jailer, &profile.jailer_sha256)?;
        }
        names.clear();
        for profile in &self.kernels {
            if sandboxd_protocol::SandboxId::new(&profile.name).is_err()
                || !names.insert(&profile.name)
            {
                return Err(Error::Config("duplicate or invalid kernel profile"));
            }
            validate_artifact(&profile.kernel, &profile.kernel_sha256)?;
            validate_artifact(&profile.initramfs, &profile.initramfs_sha256)?;
        }
        Ok(())
    }
}

impl VolumeCatalog {
    fn validate(&self) -> Result<()> {
        if self.entries.len() > 256
            || (!self.entries.is_empty() && self.max_total_bytes == 0)
            || self.max_total_bytes > (1_u64 << 50)
        {
            return Err(Error::Config("invalid volume catalog bounds"));
        }
        let mut keys = BTreeSet::new();
        for entry in &self.entries {
            if sandboxd_protocol::SandboxId::new(&entry.key).is_err()
                || !keys.insert(&entry.key)
                || !entry.path.is_absolute()
                || entry.path.parent().is_none()
                || entry.max_bytes == 0
                || entry.max_bytes > self.max_total_bytes
                || entry.path.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
                || entry
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_none()
            {
                return Err(Error::Config("invalid volume catalog entry"));
            }
        }
        Ok(())
    }
}
pub(crate) fn validate_artifact(path: &Path, digest: &str) -> Result<()> {
    if !path.is_absolute()
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Config(
            "artifact requires absolute path and lower-case sha256",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointLimits {
    pub max_count: u32,
    pub max_bytes_per_checkpoint: u64,
    pub max_total_bytes: u64,
}
impl Default for CheckpointLimits {
    fn default() -> Self {
        Self {
            max_count: 64,
            max_bytes_per_checkpoint: 64 << 30,
            max_total_bytes: 256 << 30,
        }
    }
}
impl CheckpointLimits {
    fn validate(&self) -> Result<()> {
        if self.max_count == 0
            || self.max_count > 4096
            || self.max_bytes_per_checkpoint == 0
            || self.max_bytes_per_checkpoint > 64 << 30
            || self.max_total_bytes < self.max_bytes_per_checkpoint
            || self.max_total_bytes > 1 << 50
        {
            return Err(Error::Config("invalid checkpoint limits"));
        }
        Ok(())
    }
}
