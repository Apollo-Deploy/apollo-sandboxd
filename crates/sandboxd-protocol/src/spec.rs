use crate::{ApiError, ErrorCode, ImageDigest, VolumeId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Persistence {
    Ephemeral,
    FilesystemPersistent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBucket {
    pub size: u64,
    pub one_time_burst: Option<u64>,
    pub refill_time_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiter {
    pub bandwidth: Option<TokenBucket>,
    pub operations: Option<TokenBucket>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub vcpus: u8,
    pub memory_mib: u32,
    pub state_disk_mib: u32,
    pub host_memory_max_bytes: u64,
    pub cpu_quota_us: u32,
    pub cpu_period_us: u32,
    pub cpu_profile: Option<String>,
    pub cpuset: Option<String>,
    pub state_rate_limiter: Option<RateLimiter>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAttachment {
    pub attachment_id: String,
    /// Operator catalog key, never an arbitrary caller-supplied host path.
    pub namespace_handle: String,
    pub tap_name: String,
    pub guest_mac: String,
    pub addresses: Vec<String>,
    pub gateways: Vec<String>,
    pub dns_servers: Vec<String>,
    pub mtu: u16,
    pub rx: Option<RateLimiter>,
    pub tx: Option<RateLimiter>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "attachment", rename_all = "snake_case")]
pub enum NetworkMode {
    None,
    ExternalAttachment(Box<NetworkAttachment>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    pub id: VolumeId,
    pub catalog_key: String,
    #[serde(default)]
    pub backing: Option<crate::VolumeBacking>,
    pub read_only: bool,
    pub guest_mount_point: String,
    pub filesystem: String,
    pub rate_limiter: Option<RateLimiter>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifetimes {
    pub sandbox_ttl_seconds: u32,
    pub session_max_seconds: u32,
    pub idle_seconds: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSpec {
    pub architecture: Architecture,
    pub image: ImageDigest,
    pub kernel_profile: String,
    pub runtime_profile: String,
    pub persistence: Persistence,
    pub resources: Resources,
    pub network: NetworkMode,
    pub volumes: Vec<Volume>,
    pub environment: BTreeMap<String, String>,
    pub lifetimes: Lifetimes,
}
impl SandboxSpec {
    pub fn validate(&self) -> Result<(), ApiError> {
        let invalid = || {
            ApiError::new(
                ErrorCode::ResourceLimitInvalid,
                "invalid or unbounded sandbox specification",
            )
        };
        let r = &self.resources;
        if r.vcpus == 0
            || r.vcpus > 32
            || r.memory_mib < 64
            || r.memory_mib > 1_048_576
            || r.state_disk_mib == 0
            || r.state_disk_mib > 1_048_576
            || r.host_memory_max_bytes < u64::from(r.memory_mib) * 1_048_576
            || r.host_memory_max_bytes > 2_199_023_255_552
            || r.cpu_period_us < 1_000
            || r.cpu_period_us > 1_000_000
            || r.cpu_quota_us < 1_000
            || u64::from(r.cpu_quota_us) > u64::from(r.vcpus) * u64::from(r.cpu_period_us)
            || !crate::validation::cpuset(&r.cpuset)
            || !crate::validation::rate(&r.state_rate_limiter)
            || self.volumes.len() > 16
            || self.environment.len() > 256
            || self.lifetimes.sandbox_ttl_seconds == 0
            || self.lifetimes.sandbox_ttl_seconds > 31_536_000
            || self.lifetimes.session_max_seconds == 0
            || self.lifetimes.session_max_seconds > 31_536_000
            || self.lifetimes.idle_seconds == 0
            || self.lifetimes.idle_seconds > 31_536_000
        {
            return Err(invalid());
        }
        for profile in [&self.runtime_profile, &self.kernel_profile] {
            if crate::SandboxId::new(profile.as_str()).is_err() {
                return Err(invalid());
            }
        }
        if r.cpu_profile
            .as_ref()
            .is_some_and(|profile| crate::SandboxId::new(profile).is_err())
        {
            return Err(invalid());
        }
        crate::validation::volumes(&self.volumes)?;
        let mut env_size = 0usize;
        for (key, value) in &self.environment {
            if key.is_empty()
                || key.len() > 256
                || key.contains(['=', '\0'])
                || value.contains('\0')
            {
                return Err(invalid());
            }
            env_size = env_size
                .checked_add(key.len() + value.len())
                .ok_or_else(invalid)?;
        }
        if env_size > 65_536 {
            return Err(invalid());
        }
        if let NetworkMode::ExternalAttachment(n) = &self.network {
            crate::validation::network(n)?;
        }
        Ok(())
    }
}
