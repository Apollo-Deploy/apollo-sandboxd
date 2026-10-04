use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachineConfiguration {
    pub vcpu_count: u8,
    pub mem_size_mib: u32,
    pub smt: bool,
    pub track_dirty_pages: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_template: Option<CpuTemplate>,
}

/// Serial is a separate device endpoint in the pinned Firecracker v1.17 API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerialDevice {
    pub serial_out_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<TokenBucket>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum CpuTemplate {
    C3,
    T2,
    T2S,
    T2CL,
    T2A,
    V1N1,
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<String>,
    pub boot_args: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenBucket {
    pub size: u64,
    pub one_time_burst: Option<u64>,
    pub refill_time: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimiter {
    pub bandwidth: Option<TokenBucket>,
    pub ops: Option<TokenBucket>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiter>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub iface_id: String,
    pub host_dev_name: String,
    pub guest_mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_rate_limiter: Option<RateLimiter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_rate_limiter: Option<RateLimiter>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vsock {
    pub guest_cid: u32,
    pub uds_path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Balloon {
    pub amount_mib: u32,
    pub deflate_on_oom: bool,
    pub stats_polling_interval_s: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entropy {
    pub rate_limiter: Option<RateLimiter>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Logger {
    pub log_path: String,
    pub level: String,
    pub show_level: bool,
    pub show_log_origin: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metrics {
    pub metrics_path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MmdsConfig {
    pub version: MmdsVersion,
    pub network_interfaces: Vec<String>,
    pub ipv4_address: Option<String>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum MmdsVersion {
    V2,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Version {
    pub firecracker_version: String,
}

/// Read-only observations from GET / in the pinned v1.17 API contract.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceInfo {
    pub app_name: String,
    pub id: String,
    pub state: InstanceState,
    pub vmm_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum InstanceState {
    #[serde(rename = "Not started")]
    NotStarted,
    Running,
    Paused,
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
