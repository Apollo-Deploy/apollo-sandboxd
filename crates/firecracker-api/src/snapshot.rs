use serde::{Deserialize, Serialize};

/// Only full snapshots are supported. Diff is intentionally absent.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum SnapshotType {
    Full,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotCreate {
    pub snapshot_type: SnapshotType,
    pub snapshot_path: String,
    pub mem_file_path: String,
    pub sync_snapshot_files: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkOverride {
    pub iface_id: String,
    pub host_dev_name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VsockOverride {
    pub uds_path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryBackend {
    pub backend_type: MemoryBackendType,
    pub backend_path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MemoryBackendType {
    File,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotLoad {
    pub snapshot_path: String,
    pub mem_backend: MemoryBackend,
    pub enable_diff_snapshots: bool,
    pub resume_vm: bool,
    pub network_overrides: Vec<NetworkOverride>,
    pub vsock_override: VsockOverride,
}
