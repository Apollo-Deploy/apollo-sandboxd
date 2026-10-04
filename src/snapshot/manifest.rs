use crate::error::{Error, Result};
use sandboxd_protocol::{
    Architecture, CheckpointId, ImageDigest, SandboxGeneration, SandboxId, SessionGeneration,
    SessionId, SnapshotId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSecretPolicy {
    #[default]
    Reject,
    AllowEncrypted,
}
impl From<sandboxd_protocol::SnapshotSecretPolicy> for SnapshotSecretPolicy {
    fn from(value: sandboxd_protocol::SnapshotSecretPolicy) -> Self {
        match value {
            sandboxd_protocol::SnapshotSecretPolicy::Reject => Self::Reject,
            sandboxd_protocol::SnapshotSecretPolicy::AllowEncrypted => Self::AllowEncrypted,
        }
    }
}
impl SnapshotSecretPolicy {
    pub fn authorize(self, session_has_received_secrets: bool) -> Result<()> {
        if session_has_received_secrets && self == Self::Reject {
            return Err(sandboxd_protocol::ApiError::new(
                sandboxd_protocol::ErrorCode::SecretSnapshotForbidden,
                "session has received secrets; explicit encrypted snapshot policy required",
            )
            .into());
        }
        Ok(())
    }
}

/// This metadata must itself be authenticated before any artifact is loaded.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub version: u16,
    pub id: SnapshotId,
    pub sandbox: SandboxId,
    pub sandbox_generation: SandboxGeneration,
    pub session: SessionId,
    pub session_generation: SessionGeneration,
    pub runtime_profile: String,
    pub runtime_version: String,
    pub firecracker_sha256: String,
    pub jailer_sha256: String,
    pub kernel_sha256: String,
    pub initramfs_sha256: String,
    pub base_image: ImageDigest,
    pub writable_drive_sha256: String,
    pub snapshot_format: String,
    pub memory_bytes: u64,
    pub state_bytes: u64,
    pub memory_sha256: String,
    pub state_sha256: String,
    pub secret_policy: SnapshotSecretPolicy,
    pub vsock_cid: u32,
    pub boot_nonce: guest_protocol::BootNonce,
    pub architecture: Architecture,
    pub host_boot_id: String,
    pub host_kernel_release: String,
    pub cpu_fingerprint: String,
    pub output_sha256: String,
    pub checkpoint: CheckpointId,
    pub has_received_secrets: bool,
    pub memory_mib: u32,
    pub vcpu_count: u16,
}
impl SnapshotManifest {
    pub fn validate(&self) -> Result<()> {
        let hashes = [
            &self.firecracker_sha256,
            &self.jailer_sha256,
            &self.kernel_sha256,
            &self.initramfs_sha256,
            &self.writable_drive_sha256,
            &self.memory_sha256,
            &self.state_sha256,
            &self.cpu_fingerprint,
            &self.output_sha256,
        ];
        if self.version != 1
            || self.memory_bytes == 0
            || self.memory_bytes > 1 << 40
            || self.state_bytes == 0
            || self.state_bytes > 64 << 20
            || self.memory_mib < 64
            || self.memory_bytes > u64::from(self.memory_mib) * (1 << 20)
            || self.vcpu_count == 0
            || self.vcpu_count > 32
            || self.vsock_cid < 3
            || self.vsock_cid == u32::MAX
            || self.boot_nonce.0 == [0; 32]
            || self.host_boot_id.len() != 36
            || self.host_kernel_release.is_empty()
            || self.host_kernel_release.len() > 128
            || hashes.iter().any(|h| {
                h.len() != 64
                    || !h
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || SandboxId::new(&self.runtime_profile).is_err()
            || self.runtime_version.is_empty()
            || self.runtime_version.len() > 64
            || self.snapshot_format.is_empty()
            || self.snapshot_format.len() > 64
        {
            return Err(Error::State);
        }
        self.secret_policy.authorize(self.has_received_secrets)?;
        Ok(())
    }
}
