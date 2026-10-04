use crate::error::{Error, Result};
use rusqlite::{Connection, Row};
use sandboxd_protocol::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionKey {
    pub sandbox: SandboxId,
    pub sandbox_generation: SandboxGeneration,
    pub session: SessionId,
    pub generation: SessionGeneration,
}

/// Trusted, verified catalog observations. No caller-controlled host path is
/// accepted in durable launch metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPins {
    pub architecture: Architecture,
    pub runtime_profile: String,
    pub runtime_version: String,
    pub firecracker_sha256: String,
    pub jailer_sha256: String,
    pub kernel_profile: String,
    pub kernel_sha256: String,
    pub initramfs_sha256: String,
    pub base_image: ImageDigest,
    #[serde(default)]
    pub volumes: Vec<VolumePin>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumePin {
    pub volume_id: VolumeId,
    pub catalog_key: String,
    pub device: u64,
    pub inode: u64,
    pub size_bytes: u64,
    /// The operator catalog disallows writes when true.
    pub catalog_read_only: bool,
    /// The caller's requested mount policy, pinned with the session.
    pub read_only: bool,
}
impl SessionPins {
    pub(super) fn validate(&self, spec: &SandboxSpec) -> Result<()> {
        if self.architecture != spec.architecture
            || self.runtime_profile != spec.runtime_profile
            || self.kernel_profile != spec.kernel_profile
            || self.base_image != spec.image
            || self.runtime_version.is_empty()
            || self.runtime_version.len() > 32
            || !self
                .runtime_version
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'.')
            || [
                &self.firecracker_sha256,
                &self.jailer_sha256,
                &self.kernel_sha256,
                &self.initramfs_sha256,
            ]
            .iter()
            .any(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(ApiError::new(
                ErrorCode::RuntimeProfileInvalid,
                "verified launch pins do not match sandbox",
            )
            .into());
        }
        if self.volumes.len() != spec.volumes.len()
            || self.volumes.iter().zip(&spec.volumes).any(|(pin, volume)| {
                pin.volume_id != volume.id
                    || pin.catalog_key != volume.catalog_key
                    || pin.read_only != volume.read_only
                    || (pin.catalog_read_only && !pin.read_only)
                    || pin.device == 0
                    || pin.inode == 0
                    || pin.size_bytes == 0
            })
        {
            return Err(ApiError::new(
                ErrorCode::VolumeInvalid,
                "trusted volume pins do not match sandbox",
            )
            .into());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchIntent {
    pub key: SessionKey,
    pub state: SessionState,
    pub uid: u32,
    pub gid: u32,
    pub cid: u32,
    pub host_boot_id: String,
    pub boot_nonce: [u8; 32],
    pub pins: SessionPins,
    /// Monotonic for this VM incarnation; never clear when an exec exits.
    /// Older state cannot prove that a secret was never injected.
    #[serde(default = "assume_prior_secret_injection")]
    pub has_received_secrets: bool,
}
fn assume_prior_secret_injection() -> bool {
    true
}
impl std::fmt::Debug for LaunchIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchIntent")
            .field("key", &self.key)
            .field("state", &self.state)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("cid", &self.cid)
            .field("boot_nonce", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

pub struct SessionPreparation<'a> {
    pub pins: &'a SessionPins,
    pub pools: &'a crate::config::IdentityPools,
    pub host_boot_id: &'a str,
    pub now_ms: u64,
}

pub struct PreparedSession {
    /// Original committed response, including on replay after a later stop.
    pub response: Response,
    /// Present only while that exact incarnation is still owned. An old
    /// operation receipt must never authorize a second VM launch.
    pub intent: Option<LaunchIntent>,
    pub replayed: bool,
}

pub(super) fn consistent(record: &Sandbox) -> bool {
    use SandboxState as B;
    use SessionState as S;
    match record.session.as_ref().map(|s| s.state) {
        None => matches!(record.state, B::Stopped | B::Suspended),
        Some(S::Preparing | S::JailerStarting | S::VmmConfiguring) => record.state == B::Starting,
        Some(S::VmmBooting | S::GuestHandshake) => record.state == B::Booting,
        Some(S::Active) => matches!(record.state, B::GuestReady | B::Running),
        Some(S::Paused) => matches!(record.state, B::Pausing | B::Paused),
        Some(S::Terminating) => matches!(record.state, B::Stopping | B::Suspending),
        Some(S::Failed) => record.state == B::Failed,
        Some(S::Terminated) => false,
    }
}

pub(super) fn decode(row: &Row<'_>) -> Result<LaunchIntent> {
    let blob = row.get_ref(7)?.as_blob().map_err(|_| Error::State)?;
    let value: LaunchIntent = codec::decode_body(blob)?;
    if value.key.sandbox.as_str() != row.get_ref(0)?.as_str().map_err(|_| Error::State)?
        || value.key.sandbox_generation.get() != row.get::<_, u64>(1)?
        || value.key.session.as_str() != row.get_ref(2)?.as_str().map_err(|_| Error::State)?
        || value.key.generation.get() != row.get::<_, u64>(3)?
        || value.uid != row.get::<_, u32>(4)?
        || value.gid != row.get::<_, u32>(5)?
        || value.cid != row.get::<_, u32>(6)?
        || value.boot_nonce == [0; 32]
        || value.host_boot_id.len() != 36
        || !value
            .host_boot_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err(Error::State);
    }
    Ok(value)
}

pub(super) const COLUMNS: &str =
    "sandbox,sandbox_generation,session_id,session_generation,uid,gid,cid,record";

pub(super) fn validate_all(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(&format!("SELECT {COLUMNS} FROM sessions"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let intent = decode(row)?;
        let mut sandbox = connection.prepare("SELECT id,generation,lease_expires_at,record,session_generation FROM sandboxes WHERE id=?1 AND record IS NOT NULL")?;
        let mut sandboxes = sandbox.query([intent.key.sandbox.as_str()])?;
        let row = sandboxes.next()?.ok_or(Error::State)?;
        let record = super::record::decode(row)?;
        let session = record.session.as_ref().ok_or(Error::State)?;
        if record.generation != intent.key.sandbox_generation
            || session.id != intent.key.session
            || session.generation != intent.key.generation
            || session.state != intent.state
            || session.runtime_profile != intent.pins.runtime_profile
            || row.get::<_, u64>(4)? != intent.key.generation.get()
        {
            return Err(Error::State);
        }
        intent
            .pins
            .validate(&record.spec)
            .map_err(|_| Error::State)?;
    }
    let mut statement = connection.prepare(
        "SELECT id,generation,lease_expires_at,record FROM sandboxes WHERE record IS NOT NULL",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let record = super::record::decode(row)?;
        if record.session.is_some() {
            let exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sessions WHERE sandbox=?1)",
                [record.id.as_str()],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(Error::State);
            }
        }
    }
    Ok(())
}
