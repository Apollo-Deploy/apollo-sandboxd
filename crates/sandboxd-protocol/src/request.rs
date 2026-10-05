use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fence {
    pub sandbox: SandboxId,
    pub generation: SandboxGeneration,
    pub session_generation: Option<SessionGeneration>,
    pub lease: LeaseId,
}

/// A lifecycle operation on an existing sandbox session.  Every operation is
/// fenced by the caller's sandbox/session generations and finite lease; the
/// daemon records the operation before performing a runtime side effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionControl {
    Start,
    Stop,
    Pause,
    Resume,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mutation {
    Create {
        sandbox: SandboxId,
        expected_generation: Option<SandboxGeneration>,
        spec: Box<SandboxSpec>,
        lease_seconds: u32,
    },
    Renew {
        fence: Fence,
        sequence: u64,
        duration_seconds: u32,
    },
    AcquireLease {
        fence: Fence,
        duration_seconds: u32,
    },
    Destroy {
        fence: Fence,
    },
    Session {
        fence: Fence,
        control: SessionControl,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Capabilities,
    Health,
    RuntimeList,
    Inspect {
        sandbox: SandboxId,
    },
    List {
        after: Option<SandboxId>,
        limit: u16,
    },
    Events {
        from_sequence: u64,
        limit: u16,
    },
    OperationWatermark,
    OperationInspect {
        operation: OperationId,
        operation_sequence: u64,
    },
    /// Fenced host-side process status read. It does not reserve a mutation sequence.
    ExecStatus {
        fence: Fence,
        exec: ExecId,
    },
    SnapshotInspect {
        id: SnapshotId,
    },
    SnapshotList {
        sandbox: SandboxId,
        after: Option<SnapshotId>,
        limit: u16,
    },
    Volume {
        operation: OperationId,
        operation_sequence: u64,
        command: Box<VolumeCommand>,
    },
    VolumeInspect {
        backing: VolumeBacking,
    },
    VolumeRelease {
        operation: OperationId,
        operation_sequence: u64,
        backing: VolumeBacking,
    },
    ImageInspect {
        digest: ImageDigest,
    },
    ImageList {
        after: Option<ImageDigest>,
        limit: u16,
    },
    Image {
        operation: OperationId,
        operation_sequence: u64,
        command: Box<ImageCommand>,
    },
    Snapshot {
        operation: OperationId,
        operation_sequence: u64,
        command: Box<SnapshotCommand>,
    },
    Checkpoint {
        operation: OperationId,
        operation_sequence: u64,
        command: Box<CheckpointCommand>,
    },
    Guest {
        operation: OperationId,
        operation_sequence: u64,
        fence: Fence,
        command: Box<GuestCommand>,
    },
    FilesystemExport {
        #[serde(default)]
        volume_id: Option<VolumeId>,
        operation: OperationId,
        operation_sequence: u64,
        fence: Fence,
        max_bytes: u64,
        max_entries: u32,
    },
    Mutate {
        operation: OperationId,
        operation_sequence: u64,
        mutation: Box<Mutation>,
    },
}

pub const MAX_FILESYSTEM_EXPORT_BYTES: u64 = 1 << 30;
pub const MAX_FILESYSTEM_EXPORT_ENTRIES: u32 = 100_000;

impl Request {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Volume {
                operation,
                operation_sequence,
                command,
            } if !operation.matches_sequence(*operation_sequence) || !command.validate() => {
                Err("volume mutation bounds")
            }
            Self::VolumeInspect { backing } if !backing.validate() => Err("volume backing bounds"),
            Self::VolumeRelease {
                operation,
                operation_sequence,
                backing,
            } if !operation.matches_sequence(*operation_sequence) || !backing.validate() => {
                Err("volume release bounds")
            }
            Self::OperationInspect {
                operation,
                operation_sequence,
            } if !operation.matches_sequence(*operation_sequence) => {
                Err("operation inspection sequence")
            }
            Self::FilesystemExport {
                operation,
                operation_sequence,
                max_bytes,
                max_entries,
                ..
            } if *operation_sequence == 0
                || !operation.matches_sequence(*operation_sequence)
                || *max_bytes == 0
                || *max_bytes > MAX_FILESYSTEM_EXPORT_BYTES
                || *max_entries == 0
                || *max_entries > MAX_FILESYSTEM_EXPORT_ENTRIES =>
            {
                Err("filesystem export bounds")
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub protocol_version: u16,
    pub architecture: Architecture,
    pub kvm_available: bool,
    pub runtime_profiles: Vec<String>,
    /// Only operationally connected capabilities belong here. Schema presence is not delivery.
    pub supported: Vec<String>,
    pub qualification: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub daemon: String,
    pub storage: String,
    pub runtime: String,
    pub guest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "response", content = "body", rename_all = "snake_case")]
pub enum Response {
    Capabilities(Capabilities),
    Health(Health),
    RuntimeList(Vec<String>),
    Sandbox(Box<Sandbox>),
    Sandboxes(Vec<Sandbox>),
    Events(EventPage),
    OperationWatermark {
        accepted_sequence: u64,
    },
    OperationReceipt(Box<OperationReceipt>),
    Guest(GuestReply),
    FilesystemExport(FilesystemExportInfo),
    Volume(VolumeInfo),
    VolumeReleased {
        backing: VolumeBacking,
    },
    VolumePending {
        operation: OperationId,
    },
    Image(ImageInfo),
    Images(Vec<ImageInfo>),
    Snapshot(SnapshotInfo),
    Snapshots(Vec<SnapshotInfo>),
    SnapshotDeleted {
        id: SnapshotId,
    },
    SnapshotPending {
        operation: OperationId,
    },
    Checkpoint(CheckpointInfo),
    CheckpointDeleted {
        id: CheckpointId,
    },
    Checkpoints(Vec<CheckpointInfo>),
    CheckpointPending {
        operation: OperationId,
    },
    ImagePending {
        operation: OperationId,
    },
    GuestPending {
        operation: OperationId,
    },
    Destroyed {
        sandbox: SandboxId,
        generation: SandboxGeneration,
    },
    Error(ApiError),
}

/// Receipt for a completed, immutable OCI layer export. The layer bytes are
/// delivered as one read-only response descriptor; no host path is exposed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemExportInfo {
    pub operation: OperationId,
    pub base_digest: ImageDigest,
    pub media_type: String,
    pub sha256: String,
    pub byte_len: u64,
    pub entry_count: u32,
}
