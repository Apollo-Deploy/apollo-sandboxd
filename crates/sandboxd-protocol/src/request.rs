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
    SnapshotInspect {
        id: SnapshotId,
    },
    SnapshotList {
        sandbox: SandboxId,
        after: Option<SnapshotId>,
        limit: u16,
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
    Mutate {
        operation: OperationId,
        operation_sequence: u64,
        mutation: Box<Mutation>,
    },
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
    Guest(GuestReply),
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
