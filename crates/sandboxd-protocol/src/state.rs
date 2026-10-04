use crate::{LeaseId, SandboxGeneration, SandboxId, SandboxSpec, SessionGeneration, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SandboxState {
    Absent,
    Creating,
    Stopped,
    Starting,
    Booting,
    GuestReady,
    Running,
    Pausing,
    Paused,
    Suspending,
    Suspended,
    Stopping,
    Destroying,
    Failed,
}
impl SandboxState {
    pub fn allows(self, next: Self) -> bool {
        use SandboxState::*;
        matches!(
            (self, next),
            (Absent, Creating)
                | (Creating, Stopped | Failed)
                | (Stopped, Starting | Destroying)
                | (Starting, Booting | Failed)
                | (Booting, GuestReady | Failed | Stopping)
                | (GuestReady, Running | Stopping | Failed)
                | (Running, Pausing | Suspending | Stopping | Failed)
                | (Pausing, Paused | Failed)
                | (Paused, Running | Suspending | Stopping | Failed)
                | (Suspending, Suspended | Failed)
                | (Suspended, Starting | Destroying | Stopping)
                | (Stopping, Stopped | Failed)
                | (Failed, Stopping | Destroying)
                | (Destroying, Absent | Failed)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Preparing,
    JailerStarting,
    VmmConfiguring,
    VmmBooting,
    GuestHandshake,
    Active,
    Paused,
    Terminating,
    Terminated,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub id: SessionId,
    pub generation: SessionGeneration,
    pub state: SessionState,
    pub runtime_profile: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub id: LeaseId,
    pub sandbox_generation: SandboxGeneration,
    pub session_generation: Option<SessionGeneration>,
    pub expires_at_unix_ms: u64,
    pub renewal_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    pub id: SandboxId,
    pub generation: SandboxGeneration,
    pub state: SandboxState,
    pub spec: SandboxSpec,
    pub session: Option<Session>,
    pub lease: Lease,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventKind {
    SandboxCreated,
    SessionStarting,
    SessionBooted,
    GuestReady,
    SessionPaused,
    SessionResumed,
    SessionStopped,
    SandboxSuspended,
    SandboxDestroyed,
    LeaseRenewed,
    LeaseExpired,
    LeaseAcquired,
    ExecStarted,
    ExecExited,
    ExecCancelled,
    ExecTimedOut,
    OutputGap,
    NetworkAttached,
    NetworkFailed,
    FilesystemCheckpointCreated,
    FilesystemCheckpointRestored,
    VmSnapshotCreated,
    VmSnapshotRestored,
    VmSnapshotRejected,
    VmmCrashed,
    GuestAgentLost,
    RecoveryRepaired,
    RecoveryFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub sequence: u64,
    pub timestamp_unix_ms: u64,
    pub sandbox: SandboxId,
    pub generation: SandboxGeneration,
    pub kind: EventKind,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventPage {
    pub gap: Option<(u64, u64)>,
    pub events: Vec<Event>,
    pub next_sequence: u64,
}
