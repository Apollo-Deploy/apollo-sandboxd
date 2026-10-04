use crate::{Fence, SnapshotId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSecretPolicy {
    #[default]
    Reject,
    AllowEncrypted,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SnapshotCommand {
    Create {
        id: SnapshotId,
        fence: Fence,
        #[serde(default)]
        secret_policy: SnapshotSecretPolicy,
    },
    Suspend {
        id: SnapshotId,
        fence: Fence,
        #[serde(default)]
        secret_policy: SnapshotSecretPolicy,
    },
    Restore {
        id: SnapshotId,
        fence: Fence,
    },
    Delete {
        id: SnapshotId,
        fence: Fence,
    },
}
impl SnapshotCommand {
    pub fn id(&self) -> &SnapshotId {
        match self {
            Self::Create { id, .. }
            | Self::Suspend { id, .. }
            | Self::Restore { id, .. }
            | Self::Delete { id, .. } => id,
        }
    }
    pub fn fence(&self) -> &Fence {
        match self {
            Self::Create { fence, .. }
            | Self::Suspend { fence, .. }
            | Self::Restore { fence, .. }
            | Self::Delete { fence, .. } => fence,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotInfo {
    pub id: SnapshotId,
    pub sandbox: crate::SandboxId,
    pub sandbox_generation: crate::SandboxGeneration,
    pub memory_bytes: u64,
    pub state_bytes: u64,
    pub suspended: bool,
}
