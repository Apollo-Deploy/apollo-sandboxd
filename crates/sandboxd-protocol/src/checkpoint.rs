use crate::{CheckpointId, Fence, OperationId};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckpointCommand {
    Create { id: CheckpointId, fence: Fence },
    Restore { id: CheckpointId, fence: Fence },
    Delete { id: CheckpointId, fence: Fence },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointInfo {
    pub id: CheckpointId,
    pub sandbox: String,
    pub sandbox_generation: u64,
    pub bytes: u64,
    pub sha256: String,
}
pub type CheckpointOperation = (OperationId, CheckpointCommand);
