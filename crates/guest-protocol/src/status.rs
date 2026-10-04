use sandboxd_protocol::ExecId;
use serde::{Deserialize, Serialize};

/// All status values originate inside the guest and are advisory to the host.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestHealth {
    pub ready: bool,
    pub pid: u32,
    pub running_execs: u32,
    pub control_channel: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestMetrics {
    pub running_execs: u32,
    pub completed_execs: u32,
    pub provenance: GuestTelemetryProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuestTelemetryProvenance {
    GuestReported,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestProcess {
    pub exec: ExecId,
    pub pid: u32,
    pub state: String,
    pub detached: bool,
}
