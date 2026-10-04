mod allocation;
pub(crate) mod checkpoint;
mod control_observe;
pub(crate) mod diagnostics_quota;
mod drive;
mod events;
pub(crate) mod guest_operation;
#[cfg(test)]
mod guest_operation_tests;
pub(crate) use image::PreparedImageRecord;
mod image;
mod lease;
mod migration;
mod mutation;
mod policy;
mod prelaunch;
mod record;
mod runtime_inventory;
mod runtime_loss;
mod schema;
mod session;
mod session_control;
mod session_observe;
mod session_prepare;
mod session_process;
mod session_receipt;
mod session_resources;
#[cfg(test)]
mod session_resources_tests;
mod session_schema;
mod store;
pub(crate) use control_observe::CleanupObservations;
pub use control_observe::CleanupProof;
pub use drive::StateDrive;
pub use policy::ExpiredStop;
pub use prelaunch::PrelaunchIntent;
pub use session::{
    LaunchIntent, PreparedSession, SessionKey, SessionPins, SessionPreparation, VolumePin,
};
pub use session_control::{ControlAdmission, PendingSessionControl, SessionControlContext};
pub use session_resources::StoreLaunchJournal;
pub use store::Store;

#[cfg(test)]
mod checkpoint_tests;

pub(crate) mod snapshot;
mod snapshot_finish;
mod snapshot_query;
mod snapshot_restore;

#[cfg(test)]
mod snapshot_tests;
