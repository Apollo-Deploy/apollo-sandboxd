//! Strong identity handles for daemon-managed host processes.

mod identity;
#[cfg(target_os = "linux")]
mod observe;

#[cfg(target_os = "linux")]
pub(crate) use identity::prove_recorded_absent;
pub use identity::{PersistedProcessIdentity, ProcessIdentity};
