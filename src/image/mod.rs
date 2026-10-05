//! Prepared image handoff and sandbox-owned ext4 construction.

#[cfg(target_os = "linux")]
pub(crate) mod artifactd;
#[cfg(target_os = "linux")]
mod ext4;
mod model;

#[cfg(target_os = "linux")]
pub use ext4::PreparedExt4;
#[cfg(target_os = "linux")]
pub(crate) use ext4::build_read_only_ext4_from_fd;
pub use model::{ImageConfig, ImageRootfs, RuntimeConfig, host_oci_architecture};
