//! Firecracker jailer preparation and launch contract.
//!
//! This module deliberately owns only the host-side boundary.  It never
//! executes a Firecracker path supplied by a caller and it never offers a
//! direct-VMM fallback.

mod cgroup;
mod chroot;
mod chroot_artifact;
mod chroot_cleanup;
#[cfg(test)]
mod chroot_tests;
mod launch;
mod resource_limits;

pub use cgroup::{CgroupIdentity, CgroupLimits, CgroupV2};
pub use chroot::{JailIdentity, JailInputs, JailStage, JailStageManifest};
pub(crate) use chroot_cleanup::recover_stage_manifest;
pub(crate) use chroot_cleanup::remove_owned_manifest;
pub use launch::{JailerLaunch, JailerLaunchSpec, build_jailer_command};
pub use resource_limits::VmmResourceLimits;
