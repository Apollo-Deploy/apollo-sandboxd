//! Session launch is the narrow bridge between durable intent and a jailed VMM.
mod arguments;
mod asset_mount;
mod asset_recovery;
mod asset_setup;
mod asset_verify;
mod assets;
mod boot;
mod cleanup;
mod cleanup_paths;
#[cfg(test)]
mod cleanup_paths_tests;
mod configure;
pub(crate) mod diagnostics;
mod jail_tree;
#[cfg(test)]
mod jail_tree_tests;
mod launch;
mod legacy_cleanup;
mod legacy_cleanup_mount;
pub(crate) mod reconcile_prelaunch;
pub(crate) mod snapshot_assets;
pub(crate) use arguments::validate_template as validate_kernel_arguments;
#[doc(hidden)]
pub use asset_setup::AssetSetup;
pub use assets::{
    AssetIdentity, AssetInputs, AssetVolume, AssetsManifest, MountedAsset, StagedAssets,
};
pub use boot::{BootInputs, BootJournal, BootResult, boot};
pub use cleanup::cleanup_after_recorded_exit;
pub use cleanup::stop_and_cleanup;
pub use jail_tree::{JailEntry, JailTreeManifest};
pub use launch::{LaunchInputs, LaunchJournal, LaunchManifest, LaunchResult, launch};

/// Internal entrypoint used only by the daemon's private mount-namespace helper.
#[doc(hidden)]
pub fn run_mount_recovery_helper(parent_namespace: &str) -> crate::error::Result<()> {
    legacy_cleanup_mount::run_mount_recovery_helper(parent_namespace)
}
pub(crate) fn recover_legacy_manifest(
    manifest: &LaunchManifest,
    intent: &crate::state::LaunchIntent,
    process: Option<&crate::process::ProcessIdentity>,
) -> crate::error::Result<LaunchManifest> {
    legacy_cleanup::recover_manifest(manifest, intent, process)
}
pub(crate) fn validate_cleanup_manifest(manifest: &LaunchManifest) -> crate::error::Result<()> {
    legacy_cleanup::validate_ready(manifest)
}
pub(crate) use reconcile_prelaunch::{PrelaunchCleanupProof, reconcile_prelaunch};

/// Verifies the trusted host-installed mount boundary used for every jail.
/// Runtime code never creates this anchor because doing so below a shared
/// parent could overmount peer-namespace state.
pub(crate) fn validate_mount_anchor(operator_root: &std::path::Path) -> crate::error::Result<()> {
    asset_mount::ensure_private_anchor(&operator_root.join("firecracker")).map(|_| ())
}
