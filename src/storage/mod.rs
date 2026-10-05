//! Local block artifacts. Customer files are never mounted by the host.
mod checkpoint;
pub(crate) mod checkpoint_restore;
mod drive;
pub(crate) mod dynamic_volume;
#[cfg(target_os = "linux")]
mod filesystem_export;
#[cfg(target_os = "linux")]
mod filesystem_export_store;
mod image;
pub use checkpoint::{CheckpointCatalog, CheckpointManifest, CheckpointStage};
pub use drive::{DriveFactory, DriveIdentity, DriveOwner, PinnedDrive};
#[cfg(target_os = "linux")]
pub(crate) use filesystem_export::FilesystemExportStager;
#[cfg(target_os = "linux")]
pub(crate) use filesystem_export_store::load_filesystem_export;
pub use image::{ImageCache, ImageLimits, VerifiedImage};
