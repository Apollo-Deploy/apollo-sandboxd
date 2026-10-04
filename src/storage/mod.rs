//! Local block artifacts. Customer files are never mounted by the host.
mod checkpoint;
pub(crate) mod checkpoint_restore;
mod drive;
mod image;
pub use checkpoint::{CheckpointCatalog, CheckpointManifest, CheckpointStage};
pub use drive::{DriveFactory, DriveIdentity, DriveOwner, PinnedDrive};
pub use image::{ImageCache, ImageLimits, VerifiedImage};
