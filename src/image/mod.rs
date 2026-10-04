//! OCI content-addressed image import and preparation.
//!
//! This module never executes image content. Registry bytes are verified before
//! publication, and layer extraction is confined to a caller-owned directory.

mod cache;
mod cache_lock;
mod content;
mod content_publish;
mod ext4;
mod layer_scan;
mod layers;
mod materialization;
mod materialization_fs;
mod model;
mod registry;
mod rootfs;
mod runtime_image;

pub use cache::{ImageCache, ImageImport, ImageLimits};
pub use ext4::{PreparedExt4, build_read_only_ext4};
pub use model::{
    ImageConfig, ImageManifest, ImageMetadata, ImageReference, OciDescriptor, RuntimeConfig,
    host_oci_architecture,
};
pub use registry::{RegistryAuth, RegistryClient, RegistryError};
pub use rootfs::verify_extracted_root;
pub use runtime_image::ImageService;
