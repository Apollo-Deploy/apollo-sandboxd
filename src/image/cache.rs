use super::{
    content::{
        open_layout_blob, read_bounded_file, read_layout_blob, read_verified,
        store_verified_stream, verify_blob, write_verified,
    },
    layers::{self, LayerLimits},
    model::{
        ImageConfig, ImageManifest, ImageMetadata, ImageReference, OciDescriptor,
        host_oci_architecture,
    },
    registry::{RegistryClient, RegistryError},
    rootfs::verify_extracted_root,
};
use sha2::{Digest, Sha256};
use std::{
    fmt::Display,
    fs,
    io::{self},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug)]
pub struct ImageLimits {
    pub max_blob_bytes: u64,
    pub max_cache_bytes: u64,
    pub max_layers: u32,
    pub max_entries: u64,
    pub max_uncompressed_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct ImageImport {
    pub digest: String,
    pub manifest: ImageManifest,
    pub rootfs: PathBuf,
    pub config: Option<ImageConfig>,
}

#[path = "cache_gc.rs"]
mod gc;
#[path = "cache_lookup.rs"]
mod lookup;
use gc::cache_usage;

pub struct ImageCache {
    root: PathBuf,
    limits: ImageLimits,
}

impl ImageCache {
    pub fn open(root: impl AsRef<Path>, limits: ImageLimits) -> io::Result<Self> {
        if limits.max_blob_bytes < 1 << 20
            || limits.max_blob_bytes > 1 << 40
            || limits.max_cache_bytes < limits.max_blob_bytes
            || limits.max_layers == 0
            || limits.max_layers > 256
            || limits.max_entries == 0
            || limits.max_uncompressed_bytes < 1 << 20
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid OCI cache limits",
            ));
        }
        let root = root.as_ref().to_path_buf();
        let parent = crate::security::path::SecureDir::open(
            root.parent().ok_or_else(|| invalid("cache root parent"))?,
        )
        .map_err(invalid)?;
        let directory = parent
            .ensure_private_directory(
                root.file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| invalid("cache root name"))?,
            )
            .map_err(invalid)?;
        directory
            .ensure_private_directory("blobs")
            .map_err(invalid)?
            .ensure_private_directory("sha256")
            .map_err(invalid)?;
        directory
            .ensure_private_directory("manifests")
            .map_err(invalid)?;
        directory
            .ensure_private_directory("rootfs")
            .map_err(invalid)?
            .ensure_private_directory(".commits")
            .map_err(invalid)?;
        Ok(Self { root, limits })
    }

    pub fn import_layout(&self, layout: &Path) -> io::Result<ImageImport> {
        let _lock = super::cache_lock::acquire(&self.root)?;
        self.recover_materializations()?;
        let index: super::model::OciIndex = serde_json::from_slice(&read_bounded_file(
            &layout.join("index.json"),
            self.limits
                .max_blob_bytes
                .min(super::model::MAX_METADATA_BYTES),
        )?)
        .map_err(invalid)?;
        let descriptor = index
            .manifests
            .into_iter()
            .find(|d| {
                d.platform.as_ref().is_some_and(|p| {
                    p.os == "linux"
                        && (p.architecture == host_oci_architecture()
                            || p.architecture == std::env::consts::ARCH)
                })
            })
            .ok_or_else(|| invalid("OCI layout has no supported platform"))?;
        let manifest_bytes = read_layout_blob(
            layout,
            &descriptor,
            self.limits
                .max_blob_bytes
                .min(super::model::MAX_METADATA_BYTES),
        )?;
        let manifest: ImageManifest = serde_json::from_slice(&manifest_bytes).map_err(invalid)?;
        self.import_manifest(descriptor.digest, manifest, manifest_bytes, |blob| {
            open_layout_blob(layout, blob, self.limits.max_blob_bytes)
        })
    }

    pub async fn pull(
        &self,
        reference: &ImageReference,
        registry: &RegistryClient,
    ) -> Result<ImageImport, RegistryError> {
        let (digest, manifest, manifest_bytes) =
            registry.resolve_manifest_with_bytes(reference).await?;
        let root = self.root.clone();
        let _lock = tokio::task::spawn_blocking(move || super::cache_lock::acquire(&root))
            .await
            .map_err(|_| RegistryError::Response)??;
        self.recover_materializations().map_err(RegistryError::Io)?;
        self.ensure_capacity(&digest, &manifest, manifest_bytes.len() as u64)
            .map_err(|error| match error.kind() {
                io::ErrorKind::FileTooLarge => RegistryError::Limit,
                _ => RegistryError::Io(error),
            })?;
        for layer in &manifest.layers {
            let path = self
                .blob_path(&layer.digest)
                .map_err(|_| RegistryError::Response)?;
            if path.exists() {
                verify_blob(&path, &layer.digest, layer.size).map_err(RegistryError::Io)?;
            } else {
                registry.download_blob(reference, layer, &path).await?;
            }
        }
        if let Some(config) = &manifest.config {
            let path = self
                .blob_path(&config.digest)
                .map_err(|_| RegistryError::Response)?;
            if path.exists() {
                verify_blob(&path, &config.digest, config.size).map_err(RegistryError::Io)?;
            } else {
                registry.download_blob(reference, config, &path).await?;
            }
        }
        let config = self
            .read_config(&manifest)
            .map_err(|_| RegistryError::Response)?;
        self.materialize(digest, manifest, manifest_bytes, config)
            .map_err(|_| RegistryError::Response)
    }

    fn import_manifest<F>(
        &self,
        digest: String,
        manifest: ImageManifest,
        manifest_bytes: Vec<u8>,
        mut get: F,
    ) -> io::Result<ImageImport>
    where
        F: FnMut(&OciDescriptor) -> io::Result<fs::File>,
    {
        if manifest.layers.len() as u32 > self.limits.max_layers {
            return Err(invalid("too many OCI layers"));
        }
        self.ensure_capacity(&digest, &manifest, manifest_bytes.len() as u64)?;
        for layer in &manifest.layers {
            let mut file = get(layer)?;
            store_verified_stream(
                &self.blob_path(&layer.digest)?,
                &mut file,
                &layer.digest,
                layer.size,
                self.limits.max_blob_bytes,
            )?;
        }
        if let Some(config) = &manifest.config {
            let mut file = get(config)?;
            store_verified_stream(
                &self.blob_path(&config.digest)?,
                &mut file,
                &config.digest,
                config.size,
                self.limits
                    .max_blob_bytes
                    .min(super::model::MAX_METADATA_BYTES),
            )?;
        }
        let config = self.read_config(&manifest)?;
        self.materialize(digest, manifest, manifest_bytes, config)
    }

    fn materialize(
        &self,
        digest: String,
        manifest: ImageManifest,
        manifest_bytes: Vec<u8>,
        config: Option<ImageConfig>,
    ) -> io::Result<ImageImport> {
        if format!("sha256:{:x}", Sha256::digest(&manifest_bytes)) != digest {
            return Err(invalid("OCI manifest provenance digest mismatch"));
        }
        let rootfs = self
            .root
            .join("rootfs")
            .join(digest.strip_prefix("sha256:").unwrap_or(&digest));
        let rootfs_parent = self.root.join("rootfs");
        let digest_name = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| invalid("manifest digest"))?;
        let secure_rootfs =
            crate::security::path::SecureDir::open(&rootfs_parent).map_err(invalid)?;
        if super::materialization::directory_identity(&secure_rootfs, digest_name)?.is_some() {
            super::materialization::verify_committed_root(&rootfs_parent, &digest, &rootfs)?;
            let manifest_path = self.root.join("manifests").join(digest_name);
            write_verified(&manifest_path, &manifest_bytes, &digest)?;
            return Ok(ImageImport {
                digest,
                manifest,
                rootfs,
                config,
            });
        }
        super::materialization::ensure_no_orphan_commit(&rootfs_parent, &digest)?;
        let temporary = super::materialization::MaterializingRoot::create(&rootfs_parent, &digest)?;
        let result = (|| {
            let mut remaining_entries = self.limits.max_entries;
            let mut remaining_bytes = self.limits.max_uncompressed_bytes;
            for layer in &manifest.layers {
                let blob = self.blob_path(&layer.digest)?;
                let usage = layers::apply_layer(
                    &blob,
                    &temporary.path(),
                    layer.media_type.ends_with("+gzip"),
                    LayerLimits {
                        max_entries: remaining_entries,
                        max_uncompressed_bytes: remaining_bytes,
                        max_file_bytes: self.limits.max_blob_bytes,
                    },
                )?;
                remaining_entries = remaining_entries
                    .checked_sub(usage.entries)
                    .ok_or_else(|| invalid("OCI image entry limit exceeded"))?;
                remaining_bytes = remaining_bytes
                    .checked_sub(usage.bytes)
                    .ok_or_else(|| invalid("OCI image expansion limit exceeded"))?;
            }
            verify_extracted_root(&temporary.path())?;
            super::rootfs::sync_extracted_root(&temporary.path())?;
            let identity = match temporary.publish(digest_name)? {
                super::materialization::PublishResult::Installed(identity) => identity,
                super::materialization::PublishResult::AlreadyExists => {
                    return Err(invalid("OCI digest path appeared during publication"));
                }
            };
            verify_extracted_root(&rootfs)?;
            let manifest_path = self.root.join("manifests").join(digest_name);
            write_verified(&manifest_path, &manifest_bytes, &digest)?;
            temporary.commit(digest_name, identity)
        })();
        if let Err(error) = result {
            self.recover_materializations()?;
            return Err(error);
        }
        Ok(ImageImport {
            digest,
            manifest,
            rootfs,
            config,
        })
    }

    fn recover_materializations(&self) -> io::Result<()> {
        super::materialization::recover(
            &self.root.join("rootfs"),
            &self.root.join("manifests"),
            self.limits
                .max_blob_bytes
                .min(super::model::MAX_METADATA_BYTES),
        )
    }

    fn read_config(&self, manifest: &ImageManifest) -> io::Result<Option<ImageConfig>> {
        let Some(descriptor) = manifest.config.as_ref() else {
            return Ok(None);
        };
        let path = self.blob_path(&descriptor.digest)?;
        let bytes = read_verified(
            &path,
            &descriptor.digest,
            descriptor.size,
            self.limits
                .max_blob_bytes
                .min(super::model::MAX_METADATA_BYTES),
        )?;
        let config: ImageConfig = serde_json::from_slice(&bytes).map_err(invalid)?;
        if config.os.as_deref().is_some_and(|os| os != "linux")
            || config
                .architecture
                .as_deref()
                .is_some_and(|arch| arch != host_oci_architecture())
        {
            return Err(invalid("OCI config platform mismatch"));
        }
        Ok(Some(config))
    }

    fn blob_path(&self, digest: &str) -> io::Result<PathBuf> {
        let value = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| invalid("unsupported OCI digest"))?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
        {
            return Err(invalid("invalid OCI digest"));
        }
        Ok(self.root.join("blobs/sha256").join(value))
    }

    fn ensure_capacity(
        &self,
        digest: &str,
        manifest: &ImageManifest,
        manifest_bytes: u64,
    ) -> io::Result<()> {
        if manifest.layers.len() as u32 > self.limits.max_layers {
            return Err(limit("too many OCI layers"));
        }
        let mut required = 0u64;
        for descriptor in manifest.layers.iter().chain(manifest.config.iter()) {
            if descriptor.size > self.limits.max_blob_bytes {
                return Err(limit("OCI blob exceeds cache limit"));
            }
            if missing(&self.blob_path(&descriptor.digest)?)? {
                required = required
                    .checked_add(descriptor.size)
                    .ok_or_else(|| limit("OCI cache size overflow"))?;
            }
        }
        let value = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| invalid("unsupported OCI manifest digest"))?;
        if missing(&self.root.join("manifests").join(value))? {
            required = required
                .checked_add(manifest_bytes)
                .ok_or_else(|| limit("OCI cache size overflow"))?;
        }
        if missing(&self.root.join("rootfs").join(value))? {
            required = required
                .checked_add(self.limits.max_uncompressed_bytes)
                .ok_or_else(|| limit("OCI cache size overflow"))?;
        }
        if cache_usage(&self.root)?
            .checked_add(required)
            .is_none_or(|total| total > self.limits.max_cache_bytes)
        {
            return Err(limit("OCI cache capacity exceeded"));
        }
        Ok(())
    }
}

fn invalid(value: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, value.to_string())
}

fn limit(value: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::FileTooLarge, value.to_string())
}

fn missing(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
