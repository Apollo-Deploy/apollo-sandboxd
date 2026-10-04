//! Bounded lookup and inspection of prepared OCI content.
use super::{ImageCache, ImageImport, ImageManifest, ImageMetadata, invalid};
use crate::image::content::{read_bounded_file, verify_blob};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::{fs, io, path::Path};

impl ImageCache {
    /// Import only from an operator-authorized directory. Callers provide a
    /// relative layout name; no API request can select an arbitrary host path.
    pub fn import_authorized_layout(
        &self,
        authority_root: &Path,
        relative_layout: &Path,
    ) -> io::Result<ImageImport> {
        if relative_layout.is_absolute()
            || relative_layout.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )
            })
        {
            return Err(invalid("OCI layout must be relative to operator root"));
        }
        let authority = fs::canonicalize(authority_root)?;
        let authority_meta = fs::symlink_metadata(&authority)?;
        if !authority_meta.is_dir()
            || authority_meta.uid() != rustix::process::geteuid().as_raw()
            || authority_meta.mode() & 0o077 != 0
        {
            return Err(invalid("operator image root ownership/mode mismatch"));
        }
        let layout = authority.join(relative_layout);
        let canonical = fs::canonicalize(&layout)?;
        if !canonical.starts_with(&authority) {
            return Err(invalid("OCI layout escaped operator root"));
        }
        let metadata = fs::symlink_metadata(&canonical)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("OCI layout is not an operator directory"));
        }
        self.import_layout(&canonical)
    }

    /// Resolve a previously prepared image by its content digest. This is the
    /// narrow boundary used by RuntimeAuthority; it revalidates every blob and
    /// the extracted root before returning paths to the caller.
    pub fn resolve_prepared(&self, digest: &str) -> io::Result<ImageImport> {
        let value = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| invalid("unsupported OCI digest"))?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
        {
            return Err(invalid("invalid image digest"));
        }
        let manifest_path = self.root.join("manifests").join(value);
        let manifest: ImageManifest = serde_json::from_slice(&read_bounded_file(
            &manifest_path,
            self.limits
                .max_blob_bytes
                .min(crate::image::model::MAX_METADATA_BYTES),
        )?)
        .map_err(invalid)?;
        if format!(
            "sha256:{:x}",
            Sha256::digest(&read_bounded_file(
                &manifest_path,
                self.limits
                    .max_blob_bytes
                    .min(crate::image::model::MAX_METADATA_BYTES)
            )?)
        ) != digest
        {
            return Err(invalid("cached manifest digest mismatch"));
        }
        let rootfs = self.root.join("rootfs").join(value);
        crate::image::materialization::verify_committed_root(
            &self.root.join("rootfs"),
            digest,
            &rootfs,
        )?;
        for layer in &manifest.layers {
            verify_blob(&self.blob_path(&layer.digest)?, &layer.digest, layer.size)?;
        }
        let config = self.read_config(&manifest)?;
        Ok(ImageImport {
            digest: digest.to_owned(),
            manifest,
            rootfs,
            config,
        })
    }

    pub fn inspect_prepared(&self, digest: &str) -> io::Result<ImageMetadata> {
        let image = self.resolve_prepared(digest)?;
        Ok(ImageMetadata {
            digest: image.digest,
            architecture: std::env::consts::ARCH.to_owned(),
            layers: image.manifest.layers.len() as u32,
            config_size: image
                .manifest
                .config
                .as_ref()
                .map(|descriptor| descriptor.size),
            rootfs: image.rootfs,
        })
    }

    pub fn list_prepared(&self) -> io::Result<Vec<ImageMetadata>> {
        let directory = self.root.join("manifests");
        let mut result = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() != 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                continue;
            }
            let digest = format!("sha256:{name}");
            if let Ok(metadata) = self.inspect_prepared(&digest) {
                result.push(metadata);
            }
        }
        result.sort_by(|left, right| left.digest.cmp(&right.digest));
        Ok(result)
    }
}
