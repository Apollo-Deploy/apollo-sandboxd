//! Local OCI cache accounting and garbage collection.
use super::{ImageCache, ImageManifest, invalid};
use crate::image::content::read_bounded_file;
use std::os::unix::fs::MetadataExt;
use std::{fs, io, path::Path};

impl ImageCache {
    pub fn gc(&self) -> io::Result<u64> {
        let _lock = crate::image::cache_lock::acquire(&self.root)?;
        let mut referenced = std::collections::HashSet::new();
        for entry in fs::read_dir(self.root.join("manifests"))? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || !valid_blob_name(path.file_name().and_then(|name| name.to_str()))
            {
                return Err(invalid("OCI cache manifest ownership/type mismatch"));
            }
            #[cfg(unix)]
            if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.nlink() != 1 {
                return Err(invalid("OCI cache manifest ownership/link mismatch"));
            }
            let manifest: ImageManifest = serde_json::from_slice(&read_bounded_file(
                &path,
                self.limits.max_blob_bytes.min(1 << 20),
            )?)
            .map_err(invalid)?;
            if let Some(config) = manifest.config {
                if let Some(digest) = config.digest.strip_prefix("sha256:") {
                    referenced.insert(digest.to_owned());
                }
            }
            for layer in manifest.layers {
                if let Some(digest) = layer.digest.strip_prefix("sha256:") {
                    referenced.insert(digest.to_owned());
                }
            }
        }
        let mut reclaimed = 0u64;
        for entry in fs::read_dir(self.root.join("blobs/sha256"))? {
            let path = entry?.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || !valid_blob_name(path.file_name().and_then(|value| value.to_str()))
            {
                return Err(invalid("OCI cache blob ownership/type mismatch"));
            }
            #[cfg(unix)]
            if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.nlink() != 1 {
                return Err(invalid("OCI cache blob ownership/link mismatch"));
            }
            if !referenced.contains(&name) {
                reclaimed = reclaimed
                    .checked_add(metadata.len())
                    .ok_or_else(|| invalid("OCI cache reclaimed-size overflow"))?;
                fs::remove_file(path)?;
            }
        }
        Ok(reclaimed)
    }
}

fn valid_blob_name(name: Option<&str>) -> bool {
    name.is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

pub(super) fn cache_usage(root: &Path) -> io::Result<u64> {
    fn walk(path: &Path, total: &mut u64) -> io::Result<()> {
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(invalid("OCI cache contains symlink"));
            } else if metadata.is_dir() {
                walk(&path, total)?;
            } else if metadata.is_file() {
                *total = total
                    .checked_add(metadata.len())
                    .ok_or_else(|| invalid("OCI cache size overflow"))?;
            } else {
                return Err(invalid("OCI cache contains special file"));
            }
        }
        Ok(())
    }
    let mut total = 0;
    walk(root, &mut total)?;
    Ok(total)
}
