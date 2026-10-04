use super::{ImageCache, ImageImport, ImageMetadata, ImageReference, RegistryClient};
use std::io;
use std::path::Path;

/// Bounded image administration service. API handlers should construct this
/// only from operator configuration; request payloads contain references and
/// relative layout names, never host paths or credentials.
pub struct ImageService {
    cache: ImageCache,
    authority_root: std::path::PathBuf,
}

impl ImageService {
    pub fn new(cache: ImageCache, authority_root: impl AsRef<Path>) -> io::Result<Self> {
        let root = std::fs::canonicalize(authority_root)?;
        let metadata = std::fs::symlink_metadata(&root)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "image authority is not a directory",
            ));
        }
        Ok(Self {
            cache,
            authority_root: root,
        })
    }

    pub fn import_layout(&self, relative_layout: &Path) -> io::Result<ImageImport> {
        self.cache
            .import_authorized_layout(&self.authority_root, relative_layout)
    }

    pub async fn pull(
        &self,
        reference: &ImageReference,
        registry: &RegistryClient,
    ) -> Result<ImageImport, super::RegistryError> {
        self.cache.pull(reference, registry).await
    }

    pub fn inspect(&self, digest: &str) -> io::Result<ImageMetadata> {
        self.cache.inspect_prepared(digest)
    }

    pub fn list(&self) -> io::Result<Vec<ImageMetadata>> {
        self.cache.list_prepared()
    }

    pub fn gc(&self) -> io::Result<u64> {
        self.cache.gc()
    }
}
