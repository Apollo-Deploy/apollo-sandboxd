//! Finite operator policy. Keys are installed separately from snapshot objects.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSettings {
    pub directory: PathBuf,
    pub key_file: PathBuf,
    pub max_snapshots_per_sandbox: u32,
    pub max_total_bytes: u64,
    pub max_concurrent_operations: u16,
    pub max_restore_memory_bytes: u64,
}
impl SnapshotSettings {
    pub fn validate(&self) -> Result<()> {
        if !self.directory.is_absolute()
            || !self.key_file.is_absolute()
            || [&self.directory, &self.key_file].iter().any(|path| {
                path.components()
                    .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            })
            || self.directory.parent().is_none()
            || self.key_file.starts_with(&self.directory)
            || self.max_snapshots_per_sandbox == 0
            || self.max_snapshots_per_sandbox > 4096
            || self.max_total_bytes == 0
            || self.max_total_bytes > 1 << 50
            || self.max_concurrent_operations == 0
            || self.max_concurrent_operations > 64
            || self.max_restore_memory_bytes < 64 << 20
            || self.max_restore_memory_bytes > 1 << 40
        {
            return Err(Error::Config("invalid encrypted snapshot configuration"));
        }
        Ok(())
    }
}
