//! Authenticated full-snapshot artifacts. Runtime orchestration owns VM effects.
mod artifact;
mod catalog;
#[cfg(test)]
mod catalog_tests;
mod config;
mod delete;
mod encryption;
#[cfg(test)]
mod encryption_tests;
mod key;
mod manifest;
mod memory_policy;
mod publish;
pub use artifact::{DirectoryIdentity, EncryptedArtifact, SnapshotArtifacts};
pub use catalog::{SnapshotCatalog, VerifiedSnapshot};
pub use config::SnapshotSettings;
pub use encryption::{ArtifactContext, ArtifactKind, decrypt, encrypt};
pub use key::{KeyProvider, LocalKey, SnapshotKey};
pub use manifest::{SnapshotManifest, SnapshotSecretPolicy};
pub use memory_policy::validate_memory_policy;
