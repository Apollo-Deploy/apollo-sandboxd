//! Owner-scoped daemon-owned block backing capabilities. No host path crosses
//! the public API. Imported images arrive as exactly one sealed readonly FD.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeBacking {
    pub id: String,
    pub generation: u64,
}
impl VolumeBacking {
    pub fn validate(&self) -> bool {
        self.generation > 0
            && self.generation <= i64::MAX as u64
            && self.id.len() == 64
            && self
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum VolumeCommand {
    Allocate {
        size_bytes: u64,
        writable: bool,
    },
    ImportPrepared {
        image: crate::ImageDigest,
        size_bytes: u64,
        writable: bool,
    },
    Import {
        size_bytes: u64,
        sha256: String,
        writable: bool,
    },
}
impl VolumeCommand {
    pub fn size_bytes(&self) -> u64 {
        match self {
            Self::Allocate { size_bytes, .. }
            | Self::Import { size_bytes, .. }
            | Self::ImportPrepared { size_bytes, .. } => *size_bytes,
        }
    }
    pub fn writable(&self) -> bool {
        match self {
            Self::Allocate { writable, .. }
            | Self::Import { writable, .. }
            | Self::ImportPrepared { writable, .. } => *writable,
        }
    }
    pub fn validate(&self) -> bool {
        let size = self.size_bytes();
        (1 << 20..=1 << 30).contains(&size)
            && size.is_multiple_of(4096)
            && match self {
                Self::Import { sha256, .. } => {
                    sha256.len() == 64
                        && sha256
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }
                _ => true,
            }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeInfo {
    pub backing: VolumeBacking,
    pub size_bytes: u64,
    pub writable: bool,
    pub initial_sha256: String,
}
