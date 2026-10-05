//! Image administration never accepts an arbitrary host filename.
use crate::{Architecture, ImageDigest};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImageCommand {
    ImportPrepared {
        prepared_artifact_id: String,
        manifest_digest: String,
        lease_id: String,
        architecture: Architecture,
    },
}

impl ImageCommand {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::ImportPrepared {
                prepared_artifact_id,
                manifest_digest,
                lease_id,
                ..
            } => {
                if prepared_artifact_id.is_empty()
                    || prepared_artifact_id.len() > 128
                    || !prepared_artifact_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    || manifest_digest.len() != 71
                    || !manifest_digest.starts_with("sha256:")
                    || !manifest_digest[7..]
                        .bytes()
                        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
                    || lease_id.is_empty()
                    || lease_id.len() > 128
                    || !lease_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err("prepared artifact identity outside bounds");
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageInfo {
    pub digest: ImageDigest,
    pub architecture: Architecture,
    pub rootfs_sha256: String,
    pub bytes: u64,
    pub layers: u32,
}
