//! Image administration never accepts an arbitrary host filename.
use crate::{Architecture, ImageDigest, exec::SecretValue};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImageCommand {
    Pull {
        reference: String,
        username: Option<String>,
        password: Option<SecretValue>,
    },
    ImportLayout {
        relative_layout: String,
    },
}

impl ImageCommand {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Pull {
                reference,
                username,
                password,
            } => {
                if reference.is_empty()
                    || reference.len() > 512
                    || reference.contains(['\0', '\n', '\r'])
                    || username
                        .as_ref()
                        .is_some_and(|v| v.len() > 256 || v.contains('\0'))
                    || username.is_some() != password.is_some()
                    || password.as_ref().is_some_and(|v| v.0.len() > 4096)
                {
                    return Err("image reference or credentials outside bounds");
                }
            }
            Self::ImportLayout { relative_layout } => {
                if relative_layout.is_empty()
                    || relative_layout.len() > 1024
                    || relative_layout.starts_with('/')
                    || relative_layout
                        .split('/')
                        .any(|part| part.is_empty() || part == "." || part == "..")
                    || relative_layout.contains('\0')
                {
                    return Err("image layout outside configured authority");
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
