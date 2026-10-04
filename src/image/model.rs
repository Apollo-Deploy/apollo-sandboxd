use serde::{Deserialize, Serialize};

/// JSON/configuration is bounded independently of streamed layer blobs.
pub(super) const MAX_METADATA_BYTES: u64 = 1 << 20;

pub fn host_oci_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ImageMetadata {
    pub digest: String,
    pub architecture: String,
    pub layers: u32,
    pub config_size: Option<u64>,
    pub rootfs: std::path::PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub reference: String,
}

impl ImageReference {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let (registry, remainder) = value
            .split_once('/')
            .ok_or("image reference missing repository")?;
        if registry.is_empty()
            || remainder.is_empty()
            || registry.contains('@')
            || registry.contains("//")
            || registry.contains('\n')
            || registry.contains('\r')
        {
            return Err("invalid image reference");
        }
        let (repository, reference) = match remainder.split_once('@') {
            Some((repo, digest)) if !repo.is_empty() && digest.starts_with("sha256:") => {
                (repo, digest)
            }
            _ => match remainder.rsplit_once(':') {
                Some((repo, tag)) if !repo.is_empty() && !tag.is_empty() => (repo, tag),
                _ => (remainder, "latest"),
            },
        };
        if repository
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("invalid repository path");
        }
        Ok(Self {
            registry: registry.to_owned(),
            repository: repository.to_owned(),
            reference: reference.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OciDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default)]
    pub platform: Option<OciPlatform>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OciPlatform {
    pub architecture: String,
    pub os: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImageManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(default)]
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
    #[serde(default)]
    pub config: Option<OciDescriptor>,
    #[serde(default)]
    pub layers: Vec<OciDescriptor>,
    #[serde(default)]
    pub manifests: Vec<OciDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct ImageConfig {
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub config: RuntimeConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct RuntimeConfig {
    #[serde(default)]
    #[serde(rename = "Env")]
    pub env: Vec<String>,
    #[serde(default, rename = "WorkingDir")]
    pub working_dir: String,
    #[serde(default, rename = "Entrypoint")]
    pub entrypoint: Vec<String>,
    #[serde(default, rename = "Cmd")]
    pub cmd: Vec<String>,
    #[serde(default, rename = "User")]
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct OciIndex {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub manifests: Vec<OciDescriptor>,
}
