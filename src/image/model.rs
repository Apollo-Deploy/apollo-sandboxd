use serde::{Deserialize, Serialize};

pub fn host_oci_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub rootfs: ImageRootfs,
    #[serde(default)]
    pub config: RuntimeConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct ImageRootfs {
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub diff_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct RuntimeConfig {
    #[serde(default, rename = "Env")]
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
