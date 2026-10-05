//! Operator-owned storage and launch authority. No client supplies host paths.
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use sandboxd_protocol::{Architecture, ImageDigest};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub operator_root: PathBuf,
    pub cgroup_parent: PathBuf,
    pub drive_directory: PathBuf,
    pub formatter: PathBuf,
    pub formatter_sha256: String,
    pub boot_timeout_seconds: u16,
    pub kernel_arguments: String,
    pub images: Vec<BaseImage>,
    #[serde(default)]
    pub artifactd: Option<ArtifactdSettings>,
    #[serde(default)]
    pub network_namespace_root: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactdSettings {
    pub prepared_root: PathBuf,
    pub prepared_size_mib: u32,
    pub socket: PathBuf,
    pub server_uid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution(root: &str) -> Execution {
        Execution {
            operator_root: root.into(),
            cgroup_parent: "/sys/fs/cgroup".into(),
            drive_directory: "/var/lib/apollo-sandboxd/drives".into(),
            formatter: "/opt/formatter".into(),
            formatter_sha256: "0".repeat(64),
            boot_timeout_seconds: 30,
            kernel_arguments: "console=ttyS0 pci=off".into(),
            images: vec![BaseImage {
                digest: ImageDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                architecture: Architecture::X86_64,
                path: "/opt/base.ext4".into(),
            }],
            artifactd: None,
            network_namespace_root: None,
        }
    }

    #[test]
    fn startup_rejects_unusable_socket_paths_and_guest_identity_override() {
        assert!(execution("/aaaaaaaaa").validate().is_ok());
        assert!(execution("/aaaaaaaaaa").validate().is_err());
        let mut config = execution("/a");
        config.kernel_arguments = "sandboxd.boot-nonce=forged".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn cleanup_accepts_an_owned_legacy_root_that_can_no_longer_launch() {
        let config = execution("/var/lib/apollo-sandboxd/native-boot");
        assert!(config.validate().is_err());
        assert!(config.validate_for_cleanup().is_ok());
    }

    #[test]
    fn execution_rejects_invalid_artifactd_endpoint() {
        let mut config = execution("/a");
        config.artifactd = Some(ArtifactdSettings {
            prepared_root: "/var/lib/apollo/prepared".into(),
            prepared_size_mib: 512,
            socket: "/run/artifactd.sock".into(),
            server_uid: 1001,
        });
        assert!(config.validate().is_ok());
        config.artifactd.as_mut().unwrap().server_uid = 0;
        assert!(config.validate().is_err());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseImage {
    pub digest: ImageDigest,
    pub architecture: Architecture,
    pub path: PathBuf,
}

impl Execution {
    pub fn validate(&self) -> Result<()> {
        self.validate_inner(true)
    }

    pub(crate) fn validate_for_cleanup(&self) -> Result<()> {
        self.validate_inner(false)
    }

    fn validate_inner(&self, check_socket_paths: bool) -> Result<()> {
        crate::session::validate_kernel_arguments(&self.kernel_arguments)?;
        if self.boot_timeout_seconds == 0
            || self.boot_timeout_seconds > 120
            || self.kernel_arguments.len() > 1024
            || self.images.is_empty()
            || self.images.len() > 1024
        {
            return Err(Error::Config("invalid execution catalog bounds"));
        }
        super::config::validate_artifact(&self.formatter, &self.formatter_sha256)?;
        let mut digests = BTreeSet::new();
        for image in &self.images {
            if !image.path.is_absolute() || !digests.insert(&image.digest) {
                return Err(Error::Config("invalid or duplicate base image catalog"));
            }
        }
        for root in [
            &self.operator_root,
            &self.drive_directory,
            &self.cgroup_parent,
        ] {
            if !root.is_absolute()
                || root.components().any(|c| {
                    !matches!(
                        c,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                })
            {
                return Err(Error::Path);
            }
        }
        if let Some(root) = &self.network_namespace_root {
            if !root.is_absolute()
                || root
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(Error::Path);
            }
        }
        if let Some(artifactd) = &self.artifactd {
            if !artifactd.prepared_root.is_absolute()
                || artifactd.prepared_size_mib == 0
                || artifactd.prepared_size_mib > 1_048_576
                || !artifactd.socket.is_absolute()
                || artifactd.server_uid == 0
            {
                return Err(Error::Config("invalid artifactd endpoint"));
            }
        }
        // The generated session identity has 56 bytes. Include the longest
        // Firecracker Unix endpoint (and the guest-port listener suffix).
        // Linux sockaddr_un permits 107 path bytes plus its terminating NUL.
        if check_socket_paths {
            let session = format!("session-{}", "0".repeat(48));
            for socket in ["firecracker.socket", "vsock.socket_1024"] {
                if self
                    .operator_root
                    .join("firecracker")
                    .join(&session)
                    .join("root/run")
                    .join(socket)
                    .as_os_str()
                    .len()
                    > 107
                {
                    return Err(Error::Config(
                        "execution root exceeds Firecracker Unix socket path limit",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn validate_roots(&self) -> Result<()> {
        self.validate()?;
        self.validate_root_ownership()?;
        crate::session::validate_mount_anchor(&self.operator_root)
    }

    pub(crate) fn validate_cleanup_roots(&self) -> Result<()> {
        self.validate_for_cleanup()?;
        self.validate_root_ownership()
    }

    fn validate_root_ownership(&self) -> Result<()> {
        for path in [&self.operator_root, &self.drive_directory] {
            let directory = SecureDir::open(path)?;
            let stat = rustix::fs::fstat(directory.as_fd())?;
            if stat.st_uid != 0 || stat.st_mode & 0o777 != 0o700 {
                return Err(Error::Path);
            }
        }
        SecureDir::open(&self.cgroup_parent)?;
        Ok(())
    }
}
