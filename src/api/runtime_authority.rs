//! Operator catalog descriptors are the only authority for host-side boot inputs.
use crate::{
    config::{Config, Execution, VolumeCatalog},
    error::{Error, Result},
    runtime::{VerifiedArtifact, VerifiedCatalogs, VerifiedKernel, VerifiedRuntime, verify},
    state::SessionPins,
};
use sandboxd_protocol::{
    ApiError, Architecture, ErrorCode, ImageDigest, SandboxSpec, exec::ExecutionSpec,
};
use std::{collections::BTreeMap, sync::Mutex};

pub(super) struct RuntimeAuthority {
    pub execution: Execution,
    pub boot_id: String,
    pub max_disk: u64,
    pub snapshots_enabled: bool,
    catalogs: Mutex<VerifiedCatalogs>,
    images: BTreeMap<ImageDigest, (Architecture, VerifiedArtifact)>,
    prepared: Mutex<BTreeMap<ImageDigest, (Architecture, VerifiedArtifact)>>,
    prepared_config: Mutex<BTreeMap<ImageDigest, crate::image::RuntimeConfig>>,
    formatter: VerifiedArtifact,
    volume_catalog: VolumeCatalog,
}

pub(super) struct BootArtifacts {
    pub runtime: VerifiedRuntime,
    pub kernel: VerifiedKernel,
    pub base: VerifiedArtifact,
    pub formatter: VerifiedArtifact,
    pub volumes: Vec<crate::volume_catalog::PinnedVolume>,
}

impl RuntimeAuthority {
    pub fn new(config: &Config, catalogs: VerifiedCatalogs) -> Result<Self> {
        Self::new_inner(config, catalogs, false)
    }

    pub fn new_for_cleanup(config: &Config, catalogs: VerifiedCatalogs) -> Result<Self> {
        Self::new_inner(config, catalogs, true)
    }

    fn new_inner(config: &Config, catalogs: VerifiedCatalogs, cleanup: bool) -> Result<Self> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err(Error::Config("native x86_64 Linux/KVM execution required"));
        }
        let execution = config
            .execution
            .clone()
            .ok_or(Error::Config("operator execution catalog required"))?;
        if cleanup {
            execution.validate_cleanup_roots()?;
        } else {
            execution.validate_roots()?;
        }
        let formatter = verify(&execution.formatter, &execution.formatter_sha256, true)?;
        let mut images = BTreeMap::new();
        for image in &execution.images {
            let digest = image
                .digest
                .as_str()
                .strip_prefix("sha256:")
                .ok_or(Error::State)?;
            images.insert(
                image.digest.clone(),
                (image.architecture, verify(&image.path, digest, false)?),
            );
        }
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        if boot_id.len() != 36 || !boot_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return Err(Error::Config("invalid host boot identity"));
        }
        Ok(Self {
            execution,
            boot_id,
            max_disk: u64::from(config.quotas.max_state_disk_mib) * 1_048_576,
            snapshots_enabled: config.snapshots.is_some(),
            catalogs: Mutex::new(catalogs),
            images,
            prepared: Mutex::new(BTreeMap::new()),
            prepared_config: Mutex::new(BTreeMap::new()),
            formatter,
            volume_catalog: config.volume_catalog.clone(),
        })
    }

    pub(super) fn register_prepared_image(
        &self,
        record: &crate::state::PreparedImageRecord,
    ) -> Result<()> {
        let digest = ImageDigest::new(record.digest.clone()).map_err(|_| Error::State)?;
        let architecture = match record.architecture.as_str() {
            "amd64" => Architecture::X86_64,
            "arm64" => Architecture::Aarch64,
            _ => return Err(Error::State),
        };
        let artifact = verify(
            std::path::Path::new(&record.rootfs_path),
            &record.rootfs_sha256,
            false,
        )?;
        if artifact.size != record.rootfs_size
            || artifact.device != record.rootfs_device
            || artifact.inode != record.rootfs_inode
            || artifact.sha256 != record.rootfs_sha256
        {
            return Err(Error::State);
        }
        self.prepared
            .lock()
            .map_err(|_| Error::State)?
            .insert(digest.clone(), (architecture, artifact));
        if let Some(bytes) = &record.config_json {
            let config: crate::image::ImageConfig =
                serde_json::from_slice(bytes).map_err(|_| Error::State)?;
            self.prepared_config
                .lock()
                .map_err(|_| Error::State)?
                .insert(digest, config.config);
        }
        Ok(())
    }

    /// Applies OCI defaults only where the public exec request leaves the
    /// field at its protocol default. Explicit argv remains authoritative.
    pub(super) fn apply_exec_defaults(
        &self,
        image: &ImageDigest,
        spec: &mut ExecutionSpec,
    ) -> Result<()> {
        let Some(config) = self
            .prepared_config
            .lock()
            .map_err(|_| Error::State)?
            .get(image)
            .cloned()
        else {
            return Ok(());
        };
        for entry in config.env {
            let Some((key, value)) = entry.split_once('=') else {
                continue;
            };
            spec.environment
                .entry(key.to_owned())
                .or_insert_with(|| value.to_owned());
        }
        if !spec.use_image_defaults {
            return Ok(());
        }
        if spec.cwd == "/" && !config.working_dir.is_empty() {
            spec.cwd = config.working_dir;
        }
        if spec.argv.is_empty() {
            spec.argv.extend(config.entrypoint);
            spec.argv.extend(config.cmd);
        }
        if spec.uid == 0 && spec.gid == 0 {
            let mut parts = config.user.split(':');
            if let Some(uid) = parts.next().filter(|value| !value.is_empty()) {
                let uid = uid.parse::<u32>().map_err(|_| {
                    Error::Config("OCI named users require guest account resolution")
                })?;
                let gid = parts
                    .next()
                    .map(|value| value.parse::<u32>())
                    .transpose()
                    .map_err(|_| {
                        Error::Config("OCI named groups require guest account resolution")
                    })?
                    .unwrap_or(uid);
                if parts.next().is_some() {
                    return Err(Error::Config("OCI user field has too many components"));
                }
                spec.uid = uid;
                spec.gid = gid;
            }
        }
        Ok(())
    }

    pub(super) fn oci_formatter(&self) -> Result<VerifiedArtifact> {
        self.formatter.duplicate()
    }

    pub(super) fn oci_settings(&self) -> Result<crate::config::OciSettings> {
        self.execution
            .oci
            .clone()
            .ok_or(Error::Config("OCI settings unavailable"))
    }

    pub fn pins(&self, spec: &SandboxSpec) -> Result<SessionPins> {
        spec.validate()?;
        if spec.architecture != Architecture::X86_64 {
            return Err(
                ApiError::new(ErrorCode::UnsupportedHost, "x86_64 execution required").into(),
            );
        }
        let static_match = self
            .images
            .get(&spec.image)
            .is_some_and(|(architecture, _)| *architecture == spec.architecture);
        let prepared_match = self
            .prepared
            .lock()
            .map_err(|_| Error::State)?
            .get(&spec.image)
            .is_some_and(|(architecture, _)| *architecture == spec.architecture);
        if !static_match && !prepared_match {
            return Err(ApiError::new(
                ErrorCode::ImageNotFound,
                "verified base image is absent from the operator catalog",
            )
            .into());
        }
        let volume_pins = crate::volume_catalog::capture(&self.volume_catalog, &spec.volumes)?;
        let mut pins = self
            .catalogs
            .lock()
            .map_err(|_| Error::State)?
            .session_pins(spec)?;
        pins.volumes = volume_pins;
        Ok(pins)
    }

    pub fn artifacts(&self, pins: &SessionPins) -> Result<BootArtifacts> {
        let (runtime, kernel) = {
            let mut catalogs = self.catalogs.lock().map_err(|_| Error::State)?;
            catalogs.revalidate_session(pins)?;
            catalogs.duplicate_for(pins)?
        };
        let (architecture, base) = if let Some(value) = self.images.get(&pins.base_image) {
            (value.0, value.1.duplicate()?)
        } else {
            let prepared = self.prepared.lock().map_err(|_| Error::State)?;
            let value = prepared
                .get(&pins.base_image)
                .ok_or(Error::Config("pinned image catalog entry is unavailable"))?;
            (value.0, value.1.duplicate()?)
        };
        if architecture != pins.architecture {
            return Err(Error::State);
        }
        let mut base = base;
        base.revalidate()?;
        let volumes = crate::volume_catalog::reopen(&self.volume_catalog, &pins.volumes)?;
        Ok(BootArtifacts {
            runtime,
            kernel,
            base,
            formatter: self.formatter.duplicate()?,
            volumes,
        })
    }
}
