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
    state: super::state_worker::StateClient,
    pub execution: Execution,
    pub boot_id: String,
    pub max_disk: u64,
    pub snapshots_enabled: bool,
    catalogs: Mutex<VerifiedCatalogs>,
    images: BTreeMap<ImageDigest, (Architecture, VerifiedArtifact)>,
    prepared: Mutex<BTreeMap<ImageDigest, (Architecture, VerifiedArtifact)>>,
    prepared_config: Mutex<BTreeMap<ImageDigest, crate::image::RuntimeConfig>>,
    formatter: VerifiedArtifact,
    dynamic_volumes: Mutex<BTreeMap<(u32, String), crate::state::DynamicVolumeRecord>>,
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
    pub fn new(
        config: &Config,
        catalogs: VerifiedCatalogs,
        state: super::state_worker::StateClient,
    ) -> Result<Self> {
        Self::new_inner(config, catalogs, state, false)
    }

    pub fn new_for_cleanup(
        config: &Config,
        catalogs: VerifiedCatalogs,
        state: super::state_worker::StateClient,
    ) -> Result<Self> {
        Self::new_inner(config, catalogs, state, true)
    }

    fn new_inner(
        config: &Config,
        catalogs: VerifiedCatalogs,
        state: super::state_worker::StateClient,
        cleanup: bool,
    ) -> Result<Self> {
        native_architecture().ok_or(Error::Config(
            "native Linux x86_64 or aarch64 KVM execution required",
        ))?;
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
            state,
            execution,
            boot_id,
            max_disk: u64::from(config.quotas.max_state_disk_mib) * 1_048_576,
            snapshots_enabled: config.snapshots.is_some(),
            catalogs: Mutex::new(catalogs),
            images,
            prepared: Mutex::new(BTreeMap::new()),
            prepared_config: Mutex::new(BTreeMap::new()),
            formatter,
            dynamic_volumes: Mutex::new(BTreeMap::new()),
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

    #[cfg(target_os = "linux")]
    pub(super) fn image_formatter(&self) -> Result<VerifiedArtifact> {
        self.formatter.duplicate()
    }

    #[cfg(target_os = "linux")]
    pub(super) fn artifactd_settings(&self) -> Result<crate::config::ArtifactdSettings> {
        self.execution
            .artifactd
            .clone()
            .ok_or(Error::Config("Artifactd settings unavailable"))
    }

    pub(super) fn retire_dynamic_volume(
        &self,
        uid: u32,
        backing: &sandboxd_protocol::VolumeBacking,
    ) -> Result<()> {
        self.dynamic_volumes
            .lock()
            .map_err(|_| Error::State)?
            .remove(&(uid, backing.id.clone()));
        Ok(())
    }
    pub(super) fn prepared_volume_source(
        &self,
        image: &ImageDigest,
        size: u64,
    ) -> Result<VerifiedArtifact> {
        let mut source = self
            .prepared
            .lock()
            .map_err(|_| Error::State)?
            .get(image)
            .ok_or(Error::Config("verified prepared image unavailable"))?
            .1
            .duplicate()?;
        source.revalidate()?;
        if source.size != size {
            return Err(Error::Artifact("prepared volume size mismatch"));
        }
        Ok(source)
    }
    pub(super) fn register_dynamic_volume(
        &self,
        record: &crate::state::DynamicVolumeRecord,
    ) -> Result<()> {
        if !record.published || !record.info.backing.validate() {
            return Err(Error::State);
        }
        self.open_dynamic(record, false, None)?;
        self.dynamic_volumes
            .lock()
            .map_err(|_| Error::State)?
            .insert(
                (record.owner_uid, record.info.backing.id.clone()),
                record.clone(),
            );
        Ok(())
    }
    fn open_dynamic(
        &self,
        record: &crate::state::DynamicVolumeRecord,
        writable: bool,
        store: Option<&crate::state::Store>,
    ) -> Result<std::fs::File> {
        let owners = match store {
            Some(store) => store.dynamic_volume_session_owners(record)?,
            None => {
                let owned = record.clone();
                self.state
                    .with_store_blocking(move |store| store.dynamic_volume_session_owners(&owned))?
            }
        };
        crate::storage::dynamic_volume::open_pinned(
            &self.execution.drive_directory,
            record,
            writable,
            &owners,
        )
    }
    fn open_dynamic_locked(
        &self,
        record: &crate::state::DynamicVolumeRecord,
        read_only: bool,
        store: Option<&crate::state::Store>,
    ) -> Result<crate::volume_catalog::OpenVolume> {
        let file = self.open_dynamic(record, !read_only, store)?;
        rustix::fs::flock(
            &file,
            if read_only {
                rustix::fs::FlockOperation::NonBlockingLockShared
            } else {
                rustix::fs::FlockOperation::NonBlockingLockExclusive
            },
        )
        .map_err(|_| Error::Locked)?;
        Ok(crate::volume_catalog::OpenVolume {
            file,
            device: record.device,
            inode: record.inode,
            size_bytes: record.info.size_bytes,
        })
    }
    /// Called only after the caller has obtained verified process-death cleanup
    /// proof, while the retained exclusive lock and durable pin still exist.
    pub(super) fn restore_dynamic_owners(
        &self,
        pins: &SessionPins,
        held: Option<&[crate::volume_catalog::PinnedVolume]>,
    ) -> Result<()> {
        for pin in &pins.volumes {
            if pin.read_only {
                continue;
            }
            let Some(backing) = &pin.backing else {
                continue;
            };
            let (_, record) = self.dynamic_entry(pin.owner_uid.ok_or(Error::State)?, backing)?;
            if record.device != pin.device
                || record.inode != pin.inode
                || record.info.size_bytes != pin.size_bytes
            {
                return Err(Error::State);
            }
            let opened;
            let file = if let Some(held) = held {
                &held
                    .iter()
                    .find(|v| v.volume_id == pin.volume_id.as_str() && !v.read_only)
                    .ok_or(Error::State)?
                    .file
            } else {
                opened = self.open_dynamic_locked(&record, false, None)?;
                &opened.file
            };
            crate::storage::dynamic_volume::verify_identity(file, &record)?;
            rustix::fs::fchown(
                file,
                Some(rustix::process::geteuid()),
                Some(rustix::process::getegid()),
            )?;
            rustix::fs::fchmod(file, rustix::fs::Mode::from_raw_mode(0o644))?;
            file.sync_all()?;
        }
        Ok(())
    }
    fn dynamic_entry(
        &self,
        uid: u32,
        backing: &sandboxd_protocol::VolumeBacking,
    ) -> Result<(
        crate::config::VolumeCatalogEntry,
        crate::state::DynamicVolumeRecord,
    )> {
        let record = self
            .dynamic_volumes
            .lock()
            .map_err(|_| Error::State)?
            .get(&(uid, backing.id.clone()))
            .filter(|r| r.info.backing == *backing)
            .cloned()
            .ok_or(Error::Config("owner-scoped backing unavailable"))?;
        Ok((
            crate::config::VolumeCatalogEntry {
                key: backing.id.clone(),
                path: crate::storage::dynamic_volume::path(
                    &self.execution.drive_directory,
                    &backing.id,
                ),
                max_bytes: record.info.size_bytes,
                writable: record.info.writable,
            },
            record,
        ))
    }
    fn capture_volumes(
        &self,
        uid: u32,
        volumes: &[sandboxd_protocol::Volume],
        store: Option<&crate::state::Store>,
    ) -> Result<Vec<crate::state::VolumePin>> {
        let mut pins = Vec::with_capacity(volumes.len());
        let mut total = 0u64;
        let mut unique = std::collections::BTreeSet::new();
        for volume in volumes {
            let pin = if let Some(backing) = &volume.backing {
                if !unique.insert(backing.clone().id) {
                    return Err(Error::Config("duplicate dynamic backing"));
                }
                let (entry, record) = self.dynamic_entry(uid, backing)?;
                if !entry.writable && !volume.read_only {
                    return Err(Error::Config("read-only backing requested writable"));
                }
                let opened = self.open_dynamic_locked(&record, volume.read_only, store)?;
                crate::storage::dynamic_volume::verify_identity(&opened.file, &record)?;
                crate::state::VolumePin {
                    volume_id: volume.id.clone(),
                    catalog_key: String::new(),
                    backing: Some(backing.clone()),
                    owner_uid: Some(uid),
                    device: opened.device,
                    inode: opened.inode,
                    size_bytes: opened.size_bytes,
                    catalog_read_only: !entry.writable,
                    read_only: volume.read_only,
                }
            } else {
                crate::volume_catalog::capture(&self.volume_catalog, std::slice::from_ref(volume))?
                    .remove(0)
            };
            total = total
                .checked_add(pin.size_bytes)
                .filter(|n| *n <= self.max_disk)
                .ok_or(Error::Config("aggregate backing size limit"))?;
            pins.push(pin);
        }
        Ok(pins)
    }
    fn reopen_volumes(
        &self,
        pins: &[crate::state::VolumePin],
    ) -> Result<Vec<crate::volume_catalog::PinnedVolume>> {
        let mut result = Vec::with_capacity(pins.len());
        let mut total = 0u64;
        for pin in pins {
            let volume = if let Some(backing) = &pin.backing {
                let (entry, record) =
                    self.dynamic_entry(pin.owner_uid.ok_or(Error::State)?, backing)?;
                if pin.catalog_read_only == entry.writable || (!entry.writable && !pin.read_only) {
                    return Err(Error::State);
                }
                let opened = self.open_dynamic_locked(&record, pin.read_only, None)?;
                crate::storage::dynamic_volume::verify_identity(&opened.file, &record)?;
                if opened.device != pin.device
                    || opened.inode != pin.inode
                    || opened.size_bytes != pin.size_bytes
                {
                    return Err(Error::State);
                }
                crate::volume_catalog::PinnedVolume {
                    volume_id: pin.volume_id.to_string(),
                    file: opened.file,
                    read_only: pin.read_only,
                }
            } else {
                crate::volume_catalog::reopen(&self.volume_catalog, std::slice::from_ref(pin))?
                    .remove(0)
            };
            total = total
                .checked_add(pin.size_bytes)
                .filter(|n| *n <= self.max_disk)
                .ok_or(Error::State)?;
            result.push(volume);
        }
        Ok(result)
    }

    pub fn pins(&self, owner_uid: u32, spec: &SandboxSpec) -> Result<SessionPins> {
        self.pins_with_store(owner_uid, spec, None)
    }

    // Admission already holds the sole SQLite owner; never enqueue a nested lookup.
    pub(super) fn pins_with_store(
        &self,
        owner_uid: u32,
        spec: &SandboxSpec,
        store: Option<&crate::state::Store>,
    ) -> Result<SessionPins> {
        spec.validate()?;
        let native = native_architecture().ok_or(Error::Config(
            "native Linux x86_64 or aarch64 KVM execution required",
        ))?;
        if spec.architecture != native {
            return Err(ApiError::new(
                ErrorCode::UnsupportedHost,
                "requested architecture does not match the native runtime",
            )
            .into());
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
        let volume_pins = self.capture_volumes(owner_uid, &spec.volumes, store)?;
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
        let volumes = self.reopen_volumes(&pins.volumes)?;
        Ok(BootArtifacts {
            runtime,
            kernel,
            base,
            formatter: self.formatter.duplicate()?,
            volumes,
        })
    }
}

fn native_architecture() -> Option<Architecture> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    match std::env::consts::ARCH {
        "x86_64" => Some(Architecture::X86_64),
        "aarch64" => Some(Architecture::Aarch64),
        _ => None,
    }
}
