use super::{VerifiedArtifact, VerifiedRuntime, verify, verify_runtime};
use crate::{
    config::Config,
    error::{Error, Result},
    state::SessionPins,
};
use sandboxd_protocol::{Architecture, SandboxSpec};
use std::collections::BTreeMap;

/// Trusted kernel and bootstrap inodes remain open for the daemon lifetime.
pub struct VerifiedKernel {
    pub profile_name: String,
    pub architecture: Architecture,
    pub kernel: VerifiedArtifact,
    pub initramfs: VerifiedArtifact,
}

impl VerifiedKernel {
    /// Duplicate the startup-pinned kernel descriptors for one boot job.
    pub fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            profile_name: self.profile_name.clone(),
            architecture: self.architecture,
            kernel: self.kernel.duplicate()?,
            initramfs: self.initramfs.duplicate()?,
        })
    }
}

/// Startup verification retains its handles. A later pathname replacement
/// cannot silently change a profile used for a new session.
pub struct VerifiedCatalogs {
    pub runtimes: BTreeMap<String, VerifiedRuntime>,
    pub kernels: BTreeMap<String, VerifiedKernel>,
}

impl VerifiedCatalogs {
    /// Return a descriptor-pinned launch snapshot. The catalog lock, if any,
    /// can be released before boot awaits sockets or guest readiness.
    pub fn duplicate_for(&self, pins: &SessionPins) -> Result<(VerifiedRuntime, VerifiedKernel)> {
        let runtime = self
            .runtimes
            .get(&pins.runtime_profile)
            .ok_or(Error::Artifact("pinned runtime profile is unavailable"))?;
        let kernel = self
            .kernels
            .get(&pins.kernel_profile)
            .ok_or(Error::Artifact("pinned kernel profile is unavailable"))?;
        if runtime.architecture != pins.architecture || kernel.architecture != pins.architecture {
            return Err(Error::Artifact("durable session catalog pins changed"));
        }
        Ok((runtime.duplicate()?, kernel.duplicate()?))
    }

    pub async fn load(config: &Config) -> Result<Self> {
        Self::load_inner(config, false).await
    }

    pub async fn load_for_cleanup(config: &Config) -> Result<Self> {
        Self::load_inner(config, true).await
    }

    async fn load_inner(config: &Config, cleanup: bool) -> Result<Self> {
        if cleanup {
            config.validate_for_cleanup()?;
        } else {
            config.validate()?;
        }
        let mut runtimes = BTreeMap::new();
        for profile in &config.runtimes {
            runtimes.insert(profile.name.clone(), verify_runtime(profile).await?);
        }
        let mut kernels = BTreeMap::new();
        for profile in &config.kernels {
            kernels.insert(
                profile.name.clone(),
                VerifiedKernel {
                    profile_name: profile.name.clone(),
                    architecture: profile.architecture,
                    kernel: verify(&profile.kernel, &profile.kernel_sha256, false)?,
                    initramfs: verify(&profile.initramfs, &profile.initramfs_sha256, false)?,
                },
            );
        }
        Ok(Self { runtimes, kernels })
    }

    /// Derive durable pins exclusively from verified operator catalogs. Caller
    /// image authority is still subject to image-cache verification before boot.
    pub fn session_pins(&self, spec: &SandboxSpec) -> Result<SessionPins> {
        let runtime = self
            .runtimes
            .get(&spec.runtime_profile)
            .ok_or(Error::Artifact("runtime profile is not verified"))?;
        let kernel = self
            .kernels
            .get(&spec.kernel_profile)
            .ok_or(Error::Artifact("kernel profile is not verified"))?;
        if runtime.architecture != spec.architecture || kernel.architecture != spec.architecture {
            return Err(Error::Artifact("catalog architecture mismatch"));
        }
        Ok(SessionPins {
            architecture: spec.architecture,
            runtime_profile: runtime.profile_name.clone(),
            runtime_version: runtime.version.clone(),
            firecracker_sha256: runtime.firecracker.sha256.clone(),
            jailer_sha256: runtime.jailer.sha256.clone(),
            kernel_profile: kernel.profile_name.clone(),
            kernel_sha256: kernel.kernel.sha256.clone(),
            initramfs_sha256: kernel.initramfs.sha256.clone(),
            base_image: spec.image.clone(),
            volumes: Vec::new(),
        })
    }

    /// Fail closed when live catalog observations differ from the durable
    /// session's original pins. Restart cannot repin an existing incarnation.
    pub fn revalidate_session(&mut self, pins: &SessionPins) -> Result<()> {
        let runtime = self
            .runtimes
            .get_mut(&pins.runtime_profile)
            .ok_or(Error::Artifact("pinned runtime profile is unavailable"))?;
        let kernel = self
            .kernels
            .get_mut(&pins.kernel_profile)
            .ok_or(Error::Artifact("pinned kernel profile is unavailable"))?;
        if runtime.architecture != pins.architecture
            || kernel.architecture != pins.architecture
            || runtime.version != pins.runtime_version
            || runtime.firecracker.sha256 != pins.firecracker_sha256
            || runtime.jailer.sha256 != pins.jailer_sha256
            || kernel.kernel.sha256 != pins.kernel_sha256
            || kernel.initramfs.sha256 != pins.initramfs_sha256
        {
            return Err(Error::Artifact("durable session catalog pins changed"));
        }
        runtime.firecracker.revalidate()?;
        runtime.jailer.revalidate()?;
        kernel.kernel.revalidate()?;
        kernel.initramfs.revalidate()?;
        Ok(())
    }
}
