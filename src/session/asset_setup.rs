//! Persisted progress for root and asset mounts before a complete manifest exists.
use super::{AssetIdentity, AssetsManifest, MountedAsset};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Recovery facts recorded before each corresponding mount effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetSetup {
    pub(crate) root: PathBuf,
    pub(crate) anchor_identity: AssetIdentity,
    pub(crate) anchor_mount_id: u64,
    pub(crate) mount_namespace_identity: AssetIdentity,
    pub(crate) session_identity: Option<AssetIdentity>,
    pub(crate) root_identity: Option<AssetIdentity>,
    pub(crate) run_identity: Option<AssetIdentity>,
    pub(crate) root_parent_mount_id: Option<u64>,
    pub(crate) root_mount_id: Option<u64>,
    pub(crate) assets: Vec<AssetSetupEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssetSetupEntry {
    pub(crate) path: PathBuf,
    pub(crate) source_identity: AssetIdentity,
    pub(crate) read_only: bool,
    pub(crate) placeholder_identity: Option<AssetIdentity>,
    pub(crate) mount_id: Option<u64>,
}

impl AssetSetup {
    pub(crate) fn validate(&self, expected_root: &Path) -> Result<()> {
        const NAMES: [&str; 4] = ["vmlinux", "initramfs", "base.img", "state.img"];
        let mut volume_ids = BTreeSet::new();
        if self.root != expected_root
            || self.anchor_mount_id == 0
            || self.mount_namespace_identity.inode == 0
            || self.assets.len() < NAMES.len()
            || self.assets.len() > NAMES.len() + 16
            || self.assets[..NAMES.len()]
                .iter()
                .zip(NAMES)
                .any(|(asset, name)| asset.path != self.root.join(name))
            || self.assets[NAMES.len()..].iter().any(|asset| {
                let id = asset
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_prefix("volume-")?.strip_suffix(".img"));
                asset.path.parent() != Some(self.root.as_path())
                    || id
                        .and_then(|value| sandboxd_protocol::VolumeId::new(value.to_owned()).ok())
                        .is_none_or(|value| !volume_ids.insert(value.to_string()))
            })
        {
            return Err(Error::State);
        }
        let root_observed = [
            self.session_identity.is_some(),
            self.root_identity.is_some(),
            self.run_identity.is_some(),
            self.root_parent_mount_id.is_some(),
        ];
        if root_observed.iter().any(|value| *value) && !root_observed.iter().all(|value| *value) {
            return Err(Error::State);
        }
        if self.root_mount_id.is_some() && self.root_parent_mount_id.is_none()
            || self
                .root_parent_mount_id
                .is_some_and(|id| id != self.anchor_mount_id)
            || self
                .root_mount_id
                .is_some_and(|id| id == 0 || Some(id) == self.root_parent_mount_id)
        {
            return Err(Error::State);
        }
        let mut pending = false;
        for asset in &self.assets {
            if asset.mount_id.is_some() && asset.placeholder_identity.is_none()
                || asset.mount_id.is_some() && self.root_mount_id.is_none()
                || asset
                    .mount_id
                    .is_some_and(|id| id == 0 || Some(id) == self.root_mount_id)
                || asset.placeholder_identity.is_some() && self.root_mount_id.is_none()
            {
                return Err(Error::State);
            }
            if pending && (asset.placeholder_identity.is_some() || asset.mount_id.is_some()) {
                return Err(Error::State);
            }
            pending |= asset.mount_id.is_none();
        }
        Ok(())
    }

    /// Checks that a new journal value only adds stable observations.
    pub(crate) fn ensure_successor_of(&self, previous: &Self) -> Result<()> {
        previous.validate(&previous.root)?;
        self.validate(&previous.root)?;
        if self.root != previous.root
            || self.anchor_identity != previous.anchor_identity
            || self.anchor_mount_id != previous.anchor_mount_id
            || self.mount_namespace_identity != previous.mount_namespace_identity
            || !option_is_monotonic(previous.session_identity, self.session_identity)
            || !option_is_monotonic(previous.root_identity, self.root_identity)
            || !option_is_monotonic(previous.run_identity, self.run_identity)
            || !option_is_monotonic(previous.root_parent_mount_id, self.root_parent_mount_id)
            || !option_is_monotonic(previous.root_mount_id, self.root_mount_id)
            || previous.assets.len() != self.assets.len()
            || previous.assets.iter().zip(&self.assets).any(|(old, new)| {
                old.path != new.path
                    || old.source_identity != new.source_identity
                    || old.read_only != new.read_only
                    || !option_is_monotonic(old.placeholder_identity, new.placeholder_identity)
                    || !option_is_monotonic(old.mount_id, new.mount_id)
            })
        {
            return Err(Error::State);
        }
        Ok(())
    }

    pub(crate) fn complete_manifest(&self) -> Result<AssetsManifest> {
        self.validate(&self.root)?;
        let assets = self
            .assets
            .iter()
            .map(|asset| {
                Ok(MountedAsset {
                    path: asset.path.clone(),
                    identity: asset.source_identity,
                    read_only: asset.read_only,
                    anonymous: false,
                    placeholder_identity: Some(asset.placeholder_identity.ok_or(Error::State)?),
                    mount_id: Some(asset.mount_id.ok_or(Error::State)?),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(AssetsManifest {
            root: self.root.clone(),
            root_identity: self.root_identity.ok_or(Error::State)?,
            root_mount_id: Some(self.root_mount_id.ok_or(Error::State)?),
            mount_anchor_identity: Some(self.anchor_identity),
            mount_anchor_id: Some(self.anchor_mount_id),
            session_identity: Some(self.session_identity.ok_or(Error::State)?),
            run_identity: Some(self.run_identity.ok_or(Error::State)?),
            mount_namespace_identity: Some(self.mount_namespace_identity),
            assets,
        })
    }
}

fn option_is_monotonic<T: Eq>(previous: Option<T>, next: Option<T>) -> bool {
    match (previous, next) {
        (None, _) => true,
        (Some(previous), Some(next)) => previous == next,
        (Some(_), None) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> AssetSetup {
        let root = PathBuf::from("/operator/firecracker/session/root");
        AssetSetup {
            root: root.clone(),
            anchor_identity: AssetIdentity {
                device: 1,
                inode: 2,
            },
            anchor_mount_id: 3,
            mount_namespace_identity: AssetIdentity {
                device: 4,
                inode: 5,
            },
            session_identity: None,
            root_identity: None,
            run_identity: None,
            root_parent_mount_id: None,
            root_mount_id: None,
            assets: ["vmlinux", "initramfs", "base.img", "state.img"]
                .into_iter()
                .map(|name| AssetSetupEntry {
                    path: root.join(name),
                    source_identity: AssetIdentity {
                        device: 6,
                        inode: 7,
                    },
                    read_only: name != "state.img",
                    placeholder_identity: None,
                    mount_id: None,
                })
                .collect(),
        }
    }

    fn root_mounted_setup() -> AssetSetup {
        let mut setup = setup();
        setup.session_identity = Some(AssetIdentity {
            device: 8,
            inode: 9,
        });
        setup.root_identity = Some(AssetIdentity {
            device: 10,
            inode: 11,
        });
        setup.run_identity = Some(AssetIdentity {
            device: 12,
            inode: 13,
        });
        setup.root_parent_mount_id = Some(3);
        setup.root_mount_id = Some(14);
        setup
    }

    #[test]
    fn successor_accepts_exact_replay_and_new_progress() {
        let initial = setup();
        initial.ensure_successor_of(&initial).unwrap();

        let mut progressed = root_mounted_setup();
        progressed.assets[0].placeholder_identity = Some(AssetIdentity {
            device: 15,
            inode: 16,
        });
        progressed.ensure_successor_of(&initial).unwrap();
    }

    #[test]
    fn successor_rejects_progress_rollback() {
        let progressed = root_mounted_setup();
        assert!(setup().ensure_successor_of(&progressed).is_err());
    }

    #[test]
    fn successor_rejects_anchor_and_source_conflicts() {
        let previous = setup();

        let mut changed_anchor = previous.clone();
        changed_anchor.anchor_mount_id += 1;
        assert!(changed_anchor.ensure_successor_of(&previous).is_err());

        let mut changed_source = previous.clone();
        changed_source.assets[0].source_identity.inode += 1;
        assert!(changed_source.ensure_successor_of(&previous).is_err());
    }
}
