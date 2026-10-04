//! Descriptor-pinned assets mounted into the jailer's pre-created root.
use super::asset_mount::{
    bind_fd, create_private_root, current_namespace_identity, ensure_private_anchor, observed_id,
    remount_read_only, require_private, unmount,
};
use super::asset_setup::{AssetSetup, AssetSetupEntry};
use crate::{
    error::{Error, Result},
    runtime::VerifiedArtifact,
    security::path::SecureDir,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetIdentity {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountedAsset {
    pub path: PathBuf,
    pub identity: AssetIdentity,
    pub read_only: bool,
    #[serde(default)]
    pub anonymous: bool,
    #[serde(default)]
    pub placeholder_identity: Option<AssetIdentity>,
    #[serde(default)]
    pub mount_id: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetsManifest {
    pub root: PathBuf,
    pub root_identity: AssetIdentity,
    /// Exact private self-bind that contains all session asset mounts.
    /// Legacy manifests omit this and use the host mount containing `root`.
    #[serde(default)]
    pub root_mount_id: Option<u64>,
    #[serde(default)]
    pub mount_anchor_identity: Option<AssetIdentity>,
    #[serde(default)]
    pub mount_anchor_id: Option<u64>,
    #[serde(default)]
    pub session_identity: Option<AssetIdentity>,
    #[serde(default)]
    pub run_identity: Option<AssetIdentity>,
    /// Mount IDs are scoped to the mount namespace that observed them.
    /// Legacy records omit this and must be rebound before unmounting.
    #[serde(default)]
    pub mount_namespace_identity: Option<AssetIdentity>,
    pub assets: Vec<MountedAsset>,
}

pub struct AssetInputs<'a> {
    pub operator_root: &'a Path,
    pub session_id: &'a str,
    pub kernel: &'a VerifiedArtifact,
    pub initramfs: &'a VerifiedArtifact,
    pub base: &'a VerifiedArtifact,
    pub state: &'a File,
    pub volumes: &'a [AssetVolume<'a>],
}

pub struct AssetVolume<'a> {
    pub volume_id: &'a str,
    pub file: &'a File,
    pub read_only: bool,
}
pub struct StagedAssets {
    pub manifest: AssetsManifest,
}

impl StagedAssets {
    /// Creates the exact jailer root and bind mounts only retained descriptors.
    /// `persist` must durably record every progress value before this method
    /// performs the corresponding root, placeholder, or bind effect.
    pub fn prepare(
        input: AssetInputs<'_>,
        mut persist: impl FnMut(&AssetSetup) -> Result<()>,
    ) -> Result<Self> {
        validate_id(input.session_id)?;
        let mount_namespace_identity = current_namespace_identity()?;
        let anchor = prepare_anchor(input.operator_root)?;
        let mount_anchor_id = ensure_private_anchor(&anchor)?;
        let mount_anchor_identity = identity(&fs::symlink_metadata(&anchor)?);
        let exec = SecureDir::open(&anchor)?;
        match exec.open_child(input.session_id) {
            Ok(_) => return Err(Error::Path),
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
            Err(error) => return Err(error),
        }
        let root = anchor.join(input.session_id).join("root");
        let mut sources = vec![
            (&input.kernel.file, "vmlinux".to_owned(), true),
            (&input.initramfs.file, "initramfs".to_owned(), true),
            (&input.base.file, "base.img".to_owned(), true),
            (input.state, "state.img".to_owned(), false),
        ];
        for volume in input.volumes {
            sources.push((
                &volume.file,
                crate::volume_catalog::staged_name(volume.volume_id)?,
                volume.read_only,
            ));
        }
        let mut setup = AssetSetup {
            root: root.clone(),
            anchor_identity: mount_anchor_identity,
            anchor_mount_id: mount_anchor_id,
            mount_namespace_identity,
            session_identity: None,
            root_identity: None,
            run_identity: None,
            root_parent_mount_id: None,
            root_mount_id: None,
            assets: sources
                .iter()
                .map(|(source, name, read_only)| {
                    let metadata = source.metadata()?;
                    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() == 0 {
                        return Err(Error::Artifact("asset descriptor is not a regular file"));
                    }
                    Ok(AssetSetupEntry {
                        path: root.join(name),
                        source_identity: identity(&metadata),
                        read_only: *read_only,
                        placeholder_identity: None,
                        mount_id: None,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        };
        persist(&setup)?;
        let prepared = (|| {
            prepare_root(&anchor, input.session_id)?;
            let root_meta = fs::symlink_metadata(&root)?;
            let session_meta = fs::symlink_metadata(root.parent().ok_or(Error::Path)?)?;
            let run_meta = fs::symlink_metadata(root.join("run"))?;
            let root_parent_mount_id = observed_id(&root)?;
            if root_parent_mount_id != mount_anchor_id {
                return Err(Error::Path);
            }
            setup.session_identity = Some(identity(&session_meta));
            setup.root_identity = Some(identity(&root_meta));
            setup.run_identity = Some(identity(&run_meta));
            setup.root_parent_mount_id = Some(root_parent_mount_id);
            persist(&setup)?;

            let root_mount_id = create_private_root(&root)?;
            setup.root_mount_id = Some(root_mount_id);
            if let Err(error) = persist(&setup) {
                let _ = unmount(&root);
                return Err(error);
            }
            for (index, (source, _, _)) in sources.iter().enumerate() {
                mount_asset(source, index, &mut setup, &mut persist)?;
            }
            Ok(Self {
                manifest: setup.complete_manifest()?,
            })
        })();
        if prepared.is_err() {
            let _ = super::asset_recovery::recover_setup(&setup);
        }
        prepared
    }
    pub fn unmount(self) -> Result<()> {
        unmount_manifest_assets(&self.manifest)
    }
}

/// Unmounts only the descriptor-pinned mountpoints recorded in durable state.
/// A replacement inode is rejected before any unmount is attempted.
pub(crate) fn unmount_manifest_assets(manifest: &AssetsManifest) -> Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use std::os::fd::AsRawFd;
    if (!manifest.assets.is_empty() || manifest.root_mount_id.is_some())
        && manifest.mount_namespace_identity != Some(current_namespace_identity()?)
    {
        return Err(Error::Path);
    }
    let session_path = manifest.root.parent().ok_or(Error::Path)?;
    let parent = match (manifest.mount_anchor_identity, manifest.mount_anchor_id) {
        (Some(expected_identity), Some(expected_id)) => {
            let anchor_path = session_path.parent().ok_or(Error::Path)?;
            let anchor = SecureDir::open(anchor_path)?;
            let stat = rustix::fs::fstat(anchor.as_fd())?;
            if crate::security::path::device_id(stat.st_dev) != expected_identity.device
                || stat.st_ino != expected_identity.inode
            {
                return Err(Error::Path);
            }
            let anchor_target = format!("/proc/self/fd/{}/.", anchor.as_fd().as_raw_fd());
            if observed_id(Path::new(&anchor_target))? != expected_id {
                return Err(Error::Path);
            }
            require_private(expected_id)?;
            let session_name = session_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(Error::Path)?;
            match anchor.open_child(session_name) {
                Ok(session) => session,
                Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        (None, None) => match SecureDir::open(session_path) {
            Ok(parent) => parent,
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
            Err(error) => return Err(error),
        },
        _ => return Err(Error::Path),
    };
    let session = rustix::fs::fstat(parent.as_fd())?;
    let expected_session = manifest.session_identity.ok_or(Error::Path)?;
    if crate::security::path::device_id(session.st_dev) != expected_session.device
        || session.st_ino != expected_session.inode
    {
        return Err(Error::Path);
    }
    let root_meta = match parent.stat("root") {
        Ok(meta) => meta,
        Err(Error::Kernel(rustix::io::Errno::NOENT)) => return Ok(()),
        Err(error) => return Err(error),
    };
    if crate::security::path::device_id(root_meta.st_dev) != manifest.root_identity.device
        || root_meta.st_ino != manifest.root_identity.inode
        || FileType::from_raw_mode(root_meta.st_mode) != FileType::Directory
    {
        return Err(Error::Path);
    }
    let root = rustix::fs::openat(
        parent.as_fd(),
        "root",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let root_target = format!("/proc/self/fd/{}/.", root.as_raw_fd());
    let mut root_mounted = false;
    if let Some(expected) = manifest.root_mount_id {
        let observed = observed_id(Path::new(&root_target))?;
        if observed == expected {
            require_private(expected)?;
            root_mounted = true;
        } else {
            let parent_target = format!("/proc/self/fd/{}/.", parent.as_fd().as_raw_fd());
            if observed != observed_id(Path::new(&parent_target))? {
                return Err(Error::Path);
            }
            for asset in &manifest.assets {
                let name = asset
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(Error::Path)?;
                match rustix::fs::statat(&root, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Err(rustix::io::Errno::NOENT) => {}
                    Ok(_) => return Err(Error::Path),
                    Err(error) => return Err(error.into()),
                }
            }
            return Ok(());
        }
    } else if !manifest.assets.is_empty() {
        require_private(observed_id(Path::new(&root_target))?)?;
    }
    for asset in manifest.assets.iter().rev() {
        if asset.path.parent() != Some(manifest.root.as_path()) {
            return Err(Error::Path);
        }
        let name = asset
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::Path)?;
        let metadata = match rustix::fs::statat(&root, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        let observed = AssetIdentity {
            device: crate::security::path::device_id(metadata.st_dev),
            inode: metadata.st_ino,
        };
        let placeholder = asset.placeholder_identity.ok_or(Error::Path)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_nlink
                != if asset.anonymous && observed == asset.identity {
                    0
                } else {
                    1
                }
        {
            return Err(Error::Path);
        }
        if observed == asset.identity {
            let target = format!("/proc/self/fd/{}/{}", root.as_raw_fd(), name);
            let expected_mount_id = asset.mount_id.ok_or(Error::Path)?;
            if observed_id(Path::new(&target))? != expected_mount_id {
                return Err(Error::Path);
            }
            unmount(Path::new(&target))?;
        } else if observed != placeholder {
            return Err(Error::Path);
        }
        let metadata = rustix::fs::statat(&root, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if crate::security::path::device_id(metadata.st_dev) != placeholder.device
            || metadata.st_ino != placeholder.inode
            || FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_nlink != 1
            || metadata.st_size != 0
            || metadata.st_uid != rustix::process::geteuid().as_raw()
        {
            return Err(Error::Path);
        }
        rustix::fs::unlinkat(&root, name, AtFlags::empty())?;
        rustix::fs::fsync(&root)?;
    }
    if root_mounted {
        let expected = manifest.root_mount_id.ok_or(Error::State)?;
        if observed_id(Path::new(&root_target))? != expected {
            return Err(Error::Path);
        }
        unmount(Path::new(&root_target))?;
        let visible_root = format!("/proc/self/fd/{}/root", parent.as_fd().as_raw_fd());
        let parent_target = format!("/proc/self/fd/{}/.", parent.as_fd().as_raw_fd());
        if observed_id(Path::new(&visible_root))? != observed_id(Path::new(&parent_target))? {
            return Err(Error::Path);
        }
    }
    Ok(())
}

fn prepare_anchor(base: &Path) -> Result<PathBuf> {
    let parent = SecureDir::open(base)?;
    parent.open_child("firecracker")?;
    Ok(base.join("firecracker"))
}

fn prepare_root(anchor: &Path, id: &str) -> Result<PathBuf> {
    let exec = SecureDir::open(anchor)?;
    let session = match exec.create_private_directory(id) {
        Ok(session) => session,
        Err(Error::Kernel(rustix::io::Errno::EXIST)) => return Err(Error::Path),
        Err(error) => return Err(error),
    };
    let root = session.create_private_directory("root")?;
    // Jailer and Firecracker create their Unix sockets below this directory;
    // pre-create it so the VMM cannot depend on an ambient host path.
    root.create_private_directory("run")?;
    Ok(anchor.join(id).join("root"))
}

fn mount_asset(
    source: &File,
    index: usize,
    setup: &mut AssetSetup,
    persist: &mut impl FnMut(&AssetSetup) -> Result<()>,
) -> Result<()> {
    let target = setup.assets.get(index).ok_or(Error::State)?.path.clone();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&target)?;
    let placeholder_identity = identity(&file.metadata()?);
    file.sync_all()?;
    File::open(target.parent().ok_or(Error::Path)?)?.sync_all()?;
    drop(file);
    setup.assets[index].placeholder_identity = Some(placeholder_identity);
    persist(setup)?;
    bind_fd(source, &target)?;
    let mounted = (|| {
        if setup.assets[index].read_only {
            remount_read_only(&target)?;
        }
        let target_meta = fs::symlink_metadata(&target)?;
        if !target_meta.is_file()
            || target_meta.file_type().is_symlink()
            || identity(&target_meta) != setup.assets[index].source_identity
        {
            return Err(Error::Path);
        }
        Ok(observed_id(&target)?)
    })();
    let mount_id = match mounted {
        Ok(id) => id,
        Err(error) => {
            unmount(&target)?;
            return Err(error);
        }
    };
    setup.assets[index].mount_id = Some(mount_id);
    if let Err(error) = persist(setup) {
        unmount(&target)?;
        return Err(error);
    }
    Ok(())
}

pub(super) fn identity(meta: &fs::Metadata) -> AssetIdentity {
    AssetIdentity {
        device: meta.dev(),
        inode: meta.ino(),
    }
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 120 || id == "." || id == ".." || id.contains(['/', '\\', '\0'])
    {
        return Err(Error::Path);
    }
    Ok(())
}
