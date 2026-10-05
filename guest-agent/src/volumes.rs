//! Mounts host-authorized virtio block volumes inside the guest root.
use guest_protocol::ExecutionMount;
use guest_protocol::GuestVolumeConfig;
use sandboxd_protocol::VolumeId;
use std::{
    collections::BTreeMap,
    fs::File,
    sync::{Mutex, OnceLock},
};
static VOLUMES: OnceLock<Mutex<BTreeMap<VolumeId, (GuestVolumeConfig, File)>>> = OnceLock::new();
fn registry() -> &'static Mutex<BTreeMap<VolumeId, (GuestVolumeConfig, File)>> {
    VOLUMES.get_or_init(|| Mutex::new(BTreeMap::new()))
}
pub(crate) fn selected(id: &VolumeId) -> Result<File, String> {
    registry()
        .lock()
        .map_err(|_| "volume registry unavailable")?
        .get(id)
        .ok_or("unconfigured volume ID")?
        .1
        .try_clone()
        .map_err(|_| "duplicate configured volume".into())
}
pub(crate) fn execution(mounts: &[ExecutionMount]) -> Result<Vec<(VolumeId, File, bool)>, String> {
    let registry = registry()
        .lock()
        .map_err(|_| "volume registry unavailable")?;
    let mut result = Vec::new();
    for mount in mounts {
        if let ExecutionMount::Volume {
            volume_id,
            readonly,
            ..
        } = mount
        {
            let (config, file) = registry
                .get(volume_id)
                .ok_or("unconfigured execution volume")?;
            if config.read_only && !readonly {
                return Err("execution cannot weaken volume readonly policy".into());
            }
            if !result.iter().any(|(id, _, _)| id == volume_id) {
                result.push((
                    volume_id.clone(),
                    file.try_clone().map_err(|_| "duplicate execution volume")?,
                    config.read_only,
                ));
            }
        }
    }
    Ok(result)
}
#[cfg(target_os = "linux")]
use nix::mount::{MsFlags, mount};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub fn configure(volumes: &[GuestVolumeConfig]) -> Result<(), String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = volumes;
        return Err("catalog volume mounts require Linux".into());
    }
    #[cfg(target_os = "linux")]
    {
        if volumes.len() > 16 {
            return Err("guest volume count limit".into());
        }
        let mut registry = registry()
            .lock()
            .map_err(|_| "volume registry unavailable")?;
        if !registry.is_empty() {
            return if registry.len() == volumes.len()
                && volumes.iter().all(|config| {
                    registry
                        .get(&config.volume_id)
                        .is_some_and(|(old, _)| old == config)
                }) {
                Ok(())
            } else {
                Err("volume configuration is immutable".into())
            };
        }
        for (index, volume) in volumes.iter().enumerate() {
            if usize::from(volume.device_index) != index
                || !valid_mount_point(&volume.mount_point)
                || !matches!(
                    volume.filesystem.as_str(),
                    "ext4" | "xfs" | "btrfs" | "vfat"
                )
            {
                return Err("invalid guest volume configuration".into());
            }
            let anchor = format!("/run/apollo-volumes/{index}");
            let target = Path::new(&anchor);
            ensure_mount_point(target)?;
            let device = format!("/dev/vd{}", char::from(b'c' + volume.device_index));
            let mut flags = MsFlags::MS_NODEV | MsFlags::MS_NOSUID;
            if volume.read_only {
                flags |= MsFlags::MS_RDONLY;
            }
            mount(
                Some(device.as_str()),
                target,
                Some(volume.filesystem.as_str()),
                flags,
                None::<&str>,
            )
            .map_err(|error| format!("mount catalog volume: {error}"))?;
            let file = File::open(target).map_err(|_| "pin configured volume directory")?;
            registry.insert(volume.volume_id.clone(), (volume.clone(), file));
        }
        Ok(())
    }
}

fn valid_mount_point(value: &str) -> bool {
    value.len() <= 4096
        && value.starts_with('/')
        && value != "/"
        && !value.contains('\0')
        && Path::new(value)
            .components()
            .skip(1)
            .all(|part| matches!(part, Component::Normal(_)))
}

fn ensure_mount_point(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err("invalid guest mount path".into());
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("refusing symlink guest mount target".into());
            }
            Ok(metadata) if metadata.is_dir() => (),
            Ok(_) => return Err("guest mount target is not a directory".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .map_err(|error| format!("create guest mount target: {error}"))?;
            }
            Err(error) => return Err(format!("inspect guest mount target: {error}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_targets_reject_symlink_ancestors() {
        let root = tempfile::tempdir().expect("temp dir");
        let link = root.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink("/tmp", &link).expect("symlink");
        assert!(ensure_mount_point(&link.join("data")).is_err());
    }
}

// Authoring gate: exact configured descriptor and policy are the guest authority
// boundary. No host protocol test can detect selecting another configured inode.
#[cfg(test)]
mod authority_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    #[test]
    fn execution_uses_only_configured_descriptor_and_preserves_readonly_policy() {
        let id = VolumeId::new("admitted-disk").unwrap();
        let mounts = |readonly| {
            vec![ExecutionMount::Volume {
                volume_id: id.clone(),
                target: "/work".into(),
                readonly,
            }]
        };
        assert!(execution(&mounts(true)).is_err());
        let root = tempfile::tempdir().unwrap();
        let file = File::open(root.path()).unwrap();
        let inode = file.metadata().unwrap().ino();
        let config = GuestVolumeConfig {
            volume_id: id.clone(),
            device_index: 0,
            mount_point: "/run/apollo-volumes/0".into(),
            filesystem: "ext4".into(),
            read_only: true,
        };
        registry()
            .lock()
            .unwrap()
            .insert(id.clone(), (config, file));
        assert!(execution(&mounts(false)).is_err());
        let selected = execution(&mounts(true)).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, id);
        assert_eq!(selected[0].1.metadata().unwrap().ino(), inode);
        assert!(selected[0].2);
        assert_eq!(
            self::selected(&id).unwrap().metadata().unwrap().ino(),
            inode
        );
        registry().lock().unwrap().clear();
    }
}
