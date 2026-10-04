//! Mounts host-authorized virtio block volumes inside the guest root.
use guest_protocol::GuestVolumeConfig;
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
            let target = Path::new(&volume.mount_point);
            ensure_mount_point(target)?;
            let device = format!("/dev/vd{}", char::from(b'c' + volume.device_index));
            let mut flags = MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
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
