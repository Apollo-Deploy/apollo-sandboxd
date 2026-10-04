//! Private mount-namespace recovery for legacy bind-mount placeholders.
use super::AssetsManifest;
#[cfg(target_os = "linux")]
use super::MountedAsset;
use crate::error::{Error, Result};
#[cfg(target_os = "linux")]
use std::{
    fs,
    io::{Read, Write},
    os::fd::AsFd,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
const MAX_HELPER_INPUT: usize = 16_384;
pub(crate) fn recover_mount_identities(assets: &mut AssetsManifest) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let (parent_namespace, parent_mount_ids) = observe_parent_mounts(assets)?;
        let namespace = fs::read_link("/proc/self/ns/mnt")?;
        let namespace = namespace.to_str().ok_or(Error::Path)?.to_owned();
        // Keep the helper pinned to the exact already-running daemon inode.
        // A pathname returned by `current_exe` may be replaced between this
        // observation and `execve`; the procfs executable link cannot be
        // redirected while this parent remains alive and waits for the child.
        let executable = PathBuf::from(format!("/proc/{}/exe", std::process::id()));
        let helper = unshare_program()?;
        let input = serde_json::to_vec(assets).map_err(|_| Error::State)?;
        if input.len() > MAX_HELPER_INPUT {
            return Err(Error::State);
        }
        let mut child = std::process::Command::new(helper)
            .args(["--mount", "--propagation", "private", "--"])
            .arg(executable)
            .arg("--internal-recover-mount-placeholders")
            .arg(namespace)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or(Error::State)?;
        if let Err(error) = stdin.write_all(&input) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
        drop(stdin);
        let output = child.wait_with_output()?;
        if !output.status.success() || output.stdout.len() > MAX_HELPER_INPUT {
            return Err(Error::Config(
                "private mount ownership recovery failed; quarantine required",
            ));
        }
        let mut recovered: AssetsManifest =
            serde_json::from_slice(&output.stdout).map_err(|_| Error::State)?;
        if recovered.assets.len() != parent_mount_ids.len() {
            return Err(Error::State);
        }
        recovered.mount_namespace_identity = Some(parent_namespace);
        for (asset, mount_id) in recovered.assets.iter_mut().zip(parent_mount_ids) {
            asset.mount_id = Some(mount_id);
        }
        validate_asset_manifest(assets, &recovered)?;
        *assets = recovered;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = assets;
        Err(Error::Config("legacy mount recovery requires Linux"))
    }
}

#[cfg(target_os = "linux")]
fn observe_parent_mounts(assets: &AssetsManifest) -> Result<(super::AssetIdentity, Vec<u64>)> {
    use rustix::fs::AtFlags;
    use std::os::fd::AsRawFd;

    validate_layout(assets)?;
    let namespace = super::asset_mount::current_namespace_identity()?;
    if assets
        .mount_namespace_identity
        .is_some_and(|recorded| recorded != namespace)
    {
        return Err(Error::Path);
    }
    let root = super::legacy_cleanup::open_pinned_root(assets)?;
    let root_fd = root.as_fd().as_raw_fd();
    let root_path = PathBuf::from(format!("/proc/self/fd/{root_fd}/."));
    let root_mount_id = super::asset_mount::observed_id(&root_path)?;
    let mut mount_ids = Vec::with_capacity(assets.assets.len());
    for asset in &assets.assets {
        let name = asset
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(Error::Path)?;
        let stat = rustix::fs::statat(root.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)?;
        let observed = super::AssetIdentity {
            device: crate::security::path::device_id(stat.st_dev),
            inode: stat.st_ino,
        };
        let path = PathBuf::from(format!("/proc/self/fd/{root_fd}/{name}"));
        let mount_id = super::asset_mount::observed_id(&path)?;
        validate_mount_observation(asset, observed, stat.st_nlink, mount_id, root_mount_id)?;
        super::asset_mount::require_private(mount_id).map_err(|_| {
            Error::Config("shared legacy asset mount requires explicit administrative cleanup")
        })?;
        if assets.mount_namespace_identity.is_some()
            && asset.mount_id.is_some_and(|recorded| recorded != mount_id)
        {
            return Err(Error::Path);
        }
        mount_ids.push(mount_id);
    }
    Ok((namespace, mount_ids))
}

#[cfg(target_os = "linux")]
fn unshare_program() -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    for path in ["/usr/bin/unshare", "/bin/unshare"] {
        let path = Path::new(path);
        let Ok(metadata) = fs::metadata(path) else {
            continue;
        };
        if metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
        {
            return Ok(path.to_path_buf());
        }
    }
    Err(Error::Config(
        "private mount namespace helper unavailable; quarantine required",
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn run_mount_recovery_helper(parent_namespace: &str) -> Result<()> {
    let self_namespace = fs::read_link("/proc/self/ns/mnt")?;
    let parent_pid = proc_parent_pid()?;
    let parent_namespace_observed = fs::read_link(format!("/proc/{parent_pid}/ns/mnt"))?;
    if self_namespace == parent_namespace_observed
        || parent_namespace_observed.to_str() != Some(parent_namespace)
    {
        return Err(Error::Config("mount recovery helper is not isolated"));
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take((MAX_HELPER_INPUT + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() > MAX_HELPER_INPUT {
        return Err(Error::State);
    }
    let assets: AssetsManifest = serde_json::from_slice(&input).map_err(|_| Error::State)?;
    let recovered = reveal_placeholders(&assets)?;
    serde_json::to_writer(std::io::stdout().lock(), &recovered).map_err(|_| Error::State)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn run_mount_recovery_helper(_parent_namespace: &str) -> Result<()> {
    Err(Error::Config("mount recovery requires Linux"))
}

#[cfg(target_os = "linux")]
fn proc_parent_pid() -> Result<u32> {
    let status = fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("PPid:")
                .and_then(|value| value.trim().parse().ok())
        })
        .ok_or(Error::Path)
}

#[cfg(target_os = "linux")]
fn reveal_placeholders(assets: &AssetsManifest) -> Result<AssetsManifest> {
    use rustix::fs::{AtFlags, FileType};
    use std::os::fd::AsRawFd;
    validate_layout(assets)?;
    let root = super::legacy_cleanup::open_pinned_root(assets)?;
    let root_stat = rustix::fs::fstat(root.as_fd())?;
    if crate::security::path::device_id(root_stat.st_dev) != assets.root_identity.device
        || root_stat.st_ino != assets.root_identity.inode
    {
        return Err(Error::Path);
    }
    let root_fd = root.as_fd().as_raw_fd();
    let root_path = PathBuf::from(format!("/proc/self/fd/{root_fd}/."));
    let root_mount_id = super::asset_mount::observed_id(&root_path)?;
    super::asset_mount::require_private(root_mount_id)?;
    let mut observations = Vec::with_capacity(assets.assets.len());
    for asset in &assets.assets {
        let name = asset
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(Error::Path)?;
        let stat = rustix::fs::statat(root.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)?;
        let observed = super::AssetIdentity {
            device: crate::security::path::device_id(stat.st_dev),
            inode: stat.st_ino,
        };
        let mount_path = PathBuf::from(format!("/proc/self/fd/{root_fd}/{name}"));
        let mount_id = super::asset_mount::observed_id(&mount_path)?;
        validate_mount_observation(asset, observed, stat.st_nlink, mount_id, root_mount_id)?;
        super::asset_mount::require_private(mount_id)?;
        observations.push((name.to_owned(), mount_path, mount_id));
    }
    let mut recovered = assets.clone();
    for (asset, (name, target, mount_id)) in recovered.assets.iter_mut().zip(observations) {
        rustix::mount::unmount(&target, rustix::mount::UnmountFlags::DETACH)?;
        let stat = rustix::fs::statat(root.as_fd(), name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        let placeholder = super::AssetIdentity {
            device: crate::security::path::device_id(stat.st_dev),
            inode: stat.st_ino,
        };
        let observed_mount = super::asset_mount::observed_id(&target)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || placeholder.device != crate::security::path::device_id(root_stat.st_dev)
            || stat.st_size != 0
            || stat.st_nlink != 1
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o777 != 0o600
            || observed_mount != root_mount_id
        {
            return Err(Error::Path);
        }
        if asset
            .placeholder_identity
            .is_some_and(|old| old != placeholder)
        {
            return Err(Error::Path);
        }
        asset.placeholder_identity = Some(placeholder);
        asset.mount_id = Some(mount_id);
    }
    Ok(recovered)
}

#[cfg(target_os = "linux")]
fn validate_layout(assets: &AssetsManifest) -> Result<()> {
    use std::collections::BTreeSet;

    let fixed: &[(&str, bool)] = &[
        ("vmlinux", true),
        ("initramfs", true),
        ("base.img", true),
        ("state.img", false),
    ];
    if !(4..=24).contains(&assets.assets.len()) {
        return Err(Error::Path);
    }
    for (asset, (name, read_only)) in assets.assets.iter().zip(fixed) {
        if asset.path != assets.root.join(name) || asset.read_only != *read_only || asset.anonymous
        {
            return Err(Error::Path);
        }
    }
    let mut cursor = fixed.len();
    let mut ids = BTreeSet::new();
    while let Some(asset) = assets.assets.get(cursor) {
        let Some(name) = asset.path.file_name().and_then(|name| name.to_str()) else {
            return Err(Error::Path);
        };
        let Some(id) = name
            .strip_prefix("volume-")
            .and_then(|value| value.strip_suffix(".img"))
        else {
            break;
        };
        if sandboxd_protocol::VolumeId::new(id.to_owned()).is_err()
            || !ids.insert(id.to_owned())
            || asset.path != assets.root.join(name)
            || asset.anonymous
        {
            return Err(Error::Path);
        }
        cursor += 1;
    }
    let snapshots = &assets.assets[cursor..];
    let expected: &[(&str, bool)] = match snapshots.len() {
        0 => &[],
        2 => &[("snapshot-memory", false), ("snapshot-state", false)],
        4 => &[
            ("snapshot-memory", false),
            ("snapshot-state", false),
            ("restore-memory", true),
            ("restore-state", true),
        ],
        _ => return Err(Error::Path),
    };
    for (asset, (name, read_only)) in snapshots.iter().zip(expected) {
        if asset.path != assets.root.join(name) || asset.read_only != *read_only || !asset.anonymous
        {
            return Err(Error::Path);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_mount_observation(
    asset: &MountedAsset,
    observed: super::AssetIdentity,
    links: u64,
    mount_id: u64,
    root_mount_id: u64,
) -> Result<()> {
    if observed != asset.identity
        || mount_id == 0
        || mount_id == root_mount_id
        || links != if asset.anonymous { 0 } else { 1 }
    {
        return Err(Error::Path);
    }
    Ok(())
}

fn validate_asset_manifest(before: &AssetsManifest, after: &AssetsManifest) -> Result<()> {
    if before.root != after.root
        || before.root_identity != after.root_identity
        || before.root_mount_id != after.root_mount_id
        || before.mount_anchor_identity != after.mount_anchor_identity
        || before.mount_anchor_id != after.mount_anchor_id
        || before.session_identity != after.session_identity
        || before.run_identity != after.run_identity
        || before.assets.len() != after.assets.len()
        || after.mount_namespace_identity.is_none()
        || before
            .mount_namespace_identity
            .is_some_and(|value| Some(value) != after.mount_namespace_identity)
    {
        return Err(Error::State);
    }
    for (old, new) in before.assets.iter().zip(&after.assets) {
        if old.path != new.path
            || old.identity != new.identity
            || old.read_only != new.read_only
            || old.anonymous != new.anonymous
            || old
                .placeholder_identity
                .is_some_and(|value| Some(value) != new.placeholder_identity)
            || (before.mount_namespace_identity.is_some()
                && old
                    .mount_id
                    .is_some_and(|value| Some(value) != new.mount_id))
            || new.placeholder_identity.is_none()
            || new.mount_id.is_none()
        {
            return Err(Error::State);
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn manifest(namespace: Option<super::super::AssetIdentity>, mount_base: u64) -> AssetsManifest {
        let root = PathBuf::from("/owned/session/root");
        AssetsManifest {
            root: root.clone(),
            root_identity: super::super::AssetIdentity {
                device: 1,
                inode: 2,
            },
            root_mount_id: None,
            mount_anchor_identity: None,
            mount_anchor_id: None,
            session_identity: Some(super::super::AssetIdentity {
                device: 1,
                inode: 3,
            }),
            run_identity: Some(super::super::AssetIdentity {
                device: 1,
                inode: 4,
            }),
            mount_namespace_identity: namespace,
            assets: [
                ("vmlinux", true),
                ("initramfs", true),
                ("base.img", true),
                ("state.img", false),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (name, read_only))| MountedAsset {
                path: root.join(name),
                identity: super::super::AssetIdentity {
                    device: 10,
                    inode: 20 + index as u64,
                },
                read_only,
                anonymous: false,
                placeholder_identity: Some(super::super::AssetIdentity {
                    device: 1,
                    inode: 30 + index as u64,
                }),
                mount_id: Some(mount_base + index as u64),
            })
            .collect(),
        }
    }

    #[test]
    fn replacement_mount_identity_is_rejected_before_detach() {
        let asset = MountedAsset {
            path: "/jail/root/vmlinux".into(),
            identity: super::super::AssetIdentity {
                device: 10,
                inode: 20,
            },
            read_only: true,
            anonymous: false,
            placeholder_identity: None,
            mount_id: None,
        };
        assert!(
            validate_mount_observation(
                &asset,
                super::super::AssetIdentity {
                    device: 10,
                    inode: 21,
                },
                1,
                40,
                30,
            )
            .is_err()
        );
        assert!(validate_mount_observation(&asset, asset.identity, 1, 30, 30).is_err());
    }

    #[test]
    fn unbound_legacy_mount_ids_can_be_bound_once_to_the_parent_namespace() {
        let namespace = super::super::AssetIdentity {
            device: 4,
            inode: 5,
        };
        let before = manifest(None, 1_000);
        let after = manifest(Some(namespace), 2_000);
        validate_asset_manifest(&before, &after).expect("one-time namespace binding");

        let bound = manifest(Some(namespace), 1_000);
        assert!(validate_asset_manifest(&bound, &after).is_err());
    }
}
