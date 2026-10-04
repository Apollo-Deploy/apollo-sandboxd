//! Fail-closed upgrade of pre-tree launch records before any VMM signal.
use super::{AssetsManifest, LaunchManifest};
use crate::{
    error::{Error, Result},
    process::ProcessIdentity,
    state::LaunchIntent,
};
use std::{
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
};

pub(crate) fn recover_manifest(
    manifest: &LaunchManifest,
    intent: &LaunchIntent,
    process: Option<&ProcessIdentity>,
) -> Result<LaunchManifest> {
    if manifest.sandbox_id != intent.key.sandbox.as_str()
        || manifest.session_id != intent.key.session.as_str()
        || manifest.assets.root != manifest.jail_root
        || !(4..=24).contains(&manifest.assets.assets.len())
        || manifest.jail_root.file_name() != Some(std::ffi::OsStr::new("root"))
        || manifest.jail_root.parent().and_then(Path::file_name)
            != Some(std::ffi::OsStr::new(intent.key.session.as_str()))
        || manifest
            .jail_root
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            != Some(std::ffi::OsStr::new("firecracker"))
        || manifest.api_socket != manifest.jail_root.join("run/firecracker.socket")
        || manifest.vsock_socket != manifest.jail_root.join("run/vsock.socket")
    {
        return Err(Error::State);
    }
    validate_asset_layout(manifest, intent)?;
    let mut recovered = manifest.clone();
    recover_directory_identities(&mut recovered.assets)?;
    if recovered.assets.mount_namespace_identity.is_none()
        || recovered.assets.assets.iter().any(|asset| {
            asset.placeholder_identity.is_none()
                || asset.mount_id.is_none_or(|mount_id| mount_id == 0)
        })
    {
        super::legacy_cleanup_mount::recover_mount_identities(&mut recovered.assets)?;
    }
    let staged_jail = match recovered.staged_jail.clone() {
        Some(stage) => stage,
        None => {
            let stage_root = stage_root(&recovered, intent)?;
            crate::jailer::recover_stage_manifest(
                &stage_root,
                intent.key.session.as_str(),
                &intent.pins.firecracker_sha256,
                &intent.pins.jailer_sha256,
            )?
        }
    };
    validate_stage(&recovered, intent, &staged_jail)?;
    recovered.staged_jail = Some(staged_jail);

    recovered.api_socket_identity = recover_socket_identity(
        &recovered.api_socket,
        recovered.api_socket_identity,
        &recovered.assets,
        process,
    )?;
    recovered.vsock_socket_identity = recover_socket_identity(
        &recovered.vsock_socket,
        recovered.vsock_socket_identity,
        &recovered.assets,
        process,
    )?;
    if recovered.jail_tree.is_none() {
        recovered.jail_tree = Some(super::jail_tree::capture(
            &recovered,
            intent.uid,
            intent.gid,
            &intent.pins.firecracker_sha256,
        )?);
    }
    validate_ready(&recovered)?;
    Ok(recovered)
}

fn validate_asset_layout(manifest: &LaunchManifest, intent: &LaunchIntent) -> Result<()> {
    let assets = &manifest.assets.assets;
    let base_count = 4 + intent.pins.volumes.len();
    let snapshot_count = assets.len().checked_sub(base_count).ok_or(Error::State)?;
    if !matches!(snapshot_count, 0 | 2 | 4) {
        return Err(Error::State);
    }
    for (asset, (name, read_only)) in assets[..4].iter().zip([
        ("vmlinux", true),
        ("initramfs", true),
        ("base.img", true),
        ("state.img", false),
    ]) {
        if asset.path != manifest.jail_root.join(name)
            || asset.identity.device == 0
            || asset.identity.inode == 0
            || asset.read_only != read_only
            || asset.anonymous
        {
            return Err(Error::State);
        }
    }
    for (asset, volume) in assets[4..base_count].iter().zip(&intent.pins.volumes) {
        if asset.path
            != manifest
                .jail_root
                .join(format!("volume-{}.img", volume.volume_id))
            || asset.identity.device == 0
            || asset.identity.inode == 0
            || asset.read_only != volume.read_only
            || asset.anonymous
        {
            return Err(Error::State);
        }
    }
    let expected: &[(&str, bool)] = match snapshot_count {
        0 => &[],
        2 => &[("snapshot-memory", false), ("snapshot-state", false)],
        4 => &[
            ("snapshot-memory", false),
            ("snapshot-state", false),
            ("restore-memory", true),
            ("restore-state", true),
        ],
        _ => return Err(Error::State),
    };
    for (asset, (name, read_only)) in assets[base_count..].iter().zip(expected) {
        if asset.path != manifest.jail_root.join(name)
            || asset.identity.device == 0
            || asset.identity.inode == 0
            || !asset.anonymous
            || asset.read_only != *read_only
        {
            return Err(Error::State);
        }
    }
    Ok(())
}

pub(crate) fn validate_ready(manifest: &LaunchManifest) -> Result<()> {
    if manifest.staged_jail.is_none()
        || manifest.jail_tree.is_none()
        || manifest.assets.session_identity.is_none()
        || manifest.assets.run_identity.is_none()
        || manifest
            .assets
            .mount_namespace_identity
            .is_none_or(|identity| identity.device == 0 || identity.inode == 0)
        || manifest.assets.assets.iter().any(|asset| {
            asset.placeholder_identity.is_none()
                || asset.mount_id.is_none_or(|mount_id| mount_id == 0)
        })
    {
        return Err(Error::Config(
            "legacy launch ownership is incomplete; quarantine required",
        ));
    }
    Ok(())
}

fn recover_directory_identities(assets: &mut AssetsManifest) -> Result<()> {
    let session_path = assets.root.parent().ok_or(Error::Path)?;
    let session = crate::security::path::SecureDir::open(session_path)?;
    let session_stat = rustix::fs::fstat(session.as_fd())?;
    let observed_session = super::AssetIdentity {
        device: crate::security::path::device_id(session_stat.st_dev),
        inode: session_stat.st_ino,
    };
    if assets
        .session_identity
        .is_some_and(|expected| expected != observed_session)
    {
        return Err(Error::Path);
    }
    let root = open_pinned_directory(session.as_fd(), "root", assets.root_identity)?;
    let run = open_pinned_directory_unrecorded(root.as_fd(), "run")?;
    let run_stat = rustix::fs::fstat(run.as_fd())?;
    let observed_run = super::AssetIdentity {
        device: crate::security::path::device_id(run_stat.st_dev),
        inode: run_stat.st_ino,
    };
    if assets
        .run_identity
        .is_some_and(|expected| expected != observed_run)
    {
        return Err(Error::Path);
    }
    assets.session_identity = Some(observed_session);
    assets.run_identity = Some(observed_run);
    Ok(())
}

pub(super) fn open_pinned_root(assets: &AssetsManifest) -> Result<OwnedFd> {
    let session_identity = assets.session_identity.ok_or(Error::Path)?;
    let session_path = assets.root.parent().ok_or(Error::Path)?;
    let session = crate::security::path::SecureDir::open(session_path)?;
    let session_stat = rustix::fs::fstat(session.as_fd())?;
    require_identity(&session_stat, session_identity)?;
    open_pinned_directory(session.as_fd(), "root", assets.root_identity)
}

fn open_pinned_directory(
    parent: impl AsFd,
    name: &str,
    expected: super::AssetIdentity,
) -> Result<OwnedFd> {
    let directory = open_pinned_directory_unrecorded(parent, name)?;
    require_identity(&rustix::fs::fstat(&directory)?, expected)?;
    Ok(directory)
}

fn open_pinned_directory_unrecorded(parent: impl AsFd, name: &str) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    if name.is_empty() || name.contains(['/', '\0']) || matches!(name, "." | "..") {
        return Err(Error::Path);
    }
    Ok(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

fn require_identity(stat: &rustix::fs::Stat, expected: super::AssetIdentity) -> Result<()> {
    if crate::security::path::device_id(stat.st_dev) != expected.device
        || stat.st_ino != expected.inode
        || rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
    {
        return Err(Error::Path);
    }
    Ok(())
}

fn stage_root(manifest: &LaunchManifest, intent: &LaunchIntent) -> Result<PathBuf> {
    let session = manifest.jail_root.parent().ok_or(Error::Path)?;
    let operator_root = session.parent().and_then(Path::parent).ok_or(Error::Path)?;
    Ok(operator_root
        .join(".inputs")
        .join(intent.key.session.as_str()))
}

fn validate_stage(
    manifest: &LaunchManifest,
    intent: &LaunchIntent,
    stage: &crate::jailer::JailStageManifest,
) -> Result<()> {
    let expected_root = stage_root(manifest, intent)?;
    if stage.root != expected_root
        || stage.parent != expected_root.parent().ok_or(Error::Path)?
        || stage.firecracker != expected_root.join("firecracker")
        || stage.ownership_manifest != expected_root.join("ownership.manifest")
        || stage.root_identity.device != manifest.jail_identity.device
        || stage.root_identity.inode != manifest.jail_identity.inode
        || stage.firecracker_sha256 != intent.pins.firecracker_sha256
        || stage.jailer_sha256 != intent.pins.jailer_sha256
    {
        return Err(Error::Path);
    }
    Ok(())
}

fn recover_socket_identity(
    path: &Path,
    recorded: Option<super::AssetIdentity>,
    assets: &AssetsManifest,
    process: Option<&ProcessIdentity>,
) -> Result<Option<super::AssetIdentity>> {
    let observed = socket_identity(path, assets)?;
    let Some(observed) = observed else {
        return Ok(recorded);
    };
    if recorded.is_some_and(|identity| identity != observed) {
        return Err(Error::Path);
    }
    if recorded.is_none() {
        let owner = process.ok_or(Error::Config(
            "legacy socket identity cannot be tied to the VMM; quarantine required",
        ))?;
        if !process_owns_socket_path(owner, path, observed)? {
            return Err(Error::Config(
                "legacy socket identity cannot be tied to the VMM; quarantine required",
            ));
        }
    }
    Ok(Some(observed))
}

fn socket_identity(path: &Path, assets: &AssetsManifest) -> Result<Option<super::AssetIdentity>> {
    use rustix::fs::{AtFlags, FileType};
    let root = open_pinned_root(assets)?;
    let run = open_pinned_directory(root.as_fd(), "run", assets.run_identity.ok_or(Error::Path)?)?;
    let run_stat = rustix::fs::fstat(run.as_fd())?;
    let run_identity = assets.run_identity.ok_or(Error::Path)?;
    if crate::security::path::device_id(run_stat.st_dev) != run_identity.device
        || run_stat.st_ino != run_identity.inode
    {
        return Err(Error::Path);
    }
    if path.parent() != Some(assets.root.join("run").as_path()) {
        return Err(Error::Path);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::Path)?;
    if !matches!(name, "firecracker.socket" | "vsock.socket") {
        return Err(Error::Path);
    }
    let stat = match rustix::fs::statat(run.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket {
        return Err(Error::Path);
    }
    Ok(Some(super::AssetIdentity {
        device: crate::security::path::device_id(stat.st_dev),
        inode: stat.st_ino,
    }))
}

#[cfg(target_os = "linux")]
fn process_owns_socket_path(
    process: &ProcessIdentity,
    path: &Path,
    expected: super::AssetIdentity,
) -> Result<bool> {
    use std::os::unix::net::UnixStream;

    process.verify()?;
    if process.has_exited()? {
        return Ok(false);
    }
    if !socket_path_matches(path, expected)? {
        return Ok(false);
    }
    let stream = UnixStream::connect(path)?;
    let peer = rustix::net::sockopt::socket_peercred(&stream)?;
    let peer_pid = u32::try_from(peer.pid.as_raw_nonzero().get()).map_err(|_| Error::Path)?;
    if peer_pid != process.pid() || !socket_path_matches(path, expected)? {
        return Ok(false);
    }
    process.verify()?;
    if process.has_exited()? {
        return Ok(false);
    }
    Ok(socket_path_matches(path, expected)?)
}

#[cfg(not(target_os = "linux"))]
fn process_owns_socket_path(
    _process: &ProcessIdentity,
    _path: &Path,
    _expected: super::AssetIdentity,
) -> Result<bool> {
    Err(Error::Config("legacy socket recovery requires Linux"))
}

#[cfg(target_os = "linux")]
fn socket_path_matches(path: &Path, expected: super::AssetIdentity) -> Result<bool> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::symlink_metadata(path)?;
    Ok(metadata.file_type().is_socket()
        && metadata.dev() == expected.device
        && metadata.ino() == expected.inode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixListener,
        },
    };

    fn socket_fixture() -> (tempfile::TempDir, AssetsManifest, PathBuf) {
        let directory = tempfile::Builder::new()
            .tempdir_in("/tmp")
            .expect("short tempdir");
        let firecracker = directory
            .path()
            .canonicalize()
            .expect("canonical tempdir")
            .join("firecracker");
        let session = firecracker.join("session");
        let root = session.join("root");
        let run = root.join("run");
        fs::create_dir_all(&run).expect("run directory");
        for path in [
            directory.path(),
            firecracker.as_path(),
            session.as_path(),
            root.as_path(),
            run.as_path(),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private test directory");
        }
        let identity = |path: &Path| {
            let metadata = fs::symlink_metadata(path).expect("directory metadata");
            super::super::AssetIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        };
        let path = run.join("vsock.socket");
        let assets = AssetsManifest {
            root: root.clone(),
            root_identity: identity(&root),
            root_mount_id: None,
            mount_anchor_identity: None,
            mount_anchor_id: None,
            session_identity: Some(identity(&session)),
            run_identity: Some(identity(&run)),
            mount_namespace_identity: None,
            assets: Vec::new(),
        };
        (directory, assets, path)
    }

    #[test]
    fn absent_socket_remains_idempotently_absent() {
        let (_directory, assets, path) = socket_fixture();
        let observed = recover_socket_identity(&path, None, &assets, None);
        assert!(matches!(observed, Ok(None)), "{observed:?}");
        super::super::cleanup_paths::remove_socket(&path, None, &assets)
            .expect("absent socket is safe to clean");
    }

    #[test]
    fn foreign_socket_appearing_after_absence_is_rejected() {
        let (_directory, assets, path) = socket_fixture();
        let observed = recover_socket_identity(&path, None, &assets, None);
        assert!(matches!(observed, Ok(None)), "{observed:?}");
        let _listener = UnixListener::bind(&path).expect("foreign socket");
        assert!(matches!(
            super::super::cleanup_paths::remove_socket(&path, None, &assets),
            Err(Error::Path)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recorded_jailer_owned_root_is_opened_below_root_owned_session() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let (_directory, mut assets, socket) = socket_fixture();
        assets.session_identity = None;
        assets.run_identity = None;
        let delegated_uid = rustix::process::Uid::from_raw(250_000);
        let delegated_gid = rustix::process::Gid::from_raw(250_000);
        for path in [&assets.root, &assets.root.join("run")] {
            let file = fs::File::open(path).expect("open jailer-owned directory");
            rustix::fs::fchown(&file, Some(delegated_uid), Some(delegated_gid))
                .expect("delegate directory ownership");
        }

        recover_directory_identities(&mut assets)
            .expect("recorded root identity permits jailer ownership");
        assert!(assets.session_identity.is_some());
        assert!(assets.run_identity.is_some());
        assert_eq!(
            socket_identity(&socket, &assets).expect("descriptor-relative socket lookup"),
            None
        );
    }
}
