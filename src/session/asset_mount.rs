//! Linux mount operations for descriptor-pinned session assets.
use super::AssetIdentity;
use crate::error::{Error, Result};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::{fs::File, path::Path};

#[cfg(target_os = "linux")]
static ANCHOR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "linux")]
pub(super) fn current_namespace_identity() -> Result<AssetIdentity> {
    let metadata = File::open("/proc/self/ns/mnt")?.metadata()?;
    Ok(AssetIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(target_os = "linux"))]
pub(super) fn current_namespace_identity() -> Result<AssetIdentity> {
    Err(Error::Config("mount namespace identity requires Linux"))
}

#[cfg(target_os = "linux")]
pub(super) fn observed_id(path: &Path) -> Result<u64> {
    let stat = rustix::fs::statx(
        rustix::fs::CWD,
        path,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        rustix::fs::StatxFlags::MNT_ID,
    )?;
    if stat.stx_mask & rustix::fs::StatxFlags::MNT_ID.bits() == 0 || stat.stx_mnt_id == 0 {
        return Err(Error::Path);
    }
    Ok(stat.stx_mnt_id)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn observed_id(_path: &Path) -> Result<u64> {
    Err(Error::Config("asset mounts require Linux"))
}

#[cfg(target_os = "linux")]
pub(super) fn ensure_private_anchor(anchor: &Path) -> Result<u64> {
    let _guard = ANCHOR_LOCK.lock().map_err(|_| Error::State)?;
    let parent_id = observed_id(anchor.parent().ok_or(Error::Path)?)?;
    let current_id = observed_id(anchor)?;
    // Installing an overmount below a shared parent can propagate into a peer
    // mount namespace and hide a descendant that exists only in that peer.
    // The daemon cannot make an atomic, race-free census of every namespace,
    // including namespaces retained only by an nsfs bind. Therefore the
    // trusted host setup must install this dedicated private mount before the
    // daemon starts; runtime code only verifies that invariant.
    if current_id == parent_id {
        return Err(Error::Path);
    }
    require_private(current_id)?;
    Ok(current_id)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn ensure_private_anchor(_anchor: &Path) -> Result<u64> {
    Err(Error::Config("asset mounts require Linux"))
}

#[cfg(target_os = "linux")]
pub(super) fn create_private_root(root: &Path) -> Result<u64> {
    use rustix::mount::{MountPropagationFlags, mount_change};
    rustix::mount::mount_bind(root, root)?;
    if let Err(error) = mount_change(
        root,
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    ) {
        let _ = unmount(root);
        return Err(error.into());
    }
    let id = observed_id(root)?;
    if let Err(error) = require_private(id) {
        let _ = unmount(root);
        return Err(error);
    }
    Ok(id)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn create_private_root(_root: &Path) -> Result<u64> {
    Err(Error::Config("asset mounts require Linux"))
}

#[cfg(target_os = "linux")]
pub(super) fn require_private(id: u64) -> Result<()> {
    use std::io::Read;
    const MAX_MOUNTINFO_BYTES: usize = 1 << 20;
    let mut contents = Vec::new();
    File::open("/proc/self/mountinfo")?
        .take((MAX_MOUNTINFO_BYTES + 1) as u64)
        .read_to_end(&mut contents)?;
    if contents.len() > MAX_MOUNTINFO_BYTES {
        return Err(Error::Path);
    }
    let text = std::str::from_utf8(&contents).map_err(|_| Error::Path)?;
    for line in text.lines() {
        let before_separator = line.split_once(" - ").ok_or(Error::Path)?.0;
        let mut fields = before_separator.split_whitespace();
        let mount_id = fields.next().and_then(|field| field.parse::<u64>().ok());
        if mount_id == Some(id) {
            return if fields.count() == 5 {
                Ok(())
            } else {
                Err(Error::Path)
            };
        }
    }
    Err(Error::Path)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn require_private(_id: u64) -> Result<()> {
    Err(Error::Config("asset mounts require Linux"))
}

#[cfg(target_os = "linux")]
pub(super) fn bind_fd(source: &File, target: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let source_path = format!("/proc/self/fd/{}", source.as_raw_fd());
    rustix::mount::mount_bind(source_path.as_str(), target).map_err(Error::from)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn bind_fd(_source: &File, _target: &Path) -> Result<()> {
    Err(Error::Config("asset mounts require Linux"))
}

#[cfg(target_os = "linux")]
pub(super) fn remount_read_only(target: &Path) -> Result<()> {
    use rustix::mount::{MountFlags, mount_remount};
    mount_remount(
        target,
        MountFlags::BIND | MountFlags::RDONLY | MountFlags::NODEV | MountFlags::NOSUID,
        "",
    )
    .map_err(Error::from)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn remount_read_only(_target: &Path) -> Result<()> {
    Err(Error::Config("asset mounts require Linux"))
}

#[cfg(target_os = "linux")]
pub(super) fn unmount(path: &Path) -> Result<()> {
    rustix::mount::unmount(path, rustix::mount::UnmountFlags::DETACH).map_err(Error::from)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn unmount(_path: &Path) -> Result<()> {
    Err(Error::Config("asset mounts require Linux"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::MetadataExt,
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    struct Peer(Child);
    impl Drop for Peer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[derive(Default)]
    struct Mounts {
        asset: Option<std::path::PathBuf>,
        root: Option<std::path::PathBuf>,
        anchor: Option<std::path::PathBuf>,
    }
    impl Drop for Mounts {
        fn drop(&mut self) {
            if let Some(asset) = self.asset.take() {
                let _ = unmount(&asset);
            }
            if let Some(root) = self.root.take() {
                let _ = unmount(&root);
            }
            if let Some(anchor) = self.anchor.take() {
                let _ = unmount(&anchor);
            }
        }
    }

    fn peer(pid_file: &Path) -> Peer {
        let child = Command::new("/usr/bin/unshare")
            .args(["--mount", "--propagation", "unchanged", "--"])
            .arg("/bin/sh")
            .args([
                "-c",
                "printf '%s\\n' \"$$\" > \"$PEER_PID_FILE\"; exec sleep 60",
            ])
            .env("PEER_PID_FILE", pid_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start peer mount namespace");
        Peer(child)
    }

    fn wait_for_pid(path: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(text) = fs::read_to_string(path) {
                return text.trim().parse().expect("peer pid");
            }
            assert!(Instant::now() < deadline, "peer namespace did not start");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn peer_mountpoint(pid: u32, path: &Path) -> bool {
        Command::new("/usr/bin/nsenter")
            .arg(format!("--mount=/proc/{pid}/ns/mnt"))
            .arg("--")
            .arg("/usr/bin/mountpoint")
            .arg("--quiet")
            .arg(path)
            .status()
            .expect("inspect peer mount namespace")
            .success()
    }

    fn peer_identity(pid: u32, path: &Path) -> (u64, u64) {
        let output = Command::new("/usr/bin/nsenter")
            .arg(format!("--mount=/proc/{pid}/ns/mnt"))
            .arg("--")
            .arg("/usr/bin/stat")
            .args(["-Lc", "%d:%i"])
            .arg(path)
            .output()
            .expect("inspect peer inode");
        assert!(output.status.success());
        let text = std::str::from_utf8(&output.stdout).unwrap().trim();
        let (device, inode) = text.split_once(':').unwrap();
        (device.parse().unwrap(), inode.parse().unwrap())
    }

    fn peer_bind_mount(pid: u32, path: &Path) {
        let status = Command::new("/usr/bin/nsenter")
            .arg(format!("--mount=/proc/{pid}/ns/mnt"))
            .arg("--")
            .arg("/usr/bin/mount")
            .args(["--bind"])
            .arg(path)
            .arg(path)
            .status()
            .expect("create peer-only bind mount");
        assert!(status.success());
    }

    fn peer_unmount(pid: u32, path: &Path) {
        let status = Command::new("/usr/bin/nsenter")
            .arg(format!("--mount=/proc/{pid}/ns/mnt"))
            .arg("--")
            .arg("/usr/bin/umount")
            .arg(path)
            .status()
            .expect("remove peer-only bind mount");
        assert!(status.success());
    }

    #[test]
    #[ignore = "requires root, an isolated private mount namespace, unshare, and nsenter"]
    fn private_session_root_contains_asset_mounts_across_peer_namespaces() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0, "requires root");
        let directory = tempfile::tempdir_in("/run").unwrap();
        let anchor = directory.path().join("firecracker");
        fs::create_dir(&anchor).unwrap();
        rustix::mount::mount_bind_recursive(&anchor, &anchor).unwrap();
        rustix::mount::mount_change(
            &anchor,
            rustix::mount::MountPropagationFlags::PRIVATE
                | rustix::mount::MountPropagationFlags::REC,
        )
        .unwrap();
        let source_path = directory.path().join("source");
        let mut source = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(source_path)
            .unwrap();
        source.write_all(b"trusted asset").unwrap();

        let pid_file = directory.path().join("peer.pid");
        let _peer = peer(&pid_file);
        let pid = wait_for_pid(&pid_file);
        assert!(peer_mountpoint(pid, &anchor));

        let mut mounts = Mounts::default();
        let anchor_id = ensure_private_anchor(&anchor).unwrap();
        mounts.anchor = Some(anchor.clone());
        let session = anchor.join("session");
        fs::create_dir(&session).unwrap();
        let root = session.join("root");
        fs::create_dir(&root).unwrap();
        let target = root.join("asset");
        let placeholder = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .unwrap();
        let placeholder_identity = (
            placeholder.metadata().unwrap().dev(),
            placeholder.metadata().unwrap().ino(),
        );
        drop(placeholder);
        assert!(!peer_mountpoint(pid, &root));
        let root_id = create_private_root(&root).unwrap();
        mounts.root = Some(root.clone());
        assert!(!peer_mountpoint(pid, &root));
        require_private(root_id).unwrap();
        bind_fd(&source, &target).unwrap();
        mounts.asset = Some(target.clone());
        let asset_id = observed_id(&target).unwrap();
        assert!(!peer_mountpoint(pid, &target));
        assert_eq!(peer_identity(pid, &target), placeholder_identity);

        let identity = |metadata: &fs::Metadata| super::super::AssetIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let manifest = super::super::AssetsManifest {
            root: root.clone(),
            root_identity: identity(&fs::metadata(&root).unwrap()),
            root_mount_id: Some(root_id),
            mount_anchor_identity: Some(identity(&fs::metadata(&anchor).unwrap())),
            mount_anchor_id: Some(anchor_id),
            session_identity: Some(identity(&fs::metadata(&session).unwrap())),
            run_identity: None,
            mount_namespace_identity: Some(current_namespace_identity().unwrap()),
            assets: vec![super::super::MountedAsset {
                path: target.clone(),
                identity: identity(&source.metadata().unwrap()),
                read_only: false,
                anonymous: false,
                placeholder_identity: Some(super::super::AssetIdentity {
                    device: placeholder_identity.0,
                    inode: placeholder_identity.1,
                }),
                mount_id: Some(asset_id),
            }],
        };
        super::super::assets::unmount_manifest_assets(&manifest).unwrap();
        mounts.asset = None;
        mounts.root = None;
        assert!(!peer_mountpoint(pid, &root));
        super::super::assets::unmount_manifest_assets(&manifest).unwrap();
        unmount(&anchor).unwrap();
        mounts.anchor = None;
    }

    #[test]
    #[ignore = "requires root and an isolated private mount namespace"]
    fn unmounted_anchor_is_rejected_without_hiding_descendant() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0, "requires root");
        let directory = tempfile::tempdir_in("/run").unwrap();
        let anchor = directory.path().join("firecracker");
        let legacy = anchor.join("legacy/root");
        fs::create_dir_all(&legacy).unwrap();
        let mut mounts = Mounts::default();
        rustix::mount::mount_bind(&legacy, &legacy).unwrap();
        mounts.root = Some(legacy.clone());
        assert!(ensure_private_anchor(&anchor).is_err());
        assert!(
            !Command::new("/usr/bin/mountpoint")
                .arg("--quiet")
                .arg(&anchor)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/usr/bin/mountpoint")
                .arg("--quiet")
                .arg(&legacy)
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    #[ignore = "requires root, an isolated private mount namespace, unshare, and nsenter"]
    fn existing_private_anchor_does_not_hide_peer_only_descendant() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0, "requires root");
        let directory = tempfile::tempdir_in("/run").unwrap();
        let anchor = directory.path().join("firecracker");
        let peer_only = anchor.join("peer-only");
        fs::create_dir_all(&peer_only).unwrap();
        rustix::mount::mount_bind_recursive(&anchor, &anchor).unwrap();
        rustix::mount::mount_change(
            &anchor,
            rustix::mount::MountPropagationFlags::PRIVATE
                | rustix::mount::MountPropagationFlags::REC,
        )
        .unwrap();
        let anchor_id = observed_id(&anchor).unwrap();

        let pid_file = directory.path().join("peer.pid");
        let peer = peer(&pid_file);
        let pid = wait_for_pid(&pid_file);
        peer_bind_mount(pid, &peer_only);
        assert!(peer_mountpoint(pid, &peer_only));
        assert!(
            !Command::new("/usr/bin/mountpoint")
                .arg("--quiet")
                .arg(&peer_only)
                .status()
                .unwrap()
                .success()
        );

        assert_eq!(ensure_private_anchor(&anchor).unwrap(), anchor_id);
        assert!(peer_mountpoint(pid, &peer_only));
        peer_unmount(pid, &peer_only);
        drop(peer);
        unmount(&anchor).unwrap();
    }
}
