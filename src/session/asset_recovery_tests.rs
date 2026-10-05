use super::*;
use std::{
    env, fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
#[ignore = "native Linux mount recovery; requires root, CAP_SYS_ADMIN, and util-linux"]
fn recovery_removes_an_unjournaled_empty_root_skeleton() {
    if run_in_isolated_namespace("recovery_removes_an_unjournaled_empty_root_skeleton") {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let anchor_path = directory.path().join("firecracker");
    fs::create_dir(&anchor_path).unwrap();
    fs::set_permissions(&anchor_path, fs::Permissions::from_mode(0o700)).unwrap();
    rustix::mount::mount_bind_recursive(&anchor_path, &anchor_path).unwrap();
    rustix::mount::mount_change(
        &anchor_path,
        rustix::mount::MountPropagationFlags::PRIVATE | rustix::mount::MountPropagationFlags::REC,
    )
    .unwrap();
    let session_path = anchor_path.join("session");
    let root_path = session_path.join("root");
    fs::create_dir_all(root_path.join("run")).unwrap();
    for path in [&session_path, &root_path, &root_path.join("run")] {
        fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    }
    let anchor = fs::metadata(&anchor_path).unwrap();
    let setup = AssetSetup {
        root: root_path.clone(),
        anchor_identity: AssetIdentity {
            device: anchor.dev(),
            inode: anchor.ino(),
        },
        anchor_mount_id: asset_mount::observed_id(&anchor_path).unwrap(),
        mount_namespace_identity: asset_mount::current_namespace_identity().unwrap(),
        session_identity: None,
        root_identity: None,
        run_identity: None,
        root_parent_mount_id: None,
        root_mount_id: None,
        assets: ["vmlinux", "initramfs", "base.img", "state.img"]
            .into_iter()
            .map(|name| AssetSetupEntry {
                path: root_path.join(name),
                source_identity: AssetIdentity {
                    device: 1,
                    inode: 1,
                },
                read_only: true,
                placeholder_identity: None,
                mount_id: None,
            })
            .collect(),
    };

    recover_setup(&setup).unwrap();

    assert!(!session_path.exists());
    asset_mount::unmount(&anchor_path).unwrap();
}

const ISOLATED_NAMESPACE_ENV: &str = "APOLLO_SANDBOXD_ASSET_RECOVERY_ISOLATED_NS";

/// Re-executes one native test after creating its own private mount namespace.
/// Mount effects therefore stay inside this test process tree even when the
/// qualification command is run from an ordinary host namespace.
fn run_in_isolated_namespace(test_filter: &str) -> bool {
    if env::var_os(ISOLATED_NAMESPACE_ENV).is_some() {
        return false;
    }
    assert_eq!(rustix::process::geteuid().as_raw(), 0, "requires root");
    let output = Command::new("/usr/bin/unshare")
        .args(["--mount", "--propagation", "private", "--"])
        .arg(std::env::current_exe().expect("test executable"))
        .args(["--ignored", "--nocapture", "--test-threads=1"])
        .arg(test_filter)
        .env(ISOLATED_NAMESPACE_ENV, "1")
        .output()
        .expect("start isolated mount namespace; requires util-linux unshare");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains(test_filter),
        "isolated test failed or did not run: {stdout}\n{stderr}"
    );
    println!("{stdout}");
    true
}

struct Peer(Child);

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct RecoveryFixture {
    _directory: tempfile::TempDir,
    anchor: PathBuf,
    anchor_identity: AssetIdentity,
    anchor_mount_id: u64,
    peer_only: PathBuf,
    peer_source_identity: (u64, u64),
    peer: Peer,
    peer_pid: u32,
    session: PathBuf,
    root: PathBuf,
}

impl RecoveryFixture {
    fn new() -> Self {
        assert_eq!(rustix::process::geteuid().as_raw(), 0, "requires root");
        let directory = tempfile::tempdir_in("/run").expect("temporary directory under /run");
        let anchor = directory.path().join("firecracker");
        let peer_only = anchor.join("peer-only");
        let peer_source = directory.path().join("peer-source");
        fs::create_dir(&anchor).unwrap();
        fs::create_dir(&peer_only).unwrap();
        fs::create_dir(&peer_source).unwrap();

        // This self-bind gives the anchor its own mount ID. Making that
        // mount recursively private confines both recovery and peer probes.
        rustix::mount::mount_bind_recursive(&anchor, &anchor).unwrap();
        rustix::mount::mount_change(
            &anchor,
            rustix::mount::MountPropagationFlags::PRIVATE
                | rustix::mount::MountPropagationFlags::REC,
        )
        .unwrap();
        let anchor_mount_id = asset_mount::observed_id(&anchor).unwrap();
        let containing_mount_id = asset_mount::observed_id(anchor.parent().unwrap()).unwrap();
        assert_ne!(anchor_mount_id, containing_mount_id);
        asset_mount::require_private(anchor_mount_id).unwrap();
        let metadata = fs::metadata(&anchor).unwrap();
        let anchor_identity = AssetIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };

        let peer_pid_file = directory.path().join("peer.pid");
        let peer = Command::new("/usr/bin/unshare")
            .args(["--mount", "--propagation", "unchanged", "--", "/bin/sh", "-c"])
            .arg("/usr/bin/mount --bind \"$PEER_SOURCE\" \"$PEER_TARGET\" || exit; printf '%s\\n' \"$$\" > \"$PEER_PID_FILE\"; exec /bin/sleep 60")
            .env("PEER_SOURCE", &peer_source)
            .env("PEER_TARGET", &peer_only)
            .env("PEER_PID_FILE", &peer_pid_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start peer mount namespace; requires util-linux unshare");
        let mut fixture = Self {
            _directory: directory,
            anchor,
            anchor_identity,
            anchor_mount_id,
            peer_only,
            peer_source_identity: {
                let metadata = fs::metadata(&peer_source).unwrap();
                (metadata.dev(), metadata.ino())
            },
            peer: Peer(peer),
            peer_pid: 0,
            session: PathBuf::new(),
            root: PathBuf::new(),
        };
        fixture.peer_pid = wait_for_peer_pid(&peer_pid_file, &mut fixture.peer.0);
        fixture.session = fixture.anchor.join("session");
        fixture.root = fixture.session.join("root");
        fixture.assert_peer_mount_untouched();
        fixture
    }

    fn initial_setup(&self) -> AssetSetup {
        AssetSetup {
            root: self.root.clone(),
            anchor_identity: self.anchor_identity,
            anchor_mount_id: self.anchor_mount_id,
            mount_namespace_identity: asset_mount::current_namespace_identity().unwrap(),
            session_identity: None,
            root_identity: None,
            run_identity: None,
            root_parent_mount_id: None,
            root_mount_id: None,
            assets: ["vmlinux", "initramfs", "base.img", "state.img"]
                .into_iter()
                .map(|name| AssetSetupEntry {
                    path: self.root.join(name),
                    source_identity: AssetIdentity {
                        device: 1,
                        inode: 1,
                    },
                    read_only: name != "state.img",
                    placeholder_identity: None,
                    mount_id: None,
                })
                .collect(),
        }
    }

    fn create_root(&self, setup: &mut AssetSetup, persist_root_mount_id: bool) -> u64 {
        fs::create_dir(&self.session).unwrap();
        fs::create_dir(&self.root).unwrap();
        fs::create_dir(self.root.join("run")).unwrap();
        for path in [&self.session, &self.root, &self.root.join("run")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let session_metadata = fs::metadata(&self.session).unwrap();
        let root_metadata = fs::metadata(&self.root).unwrap();
        let run_metadata = fs::metadata(self.root.join("run")).unwrap();
        let identity = |metadata: &fs::Metadata| AssetIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        setup.session_identity = Some(identity(&session_metadata));
        setup.root_identity = Some(identity(&root_metadata));
        setup.run_identity = Some(identity(&run_metadata));
        setup.root_parent_mount_id = Some(asset_mount::observed_id(&self.root).unwrap());
        assert_eq!(setup.root_parent_mount_id, Some(self.anchor_mount_id));

        let mount_id = asset_mount::create_private_root(&self.root).unwrap();
        assert_ne!(mount_id, self.anchor_mount_id);
        if persist_root_mount_id {
            setup.root_mount_id = Some(mount_id);
        }
        mount_id
    }

    fn create_placeholder(&self, setup: &mut AssetSetup, persist_identity: bool) -> AssetIdentity {
        let target = &setup.assets[0].path;
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(target)
            .unwrap();
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
        file.sync_all().unwrap();
        fs::File::open(self.root.as_path())
            .unwrap()
            .sync_all()
            .unwrap();
        let metadata = file.metadata().unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.len(), 0);
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        let identity = AssetIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        drop(file);
        if persist_identity {
            setup.assets[0].placeholder_identity = Some(identity);
        }
        identity
    }

    fn assert_peer_mount_untouched(&self) {
        assert!(peer_mountpoint(self.peer_pid, &self.peer_only));
        assert_eq!(
            peer_identity(self.peer_pid, &self.peer_only),
            self.peer_source_identity
        );
        // It remains a plain directory in this namespace, so cleanup has
        // neither hidden the peer-only mount nor mistaken it for a target.
        assert_eq!(
            asset_mount::observed_id(&self.peer_only).unwrap(),
            self.anchor_mount_id
        );
        assert_eq!(
            asset_mount::observed_id(&self.anchor).unwrap(),
            self.anchor_mount_id
        );
    }
}

impl Drop for RecoveryFixture {
    fn drop(&mut self) {
        let _ = self.peer.0.kill();
        let _ = self.peer.0.wait();
        let _ = asset_mount::unmount(&self.anchor);
    }
}

fn wait_for_peer_pid(path: &Path, peer: &mut Child) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            return text.trim().parse().expect("peer process ID");
        }
        if let Some(status) = peer.try_wait().unwrap() {
            panic!("peer mount namespace exited before setup: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "peer mount namespace did not start"
        );
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
        .expect("inspect peer mount namespace; requires util-linux nsenter")
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
        .expect("inspect peer inode; requires util-linux nsenter and coreutils stat");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let (device, inode) = text.trim().split_once(':').unwrap();
    (device.parse().unwrap(), inode.parse().unwrap())
}

fn assert_session_removed(fixture: &RecoveryFixture) {
    assert!(!fixture.session.exists(), "recovery left the session tree");
    fixture.assert_peer_mount_untouched();
}

#[test]
#[ignore = "native Linux mount recovery; requires root, CAP_SYS_ADMIN, and util-linux"]
fn recovery_removes_private_anchor_empty_skeleton() {
    if run_in_isolated_namespace("recovery_removes_private_anchor_empty_skeleton") {
        return;
    }
    let fixture = RecoveryFixture::new();
    let setup = fixture.initial_setup();
    fs::create_dir(&fixture.session).unwrap();
    fs::create_dir(&fixture.root).unwrap();
    fs::create_dir(fixture.root.join("run")).unwrap();
    for path in [&fixture.session, &fixture.root, &fixture.root.join("run")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    recover_setup(&setup).unwrap();

    assert_session_removed(&fixture);
}

#[test]
#[ignore = "native Linux mount recovery; requires root, CAP_SYS_ADMIN, and util-linux"]
fn recovery_unmounts_private_root_bind_before_root_id_persistence() {
    if run_in_isolated_namespace("recovery_unmounts_private_root_bind_before_root_id_persistence") {
        return;
    }
    let fixture = RecoveryFixture::new();
    let mut setup = fixture.initial_setup();
    let root_mount_id = fixture.create_root(&mut setup, false);
    assert_eq!(
        asset_mount::observed_id(&fixture.root).unwrap(),
        root_mount_id
    );
    assert_eq!(setup.root_mount_id, None);

    recover_setup(&setup).unwrap();

    assert_session_removed(&fixture);
}

#[test]
#[ignore = "native Linux mount recovery; requires root, CAP_SYS_ADMIN, and util-linux"]
fn recovery_unmounts_private_root_bind_after_root_id_persistence() {
    if run_in_isolated_namespace("recovery_unmounts_private_root_bind_after_root_id_persistence") {
        return;
    }
    let fixture = RecoveryFixture::new();
    let mut setup = fixture.initial_setup();
    let root_mount_id = fixture.create_root(&mut setup, true);
    assert_eq!(setup.root_mount_id, Some(root_mount_id));

    recover_setup(&setup).unwrap();

    assert_session_removed(&fixture);
}

#[test]
#[ignore = "native Linux mount recovery; requires root, CAP_SYS_ADMIN, and util-linux"]
fn recovery_removes_placeholder_before_identity_persistence() {
    if run_in_isolated_namespace("recovery_removes_placeholder_before_identity_persistence") {
        return;
    }
    let fixture = RecoveryFixture::new();
    let mut setup = fixture.initial_setup();
    fixture.create_root(&mut setup, true);
    fixture.create_placeholder(&mut setup, false);
    assert_eq!(setup.assets[0].placeholder_identity, None);

    recover_setup(&setup).unwrap();

    assert_session_removed(&fixture);
}

#[test]
#[ignore = "native Linux mount recovery; requires root, CAP_SYS_ADMIN, and util-linux"]
fn recovery_removes_placeholder_after_identity_persistence() {
    if run_in_isolated_namespace("recovery_removes_placeholder_after_identity_persistence") {
        return;
    }
    let fixture = RecoveryFixture::new();
    let mut setup = fixture.initial_setup();
    fixture.create_root(&mut setup, true);
    let identity = fixture.create_placeholder(&mut setup, true);
    assert_eq!(setup.assets[0].placeholder_identity, Some(identity));

    recover_setup(&setup).unwrap();

    assert_session_removed(&fixture);
}

#[test]
#[ignore = "native Linux mount recovery; requires root, CAP_SYS_ADMIN, and util-linux"]
fn recovery_unmounts_asset_bind_before_mount_id_persistence() {
    if run_in_isolated_namespace("recovery_unmounts_asset_bind_before_mount_id_persistence") {
        return;
    }
    let fixture = RecoveryFixture::new();
    let mut setup = fixture.initial_setup();
    let root_mount_id = fixture.create_root(&mut setup, true);
    let placeholder_identity = fixture.create_placeholder(&mut setup, true);
    let source_path = fixture._directory.path().join("source-asset");
    let mut source = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(source_path)
        .unwrap();
    source.write_all(b"recovery source").unwrap();
    source.sync_all().unwrap();
    setup.assets[0].source_identity = AssetIdentity {
        device: source.metadata().unwrap().dev(),
        inode: source.metadata().unwrap().ino(),
    };
    asset_mount::bind_fd(&source, &setup.assets[0].path).unwrap();
    let asset_mount_id = asset_mount::observed_id(&setup.assets[0].path).unwrap();
    assert_ne!(asset_mount_id, root_mount_id);
    assert_eq!(setup.assets[0].mount_id, None);
    assert_eq!(
        setup.assets[0].placeholder_identity,
        Some(placeholder_identity)
    );

    recover_setup(&setup).unwrap();

    assert_session_removed(&fixture);
}
