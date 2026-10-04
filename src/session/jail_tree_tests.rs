use super::{JailTreeManifest, LaunchManifest, jail_tree};
use crate::jailer::{CgroupIdentity, JailIdentity};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

fn fixture() -> (tempfile::TempDir, LaunchManifest, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir
        .path()
        .canonicalize()
        .expect("canonical")
        .join("firecracker");
    let session = base.join("session");
    let root = session.join("root");
    fs::create_dir_all(root.join("dev/net")).expect("dev");
    fs::create_dir(root.join("run")).expect("run");
    let binary = root.join("firecracker");
    let bytes = b"firecracker";
    fs::write(&binary, bytes).expect("binary");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o555)).expect("binary mode");
    let digest = hex::encode(Sha256::digest(bytes));
    fs::write(session.join("jailer.stderr"), b"diagnostic").expect("stderr");
    fs::set_permissions(
        session.join("jailer.stderr"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("stderr mode");
    let root_meta = fs::symlink_metadata(&root).expect("root metadata");
    let session_meta = fs::symlink_metadata(&session).expect("session metadata");
    let manifest = LaunchManifest {
        sandbox_id: "sandbox".into(),
        session_id: "session".into(),
        jail_root: root.clone(),
        cgroup: PathBuf::from("/cgroup"),
        api_socket: PathBuf::from("/api"),
        vsock_socket: PathBuf::from("/vsock"),
        api_socket_identity: None,
        vsock_socket_identity: None,
        jail_identity: JailIdentity {
            device: 1,
            inode: 1,
        },
        staged_jail: None,
        cgroup_identity: CgroupIdentity {
            device: 1,
            inode: 1,
        },
        assets: super::AssetsManifest {
            root: root.clone(),
            root_identity: super::AssetIdentity {
                device: root_meta.dev(),
                inode: root_meta.ino(),
            },
            root_mount_id: None,
            mount_anchor_identity: None,
            mount_anchor_id: None,
            assets: Vec::new(),
            session_identity: Some(super::AssetIdentity {
                device: session_meta.dev(),
                inode: session_meta.ino(),
            }),
            run_identity: Some(super::AssetIdentity {
                device: fs::symlink_metadata(root.join("run")).unwrap().dev(),
                inode: fs::symlink_metadata(root.join("run")).unwrap().ino(),
            }),
            mount_namespace_identity: None,
        },
        jail_tree: None,
        network_identity: None,
        network_attachment: None,
        network_namespace: None,
    };
    (dir, manifest, digest)
}

#[test]
fn captures_and_removes_allowlisted_jailer_tree() {
    let (dir, manifest, digest) = fixture();
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let tree = jail_tree::capture(&manifest, uid, gid, &digest).expect("capture");
    assert!(
        tree.entries
            .iter()
            .any(|entry| entry.relative == PathBuf::from("root/firecracker"))
    );
    jail_tree::remove(&manifest, &tree).expect("remove");
    jail_tree::remove(&manifest, &tree).expect("repeat remove");
    assert!(dir.path().join("firecracker/session/root").exists());
    assert!(
        !dir.path()
            .join("firecracker/session/jailer.stderr")
            .exists()
    );
}

#[test]
fn replacement_binary_is_rejected_and_preserved() {
    let (_dir, manifest, digest) = fixture();
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let tree = jail_tree::capture(&manifest, uid, gid, &digest).expect("capture");
    let path = manifest.jail_root.join("firecracker");
    fs::remove_file(&path).expect("owned binary");
    fs::write(&path, b"foreign").expect("replacement");
    assert!(jail_tree::remove(&manifest, &tree).is_err());
    assert_eq!(fs::read(path).expect("preserved"), b"foreign");
}

#[test]
fn absent_root_is_idempotent() {
    let (_dir, manifest, digest) = fixture();
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let tree: JailTreeManifest = jail_tree::capture(&manifest, uid, gid, &digest).expect("capture");
    fs::remove_dir_all(&manifest.jail_root).expect("root");
    jail_tree::remove(&manifest, &tree).expect("idempotent");
    assert!(
        !manifest
            .jail_root
            .parent()
            .unwrap()
            .join("jailer.stderr")
            .exists()
    );
}

#[test]
fn replacement_directory_is_rejected_and_preserved() {
    let (_dir, manifest, digest) = fixture();
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let tree = jail_tree::capture(&manifest, uid, gid, &digest).expect("capture");
    let path = manifest.jail_root.join("dev");
    fs::remove_dir_all(&path).expect("owned directory");
    fs::create_dir(&path).expect("replacement");
    assert!(jail_tree::remove(&manifest, &tree).is_err());
    assert!(path.is_dir());
}

#[test]
fn malformed_entry_path_is_rejected() {
    let (_dir, manifest, digest) = fixture();
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let mut tree = jail_tree::capture(&manifest, uid, gid, &digest).expect("capture");
    tree.entries.push(super::JailEntry {
        relative: PathBuf::from("root/../../foreign"),
        device: 0,
        inode: 0,
        mode: 0,
        uid,
        gid,
        rdev: 0,
        links: 1,
    });
    assert!(jail_tree::remove(&manifest, &tree).is_err());
}
