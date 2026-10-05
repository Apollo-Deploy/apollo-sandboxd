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

fn arm_sysfs(root: &std::path::Path) {
    let cache = root.join("sys/devices/system/cpu/cpu0/cache/index0");
    fs::create_dir_all(&cache).expect("ARM cache sysfs");
    for (name, value) in [
        ("level", "1\n"),
        ("type", "Data\n"),
        ("shared_cpu_map", "0\n"),
    ] {
        fs::write(cache.join(name), value).expect("ARM cache attribute");
    }
    let registers = root.join("sys/devices/system/cpu/cpu0/regs/identification");
    fs::create_dir_all(&registers).expect("ARM CPU register sysfs");
    fs::write(registers.join("midr_el1"), "0x410fd0c0\n").expect("ARM MIDR attribute");
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
    // Preserve the original inode while replacing the pathname; ext4 may
    // otherwise reuse its inode number immediately after unlink.
    let original = fs::File::open(&path).expect("open original binary");
    fs::remove_file(&path).expect("owned binary");
    fs::write(&path, b"foreign").expect("replacement");
    let original_identity = original.metadata().expect("original identity");
    let replacement_identity = fs::symlink_metadata(&path).expect("replacement identity");
    assert_ne!(
        (original_identity.dev(), original_identity.ino()),
        (replacement_identity.dev(), replacement_identity.ino()),
        "replacement must have a distinct inode identity"
    );
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
    // Keep the removed directory inode referenced so the replacement has a
    // distinct identity on filesystems that eagerly recycle inode numbers.
    let original = fs::File::open(&path).expect("open original directory");
    fs::remove_dir_all(&path).expect("owned directory");
    fs::create_dir(&path).expect("replacement");
    let original_identity = original.metadata().expect("original identity");
    let replacement_identity = fs::symlink_metadata(&path).expect("replacement identity");
    assert_ne!(
        (original_identity.dev(), original_identity.ino()),
        (replacement_identity.dev(), replacement_identity.ino()),
        "replacement must have a distinct inode identity"
    );
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

#[test]
fn captures_and_removes_bounded_arm_sysfs_mirror() {
    let (dir, manifest, digest) = fixture();
    arm_sysfs(&manifest.jail_root);
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let tree = jail_tree::capture(&manifest, uid, gid, &digest).expect("capture ARM sysfs");
    assert!(tree.entries.iter().any(|entry| {
        entry.relative
            == PathBuf::from("root/sys/devices/system/cpu/cpu0/regs/identification/midr_el1")
    }));
    jail_tree::remove(&manifest, &tree).expect("remove ARM sysfs");
    assert!(!manifest.jail_root.join("sys").exists());
    assert!(dir.path().join("firecracker/session/root").exists());
}

#[test]
fn unexpected_arm_sysfs_entry_is_preserved_and_blocks_removal() {
    let (_dir, manifest, digest) = fixture();
    arm_sysfs(&manifest.jail_root);
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let tree = jail_tree::capture(&manifest, uid, gid, &digest).expect("capture ARM sysfs");
    let foreign = manifest
        .jail_root
        .join("sys/devices/system/cpu/cpu0/cache/index0/foreign");
    fs::write(&foreign, b"preserve").expect("foreign sysfs entry");
    assert!(jail_tree::remove(&manifest, &tree).is_err());
    assert_eq!(
        fs::read(foreign).expect("preserved foreign entry"),
        b"preserve"
    );
}

#[test]
fn arm_sysfs_symlink_is_rejected_and_preserved() {
    let (_dir, manifest, digest) = fixture();
    arm_sysfs(&manifest.jail_root);
    let target = manifest.jail_root.join("sysfs-target");
    fs::write(&target, b"foreign target").expect("sysfs symlink target");
    let level = manifest
        .jail_root
        .join("sys/devices/system/cpu/cpu0/cache/index0/level");
    fs::remove_file(&level).expect("remove original cache attribute");
    std::os::unix::fs::symlink(&target, &level).expect("replace with sysfs symlink");
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    assert!(jail_tree::capture(&manifest, uid, gid, &digest).is_err());
    assert_eq!(
        fs::read(target).expect("preserved target"),
        b"foreign target"
    );
    assert!(
        fs::symlink_metadata(level)
            .expect("preserved symlink")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn unknown_arm_sysfs_entry_is_rejected_and_preserved() {
    let (_dir, manifest, digest) = fixture();
    arm_sysfs(&manifest.jail_root);
    let foreign = manifest.jail_root.join("sys/foreign");
    fs::write(&foreign, b"preserve").expect("unknown sysfs entry");
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    assert!(jail_tree::capture(&manifest, uid, gid, &digest).is_err());
    assert_eq!(
        fs::read(foreign).expect("preserved unknown entry"),
        b"preserve"
    );
}
