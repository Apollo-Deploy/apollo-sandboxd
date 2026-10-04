use super::chroot::{JailIdentity, JailStageManifest};
use super::chroot_cleanup::remove_owned_manifest;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

fn stage() -> (tempfile::TempDir, JailStageManifest, Vec<u8>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir
        .path()
        .canonicalize()
        .expect("canonical tempdir")
        .join("session");
    fs::create_dir(&root).expect("root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
    let binary = root.join("firecracker");
    let bytes = b"trusted-firecracker".to_vec();
    fs::write(&binary, &bytes).expect("binary");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o555)).expect("binary mode");
    let digest = hex::encode(Sha256::digest(&bytes));
    let manifest = root.join("ownership.manifest");
    fs::write(
        &manifest,
        format!("firecracker_sha256={digest}\njailer_sha256={digest}\n"),
    )
    .expect("manifest");
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).expect("manifest mode");
    let identity = |path: &PathBuf| {
        let meta = fs::symlink_metadata(path).expect("identity");
        JailIdentity {
            device: meta.dev(),
            inode: meta.ino(),
        }
    };
    let root_identity = identity(&root);
    let parent = root.parent().expect("parent").to_path_buf();
    let parent_identity = identity(&parent);
    let stage = JailStageManifest {
        root: root.clone(),
        parent,
        firecracker: binary.clone(),
        ownership_manifest: manifest.clone(),
        root_identity,
        parent_identity,
        firecracker_identity: identity(&binary),
        ownership_manifest_identity: identity(&manifest),
        firecracker_sha256: digest.clone(),
        jailer_sha256: digest,
    };
    (dir, stage, bytes)
}

#[test]
fn cleanup_is_idempotent_after_each_owned_object_is_missing() {
    let (dir, first_stage, _) = stage();
    fs::remove_file(&first_stage.ownership_manifest).expect("remove manifest");
    remove_owned_manifest(&first_stage).expect("partial cleanup");
    remove_owned_manifest(&first_stage).expect("repeated cleanup");
    assert!(!dir.path().join("session").exists());

    let (dir, second_stage, _) = stage();
    fs::remove_file(&second_stage.firecracker).expect("remove binary");
    remove_owned_manifest(&second_stage).expect("partial cleanup");
    assert!(!dir.path().join("session").exists());

    let (dir, third_stage, _) = stage();
    fs::remove_dir_all(&third_stage.root).expect("remove root");
    remove_owned_manifest(&third_stage).expect("missing root");
    assert!(!dir.path().join("session").exists());
}

#[test]
fn cleanup_rejects_and_preserves_foreign_replacement() {
    let (_dir, stage, _) = stage();
    fs::remove_file(&stage.firecracker).expect("remove owned binary");
    fs::write(&stage.firecracker, b"foreign").expect("replacement");
    fs::set_permissions(&stage.firecracker, fs::Permissions::from_mode(0o555)).expect("mode");
    assert!(remove_owned_manifest(&stage).is_err());
    assert_eq!(
        fs::read(&stage.firecracker).expect("foreign remains"),
        b"foreign"
    );
}
