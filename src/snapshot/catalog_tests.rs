//! Catalog attacks exercise real files; VM snapshot qualification is separate.
use super::*;
use crate::{error::Result, security::path::SecureDir};
use sandboxd_protocol::*;
#[cfg(target_os = "linux")]
use sha2::Digest;
use std::{fs, io::Write, os::unix::fs::PermissionsExt, sync::Arc};

struct TestKeys;
impl KeyProvider for TestKeys {
    fn key(&self) -> Result<SnapshotKey> {
        Ok(SnapshotKey::fixture([37; 32]))
    }
}
fn root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap()
}
fn context() -> ArtifactContext {
    ArtifactContext {
        snapshot: SnapshotId::new("snap-one").unwrap(),
        sandbox: SandboxId::new("sb-one").unwrap(),
        sandbox_generation: SandboxGeneration::new(1).unwrap(),
        session: SessionId::new("session-one").unwrap(),
        session_generation: SessionGeneration::new(2).unwrap(),
        kind: ArtifactKind::Manifest,
    }
}
#[test]
fn partial_cleanup_preserves_unknown_objects_and_foreign_inode() {
    let root = root();
    let parent = SecureDir::open(&root.path().canonicalize().unwrap()).unwrap();
    let catalog = SnapshotCatalog::open(root.path().join("snapshots"), Arc::new(TestKeys)).unwrap();
    let stage_name = ".snapshot-snap-one-12345678901234567890123456789012";
    let directory = catalog.root.create_private_directory(stage_name).unwrap();
    let mut file = directory.create_file("memory.enc").unwrap();
    let artifact = super::artifact::file_identity(&file, 20, "0".repeat(64)).unwrap();
    let record = SnapshotArtifacts {
        version: 1,
        context: context(),
        stage_name: stage_name.into(),
        directory: super::artifact::directory_identity(&directory).unwrap(),
        memory: Some(artifact),
        state: None,
        manifest: None,
    };
    file.write_all(b"partial ciphertext").unwrap();
    file.sync_all().unwrap();
    let foreign = directory.create_file("foreign").unwrap();
    assert!(catalog.delete(&record).is_err());
    assert!(
        root.path()
            .join("snapshots")
            .join(stage_name)
            .join("memory.enc")
            .exists()
    );
    let foreign_stat = rustix::fs::fstat(&foreign).unwrap();
    directory
        .remove_if_identity(
            "foreign",
            crate::security::path::device_id(foreign_stat.st_dev),
            foreign_stat.st_ino,
            rustix::fs::FileType::RegularFile,
        )
        .unwrap();
    fs::rename(
        root.path()
            .join("snapshots")
            .join(stage_name)
            .join("memory.enc"),
        root.path().join("saved-ciphertext"),
    )
    .unwrap();
    let replacement = directory.create_file("memory.enc").unwrap();
    assert!(catalog.delete(&record).is_err());
    assert!(
        root.path()
            .join("snapshots")
            .join(stage_name)
            .join("memory.enc")
            .exists()
    );
    drop(replacement);
    fs::remove_file(
        root.path()
            .join("snapshots")
            .join(stage_name)
            .join("memory.enc"),
    )
    .unwrap();
    fs::rename(
        root.path().join("saved-ciphertext"),
        root.path()
            .join("snapshots")
            .join(stage_name)
            .join("memory.enc"),
    )
    .unwrap();
    catalog.delete(&record).unwrap();
    catalog.delete(&record).unwrap();
    assert!(!root.path().join("snapshots").join(stage_name).exists());
    drop(parent);
}
#[test]
fn policy_rejects_unbounded_limits_and_key_inside_artifact_directory() {
    let mut settings = SnapshotSettings {
        directory: "/var/lib/sandboxd/snapshots".into(),
        key_file: "/etc/sandboxd/snapshot.key".into(),
        max_snapshots_per_sandbox: 4,
        max_total_bytes: 1 << 30,
        max_concurrent_operations: 2,
        max_restore_memory_bytes: 128 << 20,
    };
    assert!(settings.validate().is_ok());
    settings.key_file = settings.directory.join("key");
    assert!(settings.validate().is_err());
    settings.key_file = "/etc/sandboxd/key".into();
    settings.max_concurrent_operations = 0;
    assert!(settings.validate().is_err());
}

#[cfg(target_os = "linux")]
fn anonymous(bytes: &[u8]) -> fs::File {
    let mut file = fs::File::from(
        rustix::fs::memfd_create(
            "snapshot-catalog-test",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .unwrap(),
    );
    file.write_all(bytes).unwrap();
    file
}
#[cfg(target_os = "linux")]
fn manifest() -> SnapshotManifest {
    SnapshotManifest {
        version: 1,
        id: context().snapshot,
        sandbox: context().sandbox,
        sandbox_generation: context().sandbox_generation,
        session: context().session,
        session_generation: context().session_generation,
        runtime_profile: "fc-profile".into(),
        runtime_version: "1.17.0".into(),
        firecracker_sha256: "1".repeat(64),
        jailer_sha256: "2".repeat(64),
        kernel_sha256: "3".repeat(64),
        initramfs_sha256: "4".repeat(64),
        base_image: ImageDigest::new(format!("sha256:{}", "5".repeat(64))).unwrap(),
        writable_drive_sha256: "6".repeat(64),
        snapshot_format: "full-fc-1.17.0".into(),
        memory_bytes: 65537,
        state_bytes: 32,
        memory_sha256: "0".repeat(64),
        state_sha256: "0".repeat(64),
        secret_policy: super::SnapshotSecretPolicy::Reject,
        vsock_cid: 3,
        boot_nonce: guest_protocol::BootNonce([39; 32]),
        architecture: Architecture::X86_64,
        host_boot_id: "00000000-0000-4000-8000-000000000001".into(),
        host_kernel_release: "6.18.0".into(),
        cpu_fingerprint: "7".repeat(64),
        output_sha256: "8".repeat(64),
        checkpoint: CheckpointId::new("cp-one").unwrap(),
        has_received_secrets: false,
        memory_mib: 64,
        vcpu_count: 1,
    }
}
#[cfg(target_os = "linux")]
#[test]
fn ciphertext_catalog_round_trip_recovery_tamper_and_sealed_decrypt() {
    use std::io::Read;
    let root = root();
    let catalog = SnapshotCatalog::open(root.path().join("snapshots"), Arc::new(TestKeys)).unwrap();
    let data = vec![0x99; 65537];
    let state_data = [0xab; 32];
    let mut receipts = Vec::new();
    let record = catalog
        .publish(
            &manifest(),
            &anonymous(&data),
            &anonymous(&state_data),
            |record| {
                receipts.push(record.clone());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(receipts.len(), 7);
    assert!(receipts[0].memory.is_none());
    assert!(receipts[1].memory.as_ref().unwrap().cipher_sha256.is_none());
    let confirmed = catalog.verify(&record).unwrap();
    assert_eq!(
        confirmed.memory_sha256,
        hex::encode(sha2::Sha256::digest(&data))
    );
    let mut verified = catalog.decrypt(&record).unwrap();
    let mut actual = Vec::new();
    verified.memory.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, data);
    assert!(verified.memory.write_all(b"mutate").is_err());
    fs::rename(
        root.path().join("snapshots/snap-one"),
        root.path().join("snapshots").join(&record.stage_name),
    )
    .unwrap();
    assert!(catalog.recover_publish(&record).unwrap());
    assert!(catalog.recover_publish(&record).unwrap());
    let mut wrong = record.clone();
    wrong.context.session_generation = SessionGeneration::new(3).unwrap();
    assert!(catalog.verify(&wrong).is_err());
    let ciphertext = root.path().join("snapshots/snap-one/memory.enc");
    let bytes = fs::read(&ciphertext).unwrap();
    assert!(!bytes.windows(32).any(|w| w == [0x99; 32]));
    let mut corrupted = bytes.clone();
    corrupted[40] ^= 1;
    fs::write(&ciphertext, corrupted).unwrap();
    assert!(catalog.decrypt(&record).is_err());
    // Ownership proof permits deleting a corrupted owned artifact, but no loading it.
    catalog.delete(&record).unwrap();
    catalog.delete(&record).unwrap();
}
#[cfg(target_os = "linux")]
#[test]
fn crash_after_partial_encryption_callback_cleans_only_journaled_inodes() {
    let root = root();
    let catalog = SnapshotCatalog::open(root.path().join("snapshots"), Arc::new(TestKeys)).unwrap();
    let mut last = None;
    let mut count = 0;
    let result = catalog.publish(
        &manifest(),
        &anonymous(&vec![11; 65537]),
        &anonymous(&[22; 32]),
        |record| {
            count += 1;
            if count == 3 {
                Err(crate::error::Error::State)
            } else {
                last = Some(record.clone());
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    let record = last.unwrap();
    assert!(!catalog.recover_publish(&record).unwrap());
    catalog.delete(&record).unwrap();
    assert!(
        !root
            .path()
            .join("snapshots")
            .join(&record.stage_name)
            .exists()
    );
}
