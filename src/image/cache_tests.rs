use super::*;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;

#[test]
fn layout_descriptor_is_bounded_and_digest_path_is_strict() {
    let directory = tempfile::tempdir_in(
        std::env::temp_dir()
            .canonicalize()
            .expect("temporary directory"),
    )
    .expect("tempdir");
    let blobs = directory.path().join("blobs/sha256");
    fs::create_dir_all(&blobs).expect("blobs");
    let bytes = b"oci payload";
    let digest = format!("sha256:{:x}", Sha256::digest(bytes));
    fs::write(blobs.join(&digest[7..]), bytes).expect("blob");
    let descriptor = OciDescriptor {
        media_type: "application/octet-stream".into(),
        digest: digest.clone(),
        size: bytes.len() as u64,
        platform: None,
    };
    assert_eq!(
        read_layout_blob(directory.path(), &descriptor, 1024).expect("read"),
        bytes
    );
    assert!(read_layout_blob(directory.path(), &descriptor, 1).is_err());
    let mut invalid = descriptor;
    invalid.digest = digest.to_ascii_uppercase();
    assert!(read_layout_blob(directory.path(), &invalid, 1024).is_err());
}

#[test]
fn verified_publication_rejects_symlink_and_preserves_digest_inode() {
    let directory = tempfile::tempdir_in(
        std::env::temp_dir()
            .canonicalize()
            .expect("temporary directory"),
    )
    .expect("tempdir");
    let destination = directory.path().join("blob");
    let bytes = b"immutable";
    let digest = format!("sha256:{:x}", Sha256::digest(bytes));
    write_verified(&destination, bytes, &digest).expect("publish");
    assert_eq!(
        read_verified(&destination, &digest, bytes.len() as u64, 1024).expect("verify"),
        bytes
    );
    fs::remove_file(&destination).expect("remove");
    let outside = directory.path().join("outside");
    fs::write(&outside, bytes).expect("outside");
    std::os::unix::fs::symlink(&outside, &destination).expect("symlink");
    assert!(write_verified(&destination, bytes, &digest).is_err());
}

#[cfg(unix)]
#[test]
fn gc_rejects_symlinked_or_foreign_blob_entries() {
    let directory = tempfile::tempdir_in(
        std::env::temp_dir()
            .canonicalize()
            .expect("temporary directory"),
    )
    .expect("tempdir");
    fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private fixture");
    let cache = ImageCache::open(
        directory.path(),
        ImageLimits {
            max_blob_bytes: 1 << 20,
            max_cache_bytes: 8 << 20,
            max_layers: 8,
            max_entries: 128,
            max_uncompressed_bytes: 1 << 20,
        },
    )
    .expect("cache");
    let outside = directory.path().join("outside");
    fs::write(&outside, b"foreign").expect("outside");
    let blob = directory.path().join("blobs/sha256").join("a".repeat(64));
    std::os::unix::fs::symlink(&outside, &blob).expect("symlink");
    assert!(cache.gc().is_err());
    assert!(outside.exists());
    assert!(
        std::fs::symlink_metadata(blob)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn cache_open_rejects_symlink_without_changing_foreign_permissions_or_creating_children() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let foreign = directory.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o755)).unwrap();
    let root = directory.path().join("cache");
    std::os::unix::fs::symlink(&foreign, &root).unwrap();
    assert!(
        ImageCache::open(
            &root,
            ImageLimits {
                max_blob_bytes: 1 << 20,
                max_cache_bytes: 8 << 20,
                max_layers: 8,
                max_entries: 128,
                max_uncompressed_bytes: 1 << 20
            }
        )
        .is_err()
    );
    assert_eq!(
        fs::metadata(&foreign).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(fs::read_dir(&foreign).unwrap().next().is_none());
}

#[test]
fn materialization_error_cleans_transaction_and_retry_commits_root() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let cache = test_cache(directory.path());
    let (manifest, manifest_bytes, digest, layer_bytes, layer_digest) = test_image();
    let layer_path = cache.blob_path(&layer_digest).unwrap();
    write_verified(&layer_path, &layer_bytes, &layer_digest).unwrap();
    let _lock = crate::image::cache_lock::acquire(&cache.root).unwrap();

    fs::remove_file(&layer_path).unwrap();
    assert!(
        cache
            .materialize(
                digest.clone(),
                manifest.clone(),
                manifest_bytes.clone(),
                None,
            )
            .is_err()
    );
    assert!(
        fs::read_dir(cache.root.join("rootfs"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".txn-"))
    );

    write_verified(&layer_path, &layer_bytes, &layer_digest).unwrap();
    cache
        .materialize(digest.clone(), manifest, manifest_bytes, None)
        .expect("retry materializes and commits");
    cache
        .resolve_prepared(&digest)
        .expect("committed root resolves");
}

#[test]
fn recovery_removes_only_the_prepared_inode_from_an_interrupted_transaction() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let cache = test_cache(directory.path());
    let (_manifest, _manifest_bytes, digest, _layer_bytes, _layer_digest) = test_image();
    let digest_name = &digest[7..];
    let rootfs_path = cache.root.join("rootfs");
    let _lock = crate::image::cache_lock::acquire(&cache.root).unwrap();

    let stage =
        crate::image::materialization::MaterializingRoot::create(&rootfs_path, &digest).unwrap();
    fs::write(stage.path().join("partial"), b"staged data").unwrap();
    verify_extracted_root(&stage.path()).unwrap();
    crate::image::rootfs::sync_extracted_root(&stage.path()).unwrap();
    assert!(matches!(
        stage.publish(digest_name).unwrap(),
        crate::image::materialization::PublishResult::Installed(_)
    ));
    std::mem::forget(stage); // Simulate process death before manifest/commit publication.
    assert!(rootfs_path.join(digest_name).exists());

    cache.recover_materializations().unwrap();
    assert!(!rootfs_path.join(digest_name).exists());
    assert!(fs::read_dir(&rootfs_path).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".txn-")
    }));

    fs::create_dir(rootfs_path.join(digest_name)).unwrap();
    fs::write(rootfs_path.join(digest_name).join("foreign"), b"preserve").unwrap();
    assert!(
        cache
            .materialize(digest.clone(), _manifest, _manifest_bytes, None)
            .is_err()
    );
    assert_eq!(
        fs::read(rootfs_path.join(digest_name).join("foreign")).unwrap(),
        b"preserve"
    );
}

#[test]
fn recovery_finishes_commit_after_manifest_publication_crash() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let cache = test_cache(directory.path());
    let (_manifest, manifest_bytes, digest, _layer_bytes, _layer_digest) = test_image();
    let digest_name = &digest[7..];
    let rootfs_path = cache.root.join("rootfs");
    let _lock = crate::image::cache_lock::acquire(&cache.root).unwrap();

    let stage =
        crate::image::materialization::MaterializingRoot::create(&rootfs_path, &digest).unwrap();
    fs::write(stage.path().join("complete"), b"durable tree").unwrap();
    verify_extracted_root(&stage.path()).unwrap();
    crate::image::rootfs::sync_extracted_root(&stage.path()).unwrap();
    assert!(matches!(
        stage.publish(digest_name).unwrap(),
        crate::image::materialization::PublishResult::Installed(_)
    ));
    write_verified(
        &cache.root.join("manifests").join(digest_name),
        &manifest_bytes,
        &digest,
    )
    .unwrap();
    std::mem::forget(stage); // Simulate death after manifest fsync but before commit record.

    cache.recover_materializations().unwrap();
    crate::image::materialization::verify_committed_root(
        &rootfs_path,
        &digest,
        &rootfs_path.join(digest_name),
    )
    .expect("recovery commits the exact prepared inode");
}

fn test_cache(root: &Path) -> ImageCache {
    fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    ImageCache::open(
        root,
        ImageLimits {
            max_blob_bytes: 1 << 20,
            max_cache_bytes: 8 << 20,
            max_layers: 8,
            max_entries: 128,
            max_uncompressed_bytes: 1 << 20,
        },
    )
    .unwrap()
}

fn test_image() -> (ImageManifest, Vec<u8>, String, Vec<u8>, String) {
    let payload = b"layer payload";
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(payload.len() as u64);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    tar.append_data(&mut header, "file.txt", &payload[..])
        .unwrap();
    let layer_bytes = tar.into_inner().unwrap();
    let layer_digest = format!("sha256:{:x}", Sha256::digest(&layer_bytes));
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: Some("application/vnd.oci.image.manifest.v1+json".into()),
        config: None,
        layers: vec![OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            digest: layer_digest.clone(),
            size: layer_bytes.len() as u64,
            platform: None,
        }],
        manifests: Vec::new(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let digest = format!("sha256:{:x}", Sha256::digest(&manifest_bytes));
    (manifest, manifest_bytes, digest, layer_bytes, layer_digest)
}

#[test]
fn concurrent_publication_preserves_and_verifies_the_winning_inode() {
    use std::io::{Cursor, Read};
    use std::os::unix::fs::MetadataExt;
    struct Race {
        destination: std::path::PathBuf,
        bytes: Cursor<Vec<u8>>,
        won: bool,
    }
    impl Read for Race {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.won {
                fs::write(&self.destination, b"foreign-winner")?;
                self.won = true;
            }
            self.bytes.read(buffer)
        }
    }
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let destination = directory.path().join("blob");
    let bytes = b"verified-content";
    let digest = format!("sha256:{:x}", Sha256::digest(bytes));
    let mut source = Race {
        destination: destination.clone(),
        bytes: Cursor::new(bytes.to_vec()),
        won: false,
    };
    assert!(
        store_verified_stream(&destination, &mut source, &digest, bytes.len() as u64, 1024)
            .is_err()
    );
    let inode = fs::metadata(&destination).unwrap().ino();
    assert_eq!(fs::read(&destination).unwrap(), b"foreign-winner");
    assert!(write_verified(&destination, bytes, &digest).is_err());
    assert_eq!(fs::metadata(&destination).unwrap().ino(), inode);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn growing_or_interrupted_stream_leaves_no_published_or_temporary_object() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let destination = directory.path().join("blob");
    let digest = format!("sha256:{:x}", Sha256::digest(b"abc"));
    let mut oversized = &b"abcd"[..];
    assert!(store_verified_stream(&destination, &mut oversized, &digest, 3, 1024).is_err());
    assert!(!destination.exists());
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
    struct Broken;
    impl std::io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("interrupted fixture"))
        }
    }
    assert!(store_verified_stream(&destination, &mut Broken, &digest, 3, 1024).is_err());
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}
