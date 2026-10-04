//! Cache/security contracts using declared-format bytes, not guest boot proof.
mod support;
use apollo_sandboxd::{
    error::Error,
    storage::{ImageCache, ImageLimits},
};
use sandboxd_protocol::{ErrorCode, ImageDigest};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
};

fn bytes() -> Vec<u8> {
    let mut value = vec![0u8; 4096];
    value[1080..1082].copy_from_slice(&[0x53, 0xef]);
    value
}
fn digest(value: &[u8]) -> ImageDigest {
    ImageDigest::new(format!("sha256:{}", hex::encode(Sha256::digest(value)))).expect("digest")
}
fn limits() -> ImageLimits {
    ImageLimits {
        max_image_bytes: 8192,
        max_cache_bytes: 8192,
        max_images: 2,
    }
}

#[test]
fn cached_bytes_are_verified_and_returned_through_read_only_descriptor() {
    let directory = support::directory();
    let value = bytes();
    let id = digest(&value);
    let file = directory.path().join(&id.as_str()[7..]);
    fs::write(&file, &value).expect("fixture");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).expect("immutable");
    let cache =
        ImageCache::open(&directory.path().canonicalize().expect("path"), limits()).expect("cache");
    let mut image = cache.inspect(&id).expect("verified");
    let mut actual = Vec::new();
    image.file.read_to_end(&mut actual).expect("read");
    assert_eq!(actual, value);
    assert!(image.file.write_all(b"change").is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("corrupt fixture");
    fs::write(&file, vec![1; 4096]).expect("corruption");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).expect("immutable");
    assert!(
        matches!(cache.inspect(&id), Err(Error::Api(e)) if e.code == ErrorCode::ImageDigestMismatch)
    );
}

#[test]
fn foreign_symlink_and_hard_link_are_preserved_and_rejected() {
    let directory = support::directory();
    let foreign = support::directory();
    let value = bytes();
    let id = digest(&value);
    let target = foreign.path().join("untouched");
    fs::write(&target, &value).expect("foreign");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).expect("immutable");
    let entry = directory.path().join(&id.as_str()[7..]);
    std::os::unix::fs::symlink(&target, &entry).expect("symlink");
    let cache =
        ImageCache::open(&directory.path().canonicalize().expect("path"), limits()).expect("cache");
    assert!(cache.inspect(&id).is_err());
    assert!(
        fs::symlink_metadata(&entry)
            .expect("preserved")
            .file_type()
            .is_symlink()
    );
    fs::remove_file(&entry).expect("remove own attack fixture");
    fs::hard_link(&target, &entry).expect("hard link");
    assert!(cache.inspect(&id).is_err());
    assert_eq!(fs::read(&target).expect("foreign untouched"), value);
}

#[cfg(target_os = "linux")]
#[test]
fn imports_are_bounded_deduplicated_and_never_publish_failed_streams() {
    let directory = support::directory();
    let path = directory.path().canonicalize().expect("path");
    let mut cache = ImageCache::open(&path, limits()).expect("cache");
    let value = bytes();
    let id = digest(&value);
    let first = cache.import_raw(value.as_slice(), &id).expect("import");
    let again = cache
        .import_raw(&b"irrelevant cached reference"[..], &id)
        .expect("deduplicated");
    assert_eq!((again.device, again.inode), (first.device, first.inode));
    assert_eq!(again.bytes, value.len() as u64);
    assert!(
        matches!(cache.import_raw(value.as_slice(), &digest(b"different")), Err(Error::Api(e)) if e.code == ErrorCode::ImageDigestMismatch)
    );
    let oversized = vec![3u8; 8193];
    assert!(
        matches!(cache.import_raw(oversized.as_slice(), &digest(&oversized)), Err(Error::Api(e)) if e.code == ErrorCode::QuotaExceeded)
    );
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("interrupted input"))
        }
    }
    assert!(cache.import_raw(Broken, &digest(b"interrupted")).is_err());
    let names = fs::read_dir(&path)
        .expect("directory")
        .collect::<Result<Vec<_>, _>>()
        .expect("entries");
    assert_eq!(names.len(), 2); // Exactly the lock and completed content inode.
    drop(cache);
    let reopened = ImageCache::open(&path, limits()).expect("restart");
    assert_eq!(reopened.inspect(&id).expect("durable content").bytes, 4096);
}
