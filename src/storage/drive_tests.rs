use super::*;
use sandboxd_protocol::VolumeId;
#[cfg(target_os = "linux")]
use std::path::Path;

#[test]
fn bounds_are_fixed_and_aligned() {
    assert!(validate_size(MIN_DRIVE_BYTES).is_ok());
    assert!(validate_size(MIN_DRIVE_BYTES - 1).is_err());
    assert!(validate_size(MIN_DRIVE_BYTES + 1).is_err());
    assert!(validate_size((1 << 40) + SECTOR_BYTES).is_err());
}

#[test]
fn names_are_typed_and_path_safe() {
    let id = VolumeId::new("v-1").expect("valid id");
    assert_eq!(drive_name(&id), "volume-v-1.ext4");
}

#[test]
fn owners_are_allocator_bounded_and_non_root() {
    assert!(DriveOwner::new(100_000, 100_000).is_ok());
    assert!(DriveOwner::new(99_999, 100_000).is_err());
    assert!(DriveOwner::new(100_000, 0).is_err());
}

#[cfg(target_os = "linux")]
fn fixture_factory(root: &Path) -> DriveFactory {
    let formatter =
        std::env::var_os("APOLLO_MKFS_EXT4_PATH").expect("APOLLO_MKFS_EXT4_PATH is required");
    let digest =
        std::env::var("APOLLO_MKFS_EXT4_SHA256").expect("APOLLO_MKFS_EXT4_SHA256 is required");
    let artifact = crate::runtime::verify(Path::new(&formatter), &digest, true)
        .expect("configured formatter must verify");
    let directory = SecureDir::open(root).expect("fixture directory must be secure");
    DriveFactory::new(directory, artifact, 64 << 20).expect("valid fixture bounds")
}

#[cfg(target_os = "linux")]
#[ignore = "requires the root-owned digest-pinned native formatter fixture"]
#[test]
fn native_fixture_formats_and_reopens_pinned_drive() {
    let path =
        std::env::var_os("APOLLO_DRIVE_FIXTURE_DIR").expect("APOLLO_DRIVE_FIXTURE_DIR is required");
    let root = Path::new(&path);
    let mut factory = fixture_factory(root);
    let owner = DriveOwner::new(100_000, 100_000).expect("valid owner");
    let volume = VolumeId::new("fixture").expect("valid id");
    let drive = factory
        .create(&volume, 8 << 20, owner)
        .expect("format drive");
    assert_eq!(drive.identity.size, 8 << 20);
    let mut magic = [0u8; 2];
    std::os::unix::fs::FileExt::read_at(&drive.file, &mut magic, 1080).expect("read superblock");
    assert_eq!(magic, [0x53, 0xef]);
    let reopened = factory
        .reopen(&volume, drive.identity)
        .expect("reopen drive");
    assert_eq!(reopened.identity, drive.identity);
    let mut wrong_identity = drive.identity;
    wrong_identity.inode = wrong_identity.inode.saturating_add(1);
    assert!(factory.reopen(&volume, wrong_identity).is_err());

    let symlink_name = root.join("volume-foreign-link.ext4");
    let symlink_target = root.join("foreign-target");
    std::fs::write(&symlink_target, b"foreign").expect("foreign target");
    std::os::unix::fs::symlink(&symlink_target, &symlink_name).expect("foreign symlink");
    let link_id = VolumeId::new("foreign-link").expect("valid id");
    assert!(factory.create(&link_id, 8 << 20, owner).is_err());
    assert!(
        std::fs::symlink_metadata(&symlink_name)
            .expect("symlink metadata")
            .file_type()
            .is_symlink()
    );

    let hardlink_name = root.join("volume-foreign-hardlink.ext4");
    let hardlink_target = root.join("foreign-data");
    std::fs::write(&hardlink_target, b"foreign").expect("foreign data");
    std::fs::hard_link(&hardlink_target, &hardlink_name).expect("foreign hardlink");
    let hardlink_id = VolumeId::new("foreign-hardlink").expect("valid id");
    assert!(factory.create(&hardlink_id, 8 << 20, owner).is_err());
    assert_eq!(
        std::fs::metadata(&hardlink_target)
            .expect("hardlink metadata")
            .len(),
        7
    );

    let interrupted = VolumeId::new("interrupted").expect("valid id");
    assert!(factory.create(&interrupted, 128 << 20, owner).is_err());
    assert!(!root.join("volume-interrupted.ext4").exists());
}
