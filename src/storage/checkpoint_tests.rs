use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn private() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private")
}
#[test]
fn atomic_checkpoint_detects_corruption_and_does_not_change_source_cursor() {
    use std::io::{Seek, SeekFrom};
    let root = private();
    let path = root.path().canonicalize().expect("root");
    fs::write(path.join("source"), b"checkpoint-bytes").expect("source");
    let mut source = File::open(path.join("source")).expect("source");
    source.seek(SeekFrom::Start(7)).expect("cursor");
    let catalog = CheckpointCatalog::open(path.join("checkpoints")).expect("catalog");
    let id = CheckpointId::new("cp").expect("id");
    catalog
        .create_from_file(
            id.clone(),
            "sb".into(),
            1,
            &source,
            identity(&source).expect("identity"),
        )
        .expect("copy");
    assert_eq!(source.stream_position().expect("cursor"), 7);
    assert_eq!(
        catalog
            .verify_file(&id)
            .expect("verify")
            .metadata()
            .expect("stat")
            .len(),
        16
    );
    fs::write(path.join("checkpoints/cp/drive.img"), b"corrupt").expect("corrupt");
    assert!(catalog.verify_file(&id).is_err());
    assert!(catalog.delete(&id).is_err());
}
#[test]
fn foreign_symlinks_and_same_content_replacement_are_preserved() {
    let root = private();
    let path = root.path().canonicalize().expect("root");
    let catalog = CheckpointCatalog::open(path.join("checkpoints")).expect("catalog");
    fs::write(path.join("source"), b"bytes").expect("source");
    let source = File::open(path.join("source")).expect("source");
    let id = CheckpointId::new("cp").expect("id");
    catalog
        .create_from_file(
            id.clone(),
            "sb".into(),
            1,
            &source,
            identity(&source).expect("identity"),
        )
        .expect("copy");
    let data = path.join("checkpoints/cp/drive.img");
    fs::rename(&data, path.join("owned-old")).expect("replace");
    fs::write(&data, b"bytes").expect("foreign identical content");
    assert!(catalog.delete(&id).is_err());
    assert!(data.exists());
    fs::remove_file(&data).expect("fixture");
    symlink(path.join("source"), &data).expect("symlink");
    assert!(catalog.verify_file(&id).is_err());
    assert_eq!(
        fs::read(path.join("source")).expect("foreign preserved"),
        b"bytes"
    );
}
#[test]
fn existing_checkpoint_is_never_overwritten_and_owned_deletion_succeeds() {
    let root = private();
    let path = root.path().canonicalize().expect("root");
    let catalog = CheckpointCatalog::open(path.join("checkpoints")).expect("catalog");
    fs::write(path.join("source"), b"bytes").expect("source");
    let source = File::open(path.join("source")).expect("source");
    let id = CheckpointId::new("cp").expect("id");
    let expected = identity(&source).expect("identity");
    catalog
        .create_from_file(id.clone(), "sb".into(), 1, &source, expected)
        .expect("copy");
    assert!(
        catalog
            .create_from_file(id.clone(), "sb".into(), 1, &source, expected)
            .is_err()
    );
    catalog.verify_file(&id).expect("old remains valid");
    catalog.delete(&id).expect("owned delete");
    assert!(!path.join("checkpoints/cp").exists());
}

#[test]
fn restore_keeps_original_until_prepared_identity_commits_and_reconciles_rename() {
    use crate::storage::checkpoint_restore::open_drive;
    use sandboxd_protocol::{OperationId, VolumeId};
    let root = private();
    let path = root.path().canonicalize().unwrap();
    let volume = VolumeId::new("state").unwrap();
    let target = path.join("volume-state.ext4");
    fs::write(path.join("source"), b"good-checkpoint").unwrap();
    let source = File::open(path.join("source")).unwrap();
    let catalog = CheckpointCatalog::open(path.join("checkpoints")).unwrap();
    let checkpoint = CheckpointId::new("cp").unwrap();
    catalog
        .create_from_file(
            checkpoint.clone(),
            "sb".into(),
            1,
            &source,
            identity(&source).unwrap(),
        )
        .unwrap();
    fs::write(&target, b"changed-content").unwrap();
    let old = identity(&File::open(&target).unwrap()).unwrap();
    let operation = OperationId::new("restore").unwrap();
    let mut recorded = None;
    assert!(
        catalog
            .restore(
                &checkpoint,
                &path,
                &volume,
                old,
                &operation,
                None,
                |prepared| {
                    recorded = Some(prepared);
                    Err(Error::State)
                }
            )
            .is_err()
    );
    assert_eq!(fs::read(&target).unwrap(), b"changed-content");
    open_drive(&path, &volume, old).unwrap();
    let restored = catalog
        .restore(
            &checkpoint,
            &path,
            &volume,
            old,
            &operation,
            recorded,
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"good-checkpoint");
    assert_ne!(restored.inode, old.inode);
    // A restart after rename but before the SQLite completion recognizes the exact replacement.
    assert_eq!(
        catalog
            .restore(
                &checkpoint,
                &path,
                &volume,
                old,
                &operation,
                Some(restored),
                |_| panic!("must not copy again")
            )
            .unwrap(),
        restored
    );
    fs::rename(&target, path.join("owned-restored")).unwrap();
    fs::write(&target, b"foreign-content").unwrap();
    assert!(
        catalog
            .restore(
                &checkpoint,
                &path,
                &volume,
                old,
                &operation,
                Some(restored),
                |_| Ok(())
            )
            .is_err()
    );
    assert_eq!(fs::read(&target).unwrap(), b"foreign-content");
}

#[test]
fn checkpoint_delete_reconciles_a_crash_after_data_unlink() {
    let root = private();
    let path = root.path().canonicalize().unwrap();
    fs::write(path.join("source"), b"bytes").unwrap();
    let source = File::open(path.join("source")).unwrap();
    let catalog = CheckpointCatalog::open(path.join("checkpoints")).unwrap();
    let id = CheckpointId::new("cp").unwrap();
    catalog
        .create_from_file(
            id.clone(),
            "sb".into(),
            1,
            &source,
            identity(&source).unwrap(),
        )
        .unwrap();
    fs::rename(
        path.join("checkpoints/cp"),
        path.join("checkpoints/.deleted-cp"),
    )
    .unwrap();
    fs::remove_file(path.join("checkpoints/.deleted-cp/drive.img")).unwrap();
    catalog.delete(&id).unwrap();
    catalog.delete(&id).unwrap();
    assert!(!path.join("checkpoints/.deleted-cp").exists());
}
