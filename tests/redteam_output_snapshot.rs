use apollo_sandboxd::exec::OutputSnapshotRecord;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

#[test]
fn restore_rejects_symlink_target_without_changing_foreign_permissions() {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    let root = base.join("snapshot");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let stat = fs::symlink_metadata(&root).unwrap();
    let record = OutputSnapshotRecord {
        id: "empty".into(),
        root: root.clone(),
        bytes: 0,
        digest: [0; 32],
        root_device: stat.dev(),
        root_inode: stat.ino(),
        manifest_device: 0,
        manifest_inode: 0,
        directories: vec![],
        files: vec![],
        execs: vec![],
    };
    let foreign = base.join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755)).unwrap();
    let target = base.join("restore");
    std::os::unix::fs::symlink(&foreign, &target).unwrap();
    let result = apollo_sandboxd::exec::ExecEventRouter::snapshot_restore_journaled(
        &record,
        &target,
        &mut |_| Ok(()),
    );
    eprintln!("restore result: {result:?}");
    let mode = fs::symlink_metadata(&foreign).unwrap().mode() & 0o777;
    eprintln!("foreign mode: {mode:o}");
    assert!(result.is_err());
    assert_eq!(
        mode, 0o755,
        "foreign target permissions must remain unchanged"
    );
    assert!(target.is_symlink());
}
