use super::*;
use crate::exec::{ExecEventRouter, OutputJournal};
use sandboxd_protocol::exec::OutputPolicy;
use std::os::unix::fs::{PermissionsExt, symlink};

fn fixture() -> (
    tempfile::TempDir,
    PathBuf,
    super::super::bridge::SnapshotExec,
) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("exec");
    fs::create_dir(&source).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
    let exec = ExecId::new("exec").unwrap();
    ExecEventRouter::prepare_manifest(&source, &exec, [1; 32], OutputPolicy::Disabled, 0).unwrap();
    let mut journal = OutputJournal::open(&source, exec.clone(), 1 << 20).unwrap();
    journal
        .append(guest_protocol::Stream::Stdout, 1, 0, b"preserved")
        .unwrap();
    journal.snapshot_checkpoint().unwrap();
    drop(journal);
    (
        temp,
        root,
        super::super::bridge::SnapshotExec {
            exec,
            source,
            high_watermark: 1,
            exit: None,
            max_bytes: 1 << 20,
        },
    )
}
fn captured(root: &Path, item: super::super::bridge::SnapshotExec) -> OutputSnapshotRecord {
    capture(
        &root.join("snapshots"),
        "saved",
        8 << 20,
        &mut |_| Ok(()),
        &[item],
    )
    .unwrap()
}
#[test]
fn output_snapshot_strict_manifest_and_resumable_owned_cleanup() {
    let (_temp, root, item) = fixture();
    let record = captured(&root, item);
    verify(&record).unwrap();
    fs::remove_file(record.root.join(MANIFEST)).unwrap();
    assert!(verify(&record).is_err());
    fs::remove_file(record.root.join(&record.files[0].relative)).unwrap();
    delete(&record).unwrap();
    delete(&record).unwrap();
    assert!(!record.root.exists());
}
#[test]
fn output_snapshot_corrupt_bytes_remain_safe_to_delete() {
    let (_temp, root, item) = fixture();
    let record = captured(&root, item);
    fs::write(record.root.join(MANIFEST), b"corrupt").unwrap();
    assert!(verify(&record).is_err());
    delete(&record).unwrap();
}
#[test]
fn output_snapshot_unknown_and_replaced_children_are_untouched() {
    let (_temp, root, item) = fixture();
    let record = captured(&root, item);
    let extra = record.root.join("foreign");
    fs::write(&extra, b"keep").unwrap();
    assert!(delete(&record).is_err());
    assert!(record.root.join(&record.files[0].relative).exists());
    fs::remove_file(extra).unwrap();
    let original = record.root.join("exec");
    let moved = root.join("moved");
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(original.join("journal.sqlite3"), b"foreign").unwrap();
    assert!(delete(&record).is_err());
    assert_eq!(
        fs::read(original.join("journal.sqlite3")).unwrap(),
        b"foreign"
    );
    assert!(moved.join("journal.sqlite3").exists());
}
#[test]
fn output_snapshot_callback_failure_at_every_stage_cleans_only_owned_objects() {
    let (_temp, root, item) = fixture();
    let mut receipts = Vec::new();
    let record = capture(
        &root.join("snapshots"),
        "saved",
        8 << 20,
        &mut |record| {
            receipts.push(record.clone());
            Ok(())
        },
        &[item],
    )
    .unwrap();
    delete(&record).unwrap();
    for stop in 1..=receipts.len() {
        let (_temp, root, item) = fixture();
        let mut count = 0;
        assert!(
            capture(
                &root.join("snapshots"),
                "saved",
                8 << 20,
                &mut |record| {
                    count += 1;
                    // Every ledger callback precedes mutation of its newly introduced inode.
                    if let Some(file) = record.files.last() {
                        assert!(
                            fs::metadata(record.root.join(&file.relative))
                                .unwrap()
                                .len()
                                <= file.bytes
                        );
                    }
                    if count == stop {
                        Err(Error::State)
                    } else {
                        Ok(())
                    }
                },
                &[item]
            )
            .is_err()
        );
        assert!(!root.join("snapshots/saved").exists(), "callback {stop}");
    }
}
#[test]
fn output_snapshot_restore_refuses_existing_or_symlink_destination() {
    let (_temp, root, item) = fixture();
    let record = captured(&root, item);
    let target = root.join("target");
    fs::create_dir(&target).unwrap();
    assert!(restore(&record, &target).is_err());
    let link = root.join("link");
    symlink(&target, &link).unwrap();
    assert!(restore(&record, &link).is_err());
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
}

#[test]
fn output_snapshot_restore_journals_new_inodes_and_recovers_callback_failure() {
    let (_temp, root, item) = fixture();
    let record = captured(&root, item);
    let target = root.join("restored");
    let mut ledger = None;
    assert!(
        restore_journaled(&record, &target, &mut |entry| {
            assert_eq!(entry.root, target);
            ledger = Some(entry.clone());
            if !entry.files.is_empty() {
                Err(Error::State)
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    delete(&ledger.unwrap()).unwrap();
    assert!(!target.exists());
    verify(&record).unwrap();
}
