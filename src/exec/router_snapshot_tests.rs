use super::router::*;
use crate::exec::{JournalItem, OutputJournal};
use crate::guest::GuestPeer;
use guest_protocol::{GuestMessage, OutputRecord, Stream};
use sandboxd_protocol::{ExecId, exec::OutputPolicy};
use sandboxd_protocol::{OperationId, SnapshotId};
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn output_snapshot_restores_prior_binary_journal_state() {
    let temp = tempfile::Builder::new()
        .prefix("sandboxd-router-")
        .tempdir_in(".")
        .expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    let source = root.join("router");
    let exec = ExecId::new("exec").expect("exec");
    let exec_root = source.join(exec.as_str());
    fs::create_dir_all(&exec_root).expect("exec root");
    fs::set_permissions(&exec_root, fs::Permissions::from_mode(0o700)).expect("exec root mode");
    let digest = [3; 32];
    ExecEventRouter::prepare_manifest(&exec_root, &exec, digest, OutputPolicy::Disabled, 0)
        .expect("manifest");
    let journal = OutputJournal::open(&exec_root, exec.clone(), 1 << 20).expect("journal");
    let router = ExecEventRouter::new(&source).expect("router");
    router
        .register(exec.clone(), journal, None, None, OutputPolicy::Disabled, 0)
        .expect("register");
    let output = |sequence, payload| GuestMessage::Output {
        record: OutputRecord {
            exec: exec.clone(),
            stream: Stream::Stdout,
            sequence,
            timestamp_unix_ms: sequence,
            flags: 0,
            payload,
        },
    };
    router
        .handle(GuestPeer {
            request_id: 0,
            operation: OperationId::new("event-1").unwrap(),
            message: output(1, b"before\0".to_vec()),
        })
        .expect("first");
    let snapshot_id = SnapshotId::new("snapshot").expect("snapshot id");
    let mut persisted = false;
    let record = router
        .snapshot_capture(&root.join("snapshots"), &snapshot_id, 8 << 20, &mut |_| {
            persisted = true;
            Ok(())
        })
        .expect("capture");
    router
        .handle(GuestPeer {
            request_id: 0,
            operation: OperationId::new("event-2").unwrap(),
            message: output(2, b"after\xff".to_vec()),
        })
        .expect("second");
    assert!(persisted);
    let restored = root.join("restored");
    ExecEventRouter::snapshot_restore(&record, &restored).expect("restore");
    let recovered = ExecEventRouter::restore(&restored).expect("reopen");
    let page = recovered.replay(&exec, 1, 16).expect("replay");
    let payloads: Vec<_> = page
        .items
        .into_iter()
        .filter_map(|item| match item {
            JournalItem::Record(record) => Some(record.payload),
            JournalItem::Gap { .. } => None,
        })
        .collect();
    assert_eq!(payloads, vec![b"before\0".to_vec()]);
}

#[test]
fn output_snapshot_callback_failure_cleans_owned_partial_artifact() {
    let temp = tempfile::Builder::new()
        .prefix("sandboxd-router-partial-")
        .tempdir_in(".")
        .expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    let source = root.join("router");
    let exec = ExecId::new("exec").expect("exec");
    let exec_root = source.join(exec.as_str());
    fs::create_dir_all(&exec_root).expect("exec root");
    fs::set_permissions(&exec_root, fs::Permissions::from_mode(0o700)).expect("exec root mode");
    let digest = [3; 32];
    ExecEventRouter::prepare_manifest(&exec_root, &exec, digest, OutputPolicy::Disabled, 0)
        .expect("manifest");
    let journal = OutputJournal::open(&exec_root, exec.clone(), 1 << 20).expect("journal");
    let router = ExecEventRouter::new(&source).expect("router");
    router
        .register(exec, journal, None, None, OutputPolicy::Disabled, 0)
        .expect("register");
    let snapshot_id = SnapshotId::new("partial").expect("snapshot id");
    let error = router
        .snapshot_capture(&root.join("snapshots"), &snapshot_id, 8 << 20, &mut |_| {
            Err(crate::error::Error::State)
        })
        .expect_err("callback failure");
    assert!(matches!(error, crate::error::Error::State));
    assert!(!root.join("snapshots/partial").exists());
}
