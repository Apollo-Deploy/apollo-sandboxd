use super::{ExecEventRouter, JournalItem, OutputJournal};
use crate::guest::GuestPeer;
use guest_protocol::{GuestMessage, OutputRecord, Stream};
use sandboxd_protocol::{ExecId, OperationId, exec::OutputPolicy};
use std::{fs, os::unix::fs::PermissionsExt};

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, ExecId) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let exec = ExecId::new("saved").unwrap();
    let path = root.join(exec.as_str());
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    (temp, root, exec)
}
#[test]
fn transport_boundary_survives_reopen_without_consuming_next_sequence() {
    let (_temp, root, exec) = fixture();
    let path = root.join(exec.as_str());
    let mut journal = OutputJournal::open(&path, exec.clone(), 1 << 20).unwrap();
    journal.append(Stream::Stdout, 1, 0, b"before").unwrap();
    journal.mark_transport_gap().unwrap();
    journal.mark_transport_gap().unwrap();
    assert_eq!(journal.high_watermark().unwrap(), 1);
    drop(journal);
    let mut journal = OutputJournal::open(&path, exec, 1 << 20).unwrap();
    assert_eq!(journal.replay(2, 1).unwrap().transport_gaps, vec![1]);
    assert_eq!(
        journal
            .append_at(2, Stream::Stdout, 2, 0, b"after")
            .unwrap()
            .sequence,
        2
    );
    let page = journal.replay(2, 1).unwrap();
    assert_eq!(page.transport_gaps, vec![1]);
    assert!(matches!(&page.items[0], JournalItem::Record(record) if record.payload == b"after"));
}
#[test]
fn transport_restore_preserves_actual_lost_guest_sequence_range() {
    let (_temp, root, exec) = fixture();
    let path = root.join(exec.as_str());
    let journal = OutputJournal::open(&path, exec.clone(), 1 << 20).unwrap();
    let router = ExecEventRouter::new(&root).unwrap();
    router
        .register(exec.clone(), journal, None, None, OutputPolicy::Disabled, 0)
        .unwrap();
    router
        .handle(GuestPeer {
            request_id: 0,
            operation: OperationId::new("event").unwrap(),
            message: GuestMessage::Output {
                record: OutputRecord {
                    exec: exec.clone(),
                    sequence: 4,
                    timestamp_unix_ms: 1,
                    flags: 0,
                    stream: Stream::Stdout,
                    payload: b"fourth".to_vec(),
                },
            },
        })
        .unwrap();
    let page = router.replay(&exec, 1, 8).unwrap();
    assert_eq!(page.high_watermark, 4);
    assert_eq!(router.replay(&exec, 1, 1).unwrap().items.len(), 1);
    assert!(
        matches!(&router.replay(&exec, 4, 1).unwrap().items[0], JournalItem::Record(record) if record.sequence == 4)
    );
    assert!(matches!(
        page.items[0],
        JournalItem::Gap {
            from_sequence: 1,
            to_sequence: 3
        }
    ));
    assert!(matches!(&page.items[1], JournalItem::Record(record) if record.sequence == 4));
}
#[test]
fn transport_restore_terminal_required_output_needs_no_live_descriptors() {
    let (_temp, root, exec) = fixture();
    let path = root.join(exec.as_str());
    ExecEventRouter::prepare_manifest(&path, &exec, [7; 32], OutputPolicy::Required, 1 << 20)
        .unwrap();
    let journal = OutputJournal::open(&path, exec.clone(), 1 << 20).unwrap();
    drop(journal);
    let bytes = sandboxd_protocol::codec::encode_body(
        &serde_json::json!({"exit_code":0,"signal":null,"timed_out":false}),
    )
    .unwrap();
    fs::write(path.join("exit.cbor"), bytes).unwrap();
    fs::set_permissions(path.join("exit.cbor"), fs::Permissions::from_mode(0o600)).unwrap();
    let router = ExecEventRouter::restore(&root).unwrap();
    assert_eq!(router.exit(&exec).unwrap(), Some((Some(0), None, false)));
    assert!(
        router
            .replay(&exec, 1, 8)
            .unwrap()
            .transport_gaps
            .is_empty()
    );
}
