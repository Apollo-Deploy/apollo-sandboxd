use super::{JournalItem, OutputJournal};
use guest_protocol::Stream;
use rusqlite::Connection;
use sandboxd_protocol::ExecId;
use std::{os::unix::fs::PermissionsExt, path::PathBuf};
use tempfile::TempDir;

fn journal(max: u64) -> (TempDir, PathBuf, OutputJournal) {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().canonicalize().expect("canonical temp dir");
    let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).expect("private temp dir");
    let exec = ExecId::new("exec").expect("id");
    let journal = OutputJournal::open(&path, exec, max).expect("journal");
    (directory, path, journal)
}

#[test]
fn binary_output_reopens_and_replays() {
    let (_directory, path, mut journal) = journal(1 << 20);
    let expected = journal
        .append(Stream::Stdout, 7, 3, &[0, 255, 10])
        .expect("append");
    drop(journal);
    let exec = ExecId::new("exec").expect("id");
    let journal = OutputJournal::open(&path, exec, 1 << 20).expect("reopen");
    let page = journal.replay(1, 8).expect("replay");
    assert!(matches!(&page.items[0], JournalItem::Record(_)));
    if let JournalItem::Record(actual) = &page.items[0] {
        assert_eq!(actual.sequence, expected.sequence);
        assert_eq!(actual.timestamp_unix_ms, expected.timestamp_unix_ms);
        assert_eq!(actual.flags, expected.flags);
        assert_eq!(actual.payload, expected.payload);
    }
}

#[test]
fn retention_reports_explicit_gap() {
    let (_directory, _path, mut journal) = journal(1 << 20);
    for _ in 0..20 {
        journal
            .append(Stream::Stderr, 1, 0, &vec![4; 64 << 10])
            .expect("append");
    }
    let page = journal.replay(1, 8).expect("replay");
    assert!(matches!(page.items.first(), Some(JournalItem::Gap { .. })));
}

#[test]
fn oversized_payload_is_rejected() {
    let (_directory, _path, mut journal) = journal(1 << 20);
    assert!(
        journal
            .append(Stream::Stdout, 0, 0, &vec![0; (16 << 20) + 1])
            .is_err()
    );
    assert_eq!(journal.high_watermark().expect("watermark"), 0);
}

#[test]
fn corrupt_payload_is_reported_as_gap() {
    let (_directory, path, mut journal) = journal(1 << 20);
    journal
        .append(Stream::Stdout, 0, 0, b"original")
        .expect("append");
    drop(journal);
    let connection = Connection::open(path.join("journal.sqlite3")).expect("database");
    connection
        .execute(
            "UPDATE output_records SET payload=?1 WHERE sequence=1",
            [b"tampered".as_slice()],
        )
        .expect("tamper fixture");
    let exec = ExecId::new("exec").expect("id");
    let journal = OutputJournal::open(&path, exec, 1 << 20).expect("reopen");
    assert!(matches!(
        journal.replay(1, 8).expect("replay").items.first(),
        Some(JournalItem::Gap {
            from_sequence: 1,
            to_sequence: 1
        })
    ));
}

#[test]
fn different_exec_cannot_reopen_journal() {
    let (_directory, path, journal) = journal(1 << 20);
    drop(journal);
    let other = ExecId::new("other-exec").expect("id");
    assert!(OutputJournal::open(&path, other, 1 << 20).is_err());
}

#[test]
fn missing_middle_record_preserves_later_record() {
    let (_directory, path, mut journal) = journal(1 << 20);
    journal
        .append(Stream::Stdout, 1, 0, b"one")
        .expect("append");
    journal
        .append(Stream::Stdout, 2, 0, b"two")
        .expect("append");
    journal
        .append(Stream::Stdout, 3, 0, b"three")
        .expect("append");
    drop(journal);
    let connection = Connection::open(path.join("journal.sqlite3")).expect("database");
    connection
        .execute("DELETE FROM output_records WHERE sequence=2", [])
        .expect("delete fixture");
    let exec = ExecId::new("exec").expect("id");
    let journal = OutputJournal::open(&path, exec, 1 << 20).expect("reopen");
    let page = journal.replay(1, 8).expect("replay");
    assert!(matches!(page.items[0], JournalItem::Record(_)));
    assert!(matches!(
        page.items[1],
        JournalItem::Gap {
            from_sequence: 2,
            to_sequence: 2
        }
    ));
    assert!(matches!(page.items[2], JournalItem::Record(_)));
}

#[test]
fn truncated_database_fails_closed() {
    let (_directory, path, journal) = journal(1 << 20);
    drop(journal);
    std::fs::write(path.join("journal.sqlite3"), b"truncated").expect("truncate");
    let exec = ExecId::new("exec").expect("id");
    assert!(OutputJournal::open(&path, exec, 1 << 20).is_err());
}
