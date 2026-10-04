use super::*;
use sha2::{Digest, Sha256};
use std::path::Path;

fn page(
    path: &Path,
    cursor: Option<String>,
    limit: u16,
) -> (Vec<DirectoryEntry>, bool, Option<String>) {
    match handle(FileRequest::List {
        path: path.to_str().expect("test UTF-8 path").into(),
        cursor,
        limit,
    })
    .expect("list succeeds")
    {
        GuestMessage::FileResult {
            entries,
            eof,
            link_target,
            ..
        } => (entries, eof, link_target),
        _ => unreachable!("file result required"),
    }
}

#[test]
fn directory_pages_cover_short_final_page_and_deleted_cursor() {
    let root = tempfile::tempdir().expect("temporary directory");
    for name in ["c", "a", "e", "b", "d"] {
        fs::write(root.path().join(name), name).expect("fixture file");
    }
    let (first, eof, cursor) = page(root.path(), None, 3);
    assert_eq!(
        first.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["a", "b", "c"]
    );
    assert!(!eof);
    fs::remove_file(root.path().join("c")).expect("delete cursor entry");
    let (last, eof, cursor) = page(root.path(), cursor, 3);
    assert_eq!(
        last.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["d", "e"]
    );
    assert!(eof);
    assert!(cursor.is_none());
    assert!(page(root.path(), Some("z".into()), 3).0.is_empty());
}

#[test]
fn final_write_truncates_old_tail_and_atomic_hash_failure_preserves_destination() {
    let root = tempfile::tempdir().expect("temporary directory");
    let destination = root.path().join("file.ext");
    fs::write(&destination, b"old longer bytes").expect("fixture file");
    let path = destination.to_str().expect("UTF-8 path");
    let digest: [u8; 32] = Sha256::digest(b"new").into();
    write::write_file("replace", path, 0, b"new", true, Some(digest), false).expect("replace file");
    assert_eq!(fs::read(&destination).expect("read"), b"new");
    assert!(write::write_file("bad", path, 0, b"bad", true, Some(digest), true).is_err());
    assert_eq!(fs::read(&destination).expect("read"), b"new");
    write::write_file("good", path, 0, b"ne", false, None, true).expect("first chunk");
    write::write_file("good", path, 2, b"w", true, Some(digest), true).expect("final chunk");
    assert_eq!(fs::read(&destination).expect("read"), b"new");
}

#[test]
fn write_rejects_symlink_and_distinguishes_destination_extensions() {
    let root = tempfile::tempdir().expect("temporary directory");
    let protected = root.path().join("protected");
    fs::write(&protected, b"untouched").expect("fixture");
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&protected, &link).expect("symlink");
    assert!(
        write::write_file(
            "link",
            link.to_str().expect("path"),
            0,
            b"bad",
            true,
            None,
            false
        )
        .is_err()
    );
    assert_eq!(fs::read(protected).expect("read"), b"untouched");
    let a = root.path().join("file.a");
    let b = root.path().join("file.b");
    write::write_file(
        "same",
        a.to_str().expect("path"),
        0,
        b"a",
        false,
        None,
        true,
    )
    .expect("a pending");
    write::write_file("same", b.to_str().expect("path"), 0, b"b", true, None, true)
        .expect("b done");
    write::write_file("same", a.to_str().expect("path"), 1, b"", true, None, true).expect("a done");
    assert_eq!(fs::read(a).expect("read a"), b"a");
    assert_eq!(fs::read(b).expect("read b"), b"b");
}
