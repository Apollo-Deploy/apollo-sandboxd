//! Real filesystem boundary: export failures must release private spool capacity.
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use std::os::unix::fs::PermissionsExt;

// Authoring gate: the real exporter must release failed spool files and omit
// overlay control xattrs while preserving application xattrs. A failed walk
// left its final spool behind in the baseline. Host CAS/transport tests cannot
// reach this guest state-disk boundary, and no test-only production seam exists.
#[test]
#[ignore = "requires Linux root, matching the trusted guest supervisor identity"]
fn failed_export_releases_spool_and_preserves_only_application_metadata() {
    assert_eq!(nix::unistd::geteuid().as_raw(), 0);
    let state = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let upper = state.path().join("upper");
    fs::create_dir(&upper).unwrap();
    fs::set_permissions(&upper, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(upper.join("message"), b"guest filesystem output").unwrap();
    let state_fd = File::open(state.path()).unwrap();
    let operation = OperationId::with_sequence(1, "failure").unwrap();
    assert!(create(&state_fd, &operation, 1, 4).is_err());
    let names = fs::read_dir(state.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from("upper")],
        "failed export must leave no published or staging spool"
    );

    // A crash before publication leaves only a reserved staging name. The
    // next request cleans it without touching ordinary state files.
    fs::write(
        state.path().join(".export-stage-op-2-crashed"),
        b"interrupted",
    )
    .unwrap();
    fs::set_permissions(
        state.path().join(".export-stage-op-2-crashed"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(state.path().join("operator-marker"), b"keep").unwrap();
    xattr::set(upper.join("message"), "user.project", b"apollo").unwrap();
    xattr::set(upper.join("message"), "user.overlay.test", b"private").unwrap();
    let completed = OperationId::with_sequence(3, "complete").unwrap();
    let receipt = create(&state_fd, &completed, 16384, 4).unwrap();
    assert!(!state.path().join(".export-stage-op-2-crashed").exists());
    assert_eq!(
        fs::read(state.path().join("operator-marker")).unwrap(),
        b"keep"
    );
    let (bytes, eof) = read(&state_fd, &completed, 0, 60 * 1024).unwrap();
    assert!(eof);
    assert_eq!(bytes.len() as u64, receipt.byte_len);
    assert_eq!(hex::encode(Sha256::digest(&bytes)), receipt.sha256);
    let mut archive = tar::Archive::new(bytes.as_slice());
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    let attrs = entry
        .pax_extensions()
        .unwrap()
        .unwrap()
        .map(|ext| {
            let ext = ext.unwrap();
            (ext.key_bytes().to_vec(), ext.value_bytes().to_vec())
        })
        .collect::<Vec<_>>();
    assert!(attrs.contains(&(b"SCHILY.xattr.user.project".to_vec(), b"apollo".to_vec())));
    assert!(
        !attrs
            .iter()
            .any(|(key, _)| key.starts_with(b"SCHILY.xattr.user.overlay."))
    );
    let mut payload = Vec::new();
    entry.read_to_end(&mut payload).unwrap();
    assert_eq!(payload, b"guest filesystem output");
    retire(&state_fd, &completed).unwrap();
    assert!(
        !state
            .path()
            .join(format!("export-{}", completed.as_str()))
            .exists()
    );
}

// Native owning boundary: selected full-disk output cannot include root upper,
// secrets on a nested tmpfs, or a same-device nested bind mount. Host archive
// tests cannot exercise Linux mount identity; no production injection seam.
#[test]
#[ignore = "requires Linux root and a private mount namespace"]
fn selected_volume_archive_excludes_upper_and_nested_mounts() {
    use nix::mount::{MsFlags, mount};
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .unwrap();
    let state = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    fs::create_dir(state.path().join("upper")).unwrap();
    fs::write(state.path().join("upper/root-only"), b"exclude").unwrap();
    let disk = tempfile::tempdir().unwrap();
    fs::write(disk.path().join("keep"), b"selected disk").unwrap();
    fs::write(disk.path().join("deleted-seed"), b"seed").unwrap();
    fs::remove_file(disk.path().join("deleted-seed")).unwrap();
    let nested = disk.path().join("secret");
    fs::create_dir(&nested).unwrap();
    mount(
        Some("tmpfs"),
        nested.as_path(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=1048576"),
    )
    .unwrap();
    fs::write(nested.join("credential"), b"never export").unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("foreign"), b"exclude").unwrap();
    let bind = disk.path().join("bind");
    fs::create_dir(&bind).unwrap();
    mount(
        Some(outside.path()),
        bind.as_path(),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .unwrap();
    let state_fd = File::open(state.path()).unwrap();
    let disk_fd = File::open(disk.path()).unwrap();
    let operation = OperationId::with_sequence(1, "selected").unwrap();
    let receipt = create_selected(&state_fd, &operation, Some(&disk_fd), 65536, 32).unwrap();
    let (bytes, eof) = read(&state_fd, &operation, 0, 65536).unwrap();
    assert!(eof);
    assert_eq!(receipt.sha256, hex::encode(Sha256::digest(&bytes)));
    let mut archive = tar::Archive::new(bytes.as_slice());
    let names: Vec<_> = archive
        .entries()
        .unwrap()
        .map(|entry| entry.unwrap().path().unwrap().into_owned())
        .collect();
    assert_eq!(names, vec![PathBuf::from("keep")]);
    fs::remove_file(disk.path().join("keep")).unwrap();
    let empty = OperationId::with_sequence(2, "selected-empty").unwrap();
    let receipt = create_selected(&state_fd, &empty, Some(&disk_fd), 65536, 32).unwrap();
    assert_eq!(receipt.entry_count, 0);
    let (bytes, eof) = read(&state_fd, &empty, 0, 65536).unwrap();
    assert!(eof);
    assert!(
        tar::Archive::new(bytes.as_slice())
            .entries()
            .unwrap()
            .next()
            .is_none()
    );
}
