//! Real private-state unlink failure must preserve the retirement receipt.
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
#[ignore = "requires Linux root, matching the trusted guest supervisor identity"]
fn export_retirement_preserves_retry_authority_on_cleanup_failure() {
    assert_eq!(nix::unistd::geteuid().as_raw(), 0);
    let directory = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let upper = directory.path().join("upper");
    fs::create_dir(&upper).unwrap();
    fs::set_permissions(&upper, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(upper.join("result"), b"retained bytes").unwrap();
    let state = File::open(directory.path()).unwrap();
    let operation = OperationId::new("retirement-failure").unwrap();
    let exported = crate::filesystem_export::create(&state, &operation, 16384, 4).unwrap();
    let mut operations = HashMap::from([(
        operation.clone(),
        (
            [0; 32],
            GuestMessage::FilesystemExportReady {
                sha256: exported.sha256,
                byte_len: exported.byte_len,
                entry_count: exported.entry_count,
            },
        ),
    )]);
    let published = directory
        .path()
        .join(format!("export-{}", operation.as_str()));
    // A directory at the reserved file name causes a real unlink failure,
    // even for root. Mismatched state must survive a failed retirement.
    fs::remove_file(&published).unwrap();
    fs::create_dir(&published).unwrap();
    let rejected = retire(Some(&state), &mut operations, &operation);
    assert!(
        matches!(rejected, GuestMessage::Error { .. }),
        "cleanup failure cannot acknowledge retirement: {rejected:?}"
    );
    assert!(
        operations.contains_key(&operation),
        "failed cleanup must retain retry authority"
    );
    assert!(published.is_dir());

    // Repair permits the same receipt to settle without replaying execution.
    fs::remove_dir(&published).unwrap();
    crate::filesystem_export::create(&state, &operation, 16384, 4).unwrap();
    assert!(matches!(
        retire(Some(&state), &mut operations, &operation),
        GuestMessage::Ready
    ));
    assert!(!operations.contains_key(&operation));
    assert!(!published.exists());
}
