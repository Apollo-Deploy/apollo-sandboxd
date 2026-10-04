mod support;
use apollo_sandboxd::{
    config::Security,
    security::{path::SecureDir, peer::Peer},
};
use rustix::fs::FileType;
use std::os::unix::fs::symlink;
use support::directory;

#[test]
fn cleanup_checks_inode_identity_and_never_follows_a_replacement_symlink() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let secure = SecureDir::open(&path).expect("secure directory");
    let owned = secure.open_or_create_private("owned").expect("owned");
    let identity = rustix::fs::fstat(&owned).expect("stat");
    std::fs::rename(path.join("owned"), path.join("renamed")).expect("rename");
    std::fs::write(path.join("foreign"), b"foreign bytes").expect("foreign");
    symlink("foreign", path.join("owned")).expect("replacement");
    assert!(
        secure
            .remove_if_identity(
                "owned",
                identity.st_dev as u64,
                identity.st_ino,
                FileType::RegularFile
            )
            .is_err()
    );
    assert!(secure.open_file("owned", false).is_err());
    assert_eq!(
        std::fs::read(path.join("foreign")).expect("read"),
        b"foreign bytes"
    );
    assert!(secure.open_file("../foreign", false).is_err());
}

#[test]
fn private_directory_creation_never_adopts_a_symlink_or_changes_existing_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let secure = SecureDir::open(&path).expect("secure directory");
    let created = secure.ensure_private_directory("private").expect("create");
    let first = rustix::fs::fstat(created.as_fd()).expect("identity");
    let reopened = secure.ensure_private_directory("private").expect("reopen");
    assert_eq!(
        first.st_ino,
        rustix::fs::fstat(reopened.as_fd()).unwrap().st_ino
    );
    std::fs::create_dir(path.join("exposed")).unwrap();
    std::fs::set_permissions(path.join("exposed"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(secure.ensure_private_directory("exposed").is_err());
    assert_eq!(
        std::fs::metadata(path.join("exposed"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    symlink("private", path.join("replacement")).unwrap();
    assert!(secure.ensure_private_directory("replacement").is_err());
    assert!(secure.ensure_private_directory("../escape").is_err());
}

#[test]
fn peer_policy_requires_every_configured_constraint_and_empty_policy_denies() {
    let client_uid = rustix::process::geteuid()
        .as_raw()
        .checked_add(1)
        .expect("client UID");
    let peer = Peer {
        uid: client_uid,
        gid: 2000,
        pid: 3000,
    };
    let mut policy = Security {
        allowed_uids: vec![],
        allowed_gids: vec![],
        allowed_pids: vec![],
    };
    assert!(peer.authorize(&policy).is_err());
    policy.allowed_uids = vec![client_uid];
    assert!(peer.authorize(&policy).is_ok());
    policy.allowed_gids = vec![2001];
    assert!(peer.authorize(&policy).is_err());
    policy.allowed_gids = vec![2000];
    assert!(peer.authorize(&policy).is_ok());
    policy.allowed_pids = vec![3001];
    assert!(peer.authorize(&policy).is_err());
    policy.allowed_pids = vec![3000];
    assert!(peer.authorize(&policy).is_ok());
}

#[test]
fn daemon_filesystem_identity_cannot_be_authorized_as_an_untrusted_client() {
    let daemon_uid = rustix::process::geteuid().as_raw();
    let policy = Security {
        allowed_uids: vec![daemon_uid],
        allowed_gids: vec![],
        allowed_pids: vec![],
    };
    let peer = Peer {
        uid: daemon_uid,
        gid: rustix::process::getegid().as_raw(),
        pid: std::process::id(),
    };
    assert_eq!(peer.authorize(&policy).is_ok(), daemon_uid == 0);
    assert!(policy.validate_daemon_identity(100_001).is_ok());
    let shared = Security {
        allowed_uids: vec![100_001],
        ..policy.clone()
    };
    assert!(shared.validate_daemon_identity(100_001).is_err());
    assert!(
        Security {
            allowed_uids: vec![],
            ..shared
        }
        .validate_daemon_identity(100_001)
        .is_err()
    );
    assert!(policy.validate_daemon_identity(0).is_ok());
}
