use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

pub(super) fn fixture() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private fixture")
}

#[tokio::test]
async fn unknown_populated_staging_namespace_is_preserved() {
    let dir = fixture();
    let path = dir.path().canonicalize().expect("path");
    let stage = path.join(DIRECTORY);
    std::fs::create_dir(&stage).expect("foreign directory");
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).expect("permissions");
    std::fs::write(stage.join("foreign"), b"preserve").expect("foreign file");
    let config = Daemon {
        socket: path.join("s"),
        socket_group: rustix::process::getegid().as_raw(),
        max_connections: 2,
        request_timeout_seconds: 5,
    };
    assert!(Socket::bind(&config).await.is_err());
    assert_eq!(
        std::fs::read(stage.join("foreign")).expect("read"),
        b"preserve"
    );
    assert!(!config.socket.exists());
}

// The syscall qualification harness kills this real production bind at
// kernel-effect boundaries. No fault flag or hook exists in production code.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "subprocess driver for native syscall failure injection"]
async fn crash_driver() {
    let path = std::env::var_os("SANDBOXD_SOCKET_TEST_DIRECTORY").expect("private test directory");
    let config = Daemon {
        socket: PathBuf::from(path).join("s"),
        socket_group: rustix::process::getegid().as_raw(),
        max_connections: 2,
        request_timeout_seconds: 5,
    };
    let socket = Socket::bind(&config).await.expect("recover and bind");
    drop(socket);
}

#[tokio::test]
async fn failed_setup_removes_only_the_socket_it_just_bound() {
    let dir = fixture();
    let path = dir.path().canonicalize().expect("canonical path");
    let foreign = path.join("foreign");
    std::fs::write(&foreign, b"must survive").expect("foreign file");
    symlink(&foreign, path.join("socket-owner.cbor")).expect("symlink");
    let config = Daemon {
        socket: path.join("s"),
        socket_group: rustix::process::getegid().as_raw(),
        max_connections: 4,
        request_timeout_seconds: 5,
    };
    assert!(Socket::bind(&config).await.is_err());
    assert!(!config.socket.exists(), "failed setup left a stale socket");
    assert_eq!(std::fs::read(foreign).expect("read"), b"must survive");
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn peer_credentials_come_from_linux_and_socket_cleanup_preserves_parent() {
    use crate::{config::Security, security::peer::Peer};
    let directory = fixture();
    let path = directory.path().canonicalize().expect("path");
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let config = Daemon {
        socket: path.join("s"),
        socket_group: gid,
        max_connections: 2,
        request_timeout_seconds: 5,
    };
    let socket = Socket::bind(&config).await.expect("secure socket");
    let client = UnixStream::connect(&config.socket).await.expect("connect");
    let (server, _) = socket.listener.accept().await.expect("accept");
    let peer = Peer::from_stream(&server).expect("SO_PEERCRED");
    assert_eq!(
        (peer.uid, peer.gid, peer.pid),
        (uid, gid, std::process::id())
    );
    let policy = Security {
        allowed_uids: vec![uid],
        allowed_gids: vec![gid],
        allowed_pids: vec![std::process::id()],
    };
    assert_eq!(peer.authorize(&policy).is_ok(), uid == 0);
    assert!(
        peer.authorize(&Security {
            allowed_uids: vec![uid.wrapping_add(1)],
            ..policy
        })
        .is_err()
    );
    drop(client);
    drop(server);
    drop(socket);
    assert!(!config.socket.exists());
    assert!(path.is_dir());
    // Rebinding uses the preserved ownership manifest and lock without blind unlink.
    let second = Socket::bind(&config).await.expect("rebind");
    drop(second);
    assert!(!config.socket.exists());
}
