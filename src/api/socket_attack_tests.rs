use super::*;
use rustix::fs::XattrFlags;
use sandboxd_protocol::codec;
use std::os::unix::net::UnixListener as SyncListener;

const ATTRIBUTE: &str = "user.apollo_sandboxd.socket_owner";

fn config(path: &Path) -> Daemon {
    Daemon {
        socket: path.join("s"),
        socket_group: rustix::process::getegid().as_raw(),
        max_connections: 2,
        request_timeout_seconds: 5,
    }
}

#[tokio::test]
async fn corrupt_and_mismatched_ownership_records_never_authorize_cleanup() {
    for case in [
        "malformed",
        "version",
        "endpoint",
        "directory",
        "unknown_field",
    ] {
        let temporary = super::tests::fixture();
        let path = temporary.path().canonicalize().expect("path");
        let config = config(&path);
        drop(Socket::bind(&config).await.expect("establish namespace"));
        let stage = SecureDir::open(&path.join(DIRECTORY)).expect("stage");
        let mut buffer = [0u8; 4096];
        let size = fs::fgetxattr(stage.as_fd(), ATTRIBUTE, &mut buffer[..]).expect("record");
        let mut record: serde_json::Value =
            codec::decode_body(&buffer[..size]).expect("decode fixture");
        let bytes = match case {
            "malformed" => vec![0xff],
            "version" => {
                record["version"] = 2.into();
                codec::encode_body(&record).expect("encode")
            }
            "endpoint" => {
                record["endpoint"] = "foreign".into();
                codec::encode_body(&record).expect("encode")
            }
            "directory" => {
                record["directory"]["ino"] = 0.into();
                codec::encode_body(&record).expect("encode")
            }
            _ => {
                record["unexpected"] = true.into();
                codec::encode_body(&record).expect("encode")
            }
        };
        fs::fsetxattr(stage.as_fd(), ATTRIBUTE, &bytes, XattrFlags::REPLACE)
            .expect("inject corruption");
        let staged = path.join(DIRECTORY).join(STAGED_SOCKET);
        drop(SyncListener::bind(&staged).expect("stale socket"));
        let before = stage.stat(STAGED_SOCKET).expect("inode");
        assert!(Socket::bind(&config).await.is_err(), "accepted {case}");
        let after = stage.stat(STAGED_SOCKET).expect("unknown object preserved");
        assert_eq!(
            (before.st_dev, before.st_ino),
            (after.st_dev, after.st_ino),
            "removed {case}"
        );
        assert!(!config.socket.exists());
    }
}

#[tokio::test]
async fn substituted_public_socket_survives_drop_and_restart() {
    let temporary = super::tests::fixture();
    let path = temporary.path().canonicalize().expect("path");
    let config = config(&path);
    let socket = Socket::bind(&config).await.expect("bind");
    std::fs::rename(&config.socket, path.join("original")).expect("move original");
    drop(SyncListener::bind(&config.socket).expect("replacement"));
    let directory = SecureDir::open(&path).expect("directory");
    let before = directory.stat("s").expect("replacement inode");
    drop(socket);
    assert!(Socket::bind(&config).await.is_err());
    let after = directory.stat("s").expect("replacement retained");
    assert_eq!((before.st_dev, before.st_ino), (after.st_dev, after.st_ino));
    assert!(path.join("original").exists());
}

#[tokio::test]
async fn legacy_manifest_handoff_verifies_the_old_inode_before_adoption() {
    use std::io::Write;
    let temporary = super::tests::fixture();
    let path = temporary.path().canonicalize().expect("path");
    let config = config(&path);
    drop(SyncListener::bind(&config.socket).expect("legacy stale endpoint"));
    let directory = SecureDir::open(&path).expect("directory");
    let identity = Identity::of(&directory.stat("s").expect("inode"));
    let mut manifest = directory
        .create_file("socket-owner.cbor")
        .expect("legacy record");
    manifest
        .write_all(&codec::encode_body(&identity).expect("encode"))
        .expect("write");
    manifest.sync_all().expect("sync");
    fs::fsync(directory.as_fd()).expect("parent sync");
    drop(Socket::bind(&config).await.expect("adopt legacy record"));
    assert!(!config.socket.exists());
    assert!(
        path.join("socket-owner.cbor").exists(),
        "migration must retain old proof"
    );
}
