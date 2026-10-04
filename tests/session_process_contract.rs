//! SQLite migration/corruption contracts. No test here launches a VMM.
mod support;
use apollo_sandboxd::{
    config::IdentityPools,
    process::PersistedProcessIdentity,
    state::{LaunchIntent, SessionPins, SessionPreparation, Store},
};
use sandboxd_protocol::*;
use support::*;

fn prepare(store: &mut Store) -> LaunchIntent {
    let record = sandbox(
        store
            .mutate(1000, &op("create"), &create("one", None), 1000)
            .expect("create"),
    );
    let pins = SessionPins {
        architecture: record.spec.architecture,
        runtime_profile: record.spec.runtime_profile.clone(),
        runtime_version: "1.17.0".into(),
        firecracker_sha256: "1".repeat(64),
        jailer_sha256: "2".repeat(64),
        kernel_profile: record.spec.kernel_profile.clone(),
        kernel_sha256: "3".repeat(64),
        initramfs_sha256: "4".repeat(64),
        base_image: record.spec.image.clone(),
        volumes: Vec::new(),
    };
    store
        .prepare_session(
            1000,
            &op("start"),
            &fence(&record),
            SessionPreparation {
                pins: &pins,
                pools: &IdentityPools {
                    uid_first: 200000,
                    uid_last: 200000,
                    gid_first: 300000,
                    gid_last: 300000,
                    cid_first: 3,
                    cid_last: 3,
                },
                host_boot_id: "00000000-0000-4000-8000-000000000001",
                now_ms: 2000,
            },
        )
        .expect("reserve")
        .intent
        .expect("intent")
}

#[test]
fn schema_three_upgrade_preserves_launch_and_rejects_foreign_process_rows() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let intent = prepare(&mut store);
    store
        .begin_session_launch(1000, &intent.key, 2100)
        .expect("boundary");
    drop(store);
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).expect("database");
    let events_before: Vec<(i64, i64, i64, Vec<u8>)> = connection
        .prepare("SELECT retention_id,owner_uid,sequence,record FROM events ORDER BY retention_id")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let cursors_before: Vec<(i64, i64)> = connection
        .prepare("SELECT owner_uid,sequence FROM event_cursors ORDER BY owner_uid")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    support::historical::rebuild(&connection, 3);
    drop(connection);
    let store = open(&path, 20);
    assert_eq!(
        store
            .session_intent(1000, &intent.key)
            .expect("intent")
            .state,
        SessionState::JailerStarting
    );
    assert!(
        store
            .session_process(1000, &intent.key)
            .expect("no observation invented")
            .is_none()
    );
    assert!(store.session_process(2000, &intent.key).is_err());
    drop(store);
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).expect("database");
    let events_after: Vec<(i64, i64, i64, Vec<u8>)> = connection
        .prepare("SELECT retention_id,owner_uid,sequence,record FROM events ORDER BY retention_id")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let cursors_after: Vec<(i64, i64)> = connection
        .prepare("SELECT owner_uid,sequence FROM event_cursors ORDER BY owner_uid")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        events_after, events_before,
        "historical event rows survive upgrade"
    );
    assert_eq!(
        cursors_after, cursors_before,
        "historical event cursors survive upgrade"
    );
    // SQL foreign keys are deliberately disabled to model corrupted storage.
    connection
        .pragma_update(None, "foreign_keys", false)
        .expect("disable fixture constraints");
    connection
        .execute(
            "INSERT INTO session_processes(session_id,record) VALUES ('foreign',X'00')",
            [],
        )
        .expect("inject orphan");
    drop(connection);
    assert!(
        Store::open(
            &path,
            quotas(),
            apollo_sandboxd::config::LeaseConfig { max_seconds: 3600 },
            20
        )
        .is_err()
    );
}

#[test]
fn wrong_process_allocation_never_becomes_recoverable_identity() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let intent = prepare(&mut store);
    store
        .begin_session_launch(1000, &intent.key, 2100)
        .expect("boundary");
    drop(store);
    let foreign = PersistedProcessIdentity {
        pid: 1,
        boot_id: intent.host_boot_id.clone(),
        start_time_ticks: 1,
        uids: [intent.uid + 1; 4],
        gids: [intent.gid; 4],
        executable_device: 1,
        executable_inode: 1,
        executable_sha256: intent.pins.firecracker_sha256.clone(),
        cgroup_sha256: "5".repeat(64),
    };
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).expect("database");
    connection
        .execute(
            "INSERT INTO session_processes(session_id,record) VALUES (?1,?2)",
            rusqlite::params![
                intent.key.session.as_str(),
                codec::encode_body(&foreign).expect("fixture")
            ],
        )
        .expect("inject foreign identity");
    drop(connection);
    assert!(
        Store::open(
            &path,
            quotas(),
            apollo_sandboxd::config::LeaseConfig { max_seconds: 3600 },
            20
        )
        .is_err()
    );
}

fn manifest(intent: &LaunchIntent) -> apollo_sandboxd::session::LaunchManifest {
    use apollo_sandboxd::{
        jailer::{CgroupIdentity, JailIdentity},
        session::{AssetIdentity, AssetsManifest, LaunchManifest, MountedAsset},
    };
    let root = std::path::PathBuf::from("/operator/jails/firecracker")
        .join(intent.key.session.as_str())
        .join("root");
    LaunchManifest {
        sandbox_id: intent.key.sandbox.to_string(),
        session_id: intent.key.session.to_string(),
        cgroup: std::path::PathBuf::from("/sys/fs/cgroup/operator")
            .join(intent.key.session.as_str()),
        api_socket: root.join("run/firecracker.socket"),
        vsock_socket: root.join("run/vsock.socket"),
        api_socket_identity: None,
        vsock_socket_identity: None,
        jail_root: root.clone(),
        jail_identity: JailIdentity {
            device: 1,
            inode: 2,
        },
        staged_jail: None,
        jail_tree: None,
        network_identity: None,
        network_attachment: None,
        network_namespace: None,
        cgroup_identity: CgroupIdentity {
            device: 3,
            inode: 4,
        },
        assets: AssetsManifest {
            root: root.clone(),
            root_identity: AssetIdentity {
                device: 1,
                inode: 5,
            },
            root_mount_id: None,
            mount_anchor_identity: None,
            mount_anchor_id: None,
            session_identity: Some(AssetIdentity {
                device: 1,
                inode: 20,
            }),
            run_identity: Some(AssetIdentity {
                device: 1,
                inode: 21,
            }),
            mount_namespace_identity: Some(AssetIdentity {
                device: 1,
                inode: 22,
            }),
            assets: [
                ("vmlinux", true),
                ("initramfs", true),
                ("base.img", true),
                ("state.img", false),
            ]
            .into_iter()
            .enumerate()
            .map(|(i, (name, read_only))| MountedAsset {
                path: root.join(name),
                identity: AssetIdentity {
                    device: 1,
                    inode: 6 + i as u64,
                },
                read_only,
                anonymous: false,
                placeholder_identity: Some(AssetIdentity {
                    device: 1,
                    inode: 30 + i as u64,
                }),
                mount_id: Some(50 + i as u64),
            })
            .collect(),
        },
    }
}

#[test]
fn resource_reservation_is_durable_owner_fenced_and_never_relaunches() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let intent = prepare(&mut store);
    let expected = manifest(&intent);
    assert!(
        store
            .reserve_launch_resources(1000, &intent.key, &expected)
            .is_err(),
        "not past durable launch boundary"
    );
    store
        .begin_session_launch(1000, &intent.key, 2100)
        .expect("launch intent");
    assert!(
        store
            .reserve_launch_resources(2000, &intent.key, &expected)
            .is_err(),
        "wrong owner"
    );
    let mut invalid = expected.clone();
    invalid.assets.assets[0].path = "/foreign/vmlinux".into();
    assert!(
        store
            .reserve_launch_resources(1000, &intent.key, &invalid)
            .is_err(),
        "foreign asset path"
    );
    invalid = expected.clone();
    invalid.assets.assets[1].read_only = false;
    assert!(
        store
            .reserve_launch_resources(1000, &intent.key, &invalid)
            .is_err(),
        "mutable trusted kernel"
    );
    store
        .reserve_launch_resources(1000, &intent.key, &expected)
        .expect("durable resources");
    drop(store);
    let mut store = open(&path, 20);
    assert_eq!(
        store.session_resources(1000, &intent.key).expect("reopen"),
        Some(expected.clone())
    );
    assert!(
        store
            .reserve_launch_resources(1000, &intent.key, &expected)
            .is_err(),
        "uncertain retry cannot spawn twice"
    );
    assert!(store.session_resources(2000, &intent.key).is_err());
    let mut stale = intent.key.clone();
    stale.generation = SessionGeneration::new(stale.generation.get() + 1).expect("generation");
    assert!(store.session_resources(1000, &stale).is_err());
}
