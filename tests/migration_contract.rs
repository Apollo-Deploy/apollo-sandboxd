mod support;
use apollo_sandboxd::state::Store;
use rusqlite::{Connection, params};
use sandboxd_protocol::*;
use std::{os::unix::fs::OpenOptionsExt, path::Path};
use support::*;

fn historical_database(path: &Path, version: u8) -> Connection {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("state.sqlite3"))
        .expect("private database file");
    let connection = Connection::open(path.join("state.sqlite3")).expect("database");
    historical::create(&connection, version);
    connection
}

#[test]
fn fixed_historical_versions_upgrade_to_current_schema() {
    for &version in historical::SUPPORTED_VERSIONS {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let connection = historical_database(&path, version);
        drop(connection);

        let store = open(&path, 20);
        drop(store);
        let connection = Connection::open(path.join("state.sqlite3")).expect("database");
        let migrated: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("migrated version");
        assert_eq!(migrated, 19, "historical version {version}");
    }
}

#[test]
fn inconsistent_historical_schemas_are_rejected_before_database_changes() {
    for &version in historical::SUPPORTED_VERSIONS {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let database_path = path.join("state.sqlite3");
        let connection = historical_database(&path, version);
        connection
            .execute_batch("DROP TABLE operations;")
            .expect("make historical schema inconsistent");
        let before: Vec<(String, String, String, Option<String>)> = connection
            .prepare(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        drop(connection);

        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("operation-hash.key"))
            .expect("existing operation key")
            .set_len(32)
            .expect("key size");
        assert!(
            Store::open(
                &path,
                quotas(),
                apollo_sandboxd::config::LeaseConfig { max_seconds: 3600 },
                20,
            )
            .is_err(),
            "historical version {version}"
        );

        let connection = Connection::open(&database_path).expect("database");
        let after: Vec<(String, String, String, Option<String>)> = connection
            .prepare(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");
        let current: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("schema version");
        assert_eq!(after, before, "historical version {version} schema");
        assert_eq!(mode, "delete", "historical version {version} journal mode");
        assert_eq!(current, i64::from(version), "historical version {version}");
        assert!(!path.join("state.sqlite3-wal").exists());
    }
}

#[test]
fn version_one_migration_preserves_receipts_and_never_reuses_evicted_event_cursors() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let response = store
        .mutate(1000, &op("create-a"), &create("a", None), 1000)
        .expect("a");
    let record = sandbox(response.clone());
    store
        .mutate(2000, &op("create-b"), &create("b", None), 1000)
        .expect("b");
    drop(store);
    let connection = Connection::open(path.join("state.sqlite3")).expect("database");
    support::historical::rebuild(&connection, 1);
    let event = Event {
        sequence: 7,
        timestamp_unix_ms: 1000,
        sandbox: record.id,
        generation: record.generation,
        kind: EventKind::SandboxCreated,
    };
    connection
        .execute(
            "INSERT INTO events(sequence,owner_uid,record) VALUES (7,1000,?1)",
            [codec::encode_body(&event).expect("event")],
        )
        .expect("historical event");
    // Earlier retention deleted records through sequence 12, including all of B's events.
    connection
        .execute(
            "UPDATE sqlite_sequence SET seq=?1 WHERE name='events'",
            params![12],
        )
        .expect("high-water cursor");
    drop(connection);
    let mut store = open(&path, 20);
    assert_eq!(
        store
            .mutate(1000, &op("create-a"), &create("a", None), 2000)
            .expect("replay"),
        response
    );
    assert_eq!(
        store.events(1000, 7, 10).expect("old cursor").events[0].sequence,
        7
    );
    store
        .mutate(2000, &op("create-b2"), &create("b2", None), 2000)
        .expect("new b event");
    let page = store.events(2000, 1, 10).expect("b events");
    assert_eq!(page.gap, Some((1, 13)));
    assert_eq!(page.events[0].sequence, 13);
    store
        .mutate(1000, &op("create-a2"), &create("a2", None), 2000)
        .expect("new a event");
    assert_eq!(
        store.events(1000, 13, 10).expect("a events").events[0].sequence,
        13
    );
}
