use crate::error::{Error, Result};
use rusqlite::Connection;

pub fn initialize(connection: &Connection) -> Result<()> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !(0..=20).contains(&version) {
        return Err(Error::Config("incompatible durable state version"));
    }
    if matches!(version, 1 | 3) {
        validate_historical_schema(connection, version)?;
        validate_integrity(connection)?;
    }
    let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if mode != "wal" {
        return Err(Error::State);
    }
    connection.execute_batch(
        "PRAGMA synchronous=FULL;
        PRAGMA foreign_keys=ON;
        PRAGMA trusted_schema=OFF;
        PRAGMA wal_autocheckpoint=256;
        PRAGMA journal_size_limit=1048576;
        PRAGMA max_page_count=262144;",
    )?;
    if version == 0 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
            CREATE TABLE sandboxes (
                id TEXT PRIMARY KEY,
                owner_uid INTEGER NOT NULL,
                generation INTEGER NOT NULL CHECK(generation > 0),
                record BLOB,
                lease_expired INTEGER NOT NULL DEFAULT 0 CHECK(lease_expired IN (0,1)),
                lease_expires_at INTEGER NOT NULL
            ) STRICT;
            CREATE INDEX sandbox_owner ON sandboxes(owner_uid, id);
            CREATE INDEX sandbox_expiry ON sandboxes(lease_expired, lease_expires_at);
            CREATE TABLE operations (
                owner_uid INTEGER NOT NULL,
                id TEXT NOT NULL,
                request_digest BLOB NOT NULL CHECK(length(request_digest)=32),
                response BLOB NOT NULL,
                PRIMARY KEY(owner_uid, id)
            ) STRICT;
            CREATE TABLE events (
                retention_id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_uid INTEGER NOT NULL,
                sequence INTEGER NOT NULL CHECK(sequence > 0),
                record BLOB NOT NULL,
                UNIQUE(owner_uid, sequence)
            ) STRICT;
            CREATE TABLE event_cursors (
                owner_uid INTEGER PRIMARY KEY,
                sequence INTEGER NOT NULL CHECK(sequence > 0)
            ) STRICT;
            PRAGMA user_version=2;
            COMMIT;",
        )?;
    }
    if version == 1 {
        super::migration::private_event_sequences(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 2 {
        super::session_schema::migrate(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 3 {
        super::session_process::migrate(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 4 {
        super::session_resources::migrate(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 5 {
        super::session_control::migrate(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 6 {
        super::drive::migrate(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 7 {
        super::session_control::migrate_pending(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 8 {
        super::policy::migrate_timing(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 9 {
        super::prelaunch::migrate(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 10 {
        super::session_control::migrate_start_receipts(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 11 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE operation_watermarks (
                 owner_uid INTEGER PRIMARY KEY,
                 accepted_sequence INTEGER NOT NULL CHECK(accepted_sequence >= 0)
             ) STRICT;
             PRAGMA user_version=12;
             COMMIT;",
        )?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 12 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE sandbox_generation_allocator (
                 id INTEGER PRIMARY KEY CHECK(id=1),
                 next_generation INTEGER NOT NULL CHECK(next_generation > 0)
             ) STRICT;
             INSERT INTO sandbox_generation_allocator(id,next_generation)
             SELECT 1, COALESCE(MAX(generation),0)+1 FROM sandboxes;
             PRAGMA user_version=13;
             COMMIT;",
        )?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 13 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE prepared_images (
                 digest TEXT PRIMARY KEY,
                 architecture TEXT NOT NULL,
                 rootfs_path TEXT NOT NULL,
                 rootfs_sha256 TEXT NOT NULL CHECK(length(rootfs_sha256)=64),
                 rootfs_size INTEGER NOT NULL CHECK(rootfs_size>0),
                 rootfs_device INTEGER NOT NULL,
                 rootfs_inode INTEGER NOT NULL,
                 formatter_sha256 TEXT NOT NULL CHECK(length(formatter_sha256)=64),
                 created_at INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE image_operations (
                 owner_uid INTEGER NOT NULL,
                 operation_id TEXT NOT NULL,
                 request_digest BLOB NOT NULL CHECK(length(request_digest)=32),
                 response BLOB NOT NULL,
                 pending INTEGER NOT NULL CHECK(pending IN (0,1)),
                 PRIMARY KEY(owner_uid, operation_id)
             ) STRICT;
             PRAGMA user_version=14;
             COMMIT;",
        )?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 14 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE prepared_images ADD COLUMN layers INTEGER NOT NULL DEFAULT 0 CHECK(layers <= 256);
             ALTER TABLE prepared_images ADD COLUMN config_json BLOB CHECK(config_json IS NULL OR length(config_json) <= 65536);
             PRAGMA user_version=15;
             COMMIT;",
        )?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 15 {
        super::checkpoint::migrate(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 16 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE prepared_images ADD COLUMN published INTEGER NOT NULL DEFAULT 0 CHECK(published IN (0,1));
             PRAGMA user_version=17;
             COMMIT;",
        )?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 17 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE image_operations ADD COLUMN resolved_digest TEXT CHECK(resolved_digest IS NULL OR length(resolved_digest)=71);
             PRAGMA user_version=18;
             COMMIT;",
        )?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 18 {
        super::snapshot::migrate(connection)?;
    }
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == 19 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE diagnostic_reservations (
                 session_id TEXT PRIMARY KEY REFERENCES sessions(session_id),
                 session_uid INTEGER NOT NULL CHECK(session_uid >= 0),
                 reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes > 0)
             ) STRICT;
             PRAGMA user_version=20;
             COMMIT;",
        )?;
    }
    validate_integrity(connection)?;
    Ok(())
}

fn validate_historical_schema(connection: &Connection, version: i64) -> Result<()> {
    let expected_tables: &[&str] = if version == 1 {
        &["events", "operations", "sandboxes"]
    } else {
        &[
            "event_cursors",
            "events",
            "operations",
            "sandboxes",
            "sessions",
        ]
    };
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let tables: Vec<String> = statement
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if tables.iter().map(String::as_str).collect::<Vec<_>>() != expected_tables {
        return Err(Error::State);
    }

    if version == 1 {
        expect_columns(
            connection,
            "sandboxes",
            &[
                ("id", "TEXT", 1),
                ("owner_uid", "INTEGER", 0),
                ("generation", "INTEGER", 0),
                ("record", "BLOB", 0),
                ("lease_expired", "INTEGER", 0),
                ("lease_expires_at", "INTEGER", 0),
            ],
        )?;
        expect_columns(
            connection,
            "operations",
            &[
                ("owner_uid", "INTEGER", 1),
                ("id", "TEXT", 2),
                ("request_digest", "BLOB", 0),
                ("response", "BLOB", 0),
            ],
        )?;
        expect_columns(
            connection,
            "events",
            &[
                ("sequence", "INTEGER", 1),
                ("owner_uid", "INTEGER", 0),
                ("record", "BLOB", 0),
            ],
        )?;
        expect_named_index(
            connection,
            "sandbox_owner",
            "sandboxes",
            false,
            &["owner_uid", "id"],
        )?;
        expect_named_index(
            connection,
            "sandbox_expiry",
            "sandboxes",
            false,
            &["lease_expired", "lease_expires_at"],
        )?;
    } else {
        expect_columns(
            connection,
            "sandboxes",
            &[
                ("id", "TEXT", 1),
                ("owner_uid", "INTEGER", 0),
                ("generation", "INTEGER", 0),
                ("record", "BLOB", 0),
                ("lease_expired", "INTEGER", 0),
                ("lease_expires_at", "INTEGER", 0),
                ("session_generation", "INTEGER", 0),
            ],
        )?;
        expect_columns(
            connection,
            "operations",
            &[
                ("owner_uid", "INTEGER", 1),
                ("id", "TEXT", 2),
                ("request_digest", "BLOB", 0),
                ("response", "BLOB", 0),
            ],
        )?;
        expect_columns(
            connection,
            "events",
            &[
                ("retention_id", "INTEGER", 1),
                ("owner_uid", "INTEGER", 0),
                ("sequence", "INTEGER", 0),
                ("record", "BLOB", 0),
            ],
        )?;
        expect_columns(
            connection,
            "event_cursors",
            &[("owner_uid", "INTEGER", 1), ("sequence", "INTEGER", 0)],
        )?;
        expect_columns(
            connection,
            "sessions",
            &[
                ("sandbox", "TEXT", 1),
                ("sandbox_generation", "INTEGER", 0),
                ("session_id", "TEXT", 0),
                ("session_generation", "INTEGER", 0),
                ("uid", "INTEGER", 0),
                ("gid", "INTEGER", 0),
                ("cid", "INTEGER", 0),
                ("record", "BLOB", 0),
            ],
        )?;
        expect_named_index(
            connection,
            "event_owner_sequence",
            "events",
            true,
            &["owner_uid", "sequence"],
        )?;
    }
    Ok(())
}

fn expect_columns(
    connection: &Connection,
    table: &str,
    expected: &[(&str, &str, i64)],
) -> Result<()> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns: Vec<(String, String, i64)> = statement
        .query_map([], |row| Ok((row.get(1)?, row.get(2)?, row.get(5)?)))?
        .collect::<rusqlite::Result<_>>()?;
    if columns
        .iter()
        .map(|(name, kind, primary_key)| (name.as_str(), kind.as_str(), *primary_key))
        .collect::<Vec<_>>()
        != expected
    {
        return Err(Error::State);
    }
    Ok(())
}

fn expect_named_index(
    connection: &Connection,
    index: &str,
    table: &str,
    expected_unique: bool,
    expected_columns: &[&str],
) -> Result<()> {
    let mut statement = connection.prepare(&format!("PRAGMA index_list({table})"))?;
    let indexes: Vec<(String, bool)> = statement
        .query_map([], |row| Ok((row.get(1)?, row.get::<_, i64>(2)? != 0)))?
        .collect::<rusqlite::Result<_>>()?;
    if !indexes
        .iter()
        .any(|(name, unique)| name == index && *unique == expected_unique)
    {
        return Err(Error::State);
    }
    let mut statement = connection.prepare(&format!("PRAGMA index_info({index})"))?;
    let columns: Vec<String> = statement
        .query_map([], |row| row.get(2))?
        .collect::<rusqlite::Result<_>>()?;
    if columns.iter().map(String::as_str).collect::<Vec<_>>() != expected_columns {
        return Err(Error::State);
    }
    Ok(())
}

fn validate_integrity(connection: &Connection) -> Result<()> {
    let integrity: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" || connection.prepare("PRAGMA foreign_key_check")?.exists([])? {
        return Err(Error::State);
    }
    Ok(())
}
