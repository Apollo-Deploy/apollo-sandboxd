//! Fixed historical schemas, independent of tables added by the current binary.
use rusqlite::{Connection, params};

pub const SUPPORTED_VERSIONS: &[u8] = &[1, 3];

/// Creates an empty historical database directly from its frozen schema.
pub fn create(connection: &Connection, version: u8) {
    assert!(SUPPORTED_VERSIONS.contains(&version));
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;")
        .unwrap();
    create_schema(connection, version);
    connection
        .execute_batch("COMMIT; PRAGMA foreign_keys=ON;")
        .unwrap();
}

/// Rebuilds a live current database using a frozen historical schema. Version 1
/// intentionally starts with no retained events; its contract test inserts the
/// exact legacy retention state it needs to exercise.
pub fn rebuild(connection: &Connection, version: u8) {
    assert!(SUPPORTED_VERSIONS.contains(&version));
    let sandboxes: Vec<(String, i64, i64, Option<Vec<u8>>, i64, i64)> = connection
        .prepare(
            "SELECT id,owner_uid,generation,record,lease_expired,lease_expires_at FROM sandboxes",
        )
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let operations: Vec<(i64, String, Vec<u8>, Vec<u8>)> = connection
        .prepare("SELECT owner_uid,id,request_digest,response FROM operations")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    let (session_generations, sessions, events, event_cursors) = if version == 3 {
        let generations: Vec<(String, i64)> = connection
            .prepare("SELECT id,session_generation FROM sandboxes")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let sessions = connection
            .prepare("SELECT sandbox,sandbox_generation,session_id,session_generation,uid,gid,cid,record FROM sessions")
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?,
                    r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<(String, i64, String, i64, i64, i64, i64, Vec<u8>)>>>()
            .unwrap();
        let events = connection
            .prepare("SELECT retention_id,owner_uid,sequence,record FROM events")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<(i64, i64, i64, Vec<u8>)>>>()
            .unwrap();
        let cursors = connection
            .prepare("SELECT owner_uid,sequence FROM event_cursors")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<(i64, i64)>>>()
            .unwrap();
        (generations, sessions, events, cursors)
    } else {
        (Vec::new(), Vec::new(), Vec::new(), Vec::new())
    };

    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;")
        .unwrap();
    for table in tables {
        connection
            .execute_batch(&format!("DROP TABLE \"{}\";", table.replace('"', "\"\"")))
            .unwrap();
    }
    create_schema(connection, version);
    for (id, owner, generation, record, expired, expires) in sandboxes {
        connection
            .execute(
                "INSERT INTO sandboxes(id,owner_uid,generation,record,lease_expired,lease_expires_at) VALUES(?1,?2,?3,?4,?5,?6)",
                params![id, owner, generation, record, expired, expires],
            )
            .unwrap();
    }
    if version == 3 {
        for (id, generation) in session_generations {
            connection
                .execute(
                    "UPDATE sandboxes SET session_generation=?1 WHERE id=?2",
                    params![generation, id],
                )
                .unwrap();
        }
    }
    for (owner, id, digest, response) in operations {
        connection
            .execute(
                "INSERT INTO operations VALUES(?1,?2,?3,?4)",
                params![owner, id, digest, response],
            )
            .unwrap();
    }
    if version == 3 {
        for (retention_id, owner, sequence, record) in events {
            connection
                .execute(
                    "INSERT INTO events(retention_id,owner_uid,sequence,record) VALUES(?1,?2,?3,?4)",
                    params![retention_id, owner, sequence, record],
                )
                .unwrap();
        }
        for (owner, sequence) in event_cursors {
            connection
                .execute(
                    "INSERT INTO event_cursors(owner_uid,sequence) VALUES(?1,?2)",
                    params![owner, sequence],
                )
                .unwrap();
        }
        for (sandbox, sg, session, generation, uid, gid, cid, record) in sessions {
            connection
                .execute(
                    "INSERT INTO sessions VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![sandbox, sg, session, generation, uid, gid, cid, record],
                )
                .unwrap();
        }
    }
    connection
        .execute_batch("COMMIT; PRAGMA foreign_keys=ON;")
        .unwrap();
}

fn create_schema(connection: &Connection, version: u8) {
    connection.execute_batch(BASE).unwrap();
    if version == 1 {
        connection
            .execute_batch("CREATE TABLE events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,owner_uid INTEGER NOT NULL,record BLOB NOT NULL) STRICT;")
            .unwrap();
    } else {
        connection.execute_batch(V3).unwrap();
    }
    connection
        .pragma_update(None, "user_version", version)
        .unwrap();
}

const BASE: &str = "
CREATE TABLE sandboxes(id TEXT PRIMARY KEY,owner_uid INTEGER NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),record BLOB,lease_expired INTEGER NOT NULL DEFAULT 0 CHECK(lease_expired IN (0,1)),lease_expires_at INTEGER NOT NULL) STRICT;
CREATE INDEX sandbox_owner ON sandboxes(owner_uid,id);
CREATE INDEX sandbox_expiry ON sandboxes(lease_expired,lease_expires_at);
CREATE TABLE operations(owner_uid INTEGER NOT NULL,id TEXT NOT NULL,request_digest BLOB NOT NULL CHECK(length(request_digest)=32),response BLOB NOT NULL,PRIMARY KEY(owner_uid,id)) STRICT;
";

const V3: &str = "
CREATE TABLE events(retention_id INTEGER PRIMARY KEY AUTOINCREMENT,owner_uid INTEGER NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),record BLOB NOT NULL) STRICT;
CREATE UNIQUE INDEX event_owner_sequence ON events(owner_uid,sequence);
CREATE TABLE event_cursors(owner_uid INTEGER PRIMARY KEY,sequence INTEGER NOT NULL CHECK(sequence>0)) STRICT;
ALTER TABLE sandboxes ADD COLUMN session_generation INTEGER NOT NULL DEFAULT 0 CHECK(session_generation>=0);
CREATE TABLE sessions(sandbox TEXT PRIMARY KEY REFERENCES sandboxes(id),sandbox_generation INTEGER NOT NULL CHECK(sandbox_generation>0),session_id TEXT NOT NULL UNIQUE,session_generation INTEGER NOT NULL CHECK(session_generation>0),uid INTEGER NOT NULL UNIQUE CHECK(uid>=100000),gid INTEGER NOT NULL UNIQUE CHECK(gid>=100000),cid INTEGER NOT NULL UNIQUE CHECK(cid>=3 AND cid<4294967295),record BLOB NOT NULL CHECK(length(record)<=16384)) STRICT;
";
