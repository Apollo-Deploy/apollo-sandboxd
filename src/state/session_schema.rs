use crate::error::Result;
use rusqlite::Connection;

/// Active allocations and the session high-water generation commit together.
/// A tombstoned sandbox retains its high-water mark across recreation.
pub(super) fn migrate(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
        ALTER TABLE sandboxes ADD COLUMN session_generation INTEGER NOT NULL DEFAULT 0
            CHECK(session_generation >= 0);
        CREATE TABLE sessions (
            sandbox TEXT PRIMARY KEY REFERENCES sandboxes(id),
            sandbox_generation INTEGER NOT NULL CHECK(sandbox_generation > 0),
            session_id TEXT NOT NULL UNIQUE,
            session_generation INTEGER NOT NULL CHECK(session_generation > 0),
            uid INTEGER NOT NULL UNIQUE CHECK(uid >= 100000),
            gid INTEGER NOT NULL UNIQUE CHECK(gid >= 100000),
            cid INTEGER NOT NULL UNIQUE CHECK(cid >= 3 AND cid < 4294967295),
            record BLOB NOT NULL CHECK(length(record) <= 16384)
        ) STRICT;
        PRAGMA user_version=3;
        COMMIT;",
    )?;
    Ok(())
}
