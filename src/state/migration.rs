use crate::error::Result;
use rusqlite::Connection;

/// Preserve previously issued cursors while separating future sequence allocation
/// by principal. The transaction either commits the entire schema or rolls back.
pub fn private_event_sequences(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
        ALTER TABLE events RENAME COLUMN sequence TO retention_id;
        ALTER TABLE events ADD COLUMN sequence INTEGER NOT NULL DEFAULT 1 CHECK(sequence > 0);
        UPDATE events SET sequence=retention_id;
        CREATE UNIQUE INDEX event_owner_sequence ON events(owner_uid,sequence);
        CREATE TABLE event_cursors (
            owner_uid INTEGER PRIMARY KEY,
            sequence INTEGER NOT NULL CHECK(sequence > 0)
        ) STRICT;
        INSERT INTO event_cursors(owner_uid,sequence)
            SELECT owner_uid,(SELECT seq FROM sqlite_sequence WHERE name='events')
            FROM (SELECT owner_uid FROM events UNION SELECT owner_uid FROM sandboxes
                UNION SELECT owner_uid FROM operations)
            WHERE (SELECT seq FROM sqlite_sequence WHERE name='events') > 0;
        PRAGMA user_version=2;
        COMMIT;",
    )?;
    Ok(())
}
