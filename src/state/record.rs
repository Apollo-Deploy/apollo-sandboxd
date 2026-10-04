use crate::error::{Error, Result};
use rusqlite::{Connection, Row};
use sandboxd_protocol::{Sandbox, codec};

/// Required column order: id, generation, lease_expires_at, record.
/// SQLite structural checks cannot prove that indexed fields match the body.
pub fn decode(row: &Row<'_>) -> Result<Sandbox> {
    let id = row.get_ref(0)?.as_str().map_err(|_| Error::State)?;
    let generation: u64 = row.get(1)?;
    let expiration: u64 = row.get(2)?;
    let body = row.get_ref(3)?.as_blob().map_err(|_| Error::State)?;
    let record: Sandbox = codec::decode_body(body)?;
    if record.id.as_str() != id
        || record.generation.get() != generation
        || record.lease.expires_at_unix_ms != expiration
        || record.lease.sandbox_generation != record.generation
        || record.lease.session_generation != record.session.as_ref().map(|s| s.generation)
        || !super::session::consistent(&record)
    {
        return Err(Error::State);
    }
    record.spec.validate().map_err(|_| Error::State)?;
    Ok(record)
}

pub fn validate_all(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT id,generation,lease_expires_at,record FROM sandboxes WHERE record IS NOT NULL",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        decode(row)?;
    }
    Ok(())
}
