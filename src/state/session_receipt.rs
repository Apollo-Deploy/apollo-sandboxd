use super::SessionKey;
use crate::error::{Error, Result};
use rusqlite::{OptionalExtension, params};
use sandboxd_protocol::{Fence, Response, SessionControl, SessionState, codec};
use sha2::{Digest, Sha256};

pub(super) fn migrate(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE session_controls (
             operation_id TEXT NOT NULL,
             owner_uid INTEGER NOT NULL,
             action TEXT NOT NULL,
             fence_digest BLOB NOT NULL CHECK(length(fence_digest)=32),
             response BLOB NOT NULL CHECK(length(response)<=262144),
             PRIMARY KEY(owner_uid, operation_id)
         ) STRICT;
         PRAGMA user_version=6;
         COMMIT;",
    )?;
    Ok(())
}

pub(super) fn migrate_pending(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE pending_session_controls (
             owner_uid INTEGER NOT NULL,
             sandbox TEXT NOT NULL,
             sandbox_generation INTEGER NOT NULL CHECK(sandbox_generation > 0),
             session_id TEXT NOT NULL,
             session_generation INTEGER NOT NULL CHECK(session_generation > 0),
             operation_id TEXT NOT NULL,
             action TEXT NOT NULL,
             PRIMARY KEY(owner_uid, sandbox, session_generation)
         ) STRICT;
         PRAGMA user_version=8;
         COMMIT;",
    )?;
    Ok(())
}

pub(super) fn migrate_start_receipts(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE session_operations (
             owner_uid INTEGER NOT NULL,
             operation_id TEXT NOT NULL,
             sandbox TEXT NOT NULL,
             sandbox_generation INTEGER NOT NULL CHECK(sandbox_generation > 0),
             session_id TEXT NOT NULL,
             session_generation INTEGER NOT NULL CHECK(session_generation > 0),
             PRIMARY KEY(owner_uid, operation_id),
             UNIQUE(owner_uid, sandbox, session_generation)
         ) STRICT;
         PRAGMA user_version=11;
         COMMIT;",
    )?;
    let mut links = Vec::new();
    let mut statement = connection.prepare(
        "SELECT owner_uid,id,request_digest,response FROM operations ORDER BY owner_uid,id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let owner: u32 = row.get(0)?;
        let operation: String = row.get(1)?;
        let digest: Vec<u8> = row.get(2)?;
        let response: Response = codec::decode_body(&row.get::<_, Vec<u8>>(3)?)?;
        let Response::Sandbox(record) = response else {
            continue;
        };
        let Some(session) = record.session.as_ref() else {
            continue;
        };
        if record.state != sandboxd_protocol::SandboxState::Starting
            || session.state != SessionState::JailerStarting
        {
            continue;
        }
        let fence = Fence {
            sandbox: record.id.clone(),
            generation: record.generation,
            session_generation: Some(session.generation),
            lease: record.lease.id.clone(),
        };
        let expected = Sha256::digest(codec::encode_body(&(SessionControl::Start, fence))?);
        if digest.as_slice() == expected.as_slice() {
            links.push((
                owner,
                operation,
                record.id,
                record.generation,
                session.id.clone(),
                session.generation,
            ));
        }
    }
    drop(rows);
    drop(statement);
    connection.execute_batch("BEGIN IMMEDIATE;")?;
    for (owner, operation, sandbox, sandbox_generation, session_id, session_generation) in links {
        connection.execute(
            "INSERT OR IGNORE INTO session_operations(owner_uid,operation_id,sandbox,sandbox_generation,session_id,session_generation) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                owner,
                operation,
                sandbox.as_str(),
                sandbox_generation.get(),
                session_id.as_str(),
                session_generation.get()
            ],
        )?;
    }
    connection.execute_batch("COMMIT;")?;
    Ok(())
}

/// Completes the original public Start receipt for this exact incarnation.
/// The update and linkage removal happen in the caller's existing transaction.
pub(super) fn complete_start_receipt(
    tx: &rusqlite::Transaction<'_>,
    uid: u32,
    key: &SessionKey,
    response: &Response,
) -> Result<()> {
    let operation: Option<String> = tx
        .query_row(
            "SELECT operation_id FROM session_operations WHERE owner_uid=?1 AND sandbox=?2 AND sandbox_generation=?3 AND session_id=?4 AND session_generation=?5",
            params![uid, key.sandbox.as_str(), key.sandbox_generation.get(), key.session.as_str(), key.generation.get()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(operation) = operation else {
        return Ok(());
    };
    tx.execute(
        "UPDATE operations SET response=?1 WHERE owner_uid=?2 AND id=?3",
        params![codec::encode_body(response)?, uid, operation],
    )?;
    tx.execute(
        "DELETE FROM session_operations WHERE owner_uid=?1 AND operation_id=?2",
        params![uid, operation],
    )?;
    Ok(())
}

pub(super) fn complete_pending_control_receipt(
    tx: &rusqlite::Transaction<'_>,
    uid: u32,
    key: &SessionKey,
    response: &Response,
) -> Result<()> {
    let pending: Option<(String, String)> = tx
        .query_row(
            "SELECT operation_id,action FROM pending_session_controls WHERE owner_uid=?1 AND sandbox=?2 AND session_generation=?3",
            params![uid, key.sandbox.as_str(), key.generation.get()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((operation, action)) = pending else {
        return Ok(());
    };
    let Response::Sandbox(record) = response else {
        return Ok(());
    };
    let control = match action.as_str() {
        "stop" => SessionControl::Stop,
        "pause" => SessionControl::Pause,
        "resume" => SessionControl::Resume,
        _ => return Err(Error::State),
    };
    let fence = Fence {
        sandbox: key.sandbox.clone(),
        generation: key.sandbox_generation,
        session_generation: Some(key.generation),
        lease: record.lease.id.clone(),
    };
    let digest = Sha256::digest(codec::encode_body(&(control, fence))?);
    if tx.execute(
        "UPDATE operations SET response=?1 WHERE owner_uid=?2 AND id=?3 AND request_digest=?4",
        params![
            codec::encode_body(response)?,
            uid,
            operation,
            digest.as_slice()
        ],
    )? > 1
    {
        return Err(Error::State);
    }
    Ok(())
}
