use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sandboxd_protocol::{ApiError, ErrorCode, Event, EventKind, EventPage, Sandbox, codec};

pub fn append(
    tx: &Transaction<'_>,
    uid: u32,
    sandbox: &Sandbox,
    kind: EventKind,
    now: u64,
) -> Result<()> {
    // Public sequences belong to the authenticated UID. A separate internal ID
    // controls global bounded retention without disclosing other callers' activity.
    let previous: Option<u64> = tx
        .query_row(
            "SELECT sequence FROM event_cursors WHERE owner_uid=?1",
            [uid],
            |row| row.get(0),
        )
        .optional()?;
    let sequence = previous
        .unwrap_or(0)
        .checked_add(1)
        .filter(|value| *value < i64::MAX as u64)
        .ok_or(Error::State)?;
    let event = Event {
        sequence,
        timestamp_unix_ms: now,
        sandbox: sandbox.id.clone(),
        generation: sandbox.generation,
        kind,
    };
    tx.execute(
        "INSERT INTO events(owner_uid,sequence,record) VALUES (?1,?2,?3)",
        params![uid, sequence, codec::encode_body(&event)?],
    )?;
    tx.execute("INSERT INTO event_cursors(owner_uid,sequence) VALUES (?1,?2) ON CONFLICT(owner_uid) DO UPDATE SET sequence=excluded.sequence", params![uid, sequence])?;
    Ok(())
}
pub fn trim(tx: &Transaction<'_>, retain: u32) -> Result<()> {
    tx.execute(
        "DELETE FROM events WHERE retention_id <= (SELECT MAX(retention_id) FROM events) - ?1",
        [retain],
    )?;
    Ok(())
}
pub fn page(connection: &Connection, uid: u32, from: u64, limit: u16) -> Result<EventPage> {
    if limit == 0 || limit > 256 || from >= i64::MAX as u64 {
        return Err(ApiError::new(ErrorCode::InvalidRequest, "event page outside bounds").into());
    }
    let from = from.max(1);
    let latest: Option<u64> = connection
        .query_row(
            "SELECT sequence FROM event_cursors WHERE owner_uid=?1",
            [uid],
            |row| row.get(0),
        )
        .optional()?;
    let oldest: Option<u64> = connection.query_row(
        "SELECT MIN(sequence) FROM events WHERE owner_uid=?1",
        [uid],
        |row| row.get(0),
    )?;
    let available = oldest.unwrap_or_else(|| latest.map_or(from, |value| value + 1));
    // GAP is the half-open range [from, available), including complete eviction.
    let gap = (from < available).then_some((from, available));
    let start = from.max(available);
    let mut stmt = connection.prepare(
        "SELECT record FROM events WHERE owner_uid=?1 AND sequence>=?2 ORDER BY sequence LIMIT ?3",
    )?;
    let mut rows = stmt.query(params![uid, start, limit])?;
    let mut events: Vec<Event> = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(codec::decode_body(&row.get::<_, Vec<u8>>(0)?)?);
    }
    let next_sequence = events.last().map_or(start, |event| event.sequence + 1);
    Ok(EventPage {
        gap,
        events,
        next_sequence,
    })
}
