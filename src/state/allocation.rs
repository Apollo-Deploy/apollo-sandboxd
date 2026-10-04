use crate::error::{Error, Result};
use rusqlite::Transaction;
use sandboxd_protocol::{ApiError, ErrorCode};

pub(super) enum Pool {
    Uid,
    Gid,
    Cid,
}

/// Scan active allocations in order, finding the first hole. Historical
/// generations do not consume a slot once proven never launched or retired.
pub(super) fn first_free(tx: &Transaction<'_>, pool: Pool, first: u32, last: u32) -> Result<u32> {
    let sql = match pool {
        Pool::Uid => "SELECT uid FROM sessions WHERE uid>=?1 AND uid<=?2 ORDER BY uid",
        Pool::Gid => "SELECT gid FROM sessions WHERE gid>=?1 AND gid<=?2 ORDER BY gid",
        Pool::Cid => {
            "SELECT cid FROM sessions WHERE cid>=?1 AND cid<=?2 UNION SELECT cid FROM snapshots WHERE cid>=?1 AND cid<=?2 ORDER BY cid"
        }
    };
    let mut statement = tx.prepare(sql)?;
    let mut rows = statement.query([first, last])?;
    let mut candidate = first;
    while let Some(row) = rows.next()? {
        let allocated: u32 = row.get(0)?;
        if allocated > candidate {
            return Ok(candidate);
        }
        candidate = candidate.checked_add(1).ok_or(Error::State)?;
    }
    if candidate <= last {
        return Ok(candidate);
    }
    Err(ApiError::new(
        ErrorCode::QuotaExceeded,
        "active VM identity pool exhausted",
    )
    .into())
}
