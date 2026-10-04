use super::{events, record};
use crate::{
    config::LeaseConfig,
    error::{Error, Result},
};
use rusqlite::{Transaction, params};
use sandboxd_protocol::*;

pub fn new(generation: SandboxGeneration, expiration: u64) -> Result<Lease> {
    let mut random = [0; 24];
    getrandom::getrandom(&mut random).map_err(|_| Error::State)?;
    Ok(Lease {
        id: LeaseId::new(format!("lease-{}", hex::encode(random))).map_err(|_| Error::State)?,
        sandbox_generation: generation,
        session_generation: None,
        expires_at_unix_ms: expiration,
        renewal_sequence: 0,
    })
}
pub fn expiry(now: u64, seconds: u32, leases: &LeaseConfig) -> Result<u64> {
    if seconds == 0 || seconds > leases.max_seconds {
        return Err(ApiError::new(
            ErrorCode::LeaseMismatch,
            "lease duration outside configured bound",
        )
        .into());
    }
    now.checked_add(u64::from(seconds) * 1000)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| {
            Error::Api(ApiError::new(
                ErrorCode::InvalidRequest,
                "lease timestamp overflow",
            ))
        })
}
fn load(tx: &Transaction<'_>, uid: u32, fence: &Fence) -> Result<(Sandbox, bool)> {
    let mut statement = tx.prepare("SELECT id,generation,lease_expires_at,record,lease_expired FROM sandboxes WHERE id=?1 AND owner_uid=?2 AND record IS NOT NULL")?;
    let mut rows = statement.query(params![fence.sandbox.as_str(), uid])?;
    let row = rows
        .next()?
        .ok_or_else(|| ApiError::new(ErrorCode::SandboxNotFound, "sandbox identity not found"))?;
    let record = record::decode(row)?;
    let expired: bool = row.get(4)?;
    if record.generation != fence.generation
        || record.session.as_ref().map(|s| s.generation) != fence.session_generation
    {
        return Err(ApiError::new(
            ErrorCode::StaleGeneration,
            "sandbox/session generation is stale",
        )
        .into());
    }
    if record.lease.id != fence.lease {
        return Err(ApiError::new(ErrorCode::LeaseMismatch, "lease identity mismatch").into());
    }
    Ok((record, expired))
}
pub fn active(tx: &Transaction<'_>, uid: u32, fence: &Fence, now: u64) -> Result<Sandbox> {
    let (record, expired) = load(tx, uid, fence)?;
    if expired || now >= record.lease.expires_at_unix_ms {
        return Err(ApiError::new(ErrorCode::LeaseExpired, "lease has expired").into());
    }
    let pending: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM checkpoint_intents WHERE sandbox=?1 UNION ALL SELECT 1 FROM snapshot_intents WHERE sandbox=?1)", [record.id.as_str()], |r| r.get(0))?;
    if pending {
        return Err(ApiError::new(
            ErrorCode::SessionUnavailable,
            "checkpoint reconciliation is pending",
        )
        .into());
    }
    Ok(record)
}
pub fn renew(
    tx: &Transaction<'_>,
    uid: u32,
    fence: &Fence,
    sequence: u64,
    seconds: u32,
    now: u64,
    config: &LeaseConfig,
) -> Result<Response> {
    let mut record = active(tx, uid, fence, now)?;
    if record.lease.renewal_sequence.checked_add(1) != Some(sequence) {
        return Err(ApiError::new(
            ErrorCode::LeaseMismatch,
            "renewal sequence must advance by one",
        )
        .into());
    }
    let expiration = expiry(now, seconds, config)?;
    if expiration < record.lease.expires_at_unix_ms {
        return Err(ApiError::new(ErrorCode::LeaseMismatch, "renewal would shorten lease").into());
    }
    record.lease.expires_at_unix_ms = expiration;
    record.lease.renewal_sequence = sequence;
    save(tx, &record)?;
    events::append(tx, uid, &record, EventKind::LeaseRenewed, now)?;
    Ok(Response::Sandbox(Box::new(record)))
}
/// Reacquire stopped metadata with a new finite lease. The expired token is only
/// an identity fence; authorization still comes from the authenticated owner UID.
pub fn acquire(
    tx: &Transaction<'_>,
    uid: u32,
    fence: &Fence,
    seconds: u32,
    now: u64,
    config: &LeaseConfig,
) -> Result<Response> {
    let (mut record, expired) = load(tx, uid, fence)?;
    if record.session.is_some()
        || !matches!(
            record.state,
            SandboxState::Stopped | SandboxState::Suspended
        )
    {
        return Err(ApiError::new(
            ErrorCode::SessionUnavailable,
            "lease acquisition requires stopped compute",
        )
        .into());
    }
    if !expired && now < record.lease.expires_at_unix_ms {
        return Err(
            ApiError::new(ErrorCode::LeaseMismatch, "current lease is still active").into(),
        );
    }
    let expiration = expiry(now, seconds, config)?;
    if !expired {
        events::append(tx, uid, &record, EventKind::LeaseExpired, now)?;
    }
    record.lease = new(record.generation, expiration)?;
    save(tx, &record)?;
    tx.execute(
        "UPDATE sandboxes SET lease_expired=0 WHERE id=?1",
        [record.id.as_str()],
    )?;
    events::append(tx, uid, &record, EventKind::LeaseAcquired, now)?;
    Ok(Response::Sandbox(Box::new(record)))
}
pub(super) fn save(tx: &Transaction<'_>, record: &Sandbox) -> Result<()> {
    tx.execute(
        "UPDATE sandboxes SET record=?1,lease_expires_at=?2 WHERE id=?3",
        params![
            codec::encode_body(record)?,
            record.lease.expires_at_unix_ms,
            record.id.as_str()
        ],
    )?;
    Ok(())
}
