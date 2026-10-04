use super::{events, lease};
use crate::{
    config::{LeaseConfig, Quotas},
    error::{Error, Result},
};
use rusqlite::{OptionalExtension, Transaction, params};
use sandboxd_protocol::*;

fn next_sandbox_generation(tx: &Transaction<'_>) -> Result<SandboxGeneration> {
    let next: u64 = tx.query_row(
        "SELECT next_generation FROM sandbox_generation_allocator WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    let generation = SandboxGeneration::new(next)
        .map_err(|_| ApiError::new(ErrorCode::QuotaExceeded, "sandbox generation exhausted"))?;
    let following = next
        .checked_add(1)
        .ok_or_else(|| ApiError::new(ErrorCode::QuotaExceeded, "sandbox generation exhausted"))?;
    tx.execute(
        "UPDATE sandbox_generation_allocator SET next_generation=?1 WHERE id=1",
        [following],
    )?;
    Ok(generation)
}

fn reclaim_terminal_identity(tx: &Transaction<'_>, max: u32) -> Result<()> {
    let count: u32 = tx.query_row("SELECT COUNT(*) FROM sandboxes", [], |row| row.get(0))?;
    if count < max {
        return Ok(());
    }
    // A tombstone is reclaimable only when no persistent drive, live session,
    // or pending external-effect record still references the identity.
    tx.execute(
        "DELETE FROM sandboxes WHERE rowid=(
           SELECT s.rowid FROM sandboxes s
           WHERE s.record IS NULL
             AND NOT EXISTS (SELECT 1 FROM state_drives d WHERE d.sandbox=s.id)
             AND NOT EXISTS (SELECT 1 FROM sessions x WHERE x.sandbox=s.id)
             AND NOT EXISTS (SELECT 1 FROM pending_session_controls p
                             WHERE p.sandbox=s.id)
           ORDER BY s.rowid LIMIT 1
         )",
        [],
    )?;
    Ok(())
}

pub fn apply(
    tx: &Transaction<'_>,
    uid: u32,
    request: &Mutation,
    now: u64,
    quotas: &Quotas,
    leases: &LeaseConfig,
) -> Result<Response> {
    match request {
        Mutation::Create {
            sandbox,
            expected_generation,
            spec,
            lease_seconds,
        } => {
            spec.validate()?;
            if spec.resources.vcpus > quotas.max_vcpus
                || spec.resources.memory_mib > quotas.max_memory_mib
                || spec.resources.state_disk_mib > quotas.max_state_disk_mib
            {
                return Err(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "sandbox resources exceed daemon quotas",
                )
                .into());
            }
            let expiration = lease::expiry(now, *lease_seconds, leases)?;
            let previous: Option<(u32, u64, bool)> = tx
                .query_row(
                    "SELECT owner_uid,generation,record IS NOT NULL FROM sandboxes WHERE id=?1",
                    [sandbox.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let generation = match previous {
                Some((owner, _, _)) if owner != uid => {
                    return Err(ApiError::new(
                        ErrorCode::Unauthorized,
                        "identity belongs to another principal",
                    )
                    .into());
                }
                Some((_, _, true)) => {
                    return Err(ApiError::new(
                        ErrorCode::OperationConflict,
                        "sandbox identity already exists",
                    )
                    .into());
                }
                Some((_, previous, false)) => {
                    let previous = SandboxGeneration::new(previous).map_err(|_| Error::State)?;
                    if *expected_generation != Some(previous) {
                        return Err(stale());
                    }
                    next_sandbox_generation(tx)?
                }
                None => {
                    if expected_generation.is_some() {
                        return Err(stale());
                    }
                    reclaim_terminal_identity(tx, quotas.max_sandbox_identities)?;
                    let count: u32 =
                        tx.query_row("SELECT COUNT(*) FROM sandboxes", [], |row| row.get(0))?;
                    if count >= quotas.max_sandbox_identities {
                        return Err(ApiError::new(
                            ErrorCode::QuotaExceeded,
                            "durable identity capacity reached",
                        )
                        .into());
                    }
                    next_sandbox_generation(tx)?
                }
            };
            let lease = lease::new(generation, expiration)?;
            let record = Sandbox {
                id: sandbox.clone(),
                generation,
                state: SandboxState::Stopped,
                spec: (**spec).clone(),
                session: None,
                lease,
                created_at_unix_ms: now,
            };
            tx.execute("INSERT INTO sandboxes(id,owner_uid,generation,record,lease_expired,lease_expires_at) VALUES (?1,?2,?3,?4,0,?5)
                ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,record=excluded.record,lease_expired=0,lease_expires_at=excluded.lease_expires_at",
                params![sandbox.as_str(), uid, generation.get(), codec::encode_body(&record)?, expiration])?;
            events::append(tx, uid, &record, EventKind::SandboxCreated, now)?;
            Ok(Response::Sandbox(Box::new(record)))
        }
        Mutation::Renew {
            fence,
            sequence,
            duration_seconds,
        } => lease::renew(tx, uid, fence, *sequence, *duration_seconds, now, leases),
        Mutation::AcquireLease {
            fence,
            duration_seconds,
        } => lease::acquire(tx, uid, fence, *duration_seconds, now, leases),
        Mutation::Destroy { fence } => {
            let record = lease::active(tx, uid, fence, now)?;
            let snapshots: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM snapshots WHERE sandbox=?1)",
                [fence.sandbox.as_str()],
                |r| r.get(0),
            )?;
            if snapshots {
                return Err(ApiError::new(
                    ErrorCode::OperationConflict,
                    "delete owned snapshots before destroying sandbox",
                )
                .into());
            }
            if record.session.is_some() || record.state != SandboxState::Stopped {
                return Err(ApiError::new(
                    ErrorCode::SessionUnavailable,
                    "compute must be safely stopped before destruction",
                )
                .into());
            }
            tx.execute(
                "UPDATE sandboxes SET record=NULL WHERE id=?1",
                [record.id.as_str()],
            )?;
            events::append(tx, uid, &record, EventKind::SandboxDestroyed, now)?;
            Ok(Response::Destroyed {
                sandbox: record.id,
                generation: record.generation,
            })
        }
        // Lifecycle controls cross the durable state boundary in the daemon
        // runtime worker. Keeping this arm explicit makes protocol evolution
        // fail closed until that worker has admitted the fenced operation.
        Mutation::Session { .. } => Err(ApiError::new(
            ErrorCode::SessionUnavailable,
            "session lifecycle is not available through the metadata transaction",
        )
        .into()),
    }
}

fn stale() -> Error {
    ApiError::new(
        ErrorCode::StaleGeneration,
        "sandbox/session generation is stale",
    )
    .into()
}
