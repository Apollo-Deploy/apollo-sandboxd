//! Internal bounded lifecycle expiry policy. This is not a caller API.
use super::{Store, session};
use crate::error::{Error, Result};
use rusqlite::{TransactionBehavior, params};
use sandboxd_protocol::{
    EventKind, Fence, OperationId, SandboxState, SessionControl, SessionState, codec,
};
use sha2::{Digest, Sha256};

pub(super) fn migrate_timing(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch("BEGIN IMMEDIATE; CREATE TABLE session_timing (sandbox TEXT NOT NULL, session_generation INTEGER NOT NULL CHECK(session_generation > 0), prepared_at_ms INTEGER NOT NULL, started_at_ms INTEGER, ready_at_ms INTEGER, last_activity_ms INTEGER, active_execs INTEGER NOT NULL DEFAULT 0 CHECK(active_execs >= 0 AND active_execs <= 1024), PRIMARY KEY(sandbox, session_generation)); INSERT INTO session_timing(sandbox,session_generation,prepared_at_ms) SELECT sandbox,session_generation,0 FROM sessions; PRAGMA user_version=9; COMMIT;")?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredStop {
    pub owner_uid: u32,
    pub key: super::SessionKey,
    pub operation: OperationId,
}

impl Store {
    /// Touch durable host-admitted activity for the exact session incarnation.
    /// Positive/negative deltas track bounded active execs; zero refreshes idle.
    pub(crate) fn touch_activity(
        &mut self,
        uid: u32,
        key: &super::SessionKey,
        now_ms: u64,
        active_execs_delta: i32,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        super::control_observe::current_for_update(&tx, uid, key)?;
        let current: u32 = tx.query_row(
            "SELECT active_execs FROM session_timing WHERE sandbox=?1 AND session_generation=?2",
            params![key.sandbox.as_str(), key.generation.get()],
            |row| row.get(0),
        )?;
        let next = if active_execs_delta >= 0 {
            current
                .checked_add(active_execs_delta as u32)
                .ok_or(Error::State)?
        } else {
            current
                .checked_sub(active_execs_delta.unsigned_abs())
                .ok_or(Error::State)?
        };
        if next > 1024 || now_ms > i64::MAX as u64 {
            return Err(Error::State);
        }
        tx.execute("UPDATE session_timing SET last_activity_ms=CASE WHEN last_activity_ms IS NULL OR last_activity_ms < ?1 THEN ?1 ELSE last_activity_ms END,active_execs=?2 WHERE sandbox=?3 AND session_generation=?4", params![now_ms, next, key.sandbox.as_str(), key.generation.get()])?;
        tx.commit()?;
        Ok(())
    }

    /// Admit bounded internal Stop intents. Pending intents are returned again
    /// until verified cleanup clears them; lease renewal cancels a stale intent.
    pub(crate) fn admit_expired_session_stops(
        &mut self,
        now_ms: u64,
        limit: u16,
    ) -> Result<Vec<ExpiredStop>> {
        if limit == 0 || limit > 256 || now_ms > i64::MAX as u64 {
            return Err(Error::State);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let columns = session::COLUMNS
            .split(',')
            .map(|c| format!("s.{}", c.trim()))
            .collect::<Vec<_>>()
            .join(",");
        let mut candidates = Vec::new();
        let mut offset = 0i64;
        const PAGE_SIZE: i64 = 256;
        while candidates.len() < usize::from(limit) {
            let mut stmt = tx.prepare(&format!("SELECT {columns}, b.owner_uid, b.lease_expired, b.lease_expires_at, p.operation_id, p.action, t.started_at_ms, t.ready_at_ms, t.last_activity_ms, t.active_execs, b.record FROM sessions s JOIN sandboxes b ON s.sandbox=b.id JOIN session_timing t ON t.sandbox=s.sandbox AND t.session_generation=s.session_generation LEFT JOIN pending_session_controls p ON p.owner_uid=b.owner_uid AND p.sandbox=s.sandbox AND p.session_generation=s.session_generation WHERE b.record IS NOT NULL ORDER BY s.sandbox,s.session_generation LIMIT ?1 OFFSET ?2"))?;
            let mut rows = stmt.query(params![PAGE_SIZE, offset])?;
            let mut page_count = 0i64;
            while let Some(row) = rows.next()? {
                page_count += 1;
                let intent = session::decode(row)?;
                let was_expired = row.get::<_, bool>(9)?;
                let expires = row.get::<_, u64>(10)?;
                let pending_action = row.get::<_, Option<String>>(12)?;
                let started_at = row.get::<_, Option<u64>>(13)?;
                let last_activity = row.get::<_, Option<u64>>(15)?;
                let active_execs = row.get::<_, u32>(16)?;
                let record: sandboxd_protocol::Sandbox =
                    codec::decode_body(&row.get::<_, Vec<u8>>(17)?)?;
                let due = now_ms
                    >= record.created_at_unix_ms.saturating_add(
                        u64::from(record.spec.lifetimes.sandbox_ttl_seconds) * 1000,
                    )
                    || started_at.is_some_and(|at| {
                        now_ms
                            >= at.saturating_add(
                                u64::from(record.spec.lifetimes.session_max_seconds) * 1000,
                            )
                    })
                    || (intent.state != SessionState::Paused
                        && active_execs == 0
                        && last_activity.is_some_and(|at| {
                            now_ms
                                >= at.saturating_add(
                                    u64::from(record.spec.lifetimes.idle_seconds) * 1000,
                                )
                        }));
                if !was_expired
                    && expires > now_ms
                    && !due
                    && !(intent.state == SessionState::Terminating
                        && pending_action.as_deref() == Some("stop"))
                {
                    continue;
                }
                candidates.push((
                    intent,
                    row.get::<_, u32>(8)?,
                    row.get::<_, bool>(9)?,
                    row.get::<_, u64>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<u64>>(13)?,
                    row.get::<_, Option<u64>>(14)?,
                    row.get::<_, Option<u64>>(15)?,
                    row.get::<_, u32>(16)?,
                ));
                if candidates.len() >= usize::from(limit) {
                    break;
                }
            }
            drop(rows);
            drop(stmt);
            if page_count < PAGE_SIZE {
                break;
            }
            offset += PAGE_SIZE;
        }
        let mut admitted = Vec::new();
        for (
            mut intent,
            uid,
            was_expired,
            expires,
            pending_operation,
            pending_action,
            started_at,
            _ready_at,
            last_activity,
            active_execs,
        ) in candidates
        {
            let key = intent.key.clone();
            let mut record = super::control_observe::current_for_update(&tx, uid, &key)?;
            let due = now_ms
                >= record
                    .created_at_unix_ms
                    .saturating_add(u64::from(record.spec.lifetimes.sandbox_ttl_seconds) * 1000)
                || started_at.is_some_and(|at| {
                    now_ms
                        >= at.saturating_add(
                            u64::from(record.spec.lifetimes.session_max_seconds) * 1000,
                        )
                })
                || (intent.state != SessionState::Paused
                    && active_execs == 0
                    && last_activity.is_some_and(|at| {
                        now_ms
                            >= at.saturating_add(
                                u64::from(record.spec.lifetimes.idle_seconds) * 1000,
                            )
                    }));
            // A valid lease does not cancel or replace any durable caller
            // intent.  Pending controls may have been admitted just before a
            // policy tick; preserving them is required for crash recovery.
            if !was_expired && expires > now_ms && !due {
                continue;
            }
            if !was_expired && expires <= now_ms {
                tx.execute(
                    "UPDATE sandboxes SET lease_expired=1 WHERE id=?1",
                    [key.sandbox.as_str()],
                )?;
                super::events::append(&tx, uid, &record, EventKind::LeaseExpired, now_ms)?;
            }
            let operation = match (pending_operation, pending_action.as_deref()) {
                (Some(value), Some("stop")) => OperationId::new(value).map_err(|_| Error::State)?,
                _ => {
                    let fence = Fence {
                        sandbox: key.sandbox.clone(),
                        generation: key.sandbox_generation,
                        session_generation: Some(key.generation),
                        lease: record.lease.id.clone(),
                    };
                    let digest =
                        Sha256::digest(codec::encode_body(&(SessionControl::Stop, fence))?);
                    OperationId::new(format!("expiry-{}", hex::encode(&digest[..12])))
                        .map_err(|_| Error::State)?
                }
            };
            if matches!(intent.state, SessionState::Terminating) {
                admitted.push(ExpiredStop {
                    owner_uid: uid,
                    key,
                    operation,
                });
                continue;
            }
            if matches!(intent.state, SessionState::Terminated) {
                continue;
            }
            intent.state = SessionState::Terminating;
            record.session.as_mut().ok_or(Error::State)?.state = SessionState::Terminating;
            record.state = SandboxState::Stopping;
            tx.execute(
                "UPDATE sessions SET record=?1 WHERE session_id=?2",
                params![codec::encode_body(&intent)?, key.session.as_str()],
            )?;
            tx.execute(
                "UPDATE sandboxes SET record=?1 WHERE id=?2",
                params![codec::encode_body(&record)?, key.sandbox.as_str()],
            )?;
            tx.execute("INSERT INTO pending_session_controls(owner_uid,sandbox,sandbox_generation,session_id,session_generation,operation_id,action) VALUES (?1,?2,?3,?4,?5,?6,'stop') ON CONFLICT(owner_uid,sandbox,session_generation) DO UPDATE SET operation_id=excluded.operation_id,action='stop'", params![uid, key.sandbox.as_str(), key.sandbox_generation.get(), key.session.as_str(), key.generation.get(), operation.as_str()])?;
            admitted.push(ExpiredStop {
                owner_uid: uid,
                key,
                operation,
            });
        }
        super::events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(admitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IdentityPools, LeaseConfig, Quotas};
    use crate::state::SessionPreparation;
    use sandboxd_protocol::{
        Architecture, ImageDigest, Lifetimes, Mutation, NetworkMode, Persistence, Resources,
        Response, SandboxId, SandboxSpec,
    };
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

    fn store(path: &std::path::Path) -> Store {
        Store::open(
            path,
            Quotas {
                max_active_sandboxes: 16,
                max_booting_sandboxes: 4,
                max_sandbox_identities: 64,
                max_operation_receipts: 8,
                max_vcpus: 4,
                max_memory_mib: 1024,
                max_state_disk_mib: 1024,
            },
            LeaseConfig { max_seconds: 3600 },
            20,
        )
        .unwrap()
    }
    fn spec() -> SandboxSpec {
        SandboxSpec {
            architecture: Architecture::Aarch64,
            image: ImageDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            kernel_profile: "reference".into(),
            runtime_profile: "verified".into(),
            persistence: Persistence::FilesystemPersistent,
            resources: Resources {
                vcpus: 1,
                memory_mib: 128,
                state_disk_mib: 256,
                host_memory_max_bytes: 268435456,
                cpu_quota_us: 100000,
                cpu_period_us: 100000,
                cpu_profile: None,
                cpuset: None,
                state_rate_limiter: None,
            },
            network: NetworkMode::None,
            volumes: vec![],
            environment: BTreeMap::new(),
            lifetimes: Lifetimes {
                sandbox_ttl_seconds: 3600,
                session_max_seconds: 1800,
                idle_seconds: 300,
            },
        }
    }
    fn pools() -> IdentityPools {
        IdentityPools {
            uid_first: 200000,
            uid_last: 200001,
            gid_first: 300000,
            gid_last: 300001,
            cid_first: 3,
            cid_last: 4,
        }
    }
    fn pins(record: &sandboxd_protocol::Sandbox) -> super::super::SessionPins {
        super::super::SessionPins {
            architecture: record.spec.architecture,
            runtime_profile: record.spec.runtime_profile.clone(),
            runtime_version: "1.17.0".into(),
            firecracker_sha256: "1".repeat(64),
            jailer_sha256: "2".repeat(64),
            kernel_profile: record.spec.kernel_profile.clone(),
            kernel_sha256: "3".repeat(64),
            initramfs_sha256: "4".repeat(64),
            base_image: record.spec.image.clone(),
            volumes: Vec::new(),
        }
    }
    fn prepare(store: &mut Store, id: &str) -> super::super::LaunchIntent {
        let response = store
            .mutate(
                1000,
                &OperationId::new("create-policy").unwrap(),
                &Mutation::Create {
                    sandbox: SandboxId::new(id).unwrap(),
                    expected_generation: None,
                    spec: Box::new(spec()),
                    lease_seconds: 1,
                },
                1000,
            )
            .unwrap();
        let record = match response {
            Response::Sandbox(r) => *r,
            _ => panic!(),
        };
        let fence = Fence {
            sandbox: record.id.clone(),
            generation: record.generation,
            session_generation: None,
            lease: record.lease.id.clone(),
        };
        store
            .prepare_session(
                1000,
                &OperationId::new("start-policy").unwrap(),
                &fence,
                SessionPreparation {
                    pins: &pins(&record),
                    pools: &pools(),
                    host_boot_id: "00000000-0000-4000-8000-000000000001",
                    now_ms: 1001,
                },
            )
            .unwrap()
            .intent
            .unwrap()
    }
    #[test]
    fn expiry_is_bounded_and_replayed_without_public_receipt_collision() {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = dir.path().canonicalize().unwrap();
        let id = "a".repeat(64);
        let mut s = store(&path);
        let _intent = prepare(&mut s, &id);
        let first = s.admit_expired_session_stops(3000, 8).unwrap();
        assert_eq!(first.len(), 1);
        assert!(first[0].operation.as_str().len() <= 64);
        // Internal expiry admission has its own durable pending-control
        // namespace, so a caller can legitimately use the same operation ID.
        let caller = s
            .mutate(
                1000,
                &first[0].operation,
                &Mutation::Create {
                    sandbox: SandboxId::new("caller-collision").unwrap(),
                    expected_generation: None,
                    spec: Box::new(spec()),
                    lease_seconds: 1,
                },
                1000,
            )
            .unwrap();
        assert!(matches!(caller, Response::Sandbox(_)));
        let observed = s.inspect(1000, &SandboxId::new(&id).unwrap()).unwrap();
        let tx = s
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        super::super::session_control::complete_pending_control_receipt(
            &tx,
            1000,
            &first[0].key,
            &Response::Sandbox(Box::new(observed)),
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(
            s.mutate(
                1000,
                &first[0].operation,
                &Mutation::Create {
                    sandbox: SandboxId::new("caller-collision").unwrap(),
                    expected_generation: None,
                    spec: Box::new(spec()),
                    lease_seconds: 1,
                },
                1000,
            )
            .unwrap(),
            caller
        );
        let second = s.admit_expired_session_stops(3001, 8).unwrap();
        assert_eq!(second[0].operation, first[0].operation);
        drop(s);
        let mut s = store(&path);
        let third = s.admit_expired_session_stops(3002, 8).unwrap();
        assert_eq!(third[0].operation, first[0].operation);
    }

    #[test]
    fn activity_is_generation_fenced_monotonic_and_checked() {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = dir.path().canonicalize().unwrap();
        let mut s = store(&path);
        let intent = prepare(&mut s, "activity");
        assert!(s.touch_activity(1000, &intent.key, 2000, -1).is_err());
        s.touch_activity(1000, &intent.key, 2000, 1).unwrap();
        s.touch_activity(1000, &intent.key, 1000, 0).unwrap();
        let last: u64 = s
            .connection
            .query_row(
                "SELECT last_activity_ms FROM session_timing WHERE sandbox=?1 AND session_generation=?2",
                params![intent.key.sandbox.as_str(), intent.key.generation.get()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(last, 2000);
    }
}
