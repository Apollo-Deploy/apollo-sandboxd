use super::{LaunchIntent, PreparedSession, SessionKey, SessionPreparation};
use super::{
    Store,
    allocation::{self, Pool},
    events, lease,
    session::COLUMNS,
};
use crate::error::{Error, Result};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sandboxd_protocol::*;
use sha2::{Digest, Sha256};

impl Store {
    /// Commit ownership and launch intent before any jail, cgroup, socket or
    /// process effect. The caller supplies observations from verified catalogs.
    /// This method never starts compute or claims that the guest is ready.
    pub fn prepare_session(
        &mut self,
        uid: u32,
        operation: &OperationId,
        fence: &Fence,
        context: SessionPreparation<'_>,
    ) -> Result<PreparedSession> {
        let body = codec::encode_body(&("session_start", fence))?;
        self.prepare_session_inner(uid, operation, fence, context, body, false, None)
    }

    pub(super) fn prepare_session_control(
        &mut self,
        uid: u32,
        operation: &OperationId,
        fence: &Fence,
        context: SessionPreparation<'_>,
        operation_sequence: Option<u64>,
    ) -> Result<PreparedSession> {
        let body = codec::encode_body(&(SessionControl::Start, fence))?;
        self.prepare_session_inner(
            uid,
            operation,
            fence,
            context,
            body,
            true,
            operation_sequence,
        )
    }

    fn prepare_session_inner(
        &mut self,
        uid: u32,
        operation: &OperationId,
        fence: &Fence,
        context: SessionPreparation<'_>,
        body: Vec<u8>,
        launch_boundary: bool,
        operation_sequence: Option<u64>,
    ) -> Result<PreparedSession> {
        let SessionPreparation {
            pins,
            pools,
            host_boot_id,
            now_ms: now,
        } = context;
        let digest = Sha256::digest(&body);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT request_digest,response FROM operations WHERE owner_uid=?1 AND id=?2",
                params![uid, operation.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((previous, response)) = prior {
            if previous != digest.as_slice() {
                return Err(ApiError::new(
                    ErrorCode::OperationConflict,
                    "operation ID reused with a different body",
                )
                .into());
            }
            let response: Response = codec::decode_body(&response)?;
            if matches!(response, Response::Error(_)) {
                return Ok(PreparedSession {
                    response,
                    intent: None,
                    replayed: true,
                });
            }
            let Response::Sandbox(record) = &response else {
                return Err(Error::State);
            };
            let intent = record.session.as_ref().map(|session| {
                let mut statement = tx.prepare(&format!("SELECT {COLUMNS} FROM sessions WHERE sandbox=?1 AND sandbox_generation=?2 AND session_id=?3 AND session_generation=?4"))?;
                let mut rows = statement.query(params![
                    record.id.as_str(),
                    record.generation.get(),
                    session.id.as_str(),
                    session.generation.get()
                ])?;
                rows.next()?.map(super::session::decode).transpose()
            }).transpose()?.flatten();
            return Ok(PreparedSession {
                response,
                intent,
                replayed: true,
            });
        }
        if let Some(sequence) = operation_sequence {
            Store::reserve_operation_sequence(&tx, uid, sequence)?;
        }
        Store::collect_terminal_receipt_for_capacity(&tx, self.quotas.max_operation_receipts)?;
        pools.validate()?;
        if now > i64::MAX as u64
            || host_boot_id.len() != 36
            || !host_boot_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-')
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid launch timestamp or host identity",
            )
            .into());
        }
        let mut record = lease::active(&tx, uid, fence, now)?;
        if record.session.is_some() || record.state != SandboxState::Stopped {
            return Err(ApiError::new(
                ErrorCode::SessionUnavailable,
                "sandbox compute is already owned",
            )
            .into());
        }
        pins.validate(&record.spec)?;
        let count: u32 = tx.query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))?;
        if count >= self.quotas.max_operation_receipts {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "durable operation receipt capacity reached",
            )
            .into());
        }
        let active: u32 = tx.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))?;
        if active >= self.quotas.max_active_sandboxes {
            return Err(
                ApiError::new(ErrorCode::QuotaExceeded, "active sandbox quota reached").into(),
            );
        }
        let booting = super::session_observe::booting_count(&tx)?;
        if booting >= self.quotas.max_booting_sandboxes {
            return Err(
                ApiError::new(ErrorCode::QuotaExceeded, "booting sandbox quota reached").into(),
            );
        }
        let previous: u64 = tx.query_row(
            "SELECT session_generation FROM sandboxes WHERE id=?1",
            [record.id.as_str()],
            |row| row.get(0),
        )?;
        let generation = SessionGeneration::new(previous.checked_add(1).ok_or(Error::State)?)
            .map_err(|_| ApiError::new(ErrorCode::QuotaExceeded, "session generation exhausted"))?;
        let mut random = [0u8; 24];
        getrandom::getrandom(&mut random).map_err(|_| Error::State)?;
        let session_id =
            SessionId::new(format!("session-{}", hex::encode(random))).map_err(|_| Error::State)?;
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::State)?;
        if nonce == [0; 32] {
            return Err(Error::State);
        }
        let intent = LaunchIntent {
            key: SessionKey {
                sandbox: record.id.clone(),
                sandbox_generation: record.generation,
                session: session_id.clone(),
                generation,
            },
            state: if launch_boundary {
                SessionState::JailerStarting
            } else {
                SessionState::Preparing
            },
            uid: allocation::first_free(&tx, Pool::Uid, pools.uid_first, pools.uid_last)?,
            gid: allocation::first_free(&tx, Pool::Gid, pools.gid_first, pools.gid_last)?,
            cid: allocation::first_free(&tx, Pool::Cid, pools.cid_first, pools.cid_last)?,
            host_boot_id: host_boot_id.to_owned(),
            boot_nonce: nonce,
            pins: pins.clone(),
            has_received_secrets: false,
        };
        tx.execute("INSERT INTO sessions(sandbox,sandbox_generation,session_id,session_generation,uid,gid,cid,record) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![record.id.as_str(),record.generation.get(),session_id.as_str(),generation.get(),intent.uid,intent.gid,intent.cid,codec::encode_body(&intent)?])?;
        tx.execute(
            "INSERT INTO session_timing(sandbox,session_generation,prepared_at_ms) VALUES (?1,?2,?3)",
            params![record.id.as_str(), generation.get(), now],
        )?;
        record.state = SandboxState::Starting;
        record.session = Some(Session {
            id: session_id,
            generation,
            state: if launch_boundary {
                SessionState::JailerStarting
            } else {
                SessionState::Preparing
            },
            runtime_profile: pins.runtime_profile.clone(),
        });
        record.lease.session_generation = Some(generation);
        lease::save(&tx, &record)?;
        tx.execute(
            "UPDATE sandboxes SET session_generation=?1 WHERE id=?2",
            params![generation.get(), record.id.as_str()],
        )?;
        let response = Response::Sandbox(Box::new(record.clone()));
        tx.execute(
            "INSERT INTO operations(owner_uid,id,request_digest,response) VALUES (?1,?2,?3,?4)",
            params![
                uid,
                operation.as_str(),
                digest.as_slice(),
                codec::encode_body(&response)?
            ],
        )?;
        if launch_boundary {
            tx.execute(
                "INSERT INTO session_operations(owner_uid,operation_id,sandbox,sandbox_generation,session_id,session_generation) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    uid,
                    operation.as_str(),
                    record.id.as_str(),
                    record.generation.get(),
                    intent.key.session.as_str(),
                    intent.key.generation.get()
                ],
            )?;
        }
        events::append(&tx, uid, &record, EventKind::SessionStarting, now)?;
        events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(PreparedSession {
            response,
            intent: Some(intent),
            replayed: false,
        })
    }
}
