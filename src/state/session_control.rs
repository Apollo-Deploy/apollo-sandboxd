use super::lease;
use super::{SessionKey, SessionPins, Store};
use crate::{
    config::IdentityPools,
    error::{Error, Result},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sandboxd_protocol::{
    ApiError, ErrorCode, Fence, OperationId, Response, SessionControl, SessionState, codec,
};
use sha2::{Digest, Sha256};

pub struct SessionControlContext<'a> {
    pub pins: Option<&'a SessionPins>,
    pub pools: &'a IdentityPools,
    pub host_boot_id: &'a str,
    pub now_ms: u64,
}

pub struct ControlAdmission {
    pub response: Response,
    pub key: Option<SessionKey>,
    pub control: SessionControl,
    pub replayed: bool,
}

pub(super) use super::session_receipt::{
    complete_pending_control_receipt, complete_start_receipt, migrate, migrate_pending,
    migrate_start_receipts,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingSessionControl {
    pub operation: OperationId,
    pub control: SessionControl,
    pub key: SessionKey,
}

fn key_from_fence_tx(
    tx: &rusqlite::Transaction<'_>,
    uid: u32,
    fence: &Fence,
) -> Result<SessionKey> {
    let generation = fence.session_generation.ok_or_else(|| {
        ApiError::new(ErrorCode::StaleGeneration, "session generation is required")
    })?;
    let mut statement = tx.prepare(&format!(
        "SELECT {} FROM sessions WHERE sandbox=?1 AND sandbox_generation=?2 AND session_generation=?3 AND sandbox IN (SELECT id FROM sandboxes WHERE owner_uid=?4)",
        super::session::COLUMNS
    ))?;
    let mut rows = statement.query(params![
        fence.sandbox.as_str(),
        fence.generation.get(),
        generation.get(),
        uid
    ])?;
    rows.next()?
        .map(super::session::decode)
        .transpose()?
        .map(|intent| intent.key)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::StaleGeneration,
                "session incarnation is not current",
            )
            .into()
        })
}

fn intent_for_tx(
    tx: &rusqlite::Transaction<'_>,
    uid: u32,
    key: &SessionKey,
) -> Result<super::LaunchIntent> {
    let mut statement = tx.prepare(&format!(
        "SELECT {} FROM sessions WHERE sandbox=?1 AND sandbox_generation=?2 AND session_id=?3 AND session_generation=?4 AND sandbox IN (SELECT id FROM sandboxes WHERE owner_uid=?5)",
        super::session::COLUMNS
    ))?;
    let mut rows = statement.query(params![
        key.sandbox.as_str(),
        key.sandbox_generation.get(),
        key.session.as_str(),
        key.generation.get(),
        uid
    ])?;
    rows.next()?
        .map(super::session::decode)
        .transpose()?
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::StaleGeneration,
                "session incarnation is not current",
            )
            .into()
        })
}

fn replay_key(
    response: &Response,
    fence: &Fence,
    store: &Store,
    uid: u32,
) -> Result<Option<SessionKey>> {
    let Response::Sandbox(record) = response else {
        return Ok(None);
    };
    let Some(session) = record.session.as_ref() else {
        return Ok(None);
    };
    let key = SessionKey {
        sandbox: record.id.clone(),
        sandbox_generation: record.generation,
        session: session.id.clone(),
        generation: session.generation,
    };
    if key.sandbox != fence.sandbox
        || key.sandbox_generation != fence.generation
        || fence
            .session_generation
            .is_some_and(|generation| generation != key.generation)
    {
        return Err(ApiError::new(
            ErrorCode::StaleGeneration,
            "session incarnation is not current",
        )
        .into());
    }
    Ok(store.session_intent(uid, &key).ok().map(|_| key))
}

fn action_name(control: SessionControl) -> &'static str {
    match control {
        SessionControl::Start => "start",
        SessionControl::Stop => "stop",
        SessionControl::Pause => "pause",
        SessionControl::Resume => "resume",
    }
}

fn validate_control_state(control: SessionControl, state: SessionState) -> Result<()> {
    let valid = match control {
        SessionControl::Stop => matches!(
            state,
            SessionState::Active
                | SessionState::Paused
                | SessionState::VmmBooting
                | SessionState::GuestHandshake
                | SessionState::Terminating
                | SessionState::Failed
        ),
        SessionControl::Pause => state == SessionState::Active,
        SessionControl::Resume => state == SessionState::Paused,
        SessionControl::Start => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::SessionUnavailable,
            "session lifecycle state does not permit this action",
        )
        .into())
    }
}

impl Store {
    /// Durably admits one public lifecycle operation before a runtime effect.
    /// The receipt binds the operation ID to the complete action and fence.
    pub fn begin_session_control(
        &mut self,
        uid: u32,
        operation: &OperationId,
        fence: &Fence,
        control: SessionControl,
        context: SessionControlContext<'_>,
    ) -> Result<ControlAdmission> {
        self.begin_session_control_sequenced(uid, operation, fence, control, context, None)
    }

    pub fn begin_session_control_sequenced(
        &mut self,
        uid: u32,
        operation: &OperationId,
        fence: &Fence,
        control: SessionControl,
        context: SessionControlContext<'_>,
        operation_sequence: Option<u64>,
    ) -> Result<ControlAdmission> {
        if let Some(sequence) = operation_sequence
            && !operation.matches_sequence(sequence)
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "operation ID is not bound to operation sequence",
            )
            .into());
        }
        if let Some(admission) = self.replay_session_control(uid, operation, fence, control)? {
            return Ok(admission);
        }
        let body = codec::encode_body(&(control, fence))?;
        let digest = Sha256::digest(&body);
        let now = context.now_ms;
        if control == SessionControl::Start {
            let pins = context
                .pins
                .ok_or(Error::Config("verified catalog pins required for start"))?;
            let prepared = self.prepare_session_control(
                uid,
                operation,
                fence,
                super::SessionPreparation {
                    pins,
                    pools: context.pools,
                    host_boot_id: context.host_boot_id,
                    now_ms: now,
                },
                operation_sequence,
            )?;
            let response = prepared.response;
            let key = prepared.intent.map(|intent| intent.key);
            return Ok(ControlAdmission {
                response,
                key,
                control,
                replayed: prepared.replayed,
            });
        }
        self.admit_existing_control(
            uid,
            operation,
            fence,
            control,
            now,
            &digest,
            operation_sequence,
        )
    }

    pub(crate) fn replay_session_control(
        &self,
        uid: u32,
        operation: &OperationId,
        fence: &Fence,
        control: SessionControl,
    ) -> Result<Option<ControlAdmission>> {
        let digest = Sha256::digest(codec::encode_body(&(control, fence))?);
        let prior: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT request_digest,response FROM operations WHERE owner_uid=?1 AND id=?2",
                params![uid, operation.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((old, encoded)) = prior {
            if old.as_slice() != digest.as_slice() {
                return Err(ApiError::new(
                    ErrorCode::OperationConflict,
                    "operation ID reused with a different body",
                )
                .into());
            }
            let response: Response = codec::decode_body(&encoded)?;
            if matches!(response, Response::Error(_)) {
                return Ok(Some(ControlAdmission {
                    response,
                    key: None,
                    control,
                    replayed: true,
                }));
            }
            let key = replay_key(&response, fence, self, uid)?;
            return Ok(Some(ControlAdmission {
                response,
                key,
                control,
                replayed: true,
            }));
        }
        Ok(None)
    }

    fn admit_existing_control(
        &mut self,
        uid: u32,
        operation: &OperationId,
        fence: &Fence,
        control: SessionControl,
        now: u64,
        digest: &[u8],
        operation_sequence: Option<u64>,
    ) -> Result<ControlAdmission> {
        if fence.session_generation.is_none() {
            return Err(ApiError::new(
                ErrorCode::StaleGeneration,
                "session generation is required",
            )
            .into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let key = key_from_fence_tx(&tx, uid, fence)?;
        lease::active(&tx, uid, fence, now)?;
        let mut intent = intent_for_tx(&tx, uid, &key)?;
        validate_control_state(control, intent.state)?;
        let mut record = super::control_observe::current_for_update(&tx, uid, &key)?;
        if control == SessionControl::Stop {
            intent.state = SessionState::Terminating;
            record.session.as_mut().ok_or(Error::State)?.state = intent.state;
            record.state = sandboxd_protocol::SandboxState::Stopping;
            tx.execute(
                "UPDATE sessions SET record=?1 WHERE sandbox=?2",
                params![codec::encode_body(&intent)?, key.sandbox.as_str()],
            )?;
            tx.execute(
                "UPDATE sandboxes SET record=?1 WHERE id=?2",
                params![codec::encode_body(&record)?, key.sandbox.as_str()],
            )?;
        }
        let receipt_count: u32 =
            tx.query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))?;
        if control != SessionControl::Stop && receipt_count >= self.quotas.max_operation_receipts {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "durable operation receipt capacity reached",
            )
            .into());
        }
        if let Some(sequence) = operation_sequence {
            Store::reserve_operation_sequence(&tx, uid, sequence)?;
        }
        Store::collect_terminal_receipt_for_capacity(&tx, self.quotas.max_operation_receipts)?;
        let response = Response::Sandbox(Box::new(record));
        tx.execute(
            "INSERT INTO pending_session_controls(owner_uid,sandbox,sandbox_generation,session_id,session_generation,operation_id,action) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(owner_uid,sandbox,session_generation) DO UPDATE SET operation_id=excluded.operation_id,action=excluded.action",
            params![uid, key.sandbox.as_str(), key.sandbox_generation.get(), key.session.as_str(), key.generation.get(), operation.as_str(), action_name(control)],
        )?;
        tx.execute(
            "INSERT INTO operations(owner_uid,id,request_digest,response) VALUES (?1,?2,?3,?4)",
            params![
                uid,
                operation.as_str(),
                digest,
                codec::encode_body(&response)?
            ],
        )?;
        super::events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(ControlAdmission {
            response,
            key: Some(key),
            control,
            replayed: false,
        })
    }

    pub fn pending_session_control(
        &self,
        uid: u32,
        key: &SessionKey,
    ) -> Result<Option<PendingSessionControl>> {
        let row: Option<(String, String)> = self.connection.query_row(
            "SELECT operation_id,action FROM pending_session_controls WHERE owner_uid=?1 AND sandbox=?2 AND sandbox_generation=?3 AND session_id=?4 AND session_generation=?5",
            params![uid, key.sandbox.as_str(), key.sandbox_generation.get(), key.session.as_str(), key.generation.get()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        row.map(|(operation, action)| {
            let control = match action.as_str() {
                "stop" => SessionControl::Stop,
                "pause" => SessionControl::Pause,
                "resume" => SessionControl::Resume,
                _ => return Err(Error::State),
            };
            Ok(PendingSessionControl {
                operation: OperationId::new(operation).map_err(|_| Error::State)?,
                control,
                key: key.clone(),
            })
        })
        .transpose()
    }
}
