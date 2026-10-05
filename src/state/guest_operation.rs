//! Intent and completed receipts contain no request data or secret values.
use super::{SessionKey, Store, lease};
use crate::error::{Error, Result};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sandboxd_protocol::{
    ApiError, ErrorCode, Fence, GuestCommand, OperationId, Response, SessionState, codec,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq)]
pub(crate) enum GuestAdmission {
    Complete(Response),
    Pending(SessionKey),
}

pub(crate) fn digest(fence: &Fence, command: &GuestCommand) -> Result<[u8; 32]> {
    digest_with_sinks(fence, command, 0)
}

pub(crate) fn digest_with_sinks(
    fence: &Fence,
    command: &GuestCommand,
    sink_count: u8,
) -> Result<[u8; 32]> {
    let bytes = Zeroizing::new(codec::encode_body(&("guest_operation", fence, command))?);
    let mut hash = Sha256::new();
    hash.update(bytes.as_slice());
    hash.update([sink_count]);
    Ok(hash.finalize().into())
}

impl Store {
    pub(crate) fn active_session_key(
        &mut self,
        uid: u32,
        fence: &Fence,
        now: u64,
    ) -> Result<SessionKey> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = lease::active(&tx, uid, fence, now)?;
        let session = record.session.ok_or_else(|| {
            ApiError::new(
                ErrorCode::SessionUnavailable,
                "active guest session required",
            )
        })?;
        let key = SessionKey {
            sandbox: record.id,
            sandbox_generation: record.generation,
            session: session.id,
            generation: session.generation,
        };
        tx.commit()?;
        Ok(key)
    }

    pub(crate) fn admit_guest_operation(
        &mut self,
        uid: u32,
        operation: &OperationId,
        fence: &Fence,
        command: &GuestCommand,
        now: u64,
    ) -> Result<GuestAdmission> {
        self.admit_guest_operation_with_sinks(uid, operation, fence, command, 0, None, now)
    }

    pub(crate) fn admit_guest_operation_with_sinks(
        &mut self,
        uid: u32,
        operation: &OperationId,
        fence: &Fence,
        command: &GuestCommand,
        sink_count: u8,
        operation_sequence: Option<u64>,
        now: u64,
    ) -> Result<GuestAdmission> {
        if let Some(sequence) = operation_sequence
            && !operation.matches_sequence(sequence)
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "operation ID is not bound to operation sequence",
            )
            .into());
        }
        if let GuestCommand::ExecStart { spec } = command {
            if spec.argv.is_empty() && spec.use_image_defaults {
                let mut probe = (**spec).clone();
                probe.argv.push("/apollo-image-default".into());
                probe.validate().map_err(|_| {
                    ApiError::new(ErrorCode::InvalidRequest, "guest command outside bounds")
                })?;
            } else {
                command.validate().map_err(|_| {
                    ApiError::new(ErrorCode::InvalidRequest, "guest command outside bounds")
                })?;
            }
        } else {
            command.validate().map_err(|_| {
                ApiError::new(ErrorCode::InvalidRequest, "guest command outside bounds")
            })?;
        }
        let request_digest = digest_with_sinks(fence, command, sink_count)?;
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
        let already_pending = if let Some((old_digest, encoded)) = prior {
            if old_digest.as_slice() != request_digest {
                return Err(ApiError::new(
                    ErrorCode::OperationConflict,
                    "operation ID reused with a different body",
                )
                .into());
            }
            let response: Response = codec::decode_body(&encoded)?;
            if response
                != (Response::GuestPending {
                    operation: operation.clone(),
                })
            {
                return Ok(GuestAdmission::Complete(response));
            }
            true
        } else {
            false
        };
        let record = lease::active(&tx, uid, fence, now)?;
        let session = record.session.ok_or_else(|| {
            ApiError::new(
                ErrorCode::SessionUnavailable,
                "active guest session required",
            )
        })?;
        if session.state != SessionState::Active {
            return Err(ApiError::new(
                ErrorCode::SessionUnavailable,
                "guest session is not active",
            )
            .into());
        }
        let key = SessionKey {
            sandbox: record.id,
            sandbox_generation: record.generation,
            session: session.id,
            generation: session.generation,
        };
        if !already_pending {
            if let Some(sequence) = operation_sequence {
                Store::reserve_operation_sequence(&tx, uid, sequence)?;
            }
            Store::collect_terminal_receipt_for_capacity(&tx, self.quotas.max_operation_receipts)?;
            let count: u32 = tx.query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))?;
            if count >= self.quotas.max_operation_receipts {
                return Err(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "durable operation receipt capacity reached",
                )
                .into());
            }
            tx.execute(
                "INSERT INTO operations(owner_uid,id,request_digest,response) VALUES (?1,?2,?3,?4)",
                params![
                    uid,
                    operation.as_str(),
                    request_digest.as_slice(),
                    codec::encode_body(&Response::GuestPending {
                        operation: operation.clone()
                    })?
                ],
            )?;
        }
        if let GuestCommand::ExecStart { spec } = command
            && !spec.secret_environment.is_empty()
        {
            // Commit this marker in the same transaction as the intent,
            // before any guest delivery. Failed delivery stays conservative.
            let bytes: Vec<u8> = tx.query_row(
                "SELECT record FROM sessions WHERE sandbox=?1 AND sandbox_generation=?2 AND session_id=?3 AND session_generation=?4",
                params![key.sandbox.as_str(), key.sandbox_generation.get(), key.session.as_str(), key.generation.get()],
                |row| row.get(0),
            )?;
            let mut intent: super::LaunchIntent = codec::decode_body(&bytes)?;
            if intent.key != key {
                return Err(Error::State);
            }
            if !intent.has_received_secrets {
                intent.has_received_secrets = true;
                tx.execute(
                    "UPDATE sessions SET record=?1 WHERE sandbox=?2",
                    params![codec::encode_body(&intent)?, key.sandbox.as_str()],
                )?;
            }
        }
        tx.commit()?;
        Ok(GuestAdmission::Pending(key))
    }

    pub(crate) fn complete_guest_operation(
        &mut self,
        uid: u32,
        operation: &OperationId,
        request_digest: [u8; 32],
        response: &Response,
    ) -> Result<()> {
        if !matches!(response, Response::Guest(_) | Response::Error(_)) {
            return Err(Error::State);
        }
        let pending = codec::encode_body(&Response::GuestPending {
            operation: operation.clone(),
        })?;
        let count = self.connection.execute(
            "UPDATE operations SET response=?1 WHERE owner_uid=?2 AND id=?3 AND request_digest=?4 AND response=?5",
            params![codec::encode_body(response)?, uid, operation.as_str(), request_digest.as_slice(), pending],
        )?;
        if count != 1 {
            return Err(Error::State);
        }
        Ok(())
    }
}
