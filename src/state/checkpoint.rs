//! Durable checkpoint intents serialize filesystem replacement with lifecycle admission.
use super::{SessionKey, StateDrive, Store, drive, lease};
use crate::{
    config::CheckpointLimits,
    error::{Error, Result},
    storage::DriveIdentity,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sandboxd_protocol::{
    ApiError, CheckpointCommand, CheckpointInfo, ErrorCode, Fence, OperationId, Response,
    SandboxState, SessionState, codec,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CheckpointIntent {
    pub uid: u32,
    pub operation: OperationId,
    pub command: CheckpointCommand,
    pub drive: StateDrive,
    pub session: Option<SessionKey>,
    pub replacement: Option<DriveIdentity>,
    #[serde(default)]
    pub staging: Option<crate::storage::CheckpointStage>,
}
pub(crate) enum CheckpointAdmission {
    Complete(Response),
    Pending(CheckpointIntent),
}
pub(crate) fn fence(command: &CheckpointCommand) -> &Fence {
    match command {
        CheckpointCommand::Create { fence, .. }
        | CheckpointCommand::Restore { fence, .. }
        | CheckpointCommand::Delete { fence, .. } => fence,
    }
}
pub(crate) fn id(command: &CheckpointCommand) -> &sandboxd_protocol::CheckpointId {
    match command {
        CheckpointCommand::Create { id, .. }
        | CheckpointCommand::Restore { id, .. }
        | CheckpointCommand::Delete { id, .. } => id,
    }
}
pub(super) fn migrate(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch("BEGIN IMMEDIATE;
      CREATE TABLE checkpoint_intents(owner_uid INTEGER NOT NULL, operation_id TEXT NOT NULL,
        sandbox TEXT NOT NULL UNIQUE, record BLOB NOT NULL CHECK(length(record)<=16384),
        PRIMARY KEY(owner_uid,operation_id)) STRICT;
      CREATE TABLE checkpoints(id TEXT PRIMARY KEY, owner_uid INTEGER NOT NULL,
        sandbox TEXT NOT NULL, bytes INTEGER NOT NULL CHECK(bytes>0), record BLOB NOT NULL CHECK(length(record)<=4096)) STRICT;
      PRAGMA user_version=16; COMMIT;")?;
    Ok(())
}
impl Store {
    pub(crate) fn admit_checkpoint(
        &mut self,
        uid: u32,
        operation: &OperationId,
        sequence: u64,
        command: &CheckpointCommand,
        limits: &CheckpointLimits,
        now: u64,
    ) -> Result<CheckpointAdmission> {
        if !operation.matches_sequence(sequence) {
            return Err(
                ApiError::new(ErrorCode::InvalidRequest, "operation sequence mismatch").into(),
            );
        }
        let digest = Sha256::digest(codec::encode_body(&("checkpoint", command))?);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT request_digest,response FROM operations WHERE owner_uid=?1 AND id=?2",
                params![uid, operation.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((old, response)) = prior {
            if old != digest.as_slice() {
                return Err(
                    ApiError::new(ErrorCode::OperationConflict, "operation body differs").into(),
                );
            }
            let response: Response = codec::decode_body(&response)?;
            if matches!(response, Response::CheckpointPending { .. }) {
                let bytes: Vec<u8> = tx.query_row(
                    "SELECT record FROM checkpoint_intents WHERE owner_uid=?1 AND operation_id=?2",
                    params![uid, operation.as_str()],
                    |r| r.get(0),
                )?;
                return Ok(CheckpointAdmission::Pending(codec::decode_body(&bytes)?));
            }
            return Ok(CheckpointAdmission::Complete(response));
        }
        let f = fence(command);
        let record = lease::active(&tx, uid, f, now)?;
        let drive = drive::load(&tx, &record.id)?.ok_or(Error::State)?;
        if drive.generation != record.generation
            || drive.pending_owner.is_some()
            || drive.identity.is_none()
        {
            return Err(Error::State);
        }
        if !matches!(command, CheckpointCommand::Create { .. }) {
            let mut owned = tx.prepare("SELECT record FROM snapshots WHERE sandbox=?1")?;
            let rows = owned.query_map([record.id.as_str()], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                let snapshot: super::snapshot::SnapshotRecord = codec::decode_body(&row?)?;
                if snapshot.checkpoint == *id(command) {
                    return Err(ApiError::new(
                        ErrorCode::OperationConflict,
                        "checkpoint belongs to a full VM snapshot",
                    )
                    .into());
                }
            }
        }
        if matches!(command, CheckpointCommand::Create { .. }) {
            if record
                .session
                .as_ref()
                .is_none_or(|s| s.state != SessionState::Active)
            {
                return Err(ApiError::new(
                    ErrorCode::SessionUnavailable,
                    "checkpoint requires active compute",
                )
                .into());
            }
            let (count, bytes): (u32, u64) = tx.query_row(
                "SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM checkpoints",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            // Reservations are counted before any external effect.
            if count >= limits.max_count
                || drive.size > limits.max_bytes_per_checkpoint
                || bytes
                    .checked_add(drive.size)
                    .is_none_or(|n| n > limits.max_total_bytes)
            {
                return Err(
                    ApiError::new(ErrorCode::QuotaExceeded, "checkpoint quota exceeded").into(),
                );
            }
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM checkpoints WHERE id=?1)",
                [id(command).as_str()],
                |r| r.get(0),
            )?;
            if exists {
                return Err(ApiError::new(
                    ErrorCode::OperationConflict,
                    "checkpoint ID already reserved",
                )
                .into());
            }
            tx.execute(
                "INSERT INTO checkpoints(id,owner_uid,sandbox,bytes,record) VALUES(?1,?2,?3,?4,?5)",
                params![
                    id(command).as_str(),
                    uid,
                    record.id.as_str(),
                    drive.size,
                    Vec::<u8>::new()
                ],
            )?;
        } else {
            let encoded: Option<Vec<u8>> = tx.query_row(
                "SELECT record FROM checkpoints WHERE id=?1 AND owner_uid=?2 AND sandbox=?3 AND length(record)>0",
                params![id(command).as_str(),uid,record.id.as_str()],|r|r.get(0)).optional()?;
            let encoded = encoded.ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidRequest,
                    "checkpoint not found for sandbox",
                )
            })?;
            let info: CheckpointInfo = codec::decode_body(&encoded)?;
            if info.id != *id(command)
                || info.sandbox != record.id.as_str()
                || info.sandbox_generation != record.generation.get()
            {
                return Err(ApiError::new(
                    ErrorCode::StaleGeneration,
                    "checkpoint generation differs from sandbox",
                )
                .into());
            }
            if matches!(command, CheckpointCommand::Restore { .. })
                && (record.state != SandboxState::Stopped || record.session.is_some())
            {
                return Err(ApiError::new(
                    ErrorCode::SessionUnavailable,
                    "restore requires stopped compute",
                )
                .into());
            }
        }
        Self::reserve_operation_sequence(&tx, uid, sequence)?;
        Self::collect_terminal_receipt_for_capacity(&tx, self.quotas.max_operation_receipts)?;
        let count: u32 = tx.query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))?;
        if count >= self.quotas.max_operation_receipts {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "operation receipt quota exceeded",
            )
            .into());
        }
        let session = record.session.map(|s| SessionKey {
            sandbox: record.id.clone(),
            sandbox_generation: record.generation,
            session: s.id,
            generation: s.generation,
        });
        let intent = CheckpointIntent {
            uid,
            operation: operation.clone(),
            command: command.clone(),
            drive,
            session,
            replacement: None,
            staging: None,
        };
        tx.execute(
            "INSERT INTO checkpoint_intents VALUES(?1,?2,?3,?4)",
            params![
                uid,
                operation.as_str(),
                record.id.as_str(),
                codec::encode_body(&intent)?
            ],
        )?;
        tx.execute(
            "INSERT INTO operations VALUES(?1,?2,?3,?4)",
            params![
                uid,
                operation.as_str(),
                digest.as_slice(),
                codec::encode_body(&Response::CheckpointPending {
                    operation: operation.clone()
                })?
            ],
        )?;
        tx.commit()?;
        Ok(CheckpointAdmission::Pending(intent))
    }
    pub(crate) fn checkpoint_staging(
        &mut self,
        uid: u32,
        operation: &OperationId,
        stage: &crate::storage::CheckpointStage,
    ) -> Result<()> {
        let bytes: Vec<u8> = self.connection.query_row(
            "SELECT record FROM checkpoint_intents WHERE owner_uid=?1 AND operation_id=?2",
            params![uid, operation.as_str()],
            |r| r.get(0),
        )?;
        let mut intent: CheckpointIntent = codec::decode_body(&bytes)?;
        intent.staging = Some(stage.clone());
        self.connection.execute(
            "UPDATE checkpoint_intents SET record=?1 WHERE owner_uid=?2 AND operation_id=?3",
            params![codec::encode_body(&intent)?, uid, operation.as_str()],
        )?;
        Ok(())
    }
    pub(crate) fn checkpoint_replacement(
        &mut self,
        intent: &CheckpointIntent,
        replacement: DriveIdentity,
    ) -> Result<()> {
        let mut next = intent.clone();
        next.replacement = Some(replacement);
        let changed=self.connection.execute("UPDATE checkpoint_intents SET record=?1 WHERE owner_uid=?2 AND operation_id=?3 AND record=?4",params![codec::encode_body(&next)?,intent.uid,intent.operation.as_str(),codec::encode_body(intent)?])?;
        if changed != 1 {
            return Err(Error::State);
        }
        Ok(())
    }
    pub(crate) fn pending_checkpoints(&self) -> Result<Vec<CheckpointIntent>> {
        let mut statement = self
            .connection
            .prepare("SELECT record FROM checkpoint_intents ORDER BY sandbox LIMIT 4097")?;
        let rows = statement.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(codec::decode_body(&row?)?);
        }
        if result.len() > 4096 {
            return Err(Error::State);
        }
        Ok(result)
    }
    pub(crate) fn finish_checkpoint(
        &mut self,
        intent: &CheckpointIntent,
        response: &Response,
        info: Option<&CheckpointInfo>,
        replacement: Option<DriveIdentity>,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Vec<u8> = tx.query_row(
            "SELECT record FROM checkpoint_intents WHERE owner_uid=?1 AND operation_id=?2",
            params![intent.uid, intent.operation.as_str()],
            |r| r.get(0),
        )?;
        let current: CheckpointIntent = codec::decode_body(&current)?;
        if current.command != intent.command {
            return Err(Error::State);
        }
        if let Some(identity) = replacement {
            if current.replacement != Some(identity) {
                return Err(Error::State);
            }
            let mut drive = drive::load(&tx, &intent.drive.sandbox)?.ok_or(Error::State)?;
            if drive != intent.drive {
                return Err(Error::State);
            }
            drive.identity = Some(identity);
            drive::save(&tx, &drive)?;
        }
        if let Some(info) = info {
            tx.execute(
                "UPDATE checkpoints SET record=?1 WHERE id=?2 AND owner_uid=?3",
                params![codec::encode_body(info)?, info.id.as_str(), intent.uid],
            )?;
        } else if matches!(
            intent.command,
            CheckpointCommand::Create { .. } | CheckpointCommand::Delete { .. }
        ) {
            tx.execute(
                "DELETE FROM checkpoints WHERE id=?1 AND owner_uid=?2",
                params![id(&intent.command).as_str(), intent.uid],
            )?;
        }
        tx.execute(
            "UPDATE operations SET response=?1 WHERE owner_uid=?2 AND id=?3",
            params![
                codec::encode_body(response)?,
                intent.uid,
                intent.operation.as_str()
            ],
        )?;
        tx.execute(
            "DELETE FROM checkpoint_intents WHERE owner_uid=?1 AND operation_id=?2",
            params![intent.uid, intent.operation.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }
}
