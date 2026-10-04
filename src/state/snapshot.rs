//! Full snapshots retain a CID and a paused-drive copy independently of compute lifetime.
use super::{LaunchIntent, StateDrive, Store, drive, lease};
use crate::{
    error::{Error, Result},
    snapshot::{SnapshotArtifacts, SnapshotManifest, SnapshotSettings},
    storage::{CheckpointStage, DriveIdentity},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sandboxd_protocol::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SnapshotRecord {
    pub owner: u32,
    pub source: LaunchIntent,
    pub drive: StateDrive,
    pub checkpoint: CheckpointId,
    pub artifacts: Option<SnapshotArtifacts>,
    pub manifest: Option<SnapshotManifest>,
    pub output: Option<crate::exec::SnapshotOutput>,
    pub suspended: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SnapshotIntent {
    pub uid: u32,
    pub operation: OperationId,
    pub command: SnapshotCommand,
    pub record: SnapshotRecord,
    #[serde(default = "capture_may_have_started")]
    pub capture_started: bool,
    pub checkpoint_stage: Option<CheckpointStage>,
    pub replacement: Option<DriveIdentity>,
    pub restored_session: Option<LaunchIntent>,
    #[serde(default)]
    pub restored_output: Option<crate::exec::SnapshotOutput>,
    #[serde(default)]
    pub restore_aborted_before_launch: bool,
}
fn capture_may_have_started() -> bool {
    true
}
pub(crate) enum SnapshotAdmission {
    Complete(Response),
    Pending(SnapshotIntent),
}

pub(super) fn migrate(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch("BEGIN IMMEDIATE;
      CREATE TABLE snapshots(id TEXT PRIMARY KEY, owner_uid INTEGER NOT NULL,
        sandbox TEXT NOT NULL, cid INTEGER NOT NULL CHECK(cid>=3), bytes INTEGER NOT NULL CHECK(bytes>0),
        complete INTEGER NOT NULL CHECK(complete IN (0,1)), record BLOB NOT NULL CHECK(length(record)<=1048576)) STRICT;
      CREATE INDEX snapshot_cid ON snapshots(cid);
      CREATE TABLE snapshot_intents(owner_uid INTEGER NOT NULL, operation_id TEXT NOT NULL,
        sandbox TEXT NOT NULL UNIQUE, memory_bytes INTEGER NOT NULL CHECK(memory_bytes>=0),
        record BLOB NOT NULL CHECK(length(record)<=1048576), PRIMARY KEY(owner_uid,operation_id)) STRICT;
      CREATE TABLE snapshot_restore_memory(session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
        bytes INTEGER NOT NULL CHECK(bytes>0)) STRICT;
      PRAGMA user_version=19; COMMIT;")?;
    Ok(())
}
impl Store {
    pub(crate) fn admit_snapshot(
        &mut self,
        uid: u32,
        operation: &OperationId,
        sequence: u64,
        command: &SnapshotCommand,
        limits: &SnapshotSettings,
        now: u64,
    ) -> Result<SnapshotAdmission> {
        if !operation.matches_sequence(sequence) {
            return Err(
                ApiError::new(ErrorCode::InvalidRequest, "operation sequence mismatch").into(),
            );
        }
        let digest = Sha256::digest(codec::encode_body(&("snapshot", command))?);
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
            if matches!(response, Response::SnapshotPending { .. }) {
                return Ok(SnapshotAdmission::Pending(load_intent(
                    &tx, uid, operation,
                )?));
            }
            return Ok(SnapshotAdmission::Complete(response));
        }
        let sandbox = lease::active(&tx, uid, command.fence(), now)?;
        let (pending,reserved):(u32,u64)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(memory_bytes),0)+(SELECT COALESCE(SUM(bytes),0) FROM snapshot_restore_memory) FROM snapshot_intents",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if pending >= u32::from(limits.max_concurrent_operations) {
            return Err(quota());
        }
        let create = matches!(
            command,
            SnapshotCommand::Create { .. } | SnapshotCommand::Suspend { .. }
        );
        let record = if create {
            let session = sandbox
                .session
                .as_ref()
                .filter(|s| s.state == SessionState::Active)
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::SessionUnavailable,
                        "snapshot requires active compute",
                    )
                })?;
            let mut statement = tx.prepare(&format!(
                "SELECT {} FROM sessions WHERE session_id=?1",
                super::session::COLUMNS
            ))?;
            let mut rows = statement.query([session.id.as_str()])?;
            let source = super::session::decode(rows.next()?.ok_or(Error::State)?)?;
            let secret_policy = match command {
                SnapshotCommand::Create { secret_policy, .. }
                | SnapshotCommand::Suspend { secret_policy, .. } => secret_policy,
                _ => unreachable!(),
            };
            if source.has_received_secrets && *secret_policy == SnapshotSecretPolicy::Reject {
                return Err(ApiError::new(
                    ErrorCode::SecretSnapshotForbidden,
                    "session has received secrets; explicit encrypted snapshot policy required",
                )
                .into());
            }
            let drive = drive::load(&tx, &sandbox.id)?.ok_or(Error::State)?;
            if drive.generation != sandbox.generation
                || drive.pending_owner.is_some()
                || drive.identity.is_none()
            {
                return Err(Error::State);
            }
            let checkpoint = CheckpointId::new(hex::encode(Sha256::digest(codec::encode_body(
                &("snapshot-filesystem", command.id()),
            )?)))
            .map_err(|_| Error::State)?;
            let record = SnapshotRecord {
                owner: uid,
                source,
                drive,
                checkpoint,
                artifacts: None,
                manifest: None,
                output: None,
                suspended: false,
            };
            let (count,total):(u32,u64)=tx.query_row("SELECT (SELECT COUNT(*) FROM snapshots WHERE sandbox=?1),COALESCE(SUM(bytes),0) FROM snapshots",[sandbox.id.as_str()],|r|Ok((r.get(0)?,r.get(1)?)))?;
            let memory = u64::from(sandbox.spec.resources.memory_mib) * (1 << 20);
            // Reserve exact RAM plus bounded device state, encryption overhead and paired disk.
            let bytes = memory
                .checked_add(321 << 20)
                .and_then(|v| v.checked_add(memory / 1024))
                .and_then(|v| v.checked_add(record.drive.size))
                .ok_or_else(quota)?;
            if count >= limits.max_snapshots_per_sandbox
                || total
                    .checked_add(bytes)
                    .is_none_or(|v| v > limits.max_total_bytes)
            {
                return Err(quota());
            }
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM snapshots WHERE id=?1)",
                [command.id().as_str()],
                |r| r.get(0),
            )?;
            if exists {
                return Err(ApiError::new(
                    ErrorCode::OperationConflict,
                    "snapshot ID already reserved",
                )
                .into());
            }
            tx.execute(
                "INSERT INTO snapshots VALUES(?1,?2,?3,?4,?5,0,?6)",
                params![
                    command.id().as_str(),
                    uid,
                    sandbox.id.as_str(),
                    record.source.cid,
                    bytes,
                    codec::encode_body(&record)?
                ],
            )?;
            tx.execute(
                "INSERT INTO checkpoints VALUES(?1,?2,?3,?4,?5)",
                params![
                    record.checkpoint.as_str(),
                    uid,
                    sandbox.id.as_str(),
                    record.drive.size,
                    Vec::<u8>::new()
                ],
            )?;
            record
        } else {
            let encoded:Option<Vec<u8>>=tx.query_row("SELECT record FROM snapshots WHERE id=?1 AND owner_uid=?2 AND sandbox=?3 AND complete=1",params![command.id().as_str(),uid,sandbox.id.as_str()],|r|r.get(0)).optional()?;
            let mut record: SnapshotRecord = codec::decode_body(&encoded.ok_or_else(|| {
                ApiError::new(ErrorCode::InvalidRequest, "snapshot not found for sandbox")
            })?)?;
            if record.source.key.sandbox_generation != sandbox.generation {
                return Err(ApiError::new(
                    ErrorCode::StaleGeneration,
                    "snapshot generation differs",
                )
                .into());
            }
            if matches!(command, SnapshotCommand::Restore { .. })
                && (sandbox.session.is_some()
                    || !matches!(
                        sandbox.state,
                        SandboxState::Stopped | SandboxState::Suspended
                    ))
            {
                return Err(ApiError::new(
                    ErrorCode::SessionUnavailable,
                    "snapshot restore requires stopped compute",
                )
                .into());
            }
            if matches!(command, SnapshotCommand::Restore { .. }) {
                let current = drive::load(&tx, &sandbox.id)?.ok_or(Error::State)?;
                if current.generation != sandbox.generation
                    || current.pending_owner.is_some()
                    || current.identity.is_none()
                {
                    return Err(Error::State);
                }
                record.drive = current;
            }
            record
        };
        let memory = if matches!(command, SnapshotCommand::Delete { .. }) {
            0
        } else {
            let buffers = u64::from(sandbox.spec.resources.memory_mib) * (1 << 20) + (64 << 20);
            // Authenticated sealed memfds coexist briefly with the mountable tmpfs copies.
            if matches!(command, SnapshotCommand::Restore { .. }) {
                buffers * 2
            } else {
                buffers
            }
        };
        if reserved
            .checked_add(memory)
            .is_none_or(|v| v > limits.max_restore_memory_bytes)
        {
            return Err(quota());
        }
        Self::reserve_operation_sequence(&tx, uid, sequence)?;
        Self::collect_terminal_receipt_for_capacity(&tx, self.quotas.max_operation_receipts)?;
        let count: u32 = tx.query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))?;
        if count >= self.quotas.max_operation_receipts {
            return Err(quota());
        }
        let intent = SnapshotIntent {
            uid,
            operation: operation.clone(),
            command: command.clone(),
            record,
            capture_started: false,
            checkpoint_stage: None,
            replacement: None,
            restored_session: None,
            restored_output: None,
            restore_aborted_before_launch: false,
        };
        tx.execute(
            "INSERT INTO snapshot_intents VALUES(?1,?2,?3,?4,?5)",
            params![
                uid,
                operation.as_str(),
                sandbox.id.as_str(),
                memory,
                codec::encode_body(&intent)?
            ],
        )?;
        tx.execute(
            "INSERT INTO operations VALUES(?1,?2,?3,?4)",
            params![
                uid,
                operation.as_str(),
                digest.as_slice(),
                codec::encode_body(&Response::SnapshotPending {
                    operation: operation.clone()
                })?
            ],
        )?;
        tx.commit()?;
        Ok(SnapshotAdmission::Pending(intent))
    }
    pub(crate) fn snapshot_update(
        &mut self,
        uid: u32,
        operation: &OperationId,
        update: impl FnOnce(&mut SnapshotIntent) -> Result<()>,
    ) -> Result<SnapshotIntent> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut intent = load_intent(&tx, uid, operation)?;
        update(&mut intent)?;
        tx.execute(
            "UPDATE snapshot_intents SET record=?1 WHERE owner_uid=?2 AND operation_id=?3",
            params![codec::encode_body(&intent)?, uid, operation.as_str()],
        )?;
        tx.execute(
            "UPDATE snapshots SET record=?1 WHERE id=?2 AND owner_uid=?3",
            params![
                codec::encode_body(&intent.record)?,
                intent.command.id().as_str(),
                uid
            ],
        )?;
        tx.commit()?;
        Ok(intent)
    }
}
pub(super) fn load_intent(
    connection: &rusqlite::Connection,
    uid: u32,
    operation: &OperationId,
) -> Result<SnapshotIntent> {
    let bytes: Vec<u8> = connection.query_row(
        "SELECT record FROM snapshot_intents WHERE owner_uid=?1 AND operation_id=?2",
        params![uid, operation.as_str()],
        |r| r.get(0),
    )?;
    codec::decode_body(&bytes).map_err(Into::into)
}
fn quota() -> Error {
    ApiError::new(ErrorCode::QuotaExceeded, "snapshot quota exceeded").into()
}
