use super::{
    Store, drive, lease,
    snapshot::{SnapshotIntent, load_intent},
};
use crate::{
    error::{Error, Result},
    storage::DriveIdentity,
};
use rusqlite::{TransactionBehavior, params};
use sandboxd_protocol::*;

impl Store {
    pub(crate) fn snapshot_replace_drive(
        &mut self,
        uid: u32,
        operation: &OperationId,
        identity: DriveIdentity,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut intent = load_intent(&tx, uid, operation)?;
        if intent.replacement != Some(identity) {
            return Err(Error::State);
        }
        let mut drive = drive::load(&tx, &intent.record.drive.sandbox)?.ok_or(Error::State)?;
        if drive.identity == Some(identity) {
            return Ok(());
        }
        if drive.generation != intent.record.drive.generation
            || drive.identity != intent.record.drive.identity
        {
            return Err(Error::State);
        }
        drive.identity = Some(identity);
        drive::save(&tx, &drive)?;
        intent.record.drive = drive;
        tx.execute(
            "UPDATE snapshot_intents SET record=?1 WHERE owner_uid=?2 AND operation_id=?3",
            params![codec::encode_body(&intent)?, uid, operation.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn snapshot_begin_suspend(
        &mut self,
        uid: u32,
        operation: &OperationId,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let intent = load_intent(&tx, uid, operation)?;
        if !matches!(intent.command, SnapshotCommand::Suspend { .. })
            || intent.record.manifest.is_none()
        {
            return Err(Error::State);
        }
        let mut record =
            super::control_observe::current_for_update(&tx, uid, &intent.record.source.key)?;
        let mut source = intent.record.source.clone();
        source.state = SessionState::Terminating;
        record.state = SandboxState::Suspending;
        record.session.as_mut().ok_or(Error::State)?.state = source.state;
        tx.execute(
            "UPDATE sessions SET record=?1 WHERE session_id=?2",
            params![codec::encode_body(&source)?, source.key.session.as_str()],
        )?;
        lease::save(&tx, &record)?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn finish_snapshot(
        &mut self,
        intent: &SnapshotIntent,
        response: &Response,
        now: u64,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_intent(&tx, intent.uid, &intent.operation)?;
        if current.command != intent.command {
            return Err(Error::State);
        }
        if matches!(response, Response::SnapshotDeleted { .. })
            || (matches!(response, Response::Error(_))
                && matches!(
                    intent.command,
                    SnapshotCommand::Create { .. } | SnapshotCommand::Suspend { .. }
                ))
        {
            tx.execute(
                "DELETE FROM snapshots WHERE id=?1 AND owner_uid=?2",
                params![intent.command.id().as_str(), intent.uid],
            )?;
            tx.execute(
                "DELETE FROM checkpoints WHERE id=?1 AND owner_uid=?2",
                params![intent.record.checkpoint.as_str(), intent.uid],
            )?;
            let remaining: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM snapshots WHERE sandbox=?1)",
                [intent.record.source.key.sandbox.as_str()],
                |r| r.get(0),
            )?;
            let mut sandbox = load_sandbox(&tx, intent.uid, &intent.record.source.key.sandbox)?;
            if !remaining && sandbox.session.is_none() && sandbox.state == SandboxState::Suspended {
                sandbox.state = SandboxState::Stopped;
                lease::save(&tx, &sandbox)?;
            }
        } else if !matches!(response, Response::Error(_)) {
            let manifest = current.record.manifest.as_ref().ok_or(Error::State)?;
            manifest.validate()?;
            let artifacts = current.record.artifacts.as_ref().ok_or(Error::State)?;
            let output = current.record.output.as_ref().ok_or(Error::State)?;
            if !artifacts.matches(manifest) || hex::encode(output.digest) != manifest.output_sha256
            {
                return Err(Error::State);
            }
            if [&artifacts.memory, &artifacts.state, &artifacts.manifest]
                .iter()
                .any(|artifact| artifact.as_ref().is_none_or(|v| v.cipher_sha256.is_none()))
            {
                return Err(Error::State);
            }
            tx.execute(
                "UPDATE snapshots SET record=?1,complete=1 WHERE id=?2 AND owner_uid=?3",
                params![
                    codec::encode_body(&current.record)?,
                    intent.command.id().as_str(),
                    intent.uid
                ],
            )?;
            if matches!(intent.command, SnapshotCommand::Restore { .. }) {
                let session = current.restored_session.as_ref().ok_or(Error::State)?;
                tx.execute("INSERT INTO snapshot_restore_memory VALUES(?1,?2) ON CONFLICT(session_id) DO NOTHING",
                    params![session.key.session.as_str(),manifest.memory_bytes+manifest.state_bytes])?;
            }
            let sandbox = self::load_sandbox(&tx, intent.uid, &manifest.sandbox)?;
            let event = if matches!(intent.command, SnapshotCommand::Restore { .. }) {
                EventKind::VmSnapshotRestored
            } else {
                EventKind::VmSnapshotCreated
            };
            super::events::append(&tx, intent.uid, &sandbox, event, now)?;
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
            "DELETE FROM snapshot_intents WHERE owner_uid=?1 AND operation_id=?2",
            params![intent.uid, intent.operation.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn snapshot_mark_suspended(
        &mut self,
        uid: u32,
        operation: &OperationId,
        now: u64,
    ) -> Result<SnapshotIntent> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut intent = load_intent(&tx, uid, operation)?;
        let mut sandbox = load_sandbox(&tx, uid, &intent.record.source.key.sandbox)?;
        if sandbox.session.is_some()
            || !matches!(
                sandbox.state,
                SandboxState::Stopped | SandboxState::Suspended
            )
        {
            return Err(Error::State);
        }
        let changed = sandbox.state != SandboxState::Suspended;
        sandbox.state = SandboxState::Suspended;
        lease::save(&tx, &sandbox)?;
        intent.record.suspended = true;
        tx.execute(
            "UPDATE snapshot_intents SET record=?1 WHERE owner_uid=?2 AND operation_id=?3",
            params![codec::encode_body(&intent)?, uid, operation.as_str()],
        )?;
        if changed {
            super::events::append(&tx, uid, &sandbox, EventKind::SandboxSuspended, now)?;
        }
        tx.commit()?;
        Ok(intent)
    }
}
pub(super) fn load_sandbox(
    connection: &rusqlite::Connection,
    uid: u32,
    sandbox: &SandboxId,
) -> Result<Sandbox> {
    let mut statement=connection.prepare("SELECT id,generation,lease_expires_at,record FROM sandboxes WHERE owner_uid=?1 AND id=?2 AND record IS NOT NULL")?;
    let mut rows = statement.query(params![uid, sandbox.as_str()])?;
    super::record::decode(rows.next()?.ok_or(Error::State)?)
}
