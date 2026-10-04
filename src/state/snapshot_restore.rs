//! Restore allocates a new incarnation while retaining the snapshot's reserved vsock CID.
use super::{
    LaunchIntent, SessionKey, SessionPreparation, Store,
    allocation::{self, Pool},
    lease,
    snapshot::load_intent,
};
use crate::error::{Error, Result};
use rusqlite::{TransactionBehavior, params};
use sandboxd_protocol::*;

impl Store {
    /// No prelaunch/process/resource record means no launch effect was permitted.
    pub(crate) fn abort_snapshot_before_launch(
        &mut self,
        uid: u32,
        operation: &OperationId,
        now: u64,
    ) -> Result<bool> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut snapshot = load_intent(&tx, uid, operation)?;
        if snapshot.restore_aborted_before_launch {
            return Ok(true);
        }
        let launch = snapshot.restored_session.as_ref().ok_or(Error::State)?;
        if !matches!(snapshot.command, SnapshotCommand::Restore { .. }) {
            return Err(Error::State);
        }
        let effects:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM session_processes WHERE session_id=?1 UNION ALL SELECT 1 FROM session_resources WHERE session_id=?1 UNION ALL SELECT 1 FROM prelaunch_resources WHERE session_id=?1)", [launch.key.session.as_str()],|r|r.get(0))?;
        if effects {
            return Ok(false);
        }
        let mut sandbox = super::snapshot_finish::load_sandbox(&tx, uid, &launch.key.sandbox)?;
        if sandbox.session.as_ref().map(|v| (&v.id, v.generation))
            != Some((&launch.key.session, launch.key.generation))
        {
            return Err(Error::State);
        }
        tx.execute(
            "DELETE FROM sessions WHERE session_id=?1",
            [launch.key.session.as_str()],
        )?;
        tx.execute(
            "DELETE FROM session_timing WHERE sandbox=?1 AND session_generation=?2",
            params![launch.key.sandbox.as_str(), launch.key.generation.get()],
        )?;
        sandbox.session = None;
        sandbox.lease.session_generation = None;
        sandbox.state = SandboxState::Stopped;
        lease::save(&tx, &sandbox)?;
        super::events::append(&tx, uid, &sandbox, EventKind::SessionStopped, now)?;
        snapshot.restore_aborted_before_launch = true;
        tx.execute(
            "UPDATE snapshot_intents SET record=?1 WHERE owner_uid=?2 AND operation_id=?3",
            params![codec::encode_body(&snapshot)?, uid, operation.as_str()],
        )?;
        tx.commit()?;
        Ok(true)
    }
    pub(crate) fn prepare_snapshot_session(
        &mut self,
        uid: u32,
        operation: &OperationId,
        context: SessionPreparation<'_>,
    ) -> Result<LaunchIntent> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut snapshot = load_intent(&tx, uid, operation)?;
        if !matches!(snapshot.command, SnapshotCommand::Restore { .. }) {
            return Err(Error::State);
        }
        if let Some(intent) = snapshot.restored_session {
            return Ok(intent);
        }
        let mut sandbox =
            super::snapshot_finish::load_sandbox(&tx, uid, &snapshot.record.source.key.sandbox)?;
        if sandbox.session.is_some()
            || !matches!(
                sandbox.state,
                SandboxState::Stopped | SandboxState::Suspended
            )
            || sandbox.generation != snapshot.record.source.key.sandbox_generation
        {
            return Err(Error::State);
        }
        context.pools.validate()?;
        context.pins.validate(&sandbox.spec)?;
        if *context.pins != snapshot.record.source.pins {
            return Err(ApiError::new(
                ErrorCode::SnapshotIncompatible,
                "runtime or guest artifact pins differ",
            )
            .into());
        }
        if context.now_ms >= sandbox.lease.expires_at_unix_ms {
            return Err(ApiError::new(
                ErrorCode::LeaseExpired,
                "lease expired before snapshot restore",
            )
            .into());
        }
        let count: u32 = tx.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?;
        if count >= self.quotas.max_active_sandboxes
            || super::session_observe::booting_count(&tx)? >= self.quotas.max_booting_sandboxes
        {
            return Err(ApiError::new(ErrorCode::QuotaExceeded, "compute quota exceeded").into());
        }
        let cid = snapshot.record.source.cid;
        let busy: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE cid=?1)",
            [cid],
            |r| r.get(0),
        )?;
        if busy || cid < context.pools.cid_first || cid > context.pools.cid_last {
            return Err(
                ApiError::new(ErrorCode::SnapshotIncompatible, "snapshot CID unavailable").into(),
            );
        }
        let previous: u64 = tx.query_row(
            "SELECT session_generation FROM sandboxes WHERE id=?1",
            [sandbox.id.as_str()],
            |r| r.get(0),
        )?;
        let generation = SessionGeneration::new(previous.checked_add(1).ok_or(Error::State)?)
            .map_err(|_| Error::State)?;
        let mut random = [0u8; 24];
        getrandom::getrandom(&mut random).map_err(|_| Error::State)?;
        let session =
            SessionId::new(format!("session-{}", hex::encode(random))).map_err(|_| Error::State)?;
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::State)?;
        if nonce == [0; 32] {
            return Err(Error::State);
        }
        let intent = LaunchIntent {
            key: SessionKey {
                sandbox: sandbox.id.clone(),
                sandbox_generation: sandbox.generation,
                session: session.clone(),
                generation,
            },
            state: SessionState::JailerStarting,
            uid: allocation::first_free(
                &tx,
                Pool::Uid,
                context.pools.uid_first,
                context.pools.uid_last,
            )?,
            gid: allocation::first_free(
                &tx,
                Pool::Gid,
                context.pools.gid_first,
                context.pools.gid_last,
            )?,
            cid,
            host_boot_id: context.host_boot_id.to_owned(),
            boot_nonce: nonce,
            pins: context.pins.clone(),
            has_received_secrets: snapshot.record.source.has_received_secrets,
        };
        tx.execute(
            "INSERT INTO sessions VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                sandbox.id.as_str(),
                sandbox.generation.get(),
                session.as_str(),
                generation.get(),
                intent.uid,
                intent.gid,
                cid,
                codec::encode_body(&intent)?
            ],
        )?;
        tx.execute("INSERT INTO session_timing(sandbox,session_generation,prepared_at_ms) VALUES(?1,?2,?3)",params![sandbox.id.as_str(),generation.get(),context.now_ms])?;
        sandbox.state = SandboxState::Starting;
        sandbox.session = Some(Session {
            id: session,
            generation,
            state: intent.state,
            runtime_profile: intent.pins.runtime_profile.clone(),
        });
        sandbox.lease.session_generation = Some(generation);
        lease::save(&tx, &sandbox)?;
        tx.execute(
            "UPDATE sandboxes SET session_generation=?1 WHERE id=?2",
            params![generation.get(), sandbox.id.as_str()],
        )?;
        snapshot.restored_session = Some(intent.clone());
        tx.execute(
            "UPDATE snapshot_intents SET record=?1 WHERE owner_uid=?2 AND operation_id=?3",
            params![codec::encode_body(&snapshot)?, uid, operation.as_str()],
        )?;
        super::events::append(
            &tx,
            uid,
            &sandbox,
            EventKind::SessionStarting,
            context.now_ms,
        )?;
        tx.commit()?;
        Ok(intent)
    }
}
