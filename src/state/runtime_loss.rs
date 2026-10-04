//! Host-observed failures commit a termination intent before killing compute.
use super::{ExpiredStop, SessionKey, Store};
use crate::error::{Error, Result};
use rusqlite::{TransactionBehavior, params};
use sandboxd_protocol::{EventKind, OperationId, SandboxState, SessionState, codec};
use sha2::{Digest, Sha256};

impl Store {
    pub(crate) fn admit_runtime_loss(
        &mut self,
        uid: u32,
        key: &SessionKey,
        reason: EventKind,
        now: u64,
    ) -> Result<ExpiredStop> {
        if !matches!(
            reason,
            EventKind::VmmCrashed | EventKind::GuestAgentLost | EventKind::RecoveryFailed
        ) || now > i64::MAX as u64
        {
            return Err(Error::State);
        }
        let snapshot_reset: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM snapshot_intents WHERE sandbox=?1)",
            [key.sandbox.as_str()],
            |row| row.get(0),
        )?;
        if snapshot_reset && reason == EventKind::GuestAgentLost {
            return Err(Error::State);
        }
        self.admit_internal_stop(uid, key, Some(reason), "runtime-loss", now)
    }

    /// Commit an operator-requested offline cleanup before its process effect.
    /// The terminal SessionStopped event is emitted only after cleanup proof.
    pub(crate) fn admit_admin_stop(
        &mut self,
        uid: u32,
        key: &SessionKey,
        now: u64,
    ) -> Result<ExpiredStop> {
        self.admit_internal_stop(uid, key, None, "administrative-stop", now)
    }

    fn admit_internal_stop(
        &mut self,
        uid: u32,
        key: &SessionKey,
        reason: Option<EventKind>,
        operation_domain: &str,
        now: u64,
    ) -> Result<ExpiredStop> {
        if now > i64::MAX as u64 {
            return Err(Error::State);
        }
        let mut intent = self.session_intent(uid, key)?;
        let pending = self.pending_session_control(uid, key)?;
        if intent.state == SessionState::Terminating
            && let Some(pending) = pending
            && pending.control == sandboxd_protocol::SessionControl::Stop
        {
            return Ok(ExpiredStop {
                owner_uid: uid,
                key: key.clone(),
                operation: pending.operation,
            });
        }
        if intent.state == SessionState::Terminated {
            return Err(Error::State);
        }
        let digest = Sha256::digest(codec::encode_body(&(operation_domain, key))?);
        let operation =
            OperationId::new(format!("{operation_domain}-{}", hex::encode(&digest[..12])))
                .map_err(|_| Error::State)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = super::control_observe::current_for_update(&tx, uid, key)?;
        intent.state = SessionState::Terminating;
        record.state = SandboxState::Stopping;
        record.session.as_mut().ok_or(Error::State)?.state = intent.state;
        tx.execute(
            "UPDATE sessions SET record=?1 WHERE session_id=?2",
            params![codec::encode_body(&intent)?, key.session.as_str()],
        )?;
        tx.execute(
            "UPDATE sandboxes SET record=?1 WHERE id=?2",
            params![codec::encode_body(&record)?, key.sandbox.as_str()],
        )?;
        tx.execute("INSERT INTO pending_session_controls(owner_uid,sandbox,sandbox_generation,session_id,session_generation,operation_id,action) VALUES (?1,?2,?3,?4,?5,?6,'stop') ON CONFLICT(owner_uid,sandbox,session_generation) DO UPDATE SET operation_id=excluded.operation_id,action='stop'",
            params![uid, key.sandbox.as_str(), key.sandbox_generation.get(), key.session.as_str(), key.generation.get(), operation.as_str()])?;
        if let Some(reason) = reason {
            super::events::append(&tx, uid, &record, reason, now)?;
            super::events::trim(&tx, self.event_retention)?;
        }
        tx.commit()?;
        Ok(ExpiredStop {
            owner_uid: uid,
            key: key.clone(),
            operation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::checkpoint_tests::fixture;

    #[test]
    fn administrative_stop_is_durable_idempotent_and_does_not_report_recovery_failure() {
        let (_directory, mut store, fence) = fixture();
        let session = store
            .inspect(1000, &fence.sandbox)
            .expect("sandbox")
            .session
            .expect("session");
        let key = SessionKey {
            sandbox: fence.sandbox,
            sandbox_generation: fence.generation,
            session: session.id,
            generation: session.generation,
        };
        let events_before = store.events(1000, 1, 256).expect("events").events;

        let first = store
            .admit_admin_stop(1000, &key, 1_100)
            .expect("first admission");
        let replay = store
            .admit_admin_stop(1000, &key, 1_101)
            .expect("idempotent admission");

        assert_eq!(first.operation, replay.operation);
        assert!(first.operation.as_str().starts_with("administrative-stop-"));
        assert_eq!(
            store.session_intent(1000, &key).expect("intent").state,
            SessionState::Terminating
        );
        assert_eq!(
            store
                .pending_session_control(1000, &key)
                .expect("pending")
                .expect("stop")
                .operation,
            first.operation
        );
        assert_eq!(
            store.events(1000, 1, 256).expect("events").events,
            events_before
        );
    }
}
