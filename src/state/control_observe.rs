use super::{SessionKey, Store};
use crate::{
    error::{Error, Result},
    process::ProcessIdentity,
};
use rusqlite::{TransactionBehavior, params};
use sandboxd_protocol::{ApiError, ErrorCode, EventKind, SandboxState, SessionState};

#[derive(Debug)]
pub struct CleanupProof {
    pub(crate) key: SessionKey,
    pub(crate) observations: CleanupObservations,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CleanupObservations {
    pub(crate) process_absent: bool,
    pub(crate) staged_jail_absent: bool,
    pub(crate) cgroup_absent: bool,
    pub(crate) jail_root_absent: bool,
    pub(crate) sockets_absent: bool,
    pub(crate) diagnostics_absent: bool,
}

impl CleanupProof {
    /// Constructs an explicitly incomplete proof for negative-path callers.
    /// There is intentionally no public constructor for a successful proof.
    pub fn incomplete(key: SessionKey) -> Self {
        Self::new(
            key,
            CleanupObservations {
                process_absent: false,
                staged_jail_absent: false,
                cgroup_absent: false,
                jail_root_absent: false,
                sockets_absent: false,
                diagnostics_absent: false,
            },
        )
    }

    pub(crate) fn new(key: SessionKey, observations: CleanupObservations) -> Self {
        Self { key, observations }
    }

    fn complete(&self, key: &SessionKey) -> bool {
        self.key == *key
            && self.observations.process_absent
            && self.observations.staged_jail_absent
            && self.observations.cgroup_absent
            && self.observations.jail_root_absent
            && self.observations.sockets_absent
            && self.observations.diagnostics_absent
    }
}

impl Store {
    pub fn record_session_paused(
        &mut self,
        uid: u32,
        key: &SessionKey,
        process: &ProcessIdentity,
        now: u64,
    ) -> Result<()> {
        self.record_session_state(
            uid,
            key,
            process,
            SessionState::Paused,
            SandboxState::Paused,
            EventKind::SessionPaused,
            now,
        )
    }

    pub fn record_session_resumed(
        &mut self,
        uid: u32,
        key: &SessionKey,
        process: &ProcessIdentity,
        now: u64,
    ) -> Result<()> {
        self.record_session_state(
            uid,
            key,
            process,
            SessionState::Active,
            SandboxState::Running,
            EventKind::SessionResumed,
            now,
        )
    }

    fn record_session_state(
        &mut self,
        uid: u32,
        key: &SessionKey,
        process: &ProcessIdentity,
        next: SessionState,
        sandbox_state: SandboxState,
        event: EventKind,
        now: u64,
    ) -> Result<()> {
        process.verify()?;
        let observed = self.session_process(uid, key)?.ok_or(Error::State)?;
        if observed != process.persisted() {
            return Err(Error::State);
        }
        let mut intent = self.session_intent(uid, key)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if intent.state == next {
            let record = current_for_update(&tx, uid, key)?;
            super::session_control::complete_pending_control_receipt(
                &tx,
                uid,
                key,
                &sandboxd_protocol::Response::Sandbox(Box::new(record)),
            )?;
            tx.execute(
                "DELETE FROM pending_session_controls WHERE owner_uid=?1 AND sandbox=?2 AND session_generation=?3",
                params![uid, key.sandbox.as_str(), key.generation.get()],
            )?;
            tx.commit()?;
            return Ok(());
        }
        let valid = matches!(
            (intent.state, next),
            (SessionState::Active, SessionState::Paused)
                | (SessionState::Paused, SessionState::Active)
        );
        if !valid {
            return Err(ApiError::new(
                ErrorCode::SessionUnavailable,
                "session state transition is not valid",
            )
            .into());
        }
        let mut record = current_for_update(&tx, uid, key)?;
        intent.state = next;
        record.session.as_mut().ok_or(Error::State)?.state = next;
        record.state = sandbox_state;
        tx.execute(
            "UPDATE sessions SET record=?1 WHERE session_id=?2",
            params![
                sandboxd_protocol::codec::encode_body(&intent)?,
                key.session.as_str()
            ],
        )?;
        tx.execute(
            "UPDATE sandboxes SET record=?1 WHERE id=?2",
            params![
                sandboxd_protocol::codec::encode_body(&record)?,
                key.sandbox.as_str()
            ],
        )?;
        super::session_control::complete_pending_control_receipt(
            &tx,
            uid,
            key,
            &sandboxd_protocol::Response::Sandbox(Box::new(record.clone())),
        )?;
        tx.execute(
            "DELETE FROM pending_session_controls WHERE owner_uid=?1 AND sandbox=?2 AND session_generation=?3",
            params![uid, key.sandbox.as_str(), key.generation.get()],
        )?;
        super::events::append(&tx, uid, &record, event, now)?;
        super::events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_session_stopped(
        &mut self,
        uid: u32,
        key: &SessionKey,
        proof: CleanupProof,
        now: u64,
    ) -> Result<()> {
        if !proof.complete(key) {
            return Err(ApiError::new(
                ErrorCode::SessionUnavailable,
                "runtime cleanup proof is incomplete",
            )
            .into());
        }
        let intent = self.session_intent(uid, key)?;
        if intent.state != SessionState::Terminating {
            return Err(Error::State);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = current_for_update(&tx, uid, key)?;
        super::session_control::complete_start_receipt(
            &tx,
            uid,
            key,
            &sandboxd_protocol::Response::Error(ApiError::new(
                ErrorCode::RecoveryFailed,
                "session start failed before guest readiness",
            )),
        )?;
        tx.execute(
            "DELETE FROM diagnostic_reservations WHERE session_id=?1 AND session_uid=?2",
            params![key.session.as_str(), intent.uid],
        )?;
        tx.execute(
            "DELETE FROM sessions WHERE session_id=?1",
            [key.session.as_str()],
        )?;
        tx.execute(
            "DELETE FROM session_timing WHERE sandbox=?1 AND session_generation=?2",
            params![key.sandbox.as_str(), key.generation.get()],
        )?;
        record.session = None;
        record.lease.session_generation = None;
        record.state = SandboxState::Stopped;
        super::session_control::complete_pending_control_receipt(
            &tx,
            uid,
            key,
            &sandboxd_protocol::Response::Sandbox(Box::new(record.clone())),
        )?;
        tx.execute(
            "UPDATE sandboxes SET record=?1 WHERE id=?2",
            params![
                sandboxd_protocol::codec::encode_body(&record)?,
                key.sandbox.as_str()
            ],
        )?;
        tx.execute(
            "DELETE FROM pending_session_controls WHERE owner_uid=?1 AND sandbox=?2 AND session_generation=?3",
            params![uid, key.sandbox.as_str(), key.generation.get()],
        )?;
        super::events::append(&tx, uid, &record, EventKind::SessionStopped, now)?;
        super::events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(())
    }
}

pub(super) fn current_for_update(
    connection: &rusqlite::Connection,
    uid: u32,
    key: &SessionKey,
) -> Result<sandboxd_protocol::Sandbox> {
    let mut statement = connection.prepare("SELECT id,generation,lease_expires_at,record FROM sandboxes WHERE id=?1 AND owner_uid=?2 AND record IS NOT NULL")?;
    let mut rows = statement.query(params![key.sandbox.as_str(), uid])?;
    let record = super::record::decode(rows.next()?.ok_or(Error::State)?)?;
    if record.generation != key.sandbox_generation
        || record.session.as_ref().map(|s| (&s.id, s.generation))
            != Some((&key.session, key.generation))
    {
        return Err(Error::State);
    }
    Ok(record)
}
