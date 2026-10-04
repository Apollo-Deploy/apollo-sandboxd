use super::{LaunchIntent, SessionKey, Store, events, lease, session};
use crate::error::{Error, Result};
use rusqlite::{Connection, TransactionBehavior, params};
use sandboxd_protocol::*;

impl Store {
    pub fn session_intent(&self, uid: u32, key: &SessionKey) -> Result<LaunchIntent> {
        let mut statement = self.connection.prepare(&format!("SELECT {} FROM sessions WHERE sandbox=?1 AND sandbox_generation=?2 AND session_id=?3 AND session_generation=?4 AND sandbox IN (SELECT id FROM sandboxes WHERE owner_uid=?5)",session::COLUMNS))?;
        let mut rows = statement.query(params![
            key.sandbox.as_str(),
            key.sandbox_generation.get(),
            key.session.as_str(),
            key.generation.get(),
            uid
        ])?;
        rows.next()?
            .map(session::decode)
            .transpose()?
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::StaleGeneration,
                    "session incarnation is not current",
                )
                .into()
            })
    }

    /// Marks the non-repeatable launch boundary durably. A retry here must
    /// reconcile the recorded jail/process; it must never launch a second VM.
    pub fn begin_session_launch(&mut self, uid: u32, key: &SessionKey, now: u64) -> Result<()> {
        self.change_session(uid, key, now, false)
    }

    /// Safe reclamation requires proof no runtime effect was permitted. Once
    /// JAILER_STARTING is committed this shortcut is permanently forbidden.
    pub fn abort_session_preparation(
        &mut self,
        uid: u32,
        key: &SessionKey,
        now: u64,
    ) -> Result<()> {
        self.change_session(uid, key, now, true)
    }

    fn change_session(&mut self, uid: u32, key: &SessionKey, now: u64, abort: bool) -> Result<()> {
        if now > i64::MAX as u64 {
            return Err(Error::State);
        }
        let mut intent = self.session_intent(uid, key)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut statement = tx.prepare("SELECT id,generation,lease_expires_at,record FROM sandboxes WHERE id=?1 AND owner_uid=?2 AND record IS NOT NULL")?;
        let mut rows = statement.query(params![key.sandbox.as_str(), uid])?;
        let mut record = super::record::decode(rows.next()?.ok_or(Error::State)?)?;
        drop(rows);
        drop(statement);
        if record.generation != key.sandbox_generation
            || record.session.as_ref().map(|s| (&s.id, s.generation))
                != Some((&key.session, key.generation))
        {
            return Err(ApiError::new(
                ErrorCode::StaleGeneration,
                "session incarnation is not current",
            )
            .into());
        }
        if intent.state != SessionState::Preparing {
            return Err(ApiError::new(
                ErrorCode::OperationConflict,
                "launch boundary already crossed; recovery required",
            )
            .into());
        }
        if abort {
            tx.execute(
                "DELETE FROM sessions WHERE sandbox=?1",
                [key.sandbox.as_str()],
            )?;
            tx.execute(
                "DELETE FROM session_timing WHERE sandbox=?1 AND session_generation=?2",
                params![key.sandbox.as_str(), key.generation.get()],
            )?;
            record.session = None;
            record.lease.session_generation = None;
            record.state = SandboxState::Stopped;
            events::append(&tx, uid, &record, EventKind::SessionStopped, now)?;
            super::session_control::complete_start_receipt(
                &tx,
                uid,
                key,
                &Response::Error(ApiError::new(
                    ErrorCode::RecoveryFailed,
                    "session start was aborted before guest readiness",
                )),
            )?;
        } else {
            let fence = Fence {
                sandbox: record.id.clone(),
                generation: record.generation,
                session_generation: Some(key.generation),
                lease: record.lease.id.clone(),
            };
            lease::active(&tx, uid, &fence, now)?;
            intent.state = SessionState::JailerStarting;
            record.session.as_mut().ok_or(Error::State)?.state = intent.state;
            tx.execute(
                "UPDATE sessions SET record=?1 WHERE sandbox=?2",
                params![codec::encode_body(&intent)?, key.sandbox.as_str()],
            )?;
            tx.execute(
                "UPDATE session_timing SET started_at_ms=COALESCE(started_at_ms,?1) WHERE sandbox=?2 AND session_generation=?3",
                params![now, key.sandbox.as_str(), key.generation.get()],
            )?;
        }
        lease::save(&tx, &record)?;
        events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(())
    }

    /// Bounded recovery pagination; callers must revalidate host identity before
    /// any runtime action or resource reclamation.
    pub fn session_intents(
        &self,
        after: Option<&SandboxId>,
        limit: u16,
    ) -> Result<Vec<LaunchIntent>> {
        if limit == 0 || limit > 256 {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "session recovery page limit must be 1..256",
            )
            .into());
        }
        let mut statement = self.connection.prepare(&format!(
            "SELECT {} FROM sessions WHERE sandbox>?1 ORDER BY sandbox LIMIT ?2",
            session::COLUMNS
        ))?;
        let mut rows = statement.query(params![after.map_or("", SandboxId::as_str), limit])?;
        let mut intents = Vec::new();
        while let Some(row) = rows.next()? {
            intents.push(session::decode(row)?);
        }
        Ok(intents)
    }
}

pub(super) fn booting_count(connection: &Connection) -> Result<u32> {
    let mut statement =
        connection.prepare(&format!("SELECT {} FROM sessions", session::COLUMNS))?;
    let mut rows = statement.query([])?;
    let mut count = 0u32;
    while let Some(row) = rows.next()? {
        if matches!(
            session::decode(row)?.state,
            SessionState::Preparing
                | SessionState::JailerStarting
                | SessionState::VmmConfiguring
                | SessionState::VmmBooting
                | SessionState::GuestHandshake
        ) {
            count = count.checked_add(1).ok_or(Error::State)?;
        }
    }
    Ok(count)
}
