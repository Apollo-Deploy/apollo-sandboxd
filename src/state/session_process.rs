//! A process observation commits before VMM configuration. Allocation release
//! is deliberately separate: process death alone does not prove owned-resource cleanup.
use super::{SessionKey, Store, events, session};
use crate::{
    error::{Error, Result},
    process::{PersistedProcessIdentity, ProcessIdentity},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sandboxd_protocol::*;

pub(super) fn migrate(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
        CREATE TABLE session_processes (
            session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
            record BLOB NOT NULL CHECK(length(record) <= 4096)
        ) STRICT;
        PRAGMA user_version=4;
        COMMIT;",
    )?;
    Ok(())
}

fn matches_intent(identity: &PersistedProcessIdentity, intent: &super::LaunchIntent) -> bool {
    identity.pid > 0
        && identity.pid <= i32::MAX as u32
        && identity.start_time_ticks > 0
        && identity.boot_id == intent.host_boot_id
        && identity.uids == [intent.uid; 4]
        && identity.gids == [intent.gid; 4]
        && identity.executable_inode > 0
        && identity.executable_sha256 == intent.pins.firecracker_sha256
        && identity.cgroup_sha256.len() == 64
        && identity
            .cgroup_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn load(connection: &Connection, key: &SessionKey) -> Result<Option<PersistedProcessIdentity>> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT record FROM session_processes WHERE session_id=?1",
            [key.session.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| {
            if bytes.len() > 4096 {
                return Err(Error::State);
            }
            Ok(codec::decode_body(&bytes)?)
        })
        .transpose()
}

impl Store {
    /// A restart must reopen this complete identity, never adopt a numeric PID.
    pub fn session_process(
        &self,
        uid: u32,
        key: &SessionKey,
    ) -> Result<Option<PersistedProcessIdentity>> {
        let intent = self.session_intent(uid, key)?;
        let process = load(&self.connection, key)?;
        if process
            .as_ref()
            .is_some_and(|p| !matches_intent(p, &intent))
        {
            return Err(Error::State);
        }
        Ok(process)
    }

    /// Called immediately after privilege drop/cgroup join and strong capture,
    /// before any API configuration. Repeating the same observation is safe.
    pub fn record_vmm_process(
        &mut self,
        uid: u32,
        key: &SessionKey,
        process: &ProcessIdentity,
        now: u64,
    ) -> Result<()> {
        process.verify()?;
        let mut intent = self.session_intent(uid, key)?;
        let observed = process.persisted();
        if !matches_intent(&observed, &intent) {
            return Err(Error::State);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(previous) = load(&tx, key)? {
            return if previous == observed {
                Ok(())
            } else {
                Err(Error::State)
            };
        }
        if intent.state != SessionState::JailerStarting {
            return Err(Error::State);
        }
        if super::session_resources::load(&tx, key)?.is_none() {
            return Err(Error::State);
        }
        let mut record = current(&tx, uid, key)?;
        tx.execute(
            "INSERT INTO session_processes(session_id,record) VALUES (?1,?2)",
            params![key.session.as_str(), codec::encode_body(&observed)?],
        )?;
        intent.state = SessionState::VmmConfiguring;
        record.session.as_mut().ok_or(Error::State)?.state = intent.state;
        save(&tx, &intent, &record, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Persist a strongly captured orphan identity after an administrative Stop
    /// was durably admitted. This must not move the session out of Terminating.
    pub(crate) fn record_vmm_process_for_cleanup(
        &mut self,
        uid: u32,
        key: &SessionKey,
        process: &ProcessIdentity,
    ) -> Result<()> {
        process.verify()?;
        let intent = self.session_intent(uid, key)?;
        let pending = self.pending_session_control(uid, key)?;
        if intent.state != SessionState::Terminating
            || !pending.is_some_and(|value| value.control == SessionControl::Stop)
        {
            return Err(Error::State);
        }
        let observed = process.persisted();
        if !matches_intent(&observed, &intent) {
            return Err(Error::State);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(previous) = load(&tx, key)? {
            return if previous == observed {
                Ok(())
            } else {
                Err(Error::State)
            };
        }
        if super::session_resources::load(&tx, key)?.is_none() {
            return Err(Error::State);
        }
        tx.execute(
            "INSERT INTO session_processes(session_id,record) VALUES (?1,?2)",
            params![key.session.as_str(), codec::encode_body(&observed)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_vmm_booting(
        &mut self,
        uid: u32,
        key: &SessionKey,
        process: &ProcessIdentity,
        now: u64,
    ) -> Result<()> {
        self.advance_vmm(uid, key, process, SessionState::VmmBooting, now)
    }

    pub fn record_guest_handshake(
        &mut self,
        uid: u32,
        key: &SessionKey,
        process: &ProcessIdentity,
        now: u64,
    ) -> Result<()> {
        self.advance_vmm(uid, key, process, SessionState::GuestHandshake, now)
    }

    /// READY requires the current incarnation's full authenticated handshake.
    /// Guest root remains untrusted; readiness does not grant host authority.
    pub fn record_guest_ready(
        &mut self,
        uid: u32,
        key: &SessionKey,
        process: &ProcessIdentity,
        identity: &guest_protocol::SessionIdentity,
        now: u64,
    ) -> Result<()> {
        let intent = self.session_intent(uid, key)?;
        let expected = guest_protocol::SessionIdentity {
            sandbox: key.sandbox.clone(),
            sandbox_generation: key.sandbox_generation,
            session: key.session.clone(),
            session_generation: key.generation,
            boot_nonce: guest_protocol::BootNonce(intent.boot_nonce),
            vsock_cid: intent.cid,
            protocol_version: guest_protocol::GUEST_PROTOCOL_VERSION,
        };
        expected.authenticate(identity).map_err(|_| {
            ApiError::new(
                ErrorCode::GuestHandshakeFailed,
                "guest READY identity mismatch",
            )
        })?;
        self.advance_vmm(uid, key, process, SessionState::Active, now)
    }

    fn advance_vmm(
        &mut self,
        uid: u32,
        key: &SessionKey,
        process: &ProcessIdentity,
        next: SessionState,
        now: u64,
    ) -> Result<()> {
        process.verify()?;
        let mut intent = self.session_intent(uid, key)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if load(&tx, key)?.as_ref() != Some(&process.persisted()) {
            return Err(Error::State);
        }
        if intent.state == next {
            return Ok(());
        }
        if !matches!(
            (intent.state, next),
            (SessionState::VmmConfiguring, SessionState::VmmBooting)
                | (SessionState::VmmBooting, SessionState::GuestHandshake)
                | (SessionState::GuestHandshake, SessionState::Active)
        ) {
            return Err(Error::State);
        }
        let mut record = current(&tx, uid, key)?;
        intent.state = next;
        record.session.as_mut().ok_or(Error::State)?.state = next;
        record.state = if next == SessionState::Active {
            SandboxState::GuestReady
        } else {
            SandboxState::Booting
        };
        save(&tx, &intent, &record, now)?;
        if next == SessionState::Active {
            tx.execute("UPDATE session_timing SET ready_at_ms=COALESCE(ready_at_ms,?1),last_activity_ms=?1 WHERE sandbox=?2 AND session_generation=?3", params![now, key.sandbox.as_str(), key.generation.get()])?;
            super::session_control::complete_start_receipt(
                &tx,
                uid,
                key,
                &Response::Sandbox(Box::new(record.clone())),
            )?;
        }
        if matches!(next, SessionState::VmmBooting | SessionState::Active) {
            events::append(
                &tx,
                uid,
                &record,
                if next == SessionState::Active {
                    EventKind::GuestReady
                } else {
                    EventKind::SessionBooted
                },
                now,
            )?;
        }
        events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(())
    }
}

fn current(connection: &Connection, uid: u32, key: &SessionKey) -> Result<Sandbox> {
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

fn save(
    connection: &Connection,
    intent: &super::LaunchIntent,
    record: &Sandbox,
    now: u64,
) -> Result<()> {
    if now > i64::MAX as u64 {
        return Err(Error::State);
    }
    connection.execute(
        "UPDATE sessions SET record=?1 WHERE session_id=?2",
        params![codec::encode_body(intent)?, intent.key.session.as_str()],
    )?;
    // Same transaction updates both indexes; readers never observe one advanced alone.
    connection.execute(
        "UPDATE sandboxes SET record=?1 WHERE id=?2",
        params![codec::encode_body(record)?, record.id.as_str()],
    )?;
    Ok(())
}

pub(super) fn validate_all(connection: &Connection) -> Result<()> {
    let mut statement =
        connection.prepare(&format!("SELECT {} FROM sessions", session::COLUMNS))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let intent = session::decode(row)?;
        let process = load(connection, &intent.key)?;
        if process
            .as_ref()
            .is_some_and(|p| !matches_intent(p, &intent))
            || (matches!(
                intent.state,
                SessionState::VmmConfiguring
                    | SessionState::VmmBooting
                    | SessionState::GuestHandshake
                    | SessionState::Active
                    | SessionState::Paused
            ) && process.is_none())
            || (matches!(
                intent.state,
                SessionState::Preparing | SessionState::JailerStarting
            ) && process.is_some())
        {
            return Err(Error::State);
        }
    }
    Ok(())
}
