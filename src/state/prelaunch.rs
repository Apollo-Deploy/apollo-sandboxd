//! Durable ownership record for resources created before the launch manifest.
use super::{SessionKey, Store};
use crate::{
    error::{Error, Result},
    jailer::{CgroupIdentity, JailStageManifest},
    session::{AssetSetup, AssetsManifest},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sandboxd_protocol::codec;
use sandboxd_protocol::{EventKind, SandboxState, SessionState};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const MAX_BYTES: usize = 16_384;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrelaunchIntent {
    pub sandbox: String,
    pub session: String,
    pub sandbox_generation: u64,
    pub session_generation: u64,
    pub operator_root: PathBuf,
    pub cgroup_parent: PathBuf,
    pub firecracker_sha256: String,
    pub jailer_sha256: String,
    pub stage_root: PathBuf,
    pub jail_root: PathBuf,
    pub cgroup: PathBuf,
    pub staged_jail: Option<JailStageManifest>,
    pub assets: Option<AssetsManifest>,
    #[serde(default)]
    pub asset_setup: Option<AssetSetup>,
    pub cgroup_identity: Option<CgroupIdentity>,
}

pub(super) fn migrate(connection: &Connection) -> Result<()> {
    connection.execute_batch("BEGIN IMMEDIATE; CREATE TABLE prelaunch_resources (session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE, record BLOB NOT NULL CHECK(length(record)<=16384)) STRICT; PRAGMA user_version=10; COMMIT;")?;
    Ok(())
}

fn save(tx: &rusqlite::Transaction<'_>, key: &SessionKey, record: &PrelaunchIntent) -> Result<()> {
    validate(record)?;
    let bytes = codec::encode_body(record)?;
    if bytes.len() > MAX_BYTES {
        return Err(Error::State);
    }
    tx.execute(
        "INSERT INTO prelaunch_resources(session_id,record) VALUES (?1,?2)",
        params![key.session.as_str(), bytes],
    )?;
    Ok(())
}

fn validate(record: &PrelaunchIntent) -> Result<()> {
    if record.sandbox.is_empty()
        || record.session.is_empty()
        || record.sandbox_generation == 0
        || record.session_generation == 0
        || !record.operator_root.is_absolute()
        || !record.cgroup_parent.is_absolute()
        || record.stage_root != record.operator_root.join(".inputs").join(&record.session)
        || record.jail_root
            != record
                .operator_root
                .join("firecracker")
                .join(&record.session)
                .join("root")
        || record.cgroup != record.cgroup_parent.join(&record.session)
    {
        return Err(Error::State);
    }
    if let Some(setup) = &record.asset_setup {
        if record.assets.is_some() {
            return Err(Error::State);
        }
        setup.validate(&record.jail_root)?;
    }
    for path in [
        &record.operator_root,
        &record.cgroup_parent,
        &record.stage_root,
        &record.jail_root,
        &record.cgroup,
    ] {
        if path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(Error::State);
        }
    }
    Ok(())
}

fn validate_for_key(
    record: &PrelaunchIntent,
    key: &SessionKey,
    intent: &super::LaunchIntent,
) -> Result<()> {
    validate(record)?;
    if record.sandbox != key.sandbox.as_str()
        || record.session != key.session.as_str()
        || record.sandbox_generation != key.sandbox_generation.get()
        || record.session_generation != key.generation.get()
        || record.firecracker_sha256 != intent.pins.firecracker_sha256
        || record.jailer_sha256 != intent.pins.jailer_sha256
    {
        return Err(Error::State);
    }
    Ok(())
}

fn load(connection: &Connection, key: &SessionKey) -> Result<Option<PrelaunchIntent>> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT record FROM prelaunch_resources WHERE session_id=?1",
            [key.session.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| {
            if bytes.len() > MAX_BYTES {
                return Err(Error::State);
            }
            codec::decode_body(&bytes).map_err(|_| Error::State)
        })
        .transpose()
}

impl Store {
    pub fn reserve_prelaunch(
        &mut self,
        uid: u32,
        key: &SessionKey,
        record: &PrelaunchIntent,
    ) -> Result<()> {
        let intent = self.session_intent(uid, key)?;
        validate_for_key(record, key, &intent)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if load(&tx, key)?.is_some() {
            return Err(Error::State);
        }
        save(&tx, key, record)?;
        tx.commit()?;
        Ok(())
    }

    pub fn prelaunch(&self, uid: u32, key: &SessionKey) -> Result<Option<PrelaunchIntent>> {
        self.session_intent(uid, key)?;
        let value = load(&self.connection, key)?;
        if let Some(ref record) = value {
            validate_for_key(record, key, &self.session_intent(uid, key)?)?;
        }
        Ok(value)
    }

    pub fn record_prelaunch_stage(
        &mut self,
        uid: u32,
        key: &SessionKey,
        stage: JailStageManifest,
    ) -> Result<()> {
        self.update(uid, key, |record| {
            record.staged_jail = Some(stage);
            Ok(())
        })
    }
    pub fn record_prelaunch_assets(
        &mut self,
        uid: u32,
        key: &SessionKey,
        assets: AssetsManifest,
    ) -> Result<()> {
        self.update(uid, key, |record| {
            record.assets = Some(assets);
            record.asset_setup = None;
            Ok(())
        })
    }
    pub fn record_prelaunch_asset_setup(
        &mut self,
        uid: u32,
        key: &SessionKey,
        setup: AssetSetup,
    ) -> Result<()> {
        self.update(uid, key, |record| {
            if record.assets.is_some() {
                return Err(Error::State);
            }
            if let Some(previous) = &record.asset_setup {
                setup.ensure_successor_of(previous)?;
            } else {
                setup.validate(&record.jail_root)?;
            }
            record.asset_setup = Some(setup);
            Ok(())
        })
    }
    pub fn record_prelaunch_cgroup(
        &mut self,
        uid: u32,
        key: &SessionKey,
        identity: CgroupIdentity,
    ) -> Result<()> {
        self.update(uid, key, |record| {
            record.cgroup_identity = Some(identity);
            Ok(())
        })
    }
    pub fn clear_prelaunch(&mut self, uid: u32, key: &SessionKey) -> Result<()> {
        self.session_intent(uid, key)?;
        self.connection.execute(
            "DELETE FROM prelaunch_resources WHERE session_id=?1",
            [key.session.as_str()],
        )?;
        Ok(())
    }

    fn update(
        &mut self,
        uid: u32,
        key: &SessionKey,
        change: impl FnOnce(&mut PrelaunchIntent) -> Result<()>,
    ) -> Result<()> {
        let intent = self.session_intent(uid, key)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load(&tx, key)?.ok_or(Error::State)?;
        validate_for_key(&record, key, &intent)?;
        change(&mut record)?;
        validate_for_key(&record, key, &intent)?;
        let bytes = codec::encode_body(&record)?;
        tx.execute(
            "UPDATE prelaunch_resources SET record=?1 WHERE session_id=?2",
            params![bytes, key.session.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_prelaunch_stopped(
        &mut self,
        uid: u32,
        key: &SessionKey,
        proof: crate::session::PrelaunchCleanupProof,
        now: u64,
    ) -> Result<()> {
        if now > i64::MAX as u64 || !proof.complete(key) {
            return Err(Error::State);
        }
        let intent = self.session_intent(uid, key)?;
        if !matches!(
            intent.state,
            SessionState::JailerStarting | SessionState::Failed | SessionState::Terminating
        ) || super::session_resources::load(&self.connection, key)?.is_some()
            || self.session_process(uid, key)?.is_some()
        {
            return Err(Error::State);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = load(&tx, key)?.ok_or(Error::State)?;
        validate_for_key(&persisted, key, &intent)?;
        let mut record = super::control_observe::current_for_update(&tx, uid, key)?;
        super::session_receipt::complete_start_receipt(
            &tx,
            uid,
            key,
            &sandboxd_protocol::Response::Error(sandboxd_protocol::ApiError::new(
                sandboxd_protocol::ErrorCode::RecoveryFailed,
                "session start failed before guest readiness",
            )),
        )?;
        record.session = None;
        record.lease.session_generation = None;
        record.state = SandboxState::Stopped;
        super::session_receipt::complete_pending_control_receipt(
            &tx,
            uid,
            key,
            &sandboxd_protocol::Response::Sandbox(Box::new(record.clone())),
        )?;
        tx.execute(
            "DELETE FROM prelaunch_resources WHERE session_id=?1",
            [key.session.as_str()],
        )?;
        tx.execute(
            "DELETE FROM sessions WHERE session_id=?1",
            [key.session.as_str()],
        )?;
        tx.execute(
            "DELETE FROM session_timing WHERE sandbox=?1 AND session_generation=?2",
            params![key.sandbox.as_str(), key.generation.get()],
        )?;
        tx.execute(
            "DELETE FROM pending_session_controls WHERE owner_uid=?1 AND sandbox=?2 AND session_generation=?3",
            params![uid, key.sandbox.as_str(), key.generation.get()],
        )?;
        tx.execute(
            "UPDATE sandboxes SET record=?1 WHERE id=?2",
            params![codec::encode_body(&record)?, key.sandbox.as_str()],
        )?;
        super::events::append(&tx, uid, &record, EventKind::SessionStopped, now)?;
        super::events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(())
    }
}
