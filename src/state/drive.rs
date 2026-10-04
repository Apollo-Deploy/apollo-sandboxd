//! Durable filesystem identity survives the compute session that created it.
use super::{SessionKey, Store};
use crate::{
    error::{Error, Result},
    storage::{DriveIdentity, DriveOwner},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sandboxd_protocol::{SandboxGeneration, SandboxId, VolumeId, codec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDrive {
    pub sandbox: SandboxId,
    pub generation: SandboxGeneration,
    pub volume: VolumeId,
    pub size: u64,
    pub identity: Option<DriveIdentity>,
    pub pending_owner: Option<DriveOwner>,
}

pub(super) fn migrate(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
        CREATE TABLE state_drives (
            sandbox TEXT PRIMARY KEY REFERENCES sandboxes(id),
            generation INTEGER NOT NULL CHECK(generation>0),
            record BLOB NOT NULL CHECK(length(record)<=4096)
        ) STRICT;
        PRAGMA user_version=7;
        COMMIT;",
    )?;
    Ok(())
}

impl StateDrive {
    fn validate(&self) -> Result<()> {
        if self.volume != volume(&self.sandbox, self.generation)?
            || !(1 << 20..=1 << 40).contains(&self.size)
            || !self.size.is_multiple_of(4096)
        {
            return Err(Error::State);
        }
        if let Some(owner) = self.pending_owner {
            DriveOwner::new(owner.uid, owner.gid)?;
        }
        if let Some(identity) = self.identity {
            if identity.size != self.size || identity.inode == 0 {
                return Err(Error::State);
            }
            DriveOwner::new(identity.uid, identity.gid)?;
        } else if self.pending_owner.is_none() {
            return Err(Error::State);
        }
        Ok(())
    }
}

impl Store {
    /// The allocated session, not a caller UID, determines the next drive owner.
    /// Commit this plan before formatting or changing ownership of an inode.
    pub fn plan_state_drive(&mut self, uid: u32, key: &SessionKey) -> Result<StateDrive> {
        let intent = self.session_intent(uid, key)?;
        if intent.state != sandboxd_protocol::SessionState::JailerStarting {
            return Err(Error::State);
        }
        let sandbox = self.inspect(uid, &key.sandbox)?;
        let size = u64::from(sandbox.spec.resources.state_disk_mib) * 1_048_576;
        let owner = DriveOwner::new(intent.uid, intent.gid)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut drive = load(&tx, &key.sandbox)?.unwrap_or(StateDrive {
            sandbox: key.sandbox.clone(),
            generation: key.sandbox_generation,
            volume: volume(&key.sandbox, key.sandbox_generation)?,
            size,
            identity: None,
            pending_owner: Some(owner),
        });
        if drive.generation != key.sandbox_generation
            || drive.size != size
            || drive.pending_owner.is_some_and(|pending| pending != owner)
        {
            return Err(Error::State);
        }
        drive.pending_owner = Some(owner);
        save(&tx, &drive)?;
        tx.commit()?;
        Ok(drive)
    }

    /// Called with the anonymous formatted inode before its no-replace link.
    pub fn record_prepared_drive(
        &mut self,
        uid: u32,
        key: &SessionKey,
        identity: DriveIdentity,
    ) -> Result<()> {
        self.session_intent(uid, key)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut drive = load(&tx, &key.sandbox)?.ok_or(Error::State)?;
        if drive.generation != key.sandbox_generation
            || drive.identity.is_some()
            || drive.pending_owner
                != Some(DriveOwner {
                    uid: identity.uid,
                    gid: identity.gid,
                })
            || drive.size != identity.size
        {
            return Err(Error::State);
        }
        drive.identity = Some(identity);
        save(&tx, &drive)?;
        tx.commit()?;
        Ok(())
    }

    /// Called only after descriptor-relative reopening or fenced reassignment.
    pub fn record_published_drive(
        &mut self,
        uid: u32,
        key: &SessionKey,
        identity: DriveIdentity,
    ) -> Result<()> {
        self.session_intent(uid, key)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut drive = load(&tx, &key.sandbox)?.ok_or(Error::State)?;
        let old = drive.identity.ok_or(Error::State)?;
        if drive.generation != key.sandbox_generation
            || old.device != identity.device
            || old.inode != identity.inode
            || old.size != identity.size
            || drive.pending_owner
                != Some(DriveOwner {
                    uid: identity.uid,
                    gid: identity.gid,
                })
        {
            return Err(Error::State);
        }
        drive.identity = Some(identity);
        drive.pending_owner = None;
        save(&tx, &drive)?;
        tx.commit()?;
        Ok(())
    }
}

fn volume(id: &SandboxId, generation: SandboxGeneration) -> Result<VolumeId> {
    let bytes = codec::encode_body(&(id, generation))?;
    VolumeId::new(hex::encode(Sha256::digest(bytes))).map_err(|_| Error::State)
}

pub(super) fn save(connection: &rusqlite::Connection, drive: &StateDrive) -> Result<()> {
    drive.validate()?;
    connection.execute(
        "INSERT INTO state_drives(sandbox,generation,record) VALUES (?1,?2,?3)
        ON CONFLICT(sandbox) DO UPDATE SET generation=excluded.generation,record=excluded.record",
        params![
            drive.sandbox.as_str(),
            drive.generation.get(),
            codec::encode_body(drive)?
        ],
    )?;
    Ok(())
}

pub(super) fn load(
    connection: &rusqlite::Connection,
    id: &SandboxId,
) -> Result<Option<StateDrive>> {
    let row: Option<(u64, Vec<u8>)> = connection
        .query_row(
            "SELECT generation,record FROM state_drives WHERE sandbox=?1",
            [id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(generation, bytes)| {
        let drive: StateDrive = codec::decode_body(&bytes)?;
        drive.validate()?;
        if drive.sandbox != *id || drive.generation.get() != generation {
            return Err(Error::State);
        }
        Ok(drive)
    })
    .transpose()
}

pub(super) fn validate_all(connection: &rusqlite::Connection) -> Result<()> {
    let mut statement = connection.prepare("SELECT sandbox FROM state_drives")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let id = SandboxId::new(row.get::<_, String>(0)?).map_err(|_| Error::State)?;
        load(connection, &id)?.ok_or(Error::State)?;
    }
    Ok(())
}
