use super::{
    Store,
    snapshot::{SnapshotIntent, SnapshotRecord},
};
use crate::error::{Error, Result};
use rusqlite::{OptionalExtension, params};
use sandboxd_protocol::{ApiError, ErrorCode, SandboxId, SnapshotId, SnapshotInfo, codec};
impl Store {
    pub(crate) fn snapshot_intent(
        &self,
        uid: u32,
        operation: &sandboxd_protocol::OperationId,
    ) -> Result<super::snapshot::SnapshotIntent> {
        super::snapshot::load_intent(&self.connection, uid, operation)
    }

    pub(crate) fn pending_snapshots(&self) -> Result<Vec<SnapshotIntent>> {
        let mut statement = self
            .connection
            .prepare("SELECT record FROM snapshot_intents ORDER BY sandbox LIMIT 65")?;
        let values = statement
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .map(|v| -> Result<_> { Ok(codec::decode_body(&v?)?) })
            .collect::<Result<Vec<_>>>()?;
        if values.len() > 64 {
            return Err(Error::State);
        }
        Ok(values)
    }

    pub fn inspect_snapshot(&self, uid: u32, id: &SnapshotId) -> Result<SnapshotInfo> {
        let bytes: Vec<u8> = self
            .connection
            .query_row(
                "SELECT record FROM snapshots WHERE owner_uid=?1 AND id=?2 AND complete=1",
                params![uid, id.as_str()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| ApiError::new(ErrorCode::SnapshotNotFound, "snapshot not found"))?;
        describe(codec::decode_body(&bytes)?)
    }
    pub fn list_snapshots(
        &self,
        uid: u32,
        sandbox: &SandboxId,
        after: Option<&SnapshotId>,
        limit: u16,
    ) -> Result<Vec<SnapshotInfo>> {
        self.inspect(uid, sandbox)?;
        if limit == 0 || limit > 256 {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "snapshot list limit outside 1..256",
            )
            .into());
        }
        let mut query=self.connection.prepare("SELECT record FROM snapshots WHERE owner_uid=?1 AND sandbox=?2 AND complete=1 AND (?3 IS NULL OR id>?3) ORDER BY id LIMIT ?4")?;
        query
            .query_map(
                params![uid, sandbox.as_str(), after.map(SnapshotId::as_str), limit],
                |r| r.get::<_, Vec<u8>>(0),
            )?
            .map(|row| describe(codec::decode_body(&row?)?))
            .collect()
    }
}
fn describe(record: SnapshotRecord) -> Result<SnapshotInfo> {
    let manifest = record.manifest.ok_or(Error::State)?;
    Ok(SnapshotInfo {
        id: manifest.id,
        sandbox: manifest.sandbox,
        sandbox_generation: manifest.sandbox_generation,
        memory_bytes: manifest.memory_bytes,
        state_bytes: manifest.state_bytes,
        suspended: record.suspended,
    })
}
