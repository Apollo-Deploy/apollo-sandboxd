use super::{events, mutation, record, schema};
use crate::{
    config::{LeaseConfig, Quotas},
    error::{Error, Result},
    security::path::SecureDir,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sandboxd_protocol::{
    ApiError, ErrorCode, EventPage, Mutation, OperationId, Response, Sandbox, SandboxId, codec,
};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::{fs::File, path::Path};

pub struct Store {
    pub(super) connection: Connection,
    pub(super) quotas: Quotas,
    pub(super) leases: LeaseConfig,
    pub(super) event_retention: u32,
    _directory: SecureDir,
    _lock: File,
    pub(crate) operation_key: [u8; 32],
}
impl Store {
    /// Frees only terminal receipts when the bounded receipt table is full.
    /// Pending guest/start/control operations remain durable until recovery has
    /// resolved their external effect.
    pub(crate) fn collect_terminal_receipt_for_capacity(
        tx: &rusqlite::Transaction<'_>,
        max: u32,
    ) -> Result<()> {
        let count: u32 = tx.query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))?;
        if count < max {
            return Ok(());
        }
        let mut after_rowid = 0_i64;
        loop {
            let candidate = {
                let mut rows = tx.prepare(
                    "SELECT rowid,owner_uid,id,response FROM operations
                     WHERE rowid>?1 ORDER BY rowid ASC LIMIT 1",
                )?;
                rows.query_row([after_rowid], |row| {
                    let rowid: i64 = row.get(0)?;
                    let uid: u32 = row.get(1)?;
                    let id: String = row.get(2)?;
                    let bytes: Vec<u8> = row.get(3)?;
                    Ok((rowid, uid, id, bytes))
                })
                .optional()?
            };
            let Some((rowid, uid, id, bytes)) = candidate else {
                break;
            };
            after_rowid = rowid;
            let response: sandboxd_protocol::Response =
                match sandboxd_protocol::codec::decode_body(&bytes) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
            if matches!(
                response,
                sandboxd_protocol::Response::GuestPending { .. }
                    | sandboxd_protocol::Response::CheckpointPending { .. }
                    | sandboxd_protocol::Response::SnapshotPending { .. }
            ) {
                continue;
            }
            let linked_start: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM session_operations WHERE owner_uid=?1 AND operation_id=?2)",
                params![uid, id], |r| r.get(0))?;
            let linked_control: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pending_session_controls WHERE owner_uid=?1 AND operation_id=?2)",
                params![uid, id], |r| r.get(0))?;
            if !linked_start && !linked_control {
                tx.execute(
                    "DELETE FROM operations WHERE owner_uid=?1 AND id=?2",
                    params![uid, id],
                )?;
                return Ok(());
            }
        }
        Ok(())
    }

    pub fn operation_watermark(&self, uid: u32) -> Result<u64> {
        Ok(self
            .connection
            .query_row(
                "SELECT accepted_sequence FROM operation_watermarks WHERE owner_uid=?1",
                [uid],
                |row| row.get::<_, u64>(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    pub(crate) fn reserve_operation_sequence(
        tx: &rusqlite::Transaction<'_>,
        uid: u32,
        sequence: u64,
    ) -> Result<()> {
        if sequence == 0 || sequence > i64::MAX as u64 {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "operation sequence must be positive",
            )
            .into());
        }
        let previous: Option<u64> = tx
            .query_row(
                "SELECT accepted_sequence FROM operation_watermarks WHERE owner_uid=?1",
                [uid],
                |row| row.get(0),
            )
            .optional()?;
        let previous = previous.unwrap_or(0);
        if sequence <= previous {
            return Err(ApiError::new(
                ErrorCode::OperationReceiptUnavailable,
                "operation receipt was retired or its sequence was already accepted",
            )
            .into());
        }
        if sequence != previous.saturating_add(1) {
            return Err(ApiError::new(
                ErrorCode::OperationOutOfOrder,
                "operation sequence must be contiguous",
            )
            .into());
        }
        tx.execute(
            "INSERT INTO operation_watermarks(owner_uid,accepted_sequence) VALUES (?1,?2)
             ON CONFLICT(owner_uid) DO UPDATE SET accepted_sequence=excluded.accepted_sequence",
            params![uid, sequence],
        )?;
        Ok(())
    }
    pub fn open(
        path: &Path,
        quotas: Quotas,
        leases: LeaseConfig,
        event_retention: u32,
    ) -> Result<Self> {
        if quotas.max_active_sandboxes == 0
            || quotas.max_booting_sandboxes == 0
            || quotas.max_booting_sandboxes > quotas.max_active_sandboxes
            || event_retention == 0
            || leases.max_seconds == 0
            || quotas.max_sandbox_identities == 0
            || quotas.max_operation_receipts == 0
        {
            return Err(Error::Config("state limits must be finite and positive"));
        }
        let directory = SecureDir::open(path)?;
        let stat = rustix::fs::fstat(directory.as_fd())?;
        if stat.st_mode & 0o077 != 0 || stat.st_uid != rustix::process::geteuid().as_raw() {
            return Err(Error::Path);
        }
        let lock = directory.lock("daemon.lock")?;
        let (mut operation_key_file, new_operation_key) =
            match directory.create_file("operation-hash.key") {
                Ok(file) => (file, true),
                Err(Error::Kernel(rustix::io::Errno::EXIST)) => {
                    (directory.open_file("operation-hash.key", true)?, false)
                }
                Err(error) => return Err(error),
            };
        let mut operation_key = [0_u8; 32];
        if !new_operation_key && operation_key_file.metadata()?.len() != operation_key.len() as u64
        {
            return Err(Error::Path);
        }
        operation_key_file.seek(SeekFrom::Start(0))?;
        let read = operation_key_file.read(&mut operation_key)?;
        if new_operation_key {
            getrandom::getrandom(&mut operation_key).map_err(|_| Error::State)?;
            operation_key_file.seek(SeekFrom::Start(0))?;
            operation_key_file.write_all(&operation_key)?;
            operation_key_file.sync_all()?;
            rustix::fs::fsync(directory.as_fd())?;
        } else if read != operation_key.len() {
            return Err(Error::Path);
        }
        let database = directory.open_or_create_private("state.sqlite3")?;
        for name in ["state.sqlite3-wal", "state.sqlite3-shm"] {
            match directory.open_file(name, true) {
                Ok(file) => {
                    let stat = rustix::fs::fstat(&file)?;
                    if stat.st_mode & 0o077 != 0
                        || stat.st_uid != rustix::process::geteuid().as_raw()
                    {
                        return Err(Error::Path);
                    }
                }
                Err(Error::Kernel(rustix::io::Errno::NOENT)) => (),
                Err(error) => return Err(error),
            }
        }
        let connection = Connection::open(path.join("state.sqlite3"))?;
        // The private directory and exclusive instance lock protect SQLite sidecar creation.
        let opened = directory.stat("state.sqlite3")?;
        let original = rustix::fs::fstat(&database)?;
        if opened.st_dev != original.st_dev || opened.st_ino != original.st_ino {
            return Err(Error::Path);
        }
        schema::initialize(&connection)?;
        record::validate_all(&connection)?;
        super::session::validate_all(&connection)?;
        super::session_process::validate_all(&connection)?;
        super::session_resources::validate_all(&connection)?;
        super::drive::validate_all(&connection)?;
        rustix::fs::fsync(directory.as_fd())?;
        Ok(Self {
            connection,
            quotas,
            leases,
            event_retention,
            _directory: directory,
            _lock: lock,
            operation_key,
        })
    }
    pub fn mutate(
        &mut self,
        uid: u32,
        operation: &OperationId,
        request: &Mutation,
        now_ms: u64,
    ) -> Result<Response> {
        self.mutate_checked(uid, operation, request, now_ms, || Ok(()))
    }

    /// Replays a committed receipt before applying admission policy for a new
    /// operation. Catalog changes must not change an already committed result.
    pub(crate) fn mutate_checked(
        &mut self,
        uid: u32,
        operation: &OperationId,
        request: &Mutation,
        now_ms: u64,
        admission: impl FnOnce() -> Result<()>,
    ) -> Result<Response> {
        self.mutate_checked_sequenced(uid, operation, request, now_ms, None, admission)
    }

    pub fn mutate_checked_sequenced(
        &mut self,
        uid: u32,
        operation: &OperationId,
        request: &Mutation,
        now_ms: u64,
        operation_sequence: Option<u64>,
        admission: impl FnOnce() -> Result<()>,
    ) -> Result<Response> {
        if let Some(sequence) = operation_sequence
            && !operation.matches_sequence(sequence)
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "operation ID is not bound to operation sequence",
            )
            .into());
        }
        let encoded = codec::encode_body(request)?;
        if encoded.len() > 131_072 {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "mutation size or timestamp outside bounds",
            )
            .into());
        }
        let digest = Sha256::digest(&encoded);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT request_digest, response FROM operations WHERE owner_uid=?1 AND id=?2",
                params![uid, operation.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((old_digest, response)) = previous {
            if old_digest.as_slice() != digest.as_slice() {
                return Err(ApiError::new(
                    ErrorCode::OperationConflict,
                    "operation ID reused with a different body",
                )
                .into());
            }
            return Ok(codec::decode_body(&response)?);
        }
        if now_ms > i64::MAX as u64 - 86_400_000 {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "mutation timestamp outside bounds",
            )
            .into());
        }
        admission()?;
        if let Some(sequence) = operation_sequence {
            Self::reserve_operation_sequence(&tx, uid, sequence)?;
        }
        Self::collect_terminal_receipt_for_capacity(&tx, self.quotas.max_operation_receipts)?;
        let count: u32 = tx.query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))?;
        if count >= self.quotas.max_operation_receipts {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "durable operation receipt capacity reached",
            )
            .into());
        }
        let response = mutation::apply(&tx, uid, request, now_ms, &self.quotas, &self.leases)?;
        tx.execute(
            "INSERT INTO operations(owner_uid,id,request_digest,response) VALUES (?1,?2,?3,?4)",
            params![
                uid,
                operation.as_str(),
                digest.as_slice(),
                codec::encode_body(&response)?
            ],
        )?;
        events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(response)
    }
    pub fn inspect(&self, uid: u32, id: &SandboxId) -> Result<Sandbox> {
        let mut statement = self.connection.prepare(
            "SELECT id,generation,lease_expires_at,record FROM sandboxes WHERE id=?1 AND owner_uid=?2 AND record IS NOT NULL",
        )?;
        let mut rows = statement.query(params![id.as_str(), uid])?;
        let row = rows.next()?.ok_or_else(|| {
            ApiError::new(ErrorCode::SandboxNotFound, "sandbox identity not found")
        })?;
        record::decode(row)
    }
    pub fn list(&self, uid: u32, after: Option<&SandboxId>, limit: u16) -> Result<Vec<Sandbox>> {
        if limit == 0 || limit > 256 {
            return Err(
                ApiError::new(ErrorCode::InvalidRequest, "list limit must be 1..256").into(),
            );
        }
        let mut stmt = self.connection.prepare("SELECT id,generation,lease_expires_at,record FROM sandboxes WHERE owner_uid=?1 AND id>?2 AND record IS NOT NULL ORDER BY id LIMIT ?3")?;
        let mut rows = stmt.query(params![uid, after.map_or("", SandboxId::as_str), limit])?;
        let mut result = Vec::new();
        let mut size = 0usize;
        while let Some(row) = rows.next()? {
            size += row.get_ref(3)?.as_blob().map_err(|_| Error::State)?.len();
            if size > 786_432 {
                break;
            }
            result.push(record::decode(row)?);
        }
        Ok(result)
    }
    pub fn events(&self, uid: u32, from_sequence: u64, limit: u16) -> Result<EventPage> {
        events::page(&self.connection, uid, from_sequence, limit)
    }
    /// Records expiry once. It never renews a lease or fabricates a successful VM stop.
    pub fn expire_leases(&mut self, now_ms: u64) -> Result<usize> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if now_ms > i64::MAX as u64 {
            return Err(Error::State);
        }
        let mut stmt = tx.prepare("SELECT id,generation,lease_expires_at,record,owner_uid FROM sandboxes WHERE record IS NOT NULL AND lease_expired=0 AND lease_expires_at<=?1 ORDER BY lease_expires_at LIMIT 256")?;
        let mut rows = stmt.query([now_ms])?;
        let mut expired = Vec::new();
        while let Some(row) = rows.next()? {
            let uid: u32 = row.get(4)?;
            let record = record::decode(row)?;
            if now_ms >= record.lease.expires_at_unix_ms {
                expired.push((record.id.clone(), uid, record));
            }
        }
        drop(rows);
        drop(stmt);
        for (id, uid, record) in &expired {
            tx.execute(
                "UPDATE sandboxes SET lease_expired=1 WHERE id=?1",
                [id.as_str()],
            )?;
            events::append(
                &tx,
                *uid,
                record,
                sandboxd_protocol::EventKind::LeaseExpired,
                now_ms,
            )?;
        }
        events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(expired.len())
    }
}
