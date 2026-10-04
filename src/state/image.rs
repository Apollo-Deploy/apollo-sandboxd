use crate::error::{Error, Result};
use rusqlite::{OptionalExtension, params};
use sha2::Digest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedImageRecord {
    pub digest: String,
    pub architecture: String,
    pub rootfs_path: String,
    pub rootfs_sha256: String,
    pub rootfs_size: u64,
    pub rootfs_device: u64,
    pub rootfs_inode: u64,
    pub formatter_sha256: String,
    pub created_at: u64,
    pub layers: u32,
    pub config_json: Option<Vec<u8>>,
    pub published: bool,
}

impl super::store::Store {
    pub(crate) fn image_operation_resolution(
        &self,
        uid: u32,
        operation: &sandboxd_protocol::OperationId,
    ) -> Result<Option<String>> {
        Ok(self.connection.query_row(
            "SELECT resolved_digest FROM image_operations WHERE owner_uid=?1 AND operation_id=?2",
            params![uid, operation.as_str()],
            |row| row.get(0),
        ).optional()?.flatten())
    }

    pub(crate) fn record_image_resolution(
        &self,
        uid: u32,
        operation: &sandboxd_protocol::OperationId,
        digest: &str,
    ) -> Result<()> {
        if !digest.starts_with("sha256:") || digest.len() != 71 {
            return Err(Error::State);
        }
        let changed = self.connection.execute(
            "UPDATE image_operations SET resolved_digest=?1 WHERE owner_uid=?2 AND operation_id=?3 AND pending=1",
            params![digest, uid, operation.as_str()],
        )?;
        if changed != 1 {
            return Err(Error::State);
        }
        Ok(())
    }

    pub(crate) fn record_prepared_image(&self, record: &PreparedImageRecord) -> Result<()> {
        if !record.digest.starts_with("sha256:")
            || record.rootfs_sha256.len() != 64
            || record.formatter_sha256.len() != 64
            || record.rootfs_size == 0
        {
            return Err(Error::State);
        }
        if let Some(existing) = self.prepared_image(&record.digest)? {
            if existing.architecture != record.architecture
                || existing.rootfs_sha256 != record.rootfs_sha256
                || existing.rootfs_size != record.rootfs_size
                || existing.rootfs_device != record.rootfs_device
                || existing.rootfs_inode != record.rootfs_inode
                || existing.formatter_sha256 != record.formatter_sha256
                || existing.layers != record.layers
                || existing.config_json != record.config_json
            {
                return Err(Error::State);
            }
            return Ok(());
        }
        self.connection.execute(
            "INSERT INTO prepared_images(digest,architecture,rootfs_path,rootfs_sha256,rootfs_size,rootfs_device,rootfs_inode,formatter_sha256,created_at,layers,config_json,published)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0)
             ON CONFLICT(digest) DO NOTHING",
            params![record.digest, record.architecture, record.rootfs_path, record.rootfs_sha256, record.rootfs_size, record.rootfs_device, record.rootfs_inode, record.formatter_sha256, record.created_at, record.layers, record.config_json],
        )?;
        Ok(())
    }

    pub(crate) fn prepared_image(&self, digest: &str) -> Result<Option<PreparedImageRecord>> {
        Ok(self.connection.query_row(
            "SELECT digest,architecture,rootfs_path,rootfs_sha256,rootfs_size,rootfs_device,rootfs_inode,formatter_sha256,created_at,layers,config_json,published FROM prepared_images WHERE digest=?1",
            [digest],
            |row| Ok(PreparedImageRecord { digest: row.get(0)?, architecture: row.get(1)?, rootfs_path: row.get(2)?, rootfs_sha256: row.get(3)?, rootfs_size: row.get(4)?, rootfs_device: row.get(5)?, rootfs_inode: row.get(6)?, formatter_sha256: row.get(7)?, created_at: row.get(8)?, layers: row.get(9)?, config_json: row.get(10)?, published: row.get::<_, i64>(11)? != 0 }),
        ).optional()?)
    }

    pub(crate) fn publish_prepared_image(&self, digest: &str) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE prepared_images SET published=1 WHERE digest=?1",
            [digest],
        )?;
        if changed != 1 {
            return Err(Error::State);
        }
        Ok(())
    }

    pub(crate) fn retire_unpublished_image(&self, digest: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM prepared_images WHERE digest=?1 AND published=0",
            [digest],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LeaseConfig, Quotas};
    use sandboxd_protocol::{ImageCommand, OperationId, Response};
    use std::os::unix::fs::PermissionsExt;

    fn store(path: &std::path::Path) -> super::super::store::Store {
        let path = path.canonicalize().expect("canonical state path");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("private state path");
        super::super::store::Store::open(
            &path,
            Quotas {
                max_active_sandboxes: 8,
                max_booting_sandboxes: 4,
                max_sandbox_identities: 8,
                max_operation_receipts: 2,
                max_vcpus: 4,
                max_memory_mib: 512,
                max_state_disk_mib: 128,
            },
            LeaseConfig { max_seconds: 60 },
            8,
        )
        .expect("store")
    }

    fn command(reference: &str) -> ImageCommand {
        ImageCommand::Pull {
            reference: reference.into(),
            username: None,
            password: None,
        }
    }

    #[test]
    fn image_receipt_replays_and_conflicts_after_reopen() {
        let directory = tempfile::tempdir().expect("directory");
        let operation = OperationId::with_sequence(1, "image").expect("operation");
        let request = command("registry.example/app:latest");
        let (digest, pending) = store(directory.path())
            .admit_image_operation(1000, &operation, 1, &request)
            .expect("admit");
        assert!(pending.is_none());
        let reopened = store(directory.path());
        let (_, retry) = reopened
            .admit_image_operation(1000, &operation, 1, &request)
            .expect("pending retry");
        assert!(
            retry.is_none(),
            "pending admission must be retried, not replayed as success"
        );
        let terminal = Response::Error(sandboxd_protocol::ApiError::new(
            sandboxd_protocol::ErrorCode::StorageFailed,
            "fixture failure",
        ));
        reopened
            .complete_image_operation(1000, &operation, digest, &terminal)
            .expect("complete");
        let (_, replay) = reopened
            .admit_image_operation(1000, &operation, 1, &request)
            .expect("terminal replay");
        assert_eq!(replay, Some(terminal));
        let conflict = reopened.admit_image_operation(
            1000,
            &operation,
            1,
            &command("registry.example/app:other"),
        );
        assert!(conflict.is_err());
        assert_eq!(digest.len(), 32);
    }

    fn prepared(digest: &str, inode: u64) -> PreparedImageRecord {
        PreparedImageRecord {
            digest: digest.into(),
            architecture: "x86_64".into(),
            rootfs_path: "/var/lib/apollo-sandboxd/images/rootfs.ext4".into(),
            rootfs_sha256: "a".repeat(64),
            rootfs_size: 4096,
            rootfs_device: 1,
            rootfs_inode: inode,
            formatter_sha256: "b".repeat(64),
            created_at: 1,
            layers: 2,
            config_json: Some(br#"{"Env":["A=B"]}"#.to_vec()),
            published: false,
        }
    }

    #[test]
    fn prepared_image_publication_is_hidden_until_published_and_rejects_replacement() {
        let directory = tempfile::tempdir().expect("directory");
        let store = store(directory.path());
        let digest = "sha256:".to_string() + &"c".repeat(64);
        let record = prepared(&digest, 10);
        store.record_prepared_image(&record).expect("reserve");
        assert!(!store.prepared_image(&digest).unwrap().unwrap().published);
        assert!(store.list_prepared_images(None, 16).unwrap().is_empty());

        store.publish_prepared_image(&digest).expect("publish");
        assert_eq!(store.list_prepared_images(None, 16).unwrap().len(), 1);
        let mut replaced = record.clone();
        replaced.rootfs_inode = 11;
        assert!(store.record_prepared_image(&replaced).is_err());
    }

    #[test]
    fn unpublished_reservation_can_be_retired_when_artifact_is_absent() {
        let directory = tempfile::tempdir().expect("directory");
        let store = store(directory.path());
        let digest = "sha256:".to_string() + &"d".repeat(64);
        store
            .record_prepared_image(&prepared(&digest, 12))
            .expect("reserve");
        store.retire_unpublished_image(&digest).expect("retire");
        assert!(store.prepared_image(&digest).unwrap().is_none());
    }

    #[test]
    fn pending_receipts_are_protected_and_retired_receipts_keep_watermark() {
        let directory = tempfile::tempdir().expect("directory");
        let store = store(directory.path());
        let op1 = OperationId::with_sequence(1, "image-1").unwrap();
        let op2 = OperationId::with_sequence(2, "image-2").unwrap();
        let op3 = OperationId::with_sequence(3, "image-3").unwrap();
        let request = command("registry.example/app:latest");
        let (digest, _) = store
            .admit_image_operation(1000, &op1, 1, &request)
            .unwrap();
        store
            .complete_image_operation(
                1000,
                &op1,
                digest,
                &Response::Error(sandboxd_protocol::ApiError::new(
                    sandboxd_protocol::ErrorCode::StorageFailed,
                    "terminal",
                )),
            )
            .unwrap();
        store
            .admit_image_operation(1000, &op2, 2, &request)
            .unwrap();
        store
            .admit_image_operation(1000, &op3, 3, &request)
            .unwrap();
        let old_retry = store.admit_image_operation(1000, &op1, 1, &request);
        assert!(
            old_retry.is_err(),
            "retired operation IDs must remain fenced"
        );
        let pending_retry = store.admit_image_operation(1000, &op2, 5, &request);
        assert!(
            pending_retry.is_ok(),
            "pending receipt remains retryable/protected"
        );
    }
}

impl super::store::Store {
    pub(crate) fn admit_image_operation(
        &self,
        uid: u32,
        operation: &sandboxd_protocol::OperationId,
        sequence: u64,
        command: &sandboxd_protocol::ImageCommand,
    ) -> Result<([u8; 32], Option<sandboxd_protocol::Response>)> {
        use sha2::{Digest, Sha256};
        let body = sandboxd_protocol::codec::encode_body(&(
            "image_operation",
            command_name(command),
            image_reference(command),
            image_username(command),
            self.image_secret_digest(command),
        ))?;
        let digest: [u8; 32] = Sha256::digest(body).into();
        let existing: Option<(Vec<u8>, Vec<u8>)> = self.connection.query_row(
            "SELECT request_digest,response FROM image_operations WHERE owner_uid=?1 AND operation_id=?2",
            rusqlite::params![uid, operation.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        if let Some((saved, response)) = existing {
            if saved.as_slice() != digest {
                return Err(sandboxd_protocol::ApiError::new(
                    sandboxd_protocol::ErrorCode::OperationConflict,
                    "image operation ID reused with a different request",
                )
                .into());
            }
            let response: sandboxd_protocol::Response =
                sandboxd_protocol::codec::decode_body(&response)?;
            // A pending receipt is a durable admission marker, not a terminal
            // result. Retrying the exact request after a daemon crash reruns
            // the idempotent content-addressed import and closes the receipt.
            if matches!(response, sandboxd_protocol::Response::ImagePending { .. }) {
                return Ok((digest, None));
            }
            return Ok((digest, Some(response)));
        }
        let tx = self.connection.unchecked_transaction()?;
        super::store::Store::reserve_operation_sequence(&tx, uid, sequence)?;
        let count: u32 = tx.query_row("SELECT COUNT(*) FROM image_operations", [], |row| {
            row.get(0)
        })?;
        if count >= self.quotas.max_operation_receipts {
            let removed = tx.execute(
                "DELETE FROM image_operations WHERE rowid=(SELECT rowid FROM image_operations WHERE pending=0 ORDER BY rowid LIMIT 1)",
                [],
            )?;
            if removed == 0 {
                return Err(sandboxd_protocol::ApiError::new(
                    sandboxd_protocol::ErrorCode::QuotaExceeded,
                    "image operation receipt capacity is exhausted",
                )
                .into());
            }
        }
        let pending = sandboxd_protocol::Response::ImagePending {
            operation: operation.clone(),
        };
        tx.execute(
            "INSERT INTO image_operations(owner_uid,operation_id,request_digest,response,pending) VALUES(?1,?2,?3,?4,1)",
            rusqlite::params![uid, operation.as_str(), digest.as_slice(), sandboxd_protocol::codec::encode_body(&pending)?],
        )?;
        tx.commit()?;
        Ok((digest, None))
    }

    pub(crate) fn complete_image_operation(
        &self,
        uid: u32,
        operation: &sandboxd_protocol::OperationId,
        digest: [u8; 32],
        response: &sandboxd_protocol::Response,
    ) -> Result<()> {
        self.connection.execute(
            "UPDATE image_operations SET response=?1,pending=0 WHERE owner_uid=?2 AND operation_id=?3 AND request_digest=?4",
            rusqlite::params![sandboxd_protocol::codec::encode_body(response)?, uid, operation.as_str(), digest.as_slice()],
        )?;
        Ok(())
    }
}

fn command_name(command: &sandboxd_protocol::ImageCommand) -> &'static str {
    match command {
        sandboxd_protocol::ImageCommand::Pull { .. } => "pull",
        sandboxd_protocol::ImageCommand::ImportLayout { .. } => "import_layout",
    }
}
fn image_reference(command: &sandboxd_protocol::ImageCommand) -> Option<&str> {
    match command {
        sandboxd_protocol::ImageCommand::Pull { reference, .. } => Some(reference),
        sandboxd_protocol::ImageCommand::ImportLayout { relative_layout } => Some(relative_layout),
    }
}
fn image_username(command: &sandboxd_protocol::ImageCommand) -> Option<&str> {
    match command {
        sandboxd_protocol::ImageCommand::Pull { username, .. } => username.as_deref(),
        sandboxd_protocol::ImageCommand::ImportLayout { .. } => None,
    }
}
impl super::store::Store {
    fn image_secret_digest(&self, command: &sandboxd_protocol::ImageCommand) -> Option<[u8; 32]> {
        match command {
            sandboxd_protocol::ImageCommand::Pull {
                password: Some(secret),
                ..
            } => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(b"apollo-sandboxd image request v1");
                hasher.update(self.operation_key);
                hasher.update(secret.0.as_bytes());
                Some(hasher.finalize().into())
            }
            _ => None,
        }
    }
}

impl super::store::Store {
    pub(crate) fn list_prepared_images(
        &self,
        after: Option<&str>,
        limit: u16,
    ) -> Result<Vec<PreparedImageRecord>> {
        if limit == 0 || limit > 256 {
            return Err(Error::Path);
        }
        let mut statement = self.connection.prepare(
            "SELECT digest,architecture,rootfs_path,rootfs_sha256,rootfs_size,rootfs_device,rootfs_inode,formatter_sha256,created_at,layers,config_json,published FROM prepared_images WHERE published=1 AND (?1 IS NULL OR digest>?1) ORDER BY digest LIMIT ?2"
        )?;
        let rows = statement.query_map(rusqlite::params![after, limit], |row| {
            Ok(PreparedImageRecord {
                digest: row.get(0)?,
                architecture: row.get(1)?,
                rootfs_path: row.get(2)?,
                rootfs_sha256: row.get(3)?,
                rootfs_size: row.get(4)?,
                rootfs_device: row.get(5)?,
                rootfs_inode: row.get(6)?,
                formatter_sha256: row.get(7)?,
                created_at: row.get(8)?,
                layers: row.get(9)?,
                config_json: row.get(10)?,
                published: row.get::<_, i64>(11)? != 0,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}
