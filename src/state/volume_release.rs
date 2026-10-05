//! Backing release has its own sequenced intent; no caller death boolean exists.
use super::{DynamicVolumeRecord, Store};
use crate::error::{Error, Result};
use rusqlite::{OptionalExtension, params};
use sandboxd_protocol::{OperationId, Response, VolumeBacking};
use sha2::{Digest, Sha256};
impl Store {
    pub(crate) fn admit_volume_release(
        &self,
        uid: u32,
        operation: &OperationId,
        sequence: u64,
        backing: &VolumeBacking,
    ) -> Result<(Option<DynamicVolumeRecord>, Option<Response>)> {
        if !backing.validate() || !operation.matches_sequence(sequence) {
            return Err(Error::Path);
        }
        let digest = Sha256::digest(sandboxd_protocol::codec::encode_body(&(
            "dynamic_volume_release",
            backing,
        ))?)
        .to_vec();
        let saved:Option<(Vec<u8>,Vec<u8>,bool)>=self.connection.query_row("SELECT request_digest,response,pending FROM volume_releases WHERE owner_uid=?1 AND operation_id=?2",params![uid,operation.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((old, response, pending)) = saved {
            if old != digest {
                return Err(Error::State);
            }
            if !pending {
                return Ok((
                    None,
                    Some(sandboxd_protocol::codec::decode_body(&response)?),
                ));
            }
            self.ensure_volume_unpinned(uid, backing)?;
            return Ok((
                Some(self.dynamic_volume(uid, backing)?.ok_or(Error::State)?),
                None,
            ));
        }
        let record = self.dynamic_volume(uid, backing)?.ok_or(Error::State)?;
        self.ensure_volume_unpinned(uid, backing)?;
        let tx = self.connection.unchecked_transaction()?;
        Self::reserve_operation_sequence(&tx, uid, sequence)?;
        let retained: u32 =
            tx.query_row("SELECT count(*) FROM volume_releases", [], |r| r.get(0))?;
        if retained >= self.quotas.max_operation_receipts {
            tx.execute("DELETE FROM volume_releases WHERE pending=0", [])?;
        }
        let pending: u32 =
            tx.query_row("SELECT count(*) FROM volume_releases", [], |r| r.get(0))?;
        if pending >= self.quotas.max_operation_receipts {
            return Err(Error::Locked);
        }
        tx.execute("INSERT INTO volume_releases(owner_uid,operation_id,backing_id,request_digest,response,pending) VALUES(?1,?2,?3,?4,?5,1)",params![uid,operation.as_str(),backing.id,digest,sandboxd_protocol::codec::encode_body(&Response::VolumePending{operation:operation.clone()})?])?;
        tx.commit()?;
        Ok((Some(record), None))
    }
    fn ensure_volume_unpinned(&self, uid: u32, backing: &VolumeBacking) -> Result<()> {
        let mut query = self.connection.prepare("SELECT record FROM sessions")?;
        for bytes in query.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            let intent: super::LaunchIntent = sandboxd_protocol::codec::decode_body(&bytes?)?;
            if intent
                .pins
                .volumes
                .iter()
                .any(|p| p.owner_uid == Some(uid) && p.backing.as_ref() == Some(backing))
            {
                return Err(Error::Locked);
            }
        }
        Ok(())
    }
    pub(crate) fn complete_volume_release(
        &self,
        uid: u32,
        operation: &OperationId,
        backing: &VolumeBacking,
    ) -> Result<()> {
        let tx = self.connection.unchecked_transaction()?;
        let n=tx.execute("UPDATE volume_releases SET response=?4,pending=0 WHERE owner_uid=?1 AND operation_id=?2 AND backing_id=?3 AND pending=1",params![uid,operation.as_str(),backing.id,sandboxd_protocol::codec::encode_body(&Response::VolumeReleased{backing:backing.clone()})?])?;
        if n != 1 {
            return Err(Error::State);
        }
        let n = tx.execute(
            "UPDATE dynamic_volumes SET released=1 WHERE owner_uid=?1 AND id=?2 AND released=0",
            params![uid, backing.id],
        )?;
        if n != 1 {
            return Err(Error::State);
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{LeaseConfig, Quotas},
        storage::dynamic_volume,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    #[test]
    fn release_preserves_locked_backing_and_reconciles_unlink_after_restart() {
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let root = temp.path().canonicalize().unwrap();
        let open = || {
            Store::open(
                &root,
                Quotas {
                    max_active_sandboxes: 4,
                    max_booting_sandboxes: 2,
                    max_sandbox_identities: 8,
                    max_operation_receipts: 8,
                    max_vcpus: 4,
                    max_memory_mib: 1024,
                    max_state_disk_mib: 16,
                },
                LeaseConfig { max_seconds: 60 },
                8,
            )
            .unwrap()
        };
        let mut store = open();
        let allocate = OperationId::with_sequence(1, "allocate").unwrap();
        let command = sandboxd_protocol::VolumeCommand::Allocate {
            size_bytes: 1 << 20,
            writable: true,
        };
        let (id, _) = store.admit_volume(1000, &allocate, 1, &command).unwrap();
        let dir = dynamic_volume::directory(&root).unwrap();
        let name = format!("{id}.img");
        let file = dir.create_file(&name).unwrap();
        file.set_len(1 << 20).unwrap();
        let metadata = file.metadata().unwrap();
        let mut record = DynamicVolumeRecord {
            owner_uid: 1000,
            info: sandboxd_protocol::VolumeInfo {
                backing: VolumeBacking { id, generation: 1 },
                size_bytes: 1 << 20,
                writable: true,
                initial_sha256: "a".repeat(64),
            },
            device: metadata.dev(),
            inode: metadata.ino(),
            published: false,
        };
        store.prepare_volume(&record).unwrap();
        record.published = true;
        store.publish_volume(&record).unwrap();
        let release = OperationId::with_sequence(2, "release").unwrap();
        assert!(
            store
                .admit_volume_release(1001, &release, 2, &record.info.backing)
                .is_err()
        );
        let (admitted, _) = store
            .admit_volume_release(1000, &release, 2, &record.info.backing)
            .unwrap();
        assert!(admitted.is_some());
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        assert!(dynamic_volume::release(&root, &record).is_err());
        assert!(dir.open_file(&name, false).is_ok());
        drop(file);
        dynamic_volume::release(&root, &record).unwrap();
        assert!(dir.open_file(&name, false).is_err());
        drop(store);
        // Crash after durable unlink but before receipt settlement: exact retry
        // reconciles absence, and no fresh file/identity can be deleted accidentally.
        store = open();
        let (admitted, replay) = store
            .admit_volume_release(1000, &release, 2, &record.info.backing)
            .unwrap();
        assert!(replay.is_none());
        dynamic_volume::release(&root, &admitted.unwrap()).unwrap();
        store
            .complete_volume_release(1000, &release, &record.info.backing)
            .unwrap();
        assert!(
            store
                .dynamic_volume(1000, &record.info.backing)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .admit_volume_release(1000, &release, 2, &record.info.backing)
                .unwrap()
                .1,
            Some(Response::VolumeReleased {
                backing: record.info.backing.clone()
            })
        );
        assert_eq!(
            store.inspect_operation(1000, &release, 2).unwrap().state,
            sandboxd_protocol::OperationReceiptState::Complete
        );
    }
}
