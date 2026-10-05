//! Owner-scoped durable backing preparation intents and publication receipts.
use super::Store;
use crate::error::{Error, Result};
use rusqlite::{OptionalExtension, params};
use sandboxd_protocol::{OperationId, Response, VolumeBacking, VolumeCommand, VolumeInfo};
use sha2::{Digest, Sha256};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DynamicVolumeRecord {
    pub owner_uid: u32,
    pub info: VolumeInfo,
    pub device: u64,
    pub inode: u64,
    pub published: bool,
}
impl Store {
    /// Session allocations are removed only by verified cleanup, so an
    /// unresolved old process remains a fence even after daemon locks vanish.
    pub(crate) fn validate_dynamic_volume_attachment(
        &self,
        uid: u32,
        volumes: &[sandboxd_protocol::Volume],
    ) -> Result<()> {
        for volume in volumes {
            if let Some(backing) = &volume.backing {
                let unavailable:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM volume_releases WHERE owner_uid=?1 AND backing_id=?2 AND pending=1) OR EXISTS(SELECT 1 FROM dynamic_volumes WHERE owner_uid=?1 AND id=?2 AND released=1)",params![uid,backing.id],|r|r.get(0))?;
                if unavailable {
                    return Err(Error::Locked);
                }
            }
        }
        let mut query = self.connection.prepare("SELECT record FROM sessions")?;
        for bytes in query.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            let intent: super::LaunchIntent = sandboxd_protocol::codec::decode_body(&bytes?)?;
            for volume in volumes {
                if let Some(backing) = &volume.backing {
                    if intent.pins.volumes.iter().any(|pin| {
                        pin.owner_uid == Some(uid)
                            && pin.backing.as_ref() == Some(backing)
                            && (!pin.read_only || !volume.read_only)
                    }) {
                        return Err(Error::Locked);
                    }
                }
            }
        }
        Ok(())
    }
    /// Only retained, exact session pins authorize a backing's VMM owner.
    pub(crate) fn dynamic_volume_session_owners(
        &self,
        record: &DynamicVolumeRecord,
    ) -> Result<Vec<(u32, u32)>> {
        let mut query = self
            .connection
            .prepare(&format!("SELECT {} FROM sessions", super::session::COLUMNS))?;
        let mut rows = query.query([])?;
        let mut owners = Vec::new();
        while let Some(row) = rows.next()? {
            let intent = super::session::decode(row)?;
            if intent.pins.volumes.iter().any(|pin| {
                pin.owner_uid == Some(record.owner_uid)
                    && pin.backing.as_ref() == Some(&record.info.backing)
                    && pin.device == record.device
                    && pin.inode == record.inode
                    && pin.size_bytes == record.info.size_bytes
                    && !pin.read_only
                    && !pin.catalog_read_only
            }) {
                owners.push((intent.uid, intent.gid));
            }
        }
        Ok(owners)
    }
    pub(crate) fn admit_volume(
        &self,
        uid: u32,
        operation: &OperationId,
        sequence: u64,
        command: &VolumeCommand,
    ) -> Result<(String, Option<Response>)> {
        if !command.validate() || !operation.matches_sequence(sequence) {
            return Err(Error::Path);
        }
        let digest = Sha256::digest(sandboxd_protocol::codec::encode_body(&(
            "dynamic_volume",
            command,
        ))?)
        .to_vec();
        let saved:Option<(String,Vec<u8>,Vec<u8>,bool)>=self.connection.query_row("SELECT id,request_digest,response,pending FROM dynamic_volumes WHERE owner_uid=?1 AND operation_id=?2",params![uid,operation.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((id, old, response, pending)) = saved {
            if old != digest {
                return Err(Error::State);
            };
            return Ok((
                id,
                if pending {
                    None
                } else {
                    Some(sandboxd_protocol::codec::decode_body(&response)?)
                },
            ));
        }
        let tx = self.connection.unchecked_transaction()?;
        Self::reserve_operation_sequence(&tx, uid, sequence)?;
        let retained: u32 =
            tx.query_row("SELECT count(*) FROM dynamic_volumes", [], |r| r.get(0))?;
        if retained >= self.quotas.max_operation_receipts {
            tx.execute("DELETE FROM dynamic_volumes WHERE released=1", [])?;
        }
        let (count, total): (u32, u64) = tx.query_row(
            "SELECT count(*),coalesce(sum(CASE WHEN released=0 THEN size_bytes ELSE 0 END),0) FROM dynamic_volumes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if count >= self.quotas.max_operation_receipts
            || total
                .checked_add(command.size_bytes())
                .is_none_or(|n| n > u64::from(self.quotas.max_state_disk_mib) * 1048576)
        {
            return Err(Error::Path);
        }
        let id = hex::encode(Sha256::digest(format!(
            "volume/v1\0{uid}\0{}",
            operation.as_str()
        )));
        tx.execute("INSERT INTO dynamic_volumes(owner_uid,id,operation_id,request_digest,size_bytes,writable,response,pending) VALUES(?1,?2,?3,?4,?5,?6,?7,1)",params![uid,id,operation.as_str(),digest,command.size_bytes(),command.writable(),sandboxd_protocol::codec::encode_body(&Response::VolumePending{operation:operation.clone()})?])?;
        tx.commit()?;
        Ok((id, None))
    }
    pub(crate) fn prepare_volume(&self, record: &DynamicVolumeRecord) -> Result<()> {
        if record.published
            || !record.info.backing.validate()
            || record.info.backing.generation != 1
            || record.device == 0
            || record.inode == 0
            || record.info.initial_sha256.len() != 64
            || !record
                .info
                .initial_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Path);
        }
        let n=self.connection.execute("UPDATE dynamic_volumes SET record=?3 WHERE owner_uid=?1 AND id=?2 AND pending=1 AND size_bytes=?4 AND writable=?5",params![record.owner_uid,record.info.backing.id,serde_json::to_vec(record).map_err(|_|Error::State)?,record.info.size_bytes,record.info.writable])?;
        if n != 1 {
            return Err(Error::State);
        };
        Ok(())
    }
    pub(crate) fn publish_volume(&self, record: &DynamicVolumeRecord) -> Result<()> {
        if !record.published {
            return Err(Error::Path);
        }
        let previous = self
            .volume_preparation(record.owner_uid, &record.info.backing.id)?
            .ok_or(Error::State)?;
        if previous.published
            || previous.info != record.info
            || previous.device != record.device
            || previous.inode != record.inode
        {
            return Err(Error::State);
        }
        let n=self.connection.execute("UPDATE dynamic_volumes SET record=?3,response=?4,pending=0 WHERE owner_uid=?1 AND id=?2 AND pending=1",params![record.owner_uid,record.info.backing.id,serde_json::to_vec(record).map_err(|_|Error::State)?,sandboxd_protocol::codec::encode_body(&Response::Volume(record.info.clone()))?])?;
        if n != 1 {
            return Err(Error::State);
        };
        Ok(())
    }
    pub(crate) fn volume_preparation(
        &self,
        uid: u32,
        id: &str,
    ) -> Result<Option<DynamicVolumeRecord>> {
        let bytes: Option<Option<Vec<u8>>> = self
            .connection
            .query_row(
                "SELECT record FROM dynamic_volumes WHERE owner_uid=?1 AND id=?2",
                params![uid, id],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .flatten()
            .map(|b| serde_json::from_slice(&b).map_err(|_| Error::State))
            .transpose()
    }
    pub(crate) fn dynamic_volume(
        &self,
        uid: u32,
        backing: &VolumeBacking,
    ) -> Result<Option<DynamicVolumeRecord>> {
        if !backing.validate() {
            return Err(Error::Path);
        }
        let record: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT record FROM dynamic_volumes WHERE owner_uid=?1 AND id=?2 AND pending=0 AND released=0",
                params![uid, backing.id],
                |r| r.get(0),
            )
            .optional()?;
        let value: Option<DynamicVolumeRecord> = record
            .map(|b| serde_json::from_slice(&b).map_err(|_| Error::State))
            .transpose()?;
        Ok(value.filter(|r| r.info.backing.generation == backing.generation))
    }
    pub(crate) fn dynamic_volumes(&self) -> Result<Vec<DynamicVolumeRecord>> {
        let mut q = self
            .connection
            .prepare("SELECT record FROM dynamic_volumes WHERE pending=0 AND released=0")?;
        q.query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .map(|v| serde_json::from_slice(&v?).map_err(|_| Error::State))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LeaseConfig, Quotas};
    use std::os::unix::fs::PermissionsExt;
    fn open(path: &std::path::Path) -> Store {
        Store::open(
            path,
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
    }
    #[test]
    fn durable_volume_receipt_binds_owner_command_and_prepared_identity() {
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = temp.path().canonicalize().unwrap();
        let operation = OperationId::with_sequence(1, "volume").unwrap();
        let command = VolumeCommand::Allocate {
            size_bytes: 1 << 20,
            writable: true,
        };
        let mut store = open(&path);
        let (id, replay) = store.admit_volume(1000, &operation, 1, &command).unwrap();
        assert!(replay.is_none());
        let pending = store.inspect_operation(1000, &operation, 1).unwrap();
        assert_eq!(
            pending.state,
            sandboxd_protocol::OperationReceiptState::Pending
        );
        assert_eq!(
            pending.response,
            Some(Box::new(Response::VolumePending {
                operation: operation.clone()
            }))
        );
        let info = VolumeInfo {
            backing: VolumeBacking { id, generation: 1 },
            size_bytes: 1 << 20,
            writable: true,
            initial_sha256: "a".repeat(64),
        };
        let mut record = DynamicVolumeRecord {
            owner_uid: 1000,
            info: info.clone(),
            device: 1,
            inode: 2,
            published: false,
        };
        store.prepare_volume(&record).unwrap();
        drop(store);
        let mut store = open(&path);
        assert!(
            store
                .admit_volume(1000, &operation, 1, &command)
                .unwrap()
                .1
                .is_none()
        );
        assert!(
            store
                .admit_volume(
                    1000,
                    &operation,
                    1,
                    &VolumeCommand::Allocate {
                        size_bytes: 2 << 20,
                        writable: true
                    }
                )
                .is_err()
        );
        record.published = true;
        let mut swapped = record.clone();
        swapped.inode = 3;
        assert!(store.publish_volume(&swapped).is_err());
        store.publish_volume(&record).unwrap();
        assert!(store.dynamic_volume(1001, &info.backing).unwrap().is_none());
        let mut stale = info.backing.clone();
        stale.generation = 2;
        assert!(store.dynamic_volume(1000, &stale).unwrap().is_none());
        assert_eq!(
            store.admit_volume(1000, &operation, 1, &command).unwrap().1,
            Some(Response::Volume(info.clone()))
        );
        assert_eq!(
            store.inspect_operation(1000, &operation, 1).unwrap().state,
            sandboxd_protocol::OperationReceiptState::Complete
        );
        drop(store);
        assert_eq!(open(&path).dynamic_volumes().unwrap()[0].info, info);
    }
    #[test]
    fn unresolved_session_allocation_fences_backing_after_restart() {
        use crate::config::IdentityPools;
        use sandboxd_protocol::*;
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = temp.path().canonicalize().unwrap();
        let mut store = open(&path);
        let backing = VolumeBacking {
            id: "b".repeat(64),
            generation: 1,
        };
        let volume = Volume {
            id: VolumeId::new("cache").unwrap(),
            catalog_key: String::new(),
            backing: Some(backing.clone()),
            read_only: false,
            guest_mount_point: "/cache".into(),
            filesystem: "ext4".into(),
            rate_limiter: None,
        };
        let spec = SandboxSpec {
            architecture: Architecture::Aarch64,
            image: ImageDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            kernel_profile: "reference".into(),
            runtime_profile: "verified".into(),
            persistence: Persistence::FilesystemPersistent,
            resources: Resources {
                vcpus: 1,
                memory_mib: 128,
                state_disk_mib: 16,
                host_memory_max_bytes: 268435456,
                cpu_quota_us: 100000,
                cpu_period_us: 100000,
                cpu_profile: None,
                cpuset: None,
                state_rate_limiter: None,
            },
            network: NetworkMode::None,
            volumes: vec![volume.clone()],
            environment: std::collections::BTreeMap::new(),
            lifetimes: Lifetimes {
                sandbox_ttl_seconds: 3600,
                session_max_seconds: 1800,
                idle_seconds: 300,
            },
        };
        let sandbox = SandboxId::new("volume-owner").unwrap();
        let response = store
            .mutate(
                1000,
                &OperationId::new("create-volume-owner").unwrap(),
                &Mutation::Create {
                    sandbox: sandbox.clone(),
                    expected_generation: None,
                    spec: Box::new(spec),
                    lease_seconds: 60,
                },
                1,
            )
            .unwrap();
        let Response::Sandbox(record) = response else {
            panic!("sandbox")
        };
        let pins = super::super::SessionPins {
            architecture: record.spec.architecture,
            runtime_profile: record.spec.runtime_profile.clone(),
            runtime_version: "1.17.0".into(),
            firecracker_sha256: "1".repeat(64),
            jailer_sha256: "2".repeat(64),
            kernel_profile: record.spec.kernel_profile.clone(),
            kernel_sha256: "3".repeat(64),
            initramfs_sha256: "4".repeat(64),
            base_image: record.spec.image.clone(),
            volumes: vec![super::super::VolumePin {
                volume_id: volume.id.clone(),
                catalog_key: String::new(),
                backing: Some(backing),
                owner_uid: Some(1000),
                device: 1,
                inode: 2,
                size_bytes: 1 << 20,
                catalog_read_only: false,
                read_only: false,
            }],
        };
        let prepared = store
            .prepare_session(
                1000,
                &OperationId::new("prepare-volume-owner").unwrap(),
                &Fence {
                    sandbox,
                    generation: record.generation,
                    session_generation: None,
                    lease: record.lease.id.clone(),
                },
                super::super::SessionPreparation {
                    pins: &pins,
                    pools: &IdentityPools {
                        uid_first: 200000,
                        uid_last: 200001,
                        gid_first: 300000,
                        gid_last: 300001,
                        cid_first: 3,
                        cid_last: 4,
                    },
                    host_boot_id: "00000000-0000-4000-8000-000000000001",
                    now_ms: 2,
                },
            )
            .unwrap();
        let key = prepared.intent.unwrap().key;
        drop(store);
        let mut store = open(&path);
        assert!(
            store
                .validate_dynamic_volume_attachment(1000, std::slice::from_ref(&volume))
                .is_err()
        );
        let mut reader = volume.clone();
        reader.read_only = true;
        assert!(
            store
                .validate_dynamic_volume_attachment(1000, &[reader])
                .is_err()
        );
        assert!(
            store
                .record_session_stopped(
                    1000,
                    &key,
                    super::super::CleanupProof::incomplete(key.clone()),
                    3
                )
                .is_err()
        );
        assert!(
            store
                .validate_dynamic_volume_attachment(1000, std::slice::from_ref(&volume))
                .is_err()
        );
    }
}
