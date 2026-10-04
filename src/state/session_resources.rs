//! Resource ownership is committed before spawning jailer. A repeated launch
//! reservation is rejected: uncertain launches require reconciliation.
use super::{SessionKey, Store, session};
use crate::{
    error::{Error, Result},
    process::ProcessIdentity,
    session::{AssetIdentity, AssetsManifest, LaunchJournal, LaunchManifest},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sandboxd_protocol::{ApiError, ErrorCode, SessionState, codec};
use std::{
    path::Component,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_MANIFEST_BYTES: usize = 16_384;

pub(super) fn migrate(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
        CREATE TABLE session_resources (
            session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
            record BLOB NOT NULL CHECK(length(record) <= 16384)
        ) STRICT;
        PRAGMA user_version=5;
        COMMIT;",
    )?;
    Ok(())
}

fn validate(manifest: &LaunchManifest, key: &SessionKey) -> Result<()> {
    if manifest.sandbox_id != key.sandbox.as_str()
        || manifest.session_id != key.session.as_str()
        || manifest.jail_identity.inode == 0
        || manifest.cgroup_identity.inode == 0
    {
        return Err(Error::State);
    }
    if manifest.assets.root != manifest.jail_root
        || manifest.assets.root_identity.inode == 0
        || manifest.assets.root_mount_id == Some(0)
        || manifest.assets.mount_anchor_id == Some(0)
        || manifest.assets.root_mount_id.is_some() != manifest.assets.mount_anchor_id.is_some()
        || manifest.assets.mount_anchor_identity.is_some()
            != manifest.assets.mount_anchor_id.is_some()
        || manifest
            .assets
            .mount_anchor_identity
            .is_some_and(|identity| identity.device == 0 || identity.inode == 0)
        || manifest
            .assets
            .mount_namespace_identity
            .is_some_and(|identity| identity.device == 0 || identity.inode == 0)
    {
        return Err(Error::State);
    }
    validate_asset_layout(&manifest.assets)?;
    for path in [
        &manifest.jail_root,
        &manifest.cgroup,
        &manifest.api_socket,
        &manifest.vsock_socket,
    ] {
        if !path.is_absolute()
            || path.as_os_str().len() > 4096
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::State);
        }
    }
    for identity in [manifest.api_socket_identity, manifest.vsock_socket_identity]
        .into_iter()
        .flatten()
    {
        if identity.device == 0 || identity.inode == 0 {
            return Err(Error::State);
        }
    }
    let session_root = manifest.jail_root.parent().ok_or(Error::State)?;
    if manifest.jail_root.file_name() != Some(std::ffi::OsStr::new("root"))
        || session_root.file_name() != Some(std::ffi::OsStr::new(key.session.as_str()))
        || session_root.parent().and_then(|p| p.file_name())
            != Some(std::ffi::OsStr::new("firecracker"))
        || manifest.cgroup.file_name() != Some(std::ffi::OsStr::new(key.session.as_str()))
        || manifest.api_socket != manifest.jail_root.join("run/firecracker.socket")
        || manifest.vsock_socket != manifest.jail_root.join("run/vsock.socket")
    {
        return Err(Error::State);
    }
    Ok(())
}

fn validate_asset_layout(manifest: &AssetsManifest) -> Result<()> {
    let assets = &manifest.assets;
    if !(4..=24).contains(&assets.len()) {
        return Err(Error::State);
    }
    for (asset, (name, read_only)) in assets[..4].iter().zip([
        ("vmlinux", true),
        ("initramfs", true),
        ("base.img", true),
        ("state.img", false),
    ]) {
        if asset.path != manifest.root.join(name)
            || asset.identity.device == 0
            || asset.identity.inode == 0
            || asset.read_only != read_only
            || asset.anonymous
        {
            return Err(Error::State);
        }
    }
    let mut cursor = 4;
    let mut volume_ids = Vec::new();
    while let Some(asset) = assets.get(cursor) {
        let Some(name) = asset.path.file_name().and_then(|value| value.to_str()) else {
            return Err(Error::State);
        };
        let Some(id) = name
            .strip_prefix("volume-")
            .and_then(|value| value.strip_suffix(".img"))
        else {
            break;
        };
        if sandboxd_protocol::VolumeId::new(id.to_owned()).is_err()
            || asset.path != manifest.root.join(name)
            || asset.identity.device == 0
            || asset.identity.inode == 0
            || asset.anonymous
            || volume_ids.iter().any(|known| known == id)
        {
            return Err(Error::State);
        }
        volume_ids.push(id.to_owned());
        cursor += 1;
    }
    let snapshots = &assets[cursor..];
    let expected: &[(&str, bool)] = match snapshots.len() {
        0 => &[],
        2 => &[("snapshot-memory", false), ("snapshot-state", false)],
        4 => &[
            ("snapshot-memory", false),
            ("snapshot-state", false),
            ("restore-memory", true),
            ("restore-state", true),
        ],
        _ => return Err(Error::State),
    };
    for (asset, (name, read_only)) in snapshots.iter().zip(expected) {
        if asset.path != manifest.root.join(name)
            || asset.identity.device == 0
            || asset.identity.inode == 0
            || !asset.anonymous
            || asset.read_only != *read_only
        {
            return Err(Error::State);
        }
    }
    Ok(())
}

fn validate_recovery_additions(before: &LaunchManifest, after: &LaunchManifest) -> Result<()> {
    if before.sandbox_id != after.sandbox_id
        || before.session_id != after.session_id
        || before.jail_root != after.jail_root
        || before.cgroup != after.cgroup
        || before.api_socket != after.api_socket
        || before.vsock_socket != after.vsock_socket
        || before.jail_identity != after.jail_identity
        || before.cgroup_identity != after.cgroup_identity
        || before.network_identity != after.network_identity
        || before.network_attachment != after.network_attachment
        || before.network_namespace != after.network_namespace
        || before.assets.root != after.assets.root
        || before.assets.root_identity != after.assets.root_identity
        || before.assets.root_mount_id != after.assets.root_mount_id
        || before.assets.mount_anchor_identity != after.assets.mount_anchor_identity
        || before.assets.mount_anchor_id != after.assets.mount_anchor_id
        || before.assets.assets.len() != after.assets.assets.len()
    {
        return Err(Error::State);
    }
    let mut expected = before.clone();
    add_identity(&mut expected.api_socket_identity, after.api_socket_identity)?;
    add_identity(
        &mut expected.vsock_socket_identity,
        after.vsock_socket_identity,
    )?;
    add_optional(&mut expected.staged_jail, &after.staged_jail)?;
    add_optional(&mut expected.jail_tree, &after.jail_tree)?;
    add_identity(
        &mut expected.assets.session_identity,
        after.assets.session_identity,
    )?;
    add_identity(&mut expected.assets.run_identity, after.assets.run_identity)?;
    let legacy_unbound_mounts = expected.assets.mount_namespace_identity.is_none();
    add_identity(
        &mut expected.assets.mount_namespace_identity,
        after.assets.mount_namespace_identity,
    )?;
    for (old, new) in expected.assets.assets.iter_mut().zip(&after.assets.assets) {
        if old.path != new.path
            || old.identity != new.identity
            || old.read_only != new.read_only
            || old.anonymous != new.anonymous
        {
            return Err(Error::State);
        }
        add_identity(&mut old.placeholder_identity, new.placeholder_identity)?;
        if legacy_unbound_mounts {
            old.mount_id = new.mount_id;
        } else {
            add_optional(&mut old.mount_id, &new.mount_id)?;
        }
    }
    if expected != *after {
        return Err(Error::State);
    }
    Ok(())
}

fn add_identity(before: &mut Option<AssetIdentity>, after: Option<AssetIdentity>) -> Result<()> {
    add_optional(before, &after)
}

fn add_optional<T: Clone + Eq>(before: &mut Option<T>, after: &Option<T>) -> Result<()> {
    match (before.as_ref(), after.as_ref()) {
        (Some(old), Some(new)) if old == new => Ok(()),
        (None, Some(new)) => {
            *before = Some(new.clone());
            Ok(())
        }
        (None, None) => Ok(()),
        _ => Err(Error::State),
    }
}

pub(super) fn load(connection: &Connection, key: &SessionKey) -> Result<Option<LaunchManifest>> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT record FROM session_resources WHERE session_id=?1",
            [key.session.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| {
            if bytes.len() > MAX_MANIFEST_BYTES {
                return Err(Error::State);
            }
            let manifest = codec::decode_body(&bytes)?;
            validate(&manifest, key)?;
            Ok(manifest)
        })
        .transpose()
}

impl Store {
    /// Atomically commits only monotonic ownership observations from legacy recovery.
    pub fn record_recovered_cleanup_manifest(
        &mut self,
        uid: u32,
        key: &SessionKey,
        recovered: &LaunchManifest,
    ) -> Result<()> {
        let intent = self.session_intent(uid, key)?;
        if intent.state == SessionState::Terminated {
            return Err(Error::State);
        }
        validate(recovered, key)?;
        crate::session::validate_cleanup_manifest(recovered)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load(&tx, key)?.ok_or(Error::State)?;
        if existing != *recovered {
            validate_recovery_additions(&existing, recovered)?;
        }
        let bytes = codec::encode_body(recovered)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::State);
        }
        if existing != *recovered {
            let changed = tx.execute(
                "UPDATE session_resources SET record=?1 WHERE session_id=?2",
                params![bytes, key.session.as_str()],
            )?;
            if changed != 1 {
                return Err(Error::State);
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn record_jail_tree(
        &mut self,
        uid: u32,
        key: &SessionKey,
        tree: crate::session::JailTreeManifest,
    ) -> Result<()> {
        let intent = self.session_intent(uid, key)?;
        if tree.uid != intent.uid
            || tree.gid != intent.gid
            || tree.entries.len() > 32
            || intent.state == SessionState::Terminated
        {
            return Err(Error::State);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut manifest = load(&tx, key)?.ok_or(Error::State)?;
        if let Some(existing) = &manifest.jail_tree {
            if *existing == tree {
                return Ok(());
            }
            return Err(Error::State);
        }
        manifest.jail_tree = Some(tree);
        let bytes = codec::encode_body(&manifest)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::State);
        }
        tx.execute(
            "UPDATE session_resources SET record=?1 WHERE session_id=?2",
            params![bytes, key.session.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn session_resources(&self, uid: u32, key: &SessionKey) -> Result<Option<LaunchManifest>> {
        self.session_intent(uid, key)?;
        load(&self.connection, key)
    }

    /// This is an internal runtime callback, never a client-supplied manifest.
    pub fn reserve_launch_resources(
        &mut self,
        uid: u32,
        key: &SessionKey,
        manifest: &LaunchManifest,
    ) -> Result<()> {
        let intent = self.session_intent(uid, key)?;
        if intent.state != SessionState::JailerStarting {
            return Err(Error::State);
        }
        validate(manifest, key)?;
        let bytes = codec::encode_body(manifest)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::State);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if load(&tx, key)?.is_some() {
            return Err(ApiError::new(
                ErrorCode::OperationConflict,
                "launch resources already reserved; reconcile before retry",
            )
            .into());
        }
        tx.execute(
            "INSERT INTO session_resources(session_id,record) VALUES (?1,?2)",
            params![key.session.as_str(), bytes],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_socket_identities(
        &mut self,
        uid: u32,
        key: &SessionKey,
        api: AssetIdentity,
        vsock: AssetIdentity,
    ) -> Result<()> {
        let intent = self.session_intent(uid, key)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut manifest = load(&tx, key)?.ok_or(Error::State)?;
        if intent.state == SessionState::Terminated
            || manifest.api_socket_identity.is_some()
            || manifest.vsock_socket_identity.is_some()
        {
            return Err(Error::State);
        }
        manifest.api_socket_identity = Some(api);
        manifest.vsock_socket_identity = Some(vsock);
        validate(&manifest, key)?;
        tx.execute(
            "UPDATE session_resources SET record=?1 WHERE session_id=?2",
            params![codec::encode_body(&manifest)?, key.session.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }
}

pub(super) fn validate_all(connection: &Connection) -> Result<()> {
    let mut statement =
        connection.prepare(&format!("SELECT {} FROM sessions", session::COLUMNS))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let intent = session::decode(row)?;
        if load(connection, &intent.key)?.is_some() && intent.state == SessionState::Preparing {
            return Err(Error::State);
        }
    }
    Ok(())
}

/// Keeps the exact owner and incarnation fixed throughout one launch.
pub struct StoreLaunchJournal<'a> {
    store: &'a mut Store,
    owner_uid: u32,
    key: SessionKey,
}
impl<'a> StoreLaunchJournal<'a> {
    pub fn new(store: &'a mut Store, owner_uid: u32, key: &SessionKey) -> Self {
        Self {
            store,
            owner_uid,
            key: key.clone(),
        }
    }
}
impl LaunchJournal for StoreLaunchJournal<'_> {
    fn reserve_diagnostics(&mut self, resources: &sandboxd_protocol::Resources) -> Result<()> {
        self.store
            .reserve_diagnostics(self.owner_uid, &self.key, resources)
    }
    fn record_jail_tree(&mut self, tree: &crate::session::JailTreeManifest) -> Result<()> {
        self.store
            .record_jail_tree(self.owner_uid, &self.key, tree.clone())
    }
    fn reserve_resources(&mut self, manifest: &LaunchManifest) -> Result<()> {
        self.store
            .reserve_launch_resources(self.owner_uid, &self.key, manifest)
    }
    fn record_process(&mut self, process: &ProcessIdentity) -> Result<()> {
        self.store
            .record_vmm_process(self.owner_uid, &self.key, process, now_ms()?)
    }

    fn record_socket_identities(&mut self, api: AssetIdentity, vsock: AssetIdentity) -> Result<()> {
        self.store
            .record_socket_identities(self.owner_uid, &self.key, api, vsock)
    }
}

impl crate::session::BootJournal for StoreLaunchJournal<'_> {
    fn record_vmm_booting(&mut self, process: &ProcessIdentity) -> Result<()> {
        self.store
            .record_vmm_booting(self.owner_uid, &self.key, process, now_ms()?)
    }
    fn record_guest_handshake(&mut self, process: &ProcessIdentity) -> Result<()> {
        self.store
            .record_guest_handshake(self.owner_uid, &self.key, process, now_ms()?)
    }
    fn record_guest_ready(
        &mut self,
        process: &ProcessIdentity,
        identity: &guest_protocol::SessionIdentity,
    ) -> Result<()> {
        self.store
            .record_guest_ready(self.owner_uid, &self.key, process, identity, now_ms()?)
    }
}

fn now_ms() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::State)?
        .as_millis();
    u64::try_from(now).map_err(|_| Error::State)
}
