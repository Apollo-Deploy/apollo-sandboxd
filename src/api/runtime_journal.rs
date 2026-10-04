//! Short durable callbacks from the bounded boot worker to the SQLite owner.
use super::{handlers::now_ms, state_worker::StateClient};
use crate::{
    error::Result,
    process::ProcessIdentity,
    session::{AssetIdentity, BootJournal, LaunchJournal, LaunchManifest},
    state::SessionKey,
};
use guest_protocol::SessionIdentity;

pub(super) struct RuntimeJournal {
    pub state: StateClient,
    pub uid: u32,
    pub key: SessionKey,
}

impl LaunchJournal for RuntimeJournal {
    fn reserve_diagnostics(&mut self, resources: &sandboxd_protocol::Resources) -> Result<()> {
        let (uid, key, resources) = (self.uid, self.key.clone(), resources.clone());
        self.state
            .with_store_blocking(move |store| store.reserve_diagnostics(uid, &key, &resources))
    }
    fn reserve_resources(&mut self, manifest: &LaunchManifest) -> Result<()> {
        let manifest = manifest.clone();
        let (uid, key) = (self.uid, self.key.clone());
        self.state.with_store_blocking(move |store| {
            store.reserve_launch_resources(uid, &key, &manifest)?;
            store.clear_prelaunch(uid, &key)
        })
    }
    fn record_process(&mut self, process: &ProcessIdentity) -> Result<()> {
        self.observe(process, |store, uid, key, process, now| {
            store.record_vmm_process(uid, key, process, now)
        })
    }
    fn record_socket_identities(&mut self, api: AssetIdentity, vsock: AssetIdentity) -> Result<()> {
        let (uid, key) = (self.uid, self.key.clone());
        self.state
            .with_store_blocking(move |store| store.record_socket_identities(uid, &key, api, vsock))
    }
    fn record_jail_tree(&mut self, tree: &crate::session::JailTreeManifest) -> Result<()> {
        let (uid, key, tree) = (self.uid, self.key.clone(), tree.clone());
        self.state
            .with_store_blocking(move |store| store.record_jail_tree(uid, &key, tree))
    }
}

impl BootJournal for RuntimeJournal {
    fn record_vmm_booting(&mut self, process: &ProcessIdentity) -> Result<()> {
        self.observe(process, |store, uid, key, process, now| {
            store.record_vmm_booting(uid, key, process, now)
        })
    }
    fn record_guest_handshake(&mut self, process: &ProcessIdentity) -> Result<()> {
        self.observe(process, |store, uid, key, process, now| {
            store.record_guest_handshake(uid, key, process, now)
        })
    }
    fn record_guest_ready(
        &mut self,
        process: &ProcessIdentity,
        identity: &SessionIdentity,
    ) -> Result<()> {
        let identity = identity.clone();
        self.observe(process, move |store, uid, key, process, now| {
            store.record_guest_ready(uid, key, process, &identity, now)
        })
    }
}

impl RuntimeJournal {
    pub fn reserve_prelaunch(&self, record: crate::state::PrelaunchIntent) -> Result<()> {
        let (uid, key) = (self.uid, self.key.clone());
        self.state
            .with_store_blocking(move |store| store.reserve_prelaunch(uid, &key, &record))
    }

    pub fn record_prelaunch_stage(&self, stage: crate::jailer::JailStageManifest) -> Result<()> {
        let (uid, key) = (self.uid, self.key.clone());
        self.state
            .with_store_blocking(move |store| store.record_prelaunch_stage(uid, &key, stage))
    }

    pub fn record_prelaunch_assets(&self, assets: crate::session::AssetsManifest) -> Result<()> {
        let (uid, key) = (self.uid, self.key.clone());
        self.state
            .with_store_blocking(move |store| store.record_prelaunch_assets(uid, &key, assets))
    }

    pub fn record_prelaunch_asset_setup(&self, setup: crate::session::AssetSetup) -> Result<()> {
        let (uid, key) = (self.uid, self.key.clone());
        self.state
            .with_store_blocking(move |store| store.record_prelaunch_asset_setup(uid, &key, setup))
    }

    pub fn record_prelaunch_cgroup(&self, identity: crate::jailer::CgroupIdentity) -> Result<()> {
        let (uid, key) = (self.uid, self.key.clone());
        self.state
            .with_store_blocking(move |store| store.record_prelaunch_cgroup(uid, &key, identity))
    }

    fn observe(
        &self,
        process: &ProcessIdentity,
        observe: impl FnOnce(
            &mut crate::state::Store,
            u32,
            &SessionKey,
            &ProcessIdentity,
            u64,
        ) -> Result<()>
        + Send
        + 'static,
    ) -> Result<()> {
        let record = process.persisted();
        let (uid, key, now) = (self.uid, self.key.clone(), now_ms()?);
        self.state.with_store_blocking(move |store| {
            let process = ProcessIdentity::reopen_verified(&record)?;
            observe(store, uid, &key, &process, now)
        })
    }
}
