//! Asynchronous runtime effects and short synchronous journal callbacks.
//!
//! Runtime code never receives `Store` directly.  It obtains a bounded
//! callback through `StateClient::with_store`, which keeps SQLite ownership in
//! the state worker and prevents a boot wait from holding the store lock.

use crate::{
    api::{runtime_queue::RuntimeQueue, state_worker::StateClient},
    error::{Error, Result},
    process::ProcessIdentity,
    state::{CleanupProof, SessionKey},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct RuntimeWorker {
    state: StateClient,
    queue: RuntimeQueue,
}

impl RuntimeWorker {
    pub fn new(state: StateClient, max_concurrent: usize) -> Result<Self> {
        Ok(Self {
            state,
            queue: RuntimeQueue::new(max_concurrent, 4)?,
        })
    }

    pub fn state(&self) -> &StateClient {
        &self.state
    }

    /// Serialize effects for one sandbox while bounding the global number of
    /// VMM jobs.  The returned receiver represents the durable effect result;
    /// callers may await it without touching SQLite.
    pub async fn submit<F>(
        &self,
        sandbox: sandboxd_protocol::SandboxId,
        effect: F,
    ) -> Result<oneshot::Receiver<Result<()>>>
    where
        F: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        self.queue.submit(sandbox, effect).await
    }

    pub async fn record_process(
        &self,
        uid: u32,
        key: SessionKey,
        process: ProcessIdentity,
    ) -> Result<()> {
        let now = now_ms()?;
        self.state
            .with_store(move |store| store.record_vmm_process(uid, &key, &process, now))
            .await
    }

    pub async fn record_booting(
        &self,
        uid: u32,
        key: SessionKey,
        process: ProcessIdentity,
    ) -> Result<()> {
        let now = now_ms()?;
        self.state
            .with_store(move |store| store.record_vmm_booting(uid, &key, &process, now))
            .await
    }

    pub async fn record_handshake(
        &self,
        uid: u32,
        key: SessionKey,
        process: ProcessIdentity,
    ) -> Result<()> {
        let now = now_ms()?;
        self.state
            .with_store(move |store| store.record_guest_handshake(uid, &key, &process, now))
            .await
    }

    pub async fn record_ready(
        &self,
        uid: u32,
        key: SessionKey,
        process: ProcessIdentity,
        identity: guest_protocol::SessionIdentity,
    ) -> Result<()> {
        let now = now_ms()?;
        self.state
            .with_store(move |store| store.record_guest_ready(uid, &key, &process, &identity, now))
            .await
    }

    pub async fn record_paused(
        &self,
        uid: u32,
        key: SessionKey,
        process: ProcessIdentity,
    ) -> Result<()> {
        let now = now_ms()?;
        self.state
            .with_store(move |store| store.record_session_paused(uid, &key, &process, now))
            .await
    }

    pub async fn record_resumed(
        &self,
        uid: u32,
        key: SessionKey,
        process: ProcessIdentity,
    ) -> Result<()> {
        let now = now_ms()?;
        self.state
            .with_store(move |store| store.record_session_resumed(uid, &key, &process, now))
            .await
    }

    pub async fn record_stopped(
        &self,
        uid: u32,
        key: SessionKey,
        proof: CleanupProof,
    ) -> Result<()> {
        let now = now_ms()?;
        self.state
            .with_store(move |store| store.record_session_stopped(uid, &key, proof, now))
            .await
    }
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::State)
        .and_then(|duration| u64::try_from(duration.as_millis()).map_err(|_| Error::State))
}
