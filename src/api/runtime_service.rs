//! Public lifecycle admission and bounded, generation-specific runtime effects.
use super::{
    handlers::now_ms,
    runtime_authority::RuntimeAuthority,
    runtime_boot,
    runtime_queue::RuntimeQueue,
    state_worker::{StateClient, deadline_error},
};
use crate::{
    config::Config,
    error::{Error, Result},
    exec::ExecEventRouter,
    guest::GuestConnection,
    process::ProcessIdentity,
    runtime::VerifiedCatalogs,
    security::peer::Peer,
    session::{BootResult, LaunchManifest},
    state::{LaunchIntent, SessionControlContext, SessionKey},
};
use guest_protocol::GuestMessage;
use sandboxd_protocol::{
    ApiError, ErrorCode, Fence, Health, OperationId, Request, Response, SandboxId, SessionControl,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex, atomic::AtomicBool},
    time::Duration,
};
use tokio::{
    sync::{Mutex, oneshot},
    time::{Instant, timeout_at},
};

pub(super) struct LiveVm {
    pub owner: u32,
    pub intent: LaunchIntent,
    pub process: ProcessIdentity,
    pub manifest: LaunchManifest,
    pub guest: Mutex<Option<GuestConnection>>,
    pub exec_router: Arc<ExecEventRouter>,
    pub(super) volume_locks: StdMutex<Vec<crate::volume_catalog::PinnedVolume>>,
    pub transport_epoch: std::sync::atomic::AtomicU64,
}

pub(super) struct RuntimeService {
    pub authority: Arc<RuntimeAuthority>,
    pub checkpoints: Arc<crate::storage::CheckpointCatalog>,
    pub snapshots: Option<Arc<crate::snapshot::SnapshotCatalog>>,
    pub state: StateClient,
    pub config: Arc<Config>,
    pub live: Mutex<HashMap<SandboxId, Arc<LiveVm>>>,
    pub(super) queue: RuntimeQueue,
    pub(super) policy_running: AtomicBool,
    pub(super) policy_pending: StdMutex<HashMap<SandboxId, SessionKey>>,
    pub(super) filesystem_export_slots: Arc<tokio::sync::Semaphore>,
}

impl RuntimeService {
    pub fn stateless(&self, request: &Request) -> Option<Response> {
        match request {
            Request::Capabilities => {
                let Some(Response::Capabilities(mut capabilities)) =
                    super::handlers::stateless(&self.config, request)
                else {
                    return None;
                };
                capabilities.supported.extend(
                    [
                        "jailer_session_lifecycle",
                        "network_none",
                        "same_process_pause_resume",
                        "identity_checked_stop",
                        "filesystem_checkpoints",
                        "guest_exec",
                        "guest_exec_pty",
                        "guest_exec_output_journal",
                    ]
                    .into_iter()
                    .map(str::to_owned),
                );
                Some(Response::Capabilities(capabilities))
            }
            Request::Health => Some(Response::Health(Health {
                daemon: "READY".into(),
                storage: "OPEN".into(),
                runtime: "VERIFIED_CATALOG".into(),
                guest: "SESSION_SCOPED".into(),
            })),
            _ => None,
        }
    }

    pub fn new(
        config: Arc<Config>,
        state: StateClient,
        catalogs: VerifiedCatalogs,
    ) -> Result<Arc<Self>> {
        Self::new_inner(config, state, catalogs, false)
    }

    pub fn new_for_cleanup(
        config: Arc<Config>,
        state: StateClient,
        catalogs: VerifiedCatalogs,
    ) -> Result<Arc<Self>> {
        Self::new_inner(config, state, catalogs, true)
    }

    fn new_inner(
        config: Arc<Config>,
        state: StateClient,
        catalogs: VerifiedCatalogs,
        cleanup: bool,
    ) -> Result<Arc<Self>> {
        crate::security::path::SecureDir::open(&config.state.directory)?
            .ensure_private_directory("output")?;
        let authority = Arc::new(if cleanup {
            RuntimeAuthority::new_for_cleanup(&config, catalogs, state.clone())?
        } else {
            RuntimeAuthority::new(&config, catalogs, state.clone())?
        });
        // Load the complete bounded-by-page catalog. A single 256-row query
        // would silently make later durable images unusable after restart.
        let mut cursor = None;
        loop {
            let page = state.with_store_blocking({
                let cursor = cursor.clone();
                move |store| store.list_prepared_images(cursor.as_deref(), 256)
            })?;
            let page_len = page.len();
            for record in &page {
                authority.register_prepared_image(record)?;
            }
            if page_len < 256 {
                break;
            }
            cursor = page.last().map(|record| record.digest.clone());
        }
        for record in state.with_store_blocking(|store| store.dynamic_volumes())? {
            authority.register_dynamic_volume(&record)?;
        }
        Ok(Arc::new(Self {
            snapshots: config
                .snapshots
                .as_ref()
                .map(|settings| {
                    let keys = Arc::new(crate::snapshot::LocalKey::open(&settings.key_file)?);
                    crate::snapshot::SnapshotCatalog::open(settings.directory.clone(), keys)
                        .map(Arc::new)
                })
                .transpose()?,
            checkpoints: Arc::new(crate::storage::CheckpointCatalog::open(
                config.state.directory.join("checkpoints"),
            )?),
            authority,
            queue: RuntimeQueue::new(config.quotas.max_booting_sandboxes as usize, 4)?,
            config,
            state,
            live: Mutex::new(HashMap::new()),
            policy_running: AtomicBool::new(false),
            policy_pending: StdMutex::new(HashMap::new()),
            filesystem_export_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        }))
    }

    pub async fn control(
        self: &Arc<Self>,
        peer: Peer,
        operation: OperationId,
        fence: Fence,
        control: SessionControl,
        operation_sequence: u64,
        deadline: Instant,
    ) -> Result<Response> {
        let (reply, receive) = oneshot::channel();
        let runtime = Arc::clone(self);
        // The queue owns the effect after admission, independently of a disconnected client.
        let completed = self
            .queue
            .submit(fence.sandbox.clone(), async move {
                if reply.is_closed() || Instant::now() >= deadline {
                    let _ = reply.send(Err(deadline_error()));
                    return Ok(());
                }
                let state = runtime.state.clone();
                let authority = Arc::clone(&runtime.authority);
                let config = Arc::clone(&runtime.config);
                let effect_operation = operation.clone();
                let admitted = state
                    .with_store(move |store| {
                        // Check again on the exclusive durable-state owner, before intent commits.
                        if reply.is_closed() || Instant::now() >= deadline {
                            let _ = reply.send(Err(deadline_error()));
                            return Ok(None);
                        }
                        let admission = (|| {
                            if let Some(replay) = store
                                .replay_session_control(peer.uid, &operation, &fence, control)?
                            {
                                return Ok(replay);
                            }
                            let record = store.inspect(peer.uid, &fence.sandbox)?;
                            let pins = if control == SessionControl::Start {
                                {
                                    store.validate_dynamic_volume_attachment(
                                        peer.uid,
                                        &record.spec.volumes,
                                    )?;
                                    Some(authority.pins_with_store(
                                        peer.uid,
                                        &record.spec,
                                        Some(store),
                                    )?)
                                }
                            } else {
                                None
                            };
                            store.begin_session_control_sequenced(
                                peer.uid,
                                &operation,
                                &fence,
                                control,
                                SessionControlContext {
                                    pins: pins.as_ref(),
                                    pools: &config.identities,
                                    host_boot_id: &authority.boot_id,
                                    now_ms: now_ms()?,
                                },
                                Some(operation_sequence),
                            )
                        })();
                        let admission = match admission {
                            Ok(admission) => admission,
                            Err(error) => {
                                let _ = reply.send(Err(error));
                                return Ok(None);
                            }
                        };
                        let effect = match &admission.key {
                            Some(key) if !admission.replayed => {
                                Some(store.session_intent(peer.uid, key)?)
                            }
                            Some(key) if control != SessionControl::Start => {
                                let pending = store.pending_session_control(peer.uid, key)?;
                                if pending.as_ref().is_some_and(|p| {
                                    p.operation == operation && p.control == control
                                }) {
                                    Some(store.session_intent(peer.uid, key)?)
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        };
                        let _ = reply.send(Ok(admission.response));
                        Ok(effect)
                    })
                    .await?;
                if let Some(intent) = admitted {
                    if let Err(error) = runtime
                        .effect(peer.uid, intent, control, effect_operation)
                        .await
                    {
                        eprintln!("session runtime effect failed: {error}");
                        return Err(error);
                    }
                }
                Ok(())
            })
            .await?;
        // Dropping this receiver cannot cancel the queue-owned runtime work.
        drop(completed);
        timeout_at(deadline, receive)
            .await
            .map_err(|_| deadline_error())?
            .map_err(|_| Error::State)?
    }

    async fn effect(
        self: &Arc<Self>,
        uid: u32,
        intent: LaunchIntent,
        control: SessionControl,
        operation: OperationId,
    ) -> Result<()> {
        if control != SessionControl::Start {
            return self.apply_existing(uid, &intent.key, control).await;
        }
        let (state, sandbox) = (self.state.clone(), intent.key.sandbox.clone());
        let spec = state
            .with_store(move |store| Ok(store.inspect(uid, &sandbox)?.spec))
            .await?;
        let result = runtime_boot::start(
            self.state.clone(),
            Arc::clone(&self.authority),
            uid,
            intent.clone(),
            spec,
            operation,
        )
        .await;
        match result {
            Ok(boot) => self.install(uid, intent, boot).await,
            Err(error) => {
                let key = intent.key;
                self.state
                    .with_store(move |store| store.runtime_failed(uid, &key, now_ms()?))
                    .await?;
                Err(error)
            }
        }
    }

    pub(super) async fn install(
        self: &Arc<Self>,
        uid: u32,
        intent: LaunchIntent,
        boot: BootResult,
    ) -> Result<()> {
        let BootResult {
            launch,
            guest,
            volume_locks,
        } = boot;
        let router_root = self.session_output_root(&intent);
        let router = match if router_root.exists() {
            ExecEventRouter::restore(&router_root)
        } else {
            ExecEventRouter::new(&router_root)
        } {
            Ok(router) => Arc::new(router),
            Err(error) => {
                drop(guest);
                self.cleanup_uninstalled_boot(uid, &intent.key, &launch.process, &launch.manifest)
                    .await?;
                return Err(error);
            }
        };
        let events = guest.subscribe_events();
        let vm = Arc::new(LiveVm {
            owner: uid,
            intent,
            process: launch.process,
            manifest: launch.manifest,
            guest: Mutex::new(Some(guest)),
            exec_router: router.clone(),
            volume_locks: StdMutex::new(volume_locks),
            transport_epoch: std::sync::atomic::AtomicU64::new(0),
        });
        if let Err(error) = self.insert(Arc::clone(&vm)).await {
            self.cleanup_uninstalled_boot(uid, &vm.intent.key, &vm.process, &vm.manifest)
                .await?;
            return Err(error);
        }
        let state = self.state.clone();
        let uid_for_pump = uid;
        let key_for_pump = vm.intent.key.clone();
        let vm_for_pump = vm.clone();
        let transport_epoch = vm
            .transport_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        tokio::spawn(async move {
            if let Err(error) = router.clone().run(events).await {
                if vm_for_pump
                    .transport_epoch
                    .load(std::sync::atomic::Ordering::Acquire)
                    != transport_epoch
                {
                    return;
                }
                eprintln!("guest execution event pump stopped: {error}");
                let failed = router.take_sink_failures().unwrap_or_default();
                if !failed.is_empty() {
                    if let Some(guest) = vm_for_pump.guest.lock().await.as_ref() {
                        for exec in failed {
                            if let Ok(operation) =
                                OperationId::new(format!("sink-cancel-{}", exec.as_str()))
                            {
                                let _ = guest
                                    .request(operation, GuestMessage::ExecCancel { exec })
                                    .await;
                            }
                        }
                    }
                    return;
                }
                let key = key_for_pump.clone();
                let _ = state
                    .with_store(move |store| {
                        store.admit_runtime_loss(
                            uid_for_pump,
                            &key,
                            sandboxd_protocol::EventKind::GuestAgentLost,
                            now_ms()?,
                        )
                    })
                    .await;
            }
        });
        Ok(())
    }

    async fn cleanup_uninstalled_boot(
        &self,
        uid: u32,
        key: &SessionKey,
        process: &ProcessIdentity,
        manifest: &LaunchManifest,
    ) -> Result<()> {
        let stop_key = key.clone();
        self.state
            .with_store(move |store| {
                store.admit_runtime_loss(
                    uid,
                    &stop_key,
                    sandboxd_protocol::EventKind::RecoveryFailed,
                    now_ms()?,
                )
            })
            .await?;
        // Cleanup errors leave the durable Stop intent for reconciliation.
        let proof = crate::session::stop_and_cleanup(process, manifest, key).await?;
        let stopped_key = key.clone();
        self.state
            .with_store(move |store| {
                store.record_session_stopped(uid, &stopped_key, proof, now_ms()?)
            })
            .await
    }

    pub async fn insert(&self, vm: Arc<LiveVm>) -> Result<()> {
        let mut live = self.live.lock().await;
        if live.contains_key(&vm.intent.key.sandbox)
            || live.len() >= self.config.quotas.max_active_sandboxes as usize
        {
            return Err(Error::State);
        }
        live.insert(vm.intent.key.sandbox.clone(), vm);
        Ok(())
    }

    pub async fn current(&self, uid: u32, key: &SessionKey) -> Result<Arc<LiveVm>> {
        self.live
            .lock()
            .await
            .get(&key.sandbox)
            .filter(|vm| vm.owner == uid && vm.intent.key == *key)
            .cloned()
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::SessionUnavailable,
                    "current runtime session is unavailable",
                )
                .into()
            })
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.queue
            .close_and_drain(Duration::from_secs(
                u64::from(self.authority.execution.boot_timeout_seconds) + 10,
            ))
            .await
    }
}
