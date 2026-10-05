//! Re-adopt a running VMM only from its complete durable process/resource identity.
use super::{
    handlers::now_ms,
    runtime_control::{reconnect, validate_vmm},
    runtime_service::{LiveVm, RuntimeService},
};
use crate::{
    error::{Error, Result},
    process::ProcessIdentity,
    state::{LaunchIntent, PendingSessionControl},
};
use firecracker_api::{Client, InstanceState};
use sandboxd_protocol::{SessionControl, SessionState};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

impl RuntimeService {
    pub async fn recover(self: &Arc<Self>) -> Result<()> {
        self.reconcile_diagnostics().await?;
        self.recover_checkpoints().await?;
        self.recover_snapshots().await?;
        let mut after = None;
        let mut inspected = 0usize;
        loop {
            let cursor = after.clone();
            let page = self
                .state
                .with_store(move |store| store.runtime_inventory(cursor.as_ref(), 256))
                .await?;
            if page.is_empty() {
                return Ok(());
            }
            for (uid, intent) in page {
                after = Some(intent.key.sandbox.clone());
                inspected = inspected.checked_add(1).ok_or(Error::State)?;
                if inspected > self.config.quotas.max_active_sandboxes as usize {
                    return Err(Error::Config(
                        "durable recovery inventory exceeds active VM quota",
                    ));
                }
                if self.current(uid, &intent.key).await.is_ok() {
                    continue;
                }
                if let Err(error) = self.recover_one(uid, intent.clone()).await {
                    // Unknown or partially completed effects remain quarantined and allocated.
                    // Never start another VMM or attach to a recyclable PID to repair uncertainty.
                    eprintln!("session recovery quarantined: {error}");
                    let key = intent.key;
                    let failed_key = key.clone();
                    self.state
                        .with_store(move |store| store.runtime_failed(uid, &failed_key, now_ms()?))
                        .await?;
                    if self.current(uid, &key).await.is_ok() {
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
                        if let Err(error) =
                            self.apply_existing(uid, &key, SessionControl::Stop).await
                        {
                            eprintln!("recovered failed VM cleanup remains pending: {error}");
                        }
                    }
                }
            }
        }
    }

    async fn reconcile_diagnostics(&self) -> Result<()> {
        let mut after = None;
        let mut inspected = 0usize;
        loop {
            let cursor = after.clone();
            let page = self
                .state
                .with_store(move |store| store.runtime_inventory(cursor.as_ref(), 256))
                .await?;
            if page.is_empty() {
                break;
            }
            for (uid, intent) in page {
                after = Some(intent.key.sandbox.clone());
                inspected = inspected.checked_add(1).ok_or(Error::State)?;
                if inspected > self.config.quotas.max_active_sandboxes as usize {
                    return Err(Error::Config(
                        "durable recovery inventory exceeds active VM quota",
                    ));
                }
                if intent.state == SessionState::Preparing {
                    continue;
                }
                let key = intent.key.clone();
                self.state
                    .with_store(move |store| {
                        let resources = store.inspect(uid, &key.sandbox)?.spec.resources;
                        store.reserve_diagnostics(uid, &key, &resources)
                    })
                    .await?;
            }
        }
        let reservations = self
            .state
            .with_store(|store| store.diagnostic_reservations())
            .await?;
        let root = self.authority.execution.operator_root.clone();
        tokio::task::spawn_blocking(move || {
            crate::session::diagnostics::scan(&root, &reservations)
        })
        .await
        .map_err(|_| Error::State)??;
        Ok(())
    }

    pub(super) async fn recover_one(&self, uid: u32, intent: LaunchIntent) -> Result<()> {
        let key = intent.key.clone();
        if intent.state == SessionState::Preparing {
            let inspection_key = key.clone();
            let no_effects = self
                .state
                .with_store(move |store| {
                    Ok(store.session_process(uid, &inspection_key)?.is_none()
                        && store.session_resources(uid, &inspection_key)?.is_none()
                        && store.prelaunch(uid, &inspection_key)?.is_none())
                })
                .await?;
            if no_effects {
                let stop_key = key.clone();
                return self
                    .state
                    .with_store(move |store| {
                        store.abort_session_preparation(uid, &stop_key, now_ms()?)
                    })
                    .await;
            }
        }
        let orphan_launch = {
            let inspection_key = key.clone();
            self.state
                .with_store(move |store| {
                    Ok(store.session_process(uid, &inspection_key)?.is_none()
                        && store.session_resources(uid, &inspection_key)?.is_some()
                        && store.prelaunch(uid, &inspection_key)?.is_none())
                })
                .await?
        };
        // Keep JAILER_STARTING fenced while cleanup_untracked captures and
        // persists a live VMM identity. The generic runtime-loss path changes
        // the state to TERMINATING and would correctly reject that callback.
        if orphan_launch {
            return self.cleanup_untracked(uid, &key).await;
        }
        let inspection_key = key.clone();
        let recoverable_cleanup = self
            .state
            .with_store(move |store| {
                let record = store.session_process(uid, &inspection_key)?;
                let resources = store.session_resources(uid, &inspection_key)?;
                let prelaunch = store.prelaunch(uid, &inspection_key)?;
                match (record, resources, prelaunch) {
                    (None, None, Some(_)) => Ok(true),
                    (Some(record), Some(_), None) => {
                        #[cfg(target_os = "linux")]
                        return crate::process::prove_recorded_absent(&record);
                        #[cfg(not(target_os = "linux"))]
                        {
                            let _ = record;
                            Ok(false)
                        }
                    }
                    _ => Ok(false),
                }
            })
            .await?;
        if recoverable_cleanup {
            self.state
                .with_store(move |store| {
                    store.admit_runtime_loss(
                        uid,
                        &key,
                        sandboxd_protocol::EventKind::RecoveryFailed,
                        now_ms()?,
                    )
                })
                .await?;
            return self.cleanup_untracked(uid, &intent.key).await;
        }
        if intent.host_boot_id != self.authority.boot_id {
            return Err(Error::Config(
                "session process did not survive this host boot",
            ));
        }
        if !matches!(
            intent.state,
            SessionState::Active
                | SessionState::Paused
                | SessionState::Terminating
                | SessionState::Failed
        ) {
            return Err(Error::Config(
                "incomplete launch requires owned-resource reconciliation",
            ));
        }
        // Revalidation includes each pinned artifact, even when its runtime is no longer default.
        let authority = Arc::clone(&self.authority);
        let pins = intent.pins.clone();
        let artifacts = tokio::task::spawn_blocking(move || authority.artifacts(&pins))
            .await
            .map_err(|_| Error::State)??;
        let key = intent.key.clone();
        let (record, manifest, pending) = self
            .state
            .with_store(move |store| {
                Ok((
                    store.session_process(uid, &key)?.ok_or(Error::State)?,
                    store.session_resources(uid, &key)?.ok_or(Error::State)?,
                    store.pending_session_control(uid, &key)?,
                ))
            })
            .await?;
        let expected_root = self
            .authority
            .execution
            .operator_root
            .join("firecracker")
            .join(intent.key.session.as_str())
            .join("root");
        if manifest.jail_root != expected_root
            || manifest.cgroup
                != self
                    .authority
                    .execution
                    .cgroup_parent
                    .join(intent.key.session.as_str())
        {
            return Err(Error::Config(
                "recorded session roots differ from operator catalog",
            ));
        }
        match (
            &manifest.network_attachment,
            &manifest.network_namespace,
            &manifest.network_identity,
        ) {
            (Some(attachment), Some(namespace), Some(identity)) => {
                let root = self
                    .authority
                    .execution
                    .network_namespace_root
                    .as_deref()
                    .ok_or(Error::Config(
                        "network catalog root missing during recovery",
                    ))?;
                crate::network::verify_persisted(attachment, namespace, identity, root)
                    .map_err(Error::Config)?;
            }
            (None, None, None) => {}
            _ => return Err(Error::Config("incomplete persisted network attachment")),
        }
        let process =
            tokio::task::spawn_blocking(move || ProcessIdentity::reopen_verified(&record))
                .await
                .map_err(|_| Error::State)??;
        // Keep the verified pidfd even if API inspection or guest reconnection
        // subsequently fails. Recovery must retain authority to stop that VM.
        let router_root = self
            .config
            .state
            .directory
            .join("output")
            .join(intent.key.sandbox.as_str())
            .join(format!(
                "g{}-s{}",
                intent.key.sandbox_generation.get(),
                intent.key.generation.get()
            ));
        let router = Arc::new(if router_root.is_dir() {
            crate::exec::ExecEventRouter::restore(&router_root)?
        } else {
            crate::exec::ExecEventRouter::new(&router_root)?
        });
        let vm = Arc::new(LiveVm {
            owner: uid,
            intent: intent.clone(),
            process,
            manifest,
            guest: Mutex::new(None),
            exec_router: router.clone(),
            volume_locks: std::sync::Mutex::new(artifacts.volumes),
            transport_epoch: std::sync::atomic::AtomicU64::new(0),
        });
        self.insert(Arc::clone(&vm)).await?;
        if pending
            .as_ref()
            .is_some_and(|pending| pending.control == SessionControl::Stop)
            || intent.state == SessionState::Failed
        {
            let key = intent.key.clone();
            self.state
                .with_store(move |store| {
                    store.admit_runtime_loss(
                        uid,
                        &key,
                        sandboxd_protocol::EventKind::RecoveryFailed,
                        now_ms()?,
                    )
                })
                .await?;
            return self
                .apply_existing(uid, &intent.key, SessionControl::Stop)
                .await;
        }
        let client = Client::new(&vm.manifest.api_socket, Duration::from_secs(5))
            .and_then(|client| client.with_peer(vm.process.pid()))
            .map_err(|_| Error::Config("recovery control client rejected"))?;
        let info = client
            .instance_info()
            .await
            .map_err(|_| Error::Config("recovery VMM inspection failed"))?;
        validate_vmm(&info, &intent)?;
        let expected = expected_state(&intent, pending.as_ref());
        if pending.is_none() && info.state != expected {
            return Err(Error::Config(
                "unexplained runtime/durable session state mismatch",
            ));
        }
        let guest = if info.state == InstanceState::Running && pending.is_none() {
            Some(reconnect(&intent, &vm.manifest, &vm.process).await?)
        } else {
            None
        };
        if let Some(ref connection) = guest {
            let events = connection.subscribe_events();
            let router = router.clone();
            let state = self.state.clone();
            let uid_for_pump = uid;
            let key_for_pump = intent.key.clone();
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
                    eprintln!("recovered guest execution event pump stopped: {error}");
                    let failed = router.take_sink_failures().unwrap_or_default();
                    if !failed.is_empty() {
                        if let Some(guest) = vm_for_pump.guest.lock().await.as_ref() {
                            for exec in failed {
                                if let Ok(operation) = sandboxd_protocol::OperationId::new(format!(
                                    "sink-cancel-{}",
                                    exec.as_str()
                                )) {
                                    let _ = guest
                                        .request(
                                            operation,
                                            guest_protocol::GuestMessage::ExecCancel { exec },
                                        )
                                        .await;
                                }
                            }
                        }
                        return;
                    }
                    let _ = state
                        .with_store(move |store| {
                            store.admit_runtime_loss(
                                uid_for_pump,
                                &key_for_pump,
                                sandboxd_protocol::EventKind::GuestAgentLost,
                                now_ms()?,
                            )
                        })
                        .await;
                }
            });
        }
        *vm.guest.lock().await = guest;
        if let Some(pending) = pending {
            self.apply_existing(uid, &intent.key, pending.control)
                .await?;
        }
        Ok(())
    }
}

fn expected_state(intent: &LaunchIntent, pending: Option<&PendingSessionControl>) -> InstanceState {
    match pending.map(|p| p.control) {
        Some(SessionControl::Pause) => InstanceState::Paused,
        Some(SessionControl::Resume) => InstanceState::Running,
        _ if intent.state == SessionState::Paused => InstanceState::Paused,
        _ => InstanceState::Running,
    }
}
