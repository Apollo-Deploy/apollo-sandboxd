//! Effects are serialized by RuntimeQueue; each lookup also checks the full session key.
use super::{handlers::now_ms, runtime_service::RuntimeService};
use crate::{
    error::{Error, Result},
    guest::{GuestConnection, GuestEndpoint},
    process::ProcessIdentity,
    state::{LaunchIntent, SessionKey},
};
use firecracker_api::{Client, InstanceState};
use guest_protocol::{BootNonce, GUEST_PROTOCOL_VERSION, SessionIdentity};
use sandboxd_protocol::{OperationId, SessionControl};
use std::time::Duration;

impl RuntimeService {
    pub(super) async fn apply_existing(
        &self,
        uid: u32,
        key: &SessionKey,
        control: SessionControl,
    ) -> Result<()> {
        if control == SessionControl::Stop {
            let vm = match self.current(uid, key).await {
                Ok(vm) => vm,
                Err(_) => {
                    // Failed installation still has a durable process and
                    // manifest; reacquire that exact process for cleanup.
                    self.cleanup_untracked(uid, key).await?;
                    return Ok(());
                }
            };
            // The original pidfd remains valid after death, allowing partial cleanup retries.
            let proof = crate::session::stop_and_cleanup(&vm.process, &vm.manifest, key).await?;
            let key = key.clone();
            self.state
                .with_store(move |store| store.record_session_stopped(uid, &key, proof, now_ms()?))
                .await?;
            let mut live = self.live.lock().await;
            if live
                .get(&vm.intent.key.sandbox)
                .is_some_and(|current| current.intent.key == vm.intent.key)
            {
                live.remove(&vm.intent.key.sandbox);
            }
            return Ok(());
        }
        let vm = self.current(uid, key).await?;
        vm.process.verify()?;
        let client = Client::new(&vm.manifest.api_socket, Duration::from_secs(5))
            .and_then(|client| client.with_peer(vm.process.pid()))
            .map_err(|_| Error::Config("Firecracker control client rejected"))?;
        let target = match control {
            SessionControl::Pause => InstanceState::Paused,
            SessionControl::Resume => InstanceState::Running,
            _ => return Err(Error::State),
        };
        let before = client
            .instance_info()
            .await
            .map_err(|_| Error::Config("Firecracker state inspection failed"))?;
        validate_vmm(&before, &vm.intent)?;
        if before.state != target {
            match control {
                SessionControl::Pause => client.pause().await,
                SessionControl::Resume => client.resume().await,
                _ => return Err(Error::State),
            }
            .map_err(|_| Error::Config("Firecracker lifecycle effect failed"))?;
        }
        let after = client
            .instance_info()
            .await
            .map_err(|_| Error::Config("Firecracker state observation failed"))?;
        validate_vmm(&after, &vm.intent)?;
        if after.state != target {
            return Err(Error::State);
        }
        // A paused VM cannot answer a guest handshake. Reconnect only after actual resume.
        if control == SessionControl::Resume && vm.guest.lock().await.is_none() {
            let guest = reconnect(&vm.intent, &vm.manifest, &vm.process).await?;
            let events = guest.subscribe_events();
            let router = vm.exec_router.clone();
            let state = self.state.clone();
            let uid_for_pump = uid;
            let key_for_pump = key.clone();
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
                    eprintln!("resumed guest execution event pump stopped: {error}");
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
            *vm.guest.lock().await = Some(guest);
        }
        let (record, key) = (vm.process.persisted(), key.clone());
        self.state
            .with_store(move |store| {
                let process = ProcessIdentity::reopen_verified(&record)?;
                match control {
                    SessionControl::Pause => {
                        store.record_session_paused(uid, &key, &process, now_ms()?)
                    }
                    SessionControl::Resume => {
                        store.record_session_resumed(uid, &key, &process, now_ms()?)
                    }
                    _ => Err(Error::State),
                }
            })
            .await
    }
}

pub(super) fn validate_vmm(
    info: &firecracker_api::InstanceInfo,
    intent: &LaunchIntent,
) -> Result<()> {
    if info.id != intent.key.session.as_str()
        || info.app_name != "Firecracker"
        || info.vmm_version != intent.pins.runtime_version
    {
        return Err(Error::Config(
            "Firecracker session identity differs from durable pins",
        ));
    }
    Ok(())
}

pub(super) async fn reconnect(
    intent: &LaunchIntent,
    manifest: &crate::session::LaunchManifest,
    process: &ProcessIdentity,
) -> Result<GuestConnection> {
    #[cfg(target_os = "linux")]
    let endpoint = GuestEndpoint::observed_for_session(
        &manifest.vsock_socket,
        manifest,
        intent.uid,
        intent.gid,
    )?;
    #[cfg(not(target_os = "linux"))]
    let endpoint = GuestEndpoint::observed(&manifest.vsock_socket)?;
    let expected = SessionIdentity {
        sandbox: intent.key.sandbox.clone(),
        sandbox_generation: intent.key.sandbox_generation,
        session: intent.key.session.clone(),
        session_generation: intent.key.generation,
        boot_nonce: BootNonce(intent.boot_nonce),
        vsock_cid: intent.cid,
        protocol_version: GUEST_PROTOCOL_VERSION,
    };
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::State)?;
    let operation =
        OperationId::new(format!("handshake-{}", hex::encode(nonce))).map_err(|_| Error::State)?;
    GuestConnection::connect_with_process_timeout(
        &endpoint,
        expected,
        operation,
        Duration::from_secs(5),
        process,
    )
    .await
}
