//! Capture one full VM state and its exact paused filesystem, then restore live transport.
use super::{
    handlers::now_ms,
    runtime_control::{reconnect, validate_vmm},
    runtime_service::RuntimeService,
    runtime_snapshot::{info, operation},
    runtime_snapshot_compatibility::{cpu_fingerprint, host_kernel},
};
use crate::{
    error::{Error, Result},
    session::snapshot_assets::open_capture,
    state::snapshot::SnapshotIntent,
};
use firecracker_api::{Client, InstanceState, SnapshotCreate, SnapshotType};
use guest_protocol::GuestMessage;
use sandboxd_protocol::{Response, SessionControl, SnapshotCommand};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

impl RuntimeService {
    pub(super) async fn capture_snapshot(
        self: &Arc<Self>,
        mut intent: SnapshotIntent,
    ) -> Result<Response> {
        if intent.capture_started {
            return Err(sandboxd_protocol::ApiError::new(
                sandboxd_protocol::ErrorCode::SessionUnavailable,
                "snapshot capture requires reconciliation before retry",
            )
            .into());
        }
        let preflight = async {
            let vm = self.current(intent.uid, &intent.record.source.key).await?;
            vm.process.verify()?;
            let router = vm.exec_router.clone();
            tokio::task::spawn_blocking(move || router.validate_snapshot_capture())
                .await
                .map_err(|_| Error::State)??;

            let client = Client::new(&vm.manifest.api_socket, Duration::from_secs(30))
                .and_then(|c| c.with_peer(vm.process.pid()))
                .map_err(|_| Error::State)?;
            let before = client.instance_info().await.map_err(|_| Error::State)?;
            validate_vmm(&before, &vm.intent)?;
            if before.state != InstanceState::Running {
                return Err(Error::State);
            }
            let memory = open_capture(&vm.manifest.assets, "snapshot-memory")?;
            let state_file = open_capture(&vm.manifest.assets, "snapshot-state")?;
            memory.set_len(0)?;
            state_file.set_len(0)?;
            Ok::<_, Error>((vm, client, memory, state_file))
        }
        .await;
        let (vm, client, memory, state_file) = match preflight {
            Ok(inputs) => inputs,
            Err(error) => {
                return self
                    .complete_snapshot(intent, Response::Error(error.api()))
                    .await;
            }
        };
        let thaw =
            sandboxd_protocol::OperationId::new("snapshot-thaw").map_err(|_| Error::State)?;
        let freeze =
            sandboxd_protocol::OperationId::new("snapshot-freeze").map_err(|_| Error::State)?;
        let (uid, op) = (intent.uid, intent.operation.clone());
        intent = self
            .state
            .with_store(move |store| {
                store.snapshot_update(uid, &op, |intent| {
                    intent.capture_started = true;
                    Ok(())
                })
            })
            .await?;
        let mut result = async {
            crate::snapshot::validate_memory_policy()?;
            {
                let guest = vm.guest.lock().await;
                let guest = guest.as_ref().ok_or(Error::State)?;
                let response = guest
                    .request(freeze.clone(), GuestMessage::FilesystemQuiesce)
                    .await?;
                if !matches!(response.message, GuestMessage::Ready) {
                    return Err(Error::State);
                }
            }
            client.pause().await.map_err(|_| Error::State)?;
            let paused = client.instance_info().await.map_err(|_| Error::State)?;
            validate_vmm(&paused, &vm.intent)?;
            if paused.state != InstanceState::Paused {
                return Err(Error::State);
            }
            let catalog = self.checkpoints.clone();
            let root = self.authority.execution.drive_directory.clone();
            let saved = intent.clone();
            let state = self.state.clone();
            let checkpoint = tokio::task::spawn_blocking(move || {
                if let Some(stage) = &saved.checkpoint_stage {
                    catalog.cleanup_stage(stage)?;
                }
                let source = crate::storage::checkpoint_restore::open_drive(
                    &root,
                    &saved.record.drive.volume,
                    saved.record.drive.identity.ok_or(Error::State)?,
                )?;
                catalog.create_journaled(
                    saved.record.checkpoint.clone(),
                    saved.record.drive.sandbox.to_string(),
                    saved.record.drive.generation.get(),
                    &source,
                    saved.record.drive.identity.ok_or(Error::State)?,
                    |stage| {
                        let (uid, op, stage) = (saved.uid, saved.operation.clone(), stage.clone());
                        state.with_store_blocking(move |store| {
                            store.snapshot_update(uid, &op, |intent| {
                                intent.checkpoint_stage = Some(stage);
                                Ok(())
                            })?;
                            Ok(())
                        })
                    },
                )
            })
            .await
            .map_err(|_| Error::State)??;
            // Firecracker invalidates existing vsock streams during snapshot creation.
            vm.transport_epoch.fetch_add(1, Ordering::AcqRel);
            client
                .snapshot_create(&SnapshotCreate {
                    snapshot_type: SnapshotType::Full,
                    snapshot_path: "/snapshot-state".into(),
                    mem_file_path: "/snapshot-memory".into(),
                    sync_snapshot_files: true,
                })
                .await
                .map_err(|_| Error::State)?;
            let memory_bytes = memory.metadata()?.len();
            let state_bytes = state_file.metadata()?.len();
            let sandbox = {
                let (uid, id) = (intent.uid, intent.record.drive.sandbox.clone());
                self.state
                    .with_store(move |store| store.inspect(uid, &id))
                    .await?
            };
            if memory_bytes != u64::from(sandbox.spec.resources.memory_mib) * (1 << 20)
                || state_bytes == 0
                || state_bytes > 64 << 20
            {
                return Err(Error::State);
            }
            let output_sha256 = self.capture_snapshot_output(&vm, &intent).await?;
            let secret_policy = match intent.command {
                SnapshotCommand::Create { secret_policy, .. }
                | SnapshotCommand::Suspend { secret_policy, .. } => secret_policy,
                _ => return Err(Error::State),
            };
            let source = &intent.record.source;
            let manifest = crate::snapshot::SnapshotManifest {
                version: 1,
                id: intent.command.id().clone(),
                sandbox: source.key.sandbox.clone(),
                sandbox_generation: source.key.sandbox_generation,
                session: source.key.session.clone(),
                session_generation: source.key.generation,
                runtime_profile: source.pins.runtime_profile.clone(),
                runtime_version: source.pins.runtime_version.clone(),
                firecracker_sha256: source.pins.firecracker_sha256.clone(),
                jailer_sha256: source.pins.jailer_sha256.clone(),
                kernel_sha256: source.pins.kernel_sha256.clone(),
                initramfs_sha256: source.pins.initramfs_sha256.clone(),
                base_image: source.pins.base_image.clone(),
                writable_drive_sha256: checkpoint.sha256,
                snapshot_format: "full-v1".into(),
                memory_bytes,
                state_bytes,
                memory_sha256: "0".repeat(64),
                state_sha256: "0".repeat(64),
                output_sha256,
                secret_policy: secret_policy.into(),
                vsock_cid: source.cid,
                boot_nonce: guest_protocol::BootNonce(source.boot_nonce),
                architecture: source.pins.architecture,
                host_boot_id: source.host_boot_id.clone(),
                host_kernel_release: host_kernel()?,
                cpu_fingerprint: cpu_fingerprint()?,
                checkpoint: intent.record.checkpoint.clone(),
                has_received_secrets: source.has_received_secrets,
                memory_mib: sandbox.spec.resources.memory_mib,
                vcpu_count: u16::from(sandbox.spec.resources.vcpus),
            };
            let catalog = self.snapshots.clone().ok_or(Error::State)?;
            let saved = intent.clone();
            let state = self.state.clone();
            let (mem, device) = (memory.try_clone()?, state_file.try_clone()?);
            let manifest = tokio::task::spawn_blocking(move || {
                let record = catalog.publish(&manifest, &mem, &device, |artifacts| {
                    let (uid, op, artifacts) =
                        (saved.uid, saved.operation.clone(), artifacts.clone());
                    state.with_store_blocking(move |store| {
                        store.snapshot_update(uid, &op, |intent| {
                            intent.record.artifacts = Some(artifacts);
                            Ok(())
                        })?;
                        Ok(())
                    })
                })?;
                catalog.verify(&record)
            })
            .await
            .map_err(|_| Error::State)??;
            let (uid, op) = (intent.uid, intent.operation.clone());
            self.state
                .with_store(move |store| {
                    store.snapshot_update(uid, &op, |intent| {
                        intent.record.manifest = Some(manifest);
                        Ok(())
                    })
                })
                .await
        }
        .await;
        if result.is_ok() && matches!(intent.command, SnapshotCommand::Suspend { .. }) {
            let (uid, op) = (intent.uid, intent.operation.clone());
            // A successful suspend never schedules captured guest code again.
            let stopping = self
                .state
                .with_store(move |store| store.snapshot_begin_suspend(uid, &op))
                .await;
            if stopping.is_ok() {
                self.apply_existing(intent.uid, &intent.record.source.key, SessionControl::Stop)
                    .await?;
                let (uid, op) = (intent.uid, intent.operation.clone());
                intent = self
                    .state
                    .with_store(move |store| store.snapshot_mark_suspended(uid, &op, now_ms()?))
                    .await?;
                return self
                    .complete_snapshot(intent.clone(), Response::Snapshot(info(&intent)?))
                    .await;
            }
            result = Err(stopping.err().ok_or(Error::State)?);
        }
        // Every ordinary failure attempts both inverses, including ambiguous acknowledgements.
        let resumed = async {
            let observed = client.instance_info().await.map_err(|_| Error::State)?;
            validate_vmm(&observed, &vm.intent)?;
            match observed.state {
                InstanceState::Running => Ok(()),
                InstanceState::Paused => client.resume().await.map_err(|_| Error::State),
                _ => Err(Error::State),
            }
        }
        .await;
        vm.transport_epoch.fetch_add(1, Ordering::AcqRel);
        let router = vm.exec_router.clone();
        let gap_recorded =
            tokio::task::spawn_blocking(move || router.record_transport_reset()).await;
        let old = vm.guest.lock().await.take();
        drop(old);
        let reconnected = reconnect(&vm.intent, &vm.manifest, &vm.process).await;
        let thawed = match reconnected {
            Ok(guest) => {
                let reply = guest
                    .request(thaw.clone(), GuestMessage::FilesystemUnquiesce)
                    .await;
                if matches!(&reply, Ok(peer) if matches!(peer.message,GuestMessage::Ready)) {
                    for retired in [freeze.clone(), thaw.clone()] {
                        if let Ok(retire) = operation("retire") {
                            let _ = guest
                                .request(
                                    retire,
                                    GuestMessage::RetireOperation { operation: retired },
                                )
                                .await;
                        }
                    }
                }
                let events = guest.subscribe_events();
                *vm.guest.lock().await = Some(guest);
                let router = vm.exec_router.clone();
                let runtime = self.clone();
                let observed = vm.clone();
                let epoch = vm.transport_epoch.load(Ordering::Acquire);
                tokio::spawn(async move {
                    if router.run(events).await.is_err()
                        && observed.transport_epoch.load(Ordering::Acquire) == epoch
                    {
                        let (uid, key) = (observed.owner, observed.intent.key.clone());
                        let _ = runtime
                            .state
                            .with_store(move |store| {
                                store.admit_runtime_loss(
                                    uid,
                                    &key,
                                    sandboxd_protocol::EventKind::GuestAgentLost,
                                    now_ms()?,
                                )
                            })
                            .await;
                    }
                });
                reply.and_then(|r| {
                    if matches!(r.message, GuestMessage::Ready) {
                        Ok(())
                    } else {
                        Err(Error::State)
                    }
                })
            }
            Err(error) => Err(error),
        };
        memory.set_len(0)?;
        state_file.set_len(0)?;
        resumed?;
        thawed?;
        gap_recorded.map_err(|_| Error::State)??;
        intent = match result {
            Ok(intent) => intent,
            Err(error) => {
                self.discard_snapshot_capture(&intent).await?;
                return self
                    .complete_snapshot(intent, Response::Error(error.api()))
                    .await;
            }
        };
        let response = Response::Snapshot(info(&intent)?);
        self.complete_snapshot(intent, response).await
    }
}
