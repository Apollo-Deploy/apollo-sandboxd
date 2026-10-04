//! Recovery completes published captures; uncertain restores never launch a second VMM.
use super::{
    handlers::now_ms,
    runtime_control::{reconnect, validate_vmm},
    runtime_service::RuntimeService,
    runtime_snapshot::{info, operation},
};
use crate::{
    error::{Error, Result},
    state::snapshot::SnapshotIntent,
};
use firecracker_api::{Client, InstanceState};
use guest_protocol::GuestMessage;
use sandboxd_protocol::{ApiError, ErrorCode, Response, SnapshotCommand};
use std::{sync::Arc, time::Duration};
impl RuntimeService {
    pub(super) async fn recover_snapshots(self: &Arc<Self>) -> Result<()> {
        let pending = self
            .state
            .with_store(|store| store.pending_snapshots())
            .await?;
        for mut intent in pending {
            match &intent.command {
                SnapshotCommand::Delete { .. } => {
                    self.apply_snapshot(intent).await?;
                    continue;
                }
                SnapshotCommand::Restore { .. } => {
                    if intent.restore_aborted_before_launch {
                        if let Some(output) = intent.restored_output.clone() {
                            tokio::task::spawn_blocking(move || {
                                crate::exec::ExecEventRouter::snapshot_delete(&output)
                            })
                            .await
                            .map_err(|_| Error::State)??;
                        }
                        self.complete_snapshot(
                            intent,
                            Response::Error(ApiError::new(
                                ErrorCode::RecoveryFailed,
                                "snapshot restore interrupted before launch",
                            )),
                        )
                        .await?;
                        continue;
                    }
                    if let Some(launch) = &intent.restored_session {
                        let (uid, key) = (intent.uid, launch.key.clone());
                        let current = self
                            .state
                            .with_store(move |store| store.session_intent(uid, &key))
                            .await;
                        if let Ok(current) = current {
                            if current.state == sandboxd_protocol::SessionState::Active {
                                self.recover_one(intent.uid, current.clone()).await?;
                                let vm = self.current(intent.uid, &current.key).await?;
                                if vm.guest.lock().await.is_none() {
                                    return Err(Error::State);
                                }
                                let (uid, op) = (intent.uid, intent.operation.clone());
                                intent = self
                                    .state
                                    .with_store(move |store| {
                                        store.snapshot_update(uid, &op, |intent| {
                                            intent.record.suspended = false;
                                            Ok(())
                                        })
                                    })
                                    .await?;
                                self.complete_snapshot(
                                    intent.clone(),
                                    Response::Snapshot(info(&intent)?),
                                )
                                .await?;
                                continue;
                            }
                            let (uid, op) = (intent.uid, intent.operation.clone());
                            let absent = self
                                .state
                                .with_store(move |store| {
                                    store.abort_snapshot_before_launch(uid, &op, now_ms()?)
                                })
                                .await?;
                            if absent {
                                if let Some(output) = intent.restored_output.clone() {
                                    tokio::task::spawn_blocking(move || {
                                        crate::exec::ExecEventRouter::snapshot_delete(&output)
                                    })
                                    .await
                                    .map_err(|_| Error::State)??;
                                }
                            }
                            if !absent {
                                let (uid, key) = (intent.uid, current.key.clone());
                                self.state
                                    .with_store(move |store| {
                                        if store.session_process(uid, &key)?.is_some() {
                                            store.admit_runtime_loss(
                                                uid,
                                                &key,
                                                sandboxd_protocol::EventKind::RecoveryFailed,
                                                now_ms()?,
                                            )?;
                                        }
                                        Ok(())
                                    })
                                    .await?;
                                self.cleanup_untracked(intent.uid, &current.key).await?;
                            }
                        }
                        self.complete_snapshot(
                            intent,
                            Response::Error(ApiError::new(
                                ErrorCode::RecoveryFailed,
                                "snapshot restore interrupted; compute was not relaunched",
                            )),
                        )
                        .await?;
                    } else {
                        self.restore_snapshot(intent).await?;
                    }
                    continue;
                }
                _ => {}
            }
            if !intent.capture_started {
                self.complete_snapshot(
                    intent,
                    Response::Error(ApiError::new(
                        ErrorCode::RecoveryFailed,
                        "snapshot interrupted before capture effects",
                    )),
                )
                .await?;
                continue;
            }
            let recovered = match self.verify_recovered_snapshot(&intent).await {
                Ok(manifest) => manifest,
                Err(error) => {
                    // Authentication failure must not strand a still-running source
                    // under a guest filesystem freeze. Ownership remains journaled.
                    self.recover_failed_snapshot_source(&intent).await?;
                    return Err(error);
                }
            };
            if let Some(manifest) = recovered {
                let (uid, op) = (intent.uid, intent.operation.clone());
                intent = self
                    .state
                    .with_store(move |store| {
                        store.snapshot_update(uid, &op, |intent| {
                            intent.record.manifest = Some(manifest);
                            Ok(())
                        })
                    })
                    .await?;
                if matches!(intent.command, SnapshotCommand::Suspend { .. }) {
                    let (uid, key) = (intent.uid, intent.record.source.key.clone());
                    let current = self
                        .state
                        .with_store(move |store| {
                            let sandbox = store.inspect(uid, &key.sandbox)?;
                            if sandbox.session.is_none() {
                                Ok(None)
                            } else {
                                Ok(Some(store.session_intent(uid, &key)?))
                            }
                        })
                        .await?;
                    if let Some(current) = current {
                        let (uid, op) = (intent.uid, intent.operation.clone());
                        self.state
                            .with_store(move |store| store.snapshot_begin_suspend(uid, &op))
                            .await?;
                        self.cleanup_untracked(intent.uid, &current.key).await?;
                    }
                    let (uid, op) = (intent.uid, intent.operation.clone());
                    intent = self
                        .state
                        .with_store(move |store| store.snapshot_mark_suspended(uid, &op, now_ms()?))
                        .await?;
                } else {
                    self.recover_snapshot_transport(&intent).await?;
                }
                self.complete_snapshot(intent.clone(), Response::Snapshot(info(&intent)?))
                    .await?;
            } else {
                self.recover_snapshot_transport(&intent).await?;
                self.discard_snapshot_capture(&intent).await?;
                self.complete_snapshot(
                    intent,
                    Response::Error(ApiError::new(
                        ErrorCode::RecoveryFailed,
                        "snapshot capture interrupted before authenticated publication",
                    )),
                )
                .await?;
            }
        }
        Ok(())
    }
    async fn recover_failed_snapshot_source(&self, intent: &SnapshotIntent) -> Result<()> {
        let (uid, key) = (intent.uid, intent.record.source.key.clone());
        let terminating = self
            .state
            .with_store(move |store| {
                if store.inspect(uid, &key.sandbox)?.session.is_none() {
                    return Ok(false);
                }
                Ok(store.session_intent(uid, &key)?.state
                    == sandboxd_protocol::SessionState::Terminating)
            })
            .await?;
        if terminating {
            self.cleanup_untracked(intent.uid, &intent.record.source.key)
                .await
        } else {
            self.recover_snapshot_transport(intent).await
        }
    }
    async fn verify_recovered_snapshot(
        &self,
        intent: &SnapshotIntent,
    ) -> Result<Option<crate::snapshot::SnapshotManifest>> {
        let catalog = self.snapshots.clone().ok_or(Error::State)?;
        let checkpoints = self.checkpoints.clone();
        let intent = intent.clone();
        tokio::task::spawn_blocking(move || {
            let Some(artifacts) = intent.record.artifacts else {
                return Ok(None);
            };
            if !catalog.recover_publish(&artifacts)? {
                catalog.delete(&artifacts)?;
                return Ok(None);
            }
            let manifest = catalog.verify(&artifacts)?;
            let output = intent.record.output.ok_or(Error::State)?;
            if hex::encode(output.digest) != manifest.output_sha256 {
                return Err(Error::State);
            }
            crate::exec::ExecEventRouter::snapshot_verify(&output)?;
            if checkpoints.inspect(&intent.record.checkpoint)?.sha256
                != manifest.writable_drive_sha256
            {
                return Err(Error::State);
            }
            let _ = checkpoints.verify_file(&intent.record.checkpoint)?;
            Ok(Some(manifest))
        })
        .await
        .map_err(|_| Error::State)?
    }
    async fn recover_snapshot_transport(&self, intent: &SnapshotIntent) -> Result<()> {
        let (uid, key) = (intent.uid, intent.record.source.key.clone());
        let current = self
            .state
            .with_store(move |store| {
                let sandbox = store.inspect(uid, &key.sandbox)?;
                if sandbox.session.is_none() {
                    return Ok(None);
                }
                Ok(Some((
                    store.session_intent(uid, &key)?,
                    store.session_process(uid, &key)?.ok_or(Error::State)?,
                    store.session_resources(uid, &key)?.ok_or(Error::State)?,
                )))
            })
            .await?;
        let Some((launch, record, manifest)) = current else {
            return Ok(());
        };
        #[cfg(target_os = "linux")]
        if crate::process::prove_recorded_absent(&record)? {
            return Ok(());
        }
        let process = crate::process::ProcessIdentity::reopen_verified(&record)?;
        let client = Client::new(&manifest.api_socket, Duration::from_secs(5))
            .and_then(|c| c.with_peer(process.pid()))
            .map_err(|_| Error::State)?;
        let observed = client.instance_info().await.map_err(|_| Error::State)?;
        validate_vmm(&observed, &launch)?;
        if observed.state == InstanceState::Paused {
            client.resume().await.map_err(|_| Error::State)?;
        }
        let guest = reconnect(&launch, &manifest, &process).await?;
        let thaw = operation("recovery-thaw")?;
        let reply = guest
            .request(thaw.clone(), GuestMessage::FilesystemUnquiesce)
            .await?;
        if !matches!(reply.message, GuestMessage::Ready) {
            return Err(Error::State);
        }
        for retired in [
            sandboxd_protocol::OperationId::new("snapshot-freeze").map_err(|_| Error::State)?,
            sandboxd_protocol::OperationId::new("snapshot-thaw").map_err(|_| Error::State)?,
            thaw,
        ] {
            let _ = guest
                .request(
                    operation("recovery-retire")?,
                    GuestMessage::RetireOperation { operation: retired },
                )
                .await;
        }
        for name in ["snapshot-memory", "snapshot-state"] {
            crate::session::snapshot_assets::open_capture(&manifest.assets, name)?.set_len(0)?;
        }
        Ok(())
    }
}
