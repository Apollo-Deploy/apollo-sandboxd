use super::{
    handlers::now_ms,
    runtime_service::RuntimeService,
    runtime_snapshot::{info, operation},
    runtime_snapshot_compatibility::{cpu_fingerprint, host_kernel},
};
use crate::{
    error::{Error, Result},
    state::{SessionPreparation, snapshot::SnapshotIntent},
};
use sandboxd_protocol::{ApiError, ErrorCode, Response};
use std::sync::Arc;
impl RuntimeService {
    pub(super) async fn restore_snapshot(
        self: &Arc<Self>,
        intent: SnapshotIntent,
    ) -> Result<Response> {
        let (uid, operation) = (intent.uid, intent.operation.clone());
        match self.restore_snapshot_inner(intent).await {
            Ok(response) => Ok(response),
            Err(error) => {
                let current = self
                    .state
                    .with_store(move |store| store.snapshot_intent(uid, &operation))
                    .await?;
                if current.restored_session.is_some() {
                    let (uid, operation) = (current.uid, current.operation.clone());
                    let absent = self
                        .state
                        .with_store(move |store| {
                            store.abort_snapshot_before_launch(uid, &operation, now_ms()?)
                        })
                        .await?;
                    if absent {
                        if let Some(output) = current.restored_output.clone() {
                            tokio::task::spawn_blocking(move || {
                                crate::exec::ExecEventRouter::snapshot_delete(&output)
                            })
                            .await
                            .map_err(|_| Error::State)??;
                        }
                        return self
                            .complete_snapshot(current, Response::Error(error.api()))
                            .await;
                    }
                }
                // Before session allocation there is no possible VMM. A disk
                // replacement is settled only once its identity committed.
                if current.restored_session.is_none()
                    && (current.replacement.is_none()
                        || current.record.drive.identity == current.replacement)
                {
                    self.complete_snapshot(current, Response::Error(error.api()))
                        .await
                } else {
                    Err(error)
                }
            }
        }
    }
    async fn restore_snapshot_inner(
        self: &Arc<Self>,
        mut intent: SnapshotIntent,
    ) -> Result<Response> {
        if let Some(restored) = &intent.restored_session {
            if self.current(intent.uid, &restored.key).await.is_ok() {
                return self
                    .complete_snapshot(intent.clone(), Response::Snapshot(info(&intent)?))
                    .await;
            }
            return Err(ApiError::new(
                ErrorCode::SessionUnavailable,
                "snapshot restore requires reconciliation before retry",
            )
            .into());
        }
        let catalog = self.snapshots.clone().ok_or(Error::State)?;
        let artifacts = intent.record.artifacts.clone().ok_or(Error::State)?;
        let verified = tokio::task::spawn_blocking(move || catalog.decrypt(&artifacts))
            .await
            .map_err(|_| Error::State)??;
        let manifest = &verified.manifest;
        let (uid, sandbox) = (intent.uid, intent.record.source.key.sandbox.clone());
        let spec = self
            .state
            .with_store(move |store| Ok(store.inspect(uid, &sandbox)?.spec))
            .await?;
        self.state.with_store_blocking({
            let volumes = spec.volumes.clone();
            let uid = intent.uid;
            move |s| s.validate_dynamic_volume_attachment(uid, &volumes)
        })?;
        let pins = self.authority.pins(intent.uid, &spec)?;
        if pins != intent.record.source.pins
            || manifest.runtime_profile != pins.runtime_profile
            || manifest.runtime_version != pins.runtime_version
            || manifest.firecracker_sha256 != pins.firecracker_sha256
            || manifest.jailer_sha256 != pins.jailer_sha256
            || manifest.kernel_sha256 != pins.kernel_sha256
            || manifest.initramfs_sha256 != pins.initramfs_sha256
            || manifest.base_image != pins.base_image
            || manifest.architecture != pins.architecture
            || manifest.snapshot_format != "full-v1"
            || manifest.session != intent.record.source.key.session
            || manifest.session_generation != intent.record.source.key.generation
            || manifest.boot_nonce.0 != intent.record.source.boot_nonce
            || manifest.has_received_secrets != intent.record.source.has_received_secrets
            || manifest.cpu_fingerprint != cpu_fingerprint()?
            || manifest.host_kernel_release != host_kernel()?
            || manifest.vsock_cid != intent.record.source.cid
            || manifest.checkpoint != intent.record.checkpoint
            || manifest.memory_mib != spec.resources.memory_mib
            || manifest.vcpu_count != u16::from(spec.resources.vcpus)
        {
            return Err(ApiError::new(
                ErrorCode::SnapshotIncompatible,
                "snapshot runtime, CPU, host kernel or resource compatibility differs",
            )
            .into());
        }
        let catalog = self.checkpoints.clone();
        let root = self.authority.execution.drive_directory.clone();
        let saved = intent.clone();
        let state = self.state.clone();
        let digest = manifest.writable_drive_sha256.clone();
        let replacement = tokio::task::spawn_blocking(move || {
            let checkpoint = catalog.inspect(&saved.record.checkpoint)?;
            if checkpoint.sha256 != digest
                || checkpoint.sandbox != saved.record.source.key.sandbox.as_str()
                || checkpoint.sandbox_generation != saved.record.source.key.sandbox_generation.get()
            {
                return Err(Error::State);
            }
            catalog.restore(
                &saved.record.checkpoint,
                &root,
                &saved.record.drive.volume,
                saved.record.drive.identity.ok_or(Error::State)?,
                &saved.operation,
                saved.replacement,
                |identity| {
                    let (uid, op) = (saved.uid, saved.operation.clone());
                    state.with_store_blocking(move |store| {
                        store.snapshot_update(uid, &op, |intent| {
                            intent.replacement = Some(identity);
                            Ok(())
                        })?;
                        Ok(())
                    })
                },
            )
        })
        .await
        .map_err(|_| Error::State)??;
        let (uid, op) = (intent.uid, intent.operation.clone());
        self.state
            .with_store(move |store| store.snapshot_replace_drive(uid, &op, replacement))
            .await?;
        let (uid, op, pools, boot_id) = (
            intent.uid,
            intent.operation.clone(),
            self.config.identities.clone(),
            self.authority.boot_id.clone(),
        );
        let restored = self
            .state
            .with_store(move |store| {
                store.prepare_snapshot_session(
                    uid,
                    &op,
                    SessionPreparation {
                        pins: &pins,
                        pools: &pools,
                        host_boot_id: &boot_id,
                        now_ms: now_ms()?,
                    },
                )
            })
            .await?;
        self.restore_snapshot_output(&intent, &restored, &verified.manifest.output_sha256)
            .await?;
        let boot = super::runtime_boot::start_with_snapshot(
            self.state.clone(),
            self.authority.clone(),
            intent.uid,
            restored.clone(),
            spec,
            operation("rebind")?,
            Some(verified),
        )
        .await;
        match boot {
            Ok(boot) => self.install(intent.uid, restored, boot).await?,
            Err(error) => {
                let (uid, key) = (intent.uid, restored.key);
                self.state
                    .with_store(move |store| store.runtime_failed(uid, &key, now_ms()?))
                    .await?;
                return Err(error);
            }
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
        self.complete_snapshot(intent.clone(), Response::Snapshot(info(&intent)?))
            .await
    }
}
