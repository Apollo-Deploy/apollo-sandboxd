//! Resolve interrupted checkpoint effects before ordinary VM adoption.
use super::{
    runtime_checkpoint_create::operation,
    runtime_control::{reconnect, validate_vmm},
    runtime_service::RuntimeService,
};
use crate::{
    error::{Error, Result},
    state::checkpoint::id,
};
use firecracker_api::{Client, InstanceState};
use guest_protocol::GuestMessage;
use sandboxd_protocol::Response;
use std::time::Duration;
impl RuntimeService {
    /// Executed before normal VM reconciliation so a crash during copy cannot leave an unexplained pause.
    pub(super) async fn recover_checkpoints(&self) -> Result<()> {
        let intents = self
            .state
            .with_store(|store| store.pending_checkpoints())
            .await?;
        for intent in intents {
            if !matches!(
                intent.command,
                sandboxd_protocol::CheckpointCommand::Create { .. }
            ) {
                self.apply_checkpoint(intent).await?;
                continue;
            }
            let key = intent.session.clone().ok_or(Error::State)?;
            let uid = intent.uid;
            let current = self
                .state
                .with_store(move |store| {
                    let sandbox = store.inspect(uid, &key.sandbox)?;
                    if sandbox.generation != key.sandbox_generation {
                        return Err(Error::State);
                    }
                    if sandbox.session.is_none()
                        && sandbox.state == sandboxd_protocol::SandboxState::Stopped
                    {
                        return Ok(None);
                    }
                    Ok(Some((
                        store.session_intent(uid, &key)?,
                        store.session_process(uid, &key)?.ok_or(Error::State)?,
                        store.session_resources(uid, &key)?.ok_or(Error::State)?,
                    )))
                })
                .await?;
            if let Some((launch, record, manifest)) = current {
                #[cfg(target_os = "linux")]
                let absent = crate::process::prove_recorded_absent(&record)?;
                #[cfg(not(target_os = "linux"))]
                let absent = false;
                if !absent {
                    let process = crate::process::ProcessIdentity::reopen_verified(&record)?;
                    let client = Client::new(&manifest.api_socket, Duration::from_secs(5))
                        .and_then(|c| c.with_peer(process.pid()))
                        .map_err(|_| Error::State)?;
                    let info = client.instance_info().await.map_err(|_| Error::State)?;
                    validate_vmm(&info, &launch)?;
                    if info.state == InstanceState::Paused {
                        client.resume().await.map_err(|_| Error::State)?;
                    }
                    let guest = reconnect(&launch, &manifest, &process).await?;
                    let reply = guest
                        .request(
                            operation(&intent, "recover-thaw")?,
                            GuestMessage::FilesystemUnquiesce,
                        )
                        .await?;
                    if !matches!(reply.message, GuestMessage::Ready) {
                        return Err(Error::State);
                    }
                }
            }
            let catalog = self.checkpoints.clone();
            let checkpoint = id(&intent.command).clone();
            let stage = intent.staging.clone();
            let info = tokio::task::spawn_blocking(move || {
                if let Some(stage) = stage {
                    catalog.cleanup_stage(&stage)?;
                }
                let manifest = catalog.inspect(&checkpoint)?;
                catalog.verify_file(&checkpoint)?;
                Ok::<_, Error>(manifest)
            })
            .await
            .map_err(|_| Error::State)?;
            let (response, info) = match info {
                Ok(manifest)
                    if manifest.sandbox == intent.drive.sandbox.as_str()
                        && manifest.sandbox_generation == intent.drive.generation.get()
                        && Some(manifest.source) == intent.drive.identity =>
                {
                    let info: sandboxd_protocol::CheckpointInfo = manifest.into();
                    (Response::Checkpoint(info.clone()), Some(info))
                }
                Err(Error::Kernel(rustix::io::Errno::NOENT)) => (
                    Response::Error(sandboxd_protocol::ApiError::new(
                        sandboxd_protocol::ErrorCode::RecoveryFailed,
                        "checkpoint interrupted before publication",
                    )),
                    None,
                ),
                _ => return Err(Error::State),
            };
            self.state
                .with_store(move |store| {
                    store.finish_checkpoint(&intent, &response, info.as_ref(), None)
                })
                .await?;
        }
        Ok(())
    }
}
