//! Freeze the guest filesystem then pause the VMM; restore both on every ordinary failure.
use super::{runtime_control::validate_vmm, runtime_service::RuntimeService};
use crate::{
    error::{Error, Result},
    state::checkpoint::{CheckpointIntent, id},
    storage::checkpoint_restore::open_drive,
};
use firecracker_api::{Client, InstanceState};
use guest_protocol::GuestMessage;
use sandboxd_protocol::{OperationId, Response};
use std::time::Duration;

pub(super) fn operation(intent: &CheckpointIntent, phase: &str) -> Result<OperationId> {
    use sha2::{Digest, Sha256};
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::State)?;
    OperationId::new(format!(
        "cp-{phase}-{}-{}",
        hex::encode(nonce),
        &hex::encode(Sha256::digest(intent.operation.as_str().as_bytes()))[..16]
    ))
    .map_err(|_| Error::State)
}

impl RuntimeService {
    pub(super) async fn create_checkpoint(&self, intent: CheckpointIntent) -> Result<Response> {
        // Allocate identifiers before any guest/VMM effect so cleanup cannot fail on randomness.
        let freeze_operation = operation(&intent, "freeze")?;
        let thaw_operation = operation(&intent, "thaw")?;
        let retry_operation = operation(&intent, "retry-thaw")?;
        let key = intent.session.as_ref().ok_or(Error::State)?;
        let vm = self.current(intent.uid, key).await?;
        vm.process.verify()?;
        let client = Client::new(&vm.manifest.api_socket, Duration::from_secs(5))
            .and_then(|c| c.with_peer(vm.process.pid()))
            .map_err(|_| Error::State)?;
        let before = client.instance_info().await.map_err(|_| Error::State)?;
        validate_vmm(&before, &vm.intent)?;
        if before.state == InstanceState::Paused {
            // A prior attempt can lose the resume acknowledgement while retaining its durable intent.
            client.resume().await.map_err(|_| Error::State)?;
        } else if before.state != InstanceState::Running {
            return Err(Error::State);
        }
        let guest = vm.guest.lock().await;
        let guest = guest.as_ref().ok_or(Error::State)?;
        let result = async {
            let thaw = guest
                .request(retry_operation.clone(), GuestMessage::FilesystemUnquiesce)
                .await?;
            if !matches!(thaw.message, GuestMessage::Ready) {
                return Err(Error::State);
            }

            let reply = guest
                .request(freeze_operation.clone(), GuestMessage::FilesystemQuiesce)
                .await?;
            if !matches!(reply.message, GuestMessage::Ready) {
                return Err(Error::State);
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
            tokio::task::spawn_blocking(move || {
                let checkpoint = id(&saved.command);
                if let Some(stage) = &saved.staging {
                    catalog.cleanup_stage(stage)?;
                }
                let manifest = match catalog.inspect(checkpoint) {
                    Ok(manifest) => manifest,
                    Err(Error::Kernel(rustix::io::Errno::NOENT)) => {
                        let source = open_drive(
                            &root,
                            &saved.drive.volume,
                            saved.drive.identity.ok_or(Error::State)?,
                        )?;
                        catalog.create_journaled(
                            checkpoint.clone(),
                            saved.drive.sandbox.to_string(),
                            saved.drive.generation.get(),
                            &source,
                            saved.drive.identity.ok_or(Error::State)?,
                            |stage| {
                                let stage = stage.clone();
                                let operation = saved.operation.clone();
                                let uid = saved.uid;
                                state.with_store_blocking(move |store| {
                                    store.checkpoint_staging(uid, &operation, &stage)
                                })
                            },
                        )?
                    }
                    Err(error) => return Err(error),
                };
                if manifest.sandbox != saved.drive.sandbox.as_str()
                    || manifest.sandbox_generation != saved.drive.generation.get()
                    || manifest.source != saved.drive.identity.ok_or(Error::State)?
                {
                    return Err(Error::State);
                }
                catalog.verify_file(checkpoint)?;
                Ok(manifest)
            })
            .await
            .map_err(|_| Error::State)?
        }
        .await;
        // A timeout may mean the pause/freeze took effect. Always send both inverses.
        let resumed = client.resume().await.map_err(|_| Error::State);
        let thawed = guest
            .request(thaw_operation.clone(), GuestMessage::FilesystemUnquiesce)
            .await
            .and_then(|r| {
                if matches!(r.message, GuestMessage::Ready) {
                    Ok(())
                } else {
                    Err(Error::State)
                }
            });
        if thawed.is_ok() {
            for target in [freeze_operation, thaw_operation, retry_operation] {
                use sha2::{Digest, Sha256};
                let retired = OperationId::new(format!(
                    "retire-{}",
                    &hex::encode(Sha256::digest(target.as_str().as_bytes()))[..24]
                ))
                .map_err(|_| Error::State)?;
                let _ = guest
                    .request(retired, GuestMessage::RetireOperation { operation: target })
                    .await;
            }
        }
        resumed?;
        thawed?;
        let after = client.instance_info().await.map_err(|_| Error::State)?;
        validate_vmm(&after, &vm.intent)?;
        if after.state != InstanceState::Running {
            return Err(Error::State);
        }
        // Failures leave a durable reservation for recovery: partial publication is never forgotten.
        let manifest = result?;
        let info: sandboxd_protocol::CheckpointInfo = manifest.into();
        let response = Response::Checkpoint(info.clone());
        let saved = response.clone();
        self.state
            .with_store(move |store| store.finish_checkpoint(&intent, &saved, Some(&info), None))
            .await?;
        Ok(response)
    }
}
