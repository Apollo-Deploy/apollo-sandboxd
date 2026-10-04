//! Queue-owned checkpoint effects continue after caller disconnect and retain unresolved intents.
use super::{handlers::now_ms, runtime_service::RuntimeService, state_worker::deadline_error};
use crate::{
    error::{Error, Result},
    security::peer::Peer,
    state::checkpoint::{CheckpointAdmission, CheckpointIntent, fence, id},
};
use sandboxd_protocol::{CheckpointCommand, CheckpointInfo, Request, Response};
use std::sync::Arc;
use tokio::{
    sync::oneshot,
    time::{Instant, timeout_at},
};
impl RuntimeService {
    pub async fn checkpoint_request(
        self: &Arc<Self>,
        peer: Peer,
        request: Request,
        deadline: Instant,
    ) -> Result<Response> {
        let Request::Checkpoint {
            operation,
            operation_sequence,
            command,
        } = request
        else {
            return Err(Error::State);
        };
        let sandbox = fence(&command).sandbox.clone();
        let runtime = self.clone();
        let (reply, receive) = oneshot::channel();
        let completed = self
            .queue
            .submit(sandbox, async move {
                let limits = runtime.config.checkpoints.clone();
                let admitted = runtime
                    .state
                    .with_store(move |store| {
                        if reply.is_closed() || Instant::now() >= deadline {
                            let _ = reply.send(Err(deadline_error()));
                            return Ok(None);
                        }
                        let result = store.admit_checkpoint(
                            peer.uid,
                            &operation,
                            operation_sequence,
                            &command,
                            &limits,
                            now_ms()?,
                        );
                        Ok(Some((reply, result)))
                    })
                    .await?;
                if let Some((reply, result)) = admitted {
                    let response = match result {
                        Ok(CheckpointAdmission::Complete(response)) => Ok(response),
                        Ok(CheckpointAdmission::Pending(intent)) => {
                            runtime.apply_checkpoint(intent).await
                        }
                        Err(error) => Err(error),
                    };
                    let _ = reply.send(response);
                }
                Ok(())
            })
            .await?;
        drop(completed);
        timeout_at(deadline, receive)
            .await
            .map_err(|_| deadline_error())?
            .map_err(|_| Error::State)?
    }
    pub(super) async fn apply_checkpoint(&self, intent: CheckpointIntent) -> Result<Response> {
        match intent.command {
            CheckpointCommand::Create { .. } => self.create_checkpoint(intent).await,
            CheckpointCommand::Restore { .. } => {
                let catalog = self.checkpoints.clone();
                let root = self.authority.execution.drive_directory.clone();
                let state = self.state.clone();
                let saved = intent.clone();
                let replacement = tokio::task::spawn_blocking(move || {
                    let manifest = catalog.inspect(id(&saved.command))?;
                    if manifest.sandbox != saved.drive.sandbox.as_str()
                        || manifest.sandbox_generation != saved.drive.generation.get()
                    {
                        return Err(Error::State);
                    }
                    let recorded = saved.clone();
                    catalog.restore(
                        id(&saved.command),
                        &root,
                        &saved.drive.volume,
                        saved.drive.identity.ok_or(Error::State)?,
                        &saved.operation,
                        saved.replacement,
                        |identity| {
                            state.with_store_blocking(move |store| {
                                store.checkpoint_replacement(&recorded, identity)
                            })
                        },
                    )
                })
                .await
                .map_err(|_| Error::State)??;
                let catalog = self.checkpoints.clone();
                let checkpoint = id(&intent.command).clone();
                let info = tokio::task::spawn_blocking(move || catalog.inspect(&checkpoint))
                    .await
                    .map_err(|_| Error::State)??;
                let response = Response::Checkpoint(info.into());
                let saved = response.clone();
                self.state
                    .with_store(move |store| {
                        store.finish_checkpoint(&intent, &saved, None, Some(replacement))
                    })
                    .await?;
                Ok(response)
            }
            CheckpointCommand::Delete { .. } => {
                let catalog = self.checkpoints.clone();
                let checkpoint = id(&intent.command).clone();
                tokio::task::spawn_blocking(move || catalog.delete(&checkpoint))
                    .await
                    .map_err(|_| Error::State)??;
                let response = Response::CheckpointDeleted {
                    id: id(&intent.command).clone(),
                };
                let saved = response.clone();
                self.state
                    .with_store(move |store| store.finish_checkpoint(&intent, &saved, None, None))
                    .await?;
                Ok(response)
            }
        }
    }
}
impl From<crate::storage::CheckpointManifest> for CheckpointInfo {
    fn from(manifest: crate::storage::CheckpointManifest) -> Self {
        Self {
            id: manifest.id,
            sandbox: manifest.sandbox,
            sandbox_generation: manifest.sandbox_generation,
            bytes: manifest.bytes,
            sha256: manifest.sha256,
        }
    }
}
