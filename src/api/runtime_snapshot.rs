//! Public fenced snapshot operations run in the same per-sandbox lifecycle queue.
use super::{handlers::now_ms, runtime_service::RuntimeService, state_worker::deadline_error};
use crate::{
    error::{Error, Result},
    security::peer::Peer,
    state::snapshot::{SnapshotAdmission, SnapshotIntent},
};
use sandboxd_protocol::{Request, Response, SnapshotCommand, SnapshotInfo};
use std::sync::Arc;
use tokio::{
    sync::oneshot,
    time::{Instant, timeout_at},
};
impl RuntimeService {
    pub async fn snapshot_request(
        self: &Arc<Self>,
        peer: Peer,
        request: Request,
        deadline: Instant,
    ) -> Result<Response> {
        let Request::Snapshot {
            operation,
            operation_sequence,
            command,
        } = request
        else {
            return Err(Error::State);
        };
        let limits = self.config.snapshots.clone().ok_or_else(|| {
            sandboxd_protocol::ApiError::new(
                sandboxd_protocol::ErrorCode::UnsupportedCapability,
                "encrypted snapshots are not configured",
            )
        })?;
        let runtime = self.clone();
        let (reply, receive) = oneshot::channel();
        let completed = self
            .queue
            .submit(command.fence().sandbox.clone(), async move {
                let admitted = runtime
                    .state
                    .with_store(move |store| {
                        if reply.is_closed() || Instant::now() >= deadline {
                            let _ = reply.send(Err(deadline_error()));
                            return Ok(None);
                        }
                        let result = store.admit_snapshot(
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
                        Ok(SnapshotAdmission::Complete(response)) => Ok(response),
                        Ok(SnapshotAdmission::Pending(intent)) => {
                            runtime.apply_snapshot(intent).await
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
    pub(super) async fn apply_snapshot(
        self: &Arc<Self>,
        intent: SnapshotIntent,
    ) -> Result<Response> {
        match &intent.command {
            SnapshotCommand::Create { .. } | SnapshotCommand::Suspend { .. } => {
                self.capture_snapshot(intent).await
            }
            SnapshotCommand::Restore { .. } => self.restore_snapshot(intent).await,
            SnapshotCommand::Delete { .. } => {
                let catalog = self.snapshots.clone().ok_or(Error::State)?;
                let checkpoints = self.checkpoints.clone();
                let saved = intent.clone();
                tokio::task::spawn_blocking(move || {
                    catalog.delete(saved.record.artifacts.as_ref().ok_or(Error::State)?)?;
                    if let Some(output) = &saved.record.output {
                        crate::exec::ExecEventRouter::snapshot_delete(output)?;
                    }
                    checkpoints.delete(&saved.record.checkpoint)
                })
                .await
                .map_err(|_| Error::State)??;
                let response = Response::SnapshotDeleted {
                    id: intent.command.id().clone(),
                };
                self.complete_snapshot(intent, response).await
            }
        }
    }
    pub(super) async fn complete_snapshot(
        &self,
        intent: SnapshotIntent,
        response: Response,
    ) -> Result<Response> {
        let saved = response.clone();
        self.state
            .with_store(move |store| store.finish_snapshot(&intent, &saved, now_ms()?))
            .await?;
        Ok(response)
    }
}
pub(super) fn info(intent: &SnapshotIntent) -> Result<SnapshotInfo> {
    let manifest = intent.record.manifest.as_ref().ok_or(Error::State)?;
    Ok(SnapshotInfo {
        id: manifest.id.clone(),
        sandbox: manifest.sandbox.clone(),
        sandbox_generation: manifest.sandbox_generation,
        memory_bytes: manifest.memory_bytes,
        state_bytes: manifest.state_bytes,
        suspended: intent.record.suspended,
    })
}
pub(super) fn operation(phase: &str) -> Result<sandboxd_protocol::OperationId> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::State)?;
    sandboxd_protocol::OperationId::new(format!("snap-{phase}-{}", hex::encode(nonce)))
        .map_err(|_| Error::State)
}
