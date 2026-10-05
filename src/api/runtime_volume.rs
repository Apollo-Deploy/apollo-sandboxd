//! Sequenced owner-scoped dynamic backing preparation and reconciliation.
use super::runtime_service::RuntimeService;
use crate::{
    error::{Error, Result},
    security::peer::Peer,
    state::DynamicVolumeRecord,
};
use sandboxd_protocol::{OperationId, Request, Response, SandboxId, VolumeCommand};
use std::{os::fd::OwnedFd, sync::Arc};
use tokio::time::Instant;

#[cfg(target_os = "linux")]
fn prepare(
    runtime: &RuntimeService,
    uid: u32,
    id: String,
    command: &VolumeCommand,
    input: Option<std::fs::File>,
) -> Result<DynamicVolumeRecord> {
    let previous = runtime.state.with_store_blocking({
        let id = id.clone();
        move |s| s.volume_preparation(uid, &id)
    })?;
    let (input, prepared_hash) = if let VolumeCommand::ImportPrepared {
        image, size_bytes, ..
    } = command
    {
        let artifact = runtime
            .authority
            .prepared_volume_source(image, *size_bytes)?;
        (Some(artifact.file), Some(artifact.sha256))
    } else {
        (input, None)
    };
    let state = runtime.state.clone();
    crate::storage::dynamic_volume::create(
        &runtime.authority.execution.drive_directory,
        uid,
        id,
        command,
        input,
        prepared_hash,
        runtime.authority.image_formatter()?,
        previous,
        move |record| {
            let record = record.clone();
            state.with_store_blocking(move |s| s.prepare_volume(&record))
        },
    )
}
#[cfg(not(target_os = "linux"))]
fn prepare(
    _: &RuntimeService,
    _: u32,
    _: String,
    _: &VolumeCommand,
    _: Option<std::fs::File>,
) -> Result<DynamicVolumeRecord> {
    Err(Error::Config("dynamic ext4 preparation requires Linux"))
}

impl RuntimeService {
    fn volume_replay(&self, uid: u32, response: Response) -> Result<Response> {
        if let Response::Volume(info) = &response {
            let backing = info.backing.clone();
            // A terminal creation receipt remains historical after Release.
            // Re-register only a live backing; exact replay never resurrects it.
            if let Some(record) = self
                .state
                .with_store_blocking(move |s| s.dynamic_volume(uid, &backing))?
            {
                self.authority.register_dynamic_volume(&record)?;
            }
        }
        Ok(response)
    }
    async fn prepare_volume_operation(
        self: &Arc<Self>,
        uid: u32,
        operation: OperationId,
        sequence: u64,
        id: String,
        command: Box<VolumeCommand>,
        input: Option<std::fs::File>,
    ) -> Result<Response> {
        // Recheck after serialization: another exact retry may have completed
        // while this operation waited in the queue.
        let replay = self
            .state
            .with_store_blocking({
                let operation = operation.clone();
                let command = command.clone();
                move |s| s.admit_volume(uid, &operation, sequence, &command)
            })?
            .1;
        if let Some(response) = replay {
            return self.volume_replay(uid, response);
        }
        let runtime = Arc::clone(self);
        let record =
            tokio::task::spawn_blocking(move || prepare(&runtime, uid, id, &command, input))
                .await
                .map_err(|_| Error::State)??;
        self.state.with_store_blocking({
            let record = record.clone();
            move |s| s.publish_volume(&record)
        })?;
        self.authority.register_dynamic_volume(&record)?;
        Ok(Response::Volume(record.info))
    }
    pub(super) async fn volume_request(
        self: &Arc<Self>,
        peer: Peer,
        request: Request,
        mut fds: Vec<OwnedFd>,
        deadline: Instant,
    ) -> Result<Response> {
        match request {
            Request::VolumeRelease {
                operation,
                operation_sequence,
                backing,
            } => {
                let runtime = Arc::clone(self);
                let pending = operation.clone();
                let (reply, receiver) = tokio::sync::oneshot::channel();
                let queued = self
                    .queue
                    .submit(
                        SandboxId::new("dynamic-volume-preparation").map_err(|_| Error::State)?,
                        async move {
                            let result: Result<Response> = async {
                                let (record, replay) = runtime.state.with_store_blocking({
                                    let operation = operation.clone();
                                    let backing = backing.clone();
                                    move |s| {
                                        s.admit_volume_release(
                                            peer.uid,
                                            &operation,
                                            operation_sequence,
                                            &backing,
                                        )
                                    }
                                })?;
                                if let Some(response) = replay {
                                    return Ok(response);
                                }
                                let record = record.ok_or(Error::State)?;
                                let root = runtime.authority.execution.drive_directory.clone();
                                match tokio::task::spawn_blocking(move || {
                                    crate::storage::dynamic_volume::release(&root, &record)
                                })
                                .await
                                {
                                    Ok(Ok(())) => (),
                                    _ => {
                                        return Ok(Response::VolumePending {
                                            operation: operation.clone(),
                                        });
                                    }
                                }
                                runtime.state.with_store_blocking({
                                    let operation = operation.clone();
                                    let backing = backing.clone();
                                    move |s| {
                                        s.complete_volume_release(peer.uid, &operation, &backing)
                                    }
                                })?;
                                runtime
                                    .authority
                                    .retire_dynamic_volume(peer.uid, &backing)?;
                                Ok(Response::VolumeReleased { backing })
                            }
                            .await;
                            let _ = reply.send(result.map_err(|e| e.api()));
                            Ok(())
                        },
                    )
                    .await?;
                drop(queued);
                match tokio::time::timeout_at(deadline, receiver).await {
                    Ok(Ok(Ok(response))) => Ok(response),
                    Ok(Ok(Err(error))) => Err(error.into()),
                    _ => Ok(Response::VolumePending { operation: pending }),
                }
            }
            Request::VolumeInspect { backing } => {
                let info = self
                    .state
                    .with_store_blocking(move |s| s.dynamic_volume(peer.uid, &backing))?
                    .ok_or(Error::Config("owner-scoped backing unavailable"))?
                    .info;
                self.volume_replay(peer.uid, Response::Volume(info))
            }
            Request::Volume {
                operation,
                operation_sequence,
                command,
            } => {
                let admitted_operation = operation.clone();
                let admitted_command = command.clone();
                let (id, replay) = self.state.with_store_blocking(move |s| {
                    s.admit_volume(
                        peer.uid,
                        &admitted_operation,
                        operation_sequence,
                        &admitted_command,
                    )
                })?;
                if let Some(response) = replay {
                    return self.volume_replay(peer.uid, response);
                }
                let runtime = Arc::clone(self);
                let pending = operation.clone();
                let input = fds.pop().map(std::fs::File::from);
                let (reply, receiver) = tokio::sync::oneshot::channel();
                let queued = self
                    .queue
                    .submit(
                        SandboxId::new("dynamic-volume-preparation").map_err(|_| Error::State)?,
                        async move {
                            let result = runtime
                                .prepare_volume_operation(
                                    peer.uid,
                                    operation,
                                    operation_sequence,
                                    id,
                                    command,
                                    input,
                                )
                                .await;
                            let _ = reply.send(result.map_err(|e| e.api()));
                            Ok(())
                        },
                    )
                    .await?;
                drop(queued);
                match tokio::time::timeout_at(deadline, receiver).await {
                    Ok(Ok(Ok(response))) => Ok(response),
                    Ok(Ok(Err(error))) => Err(error.into()),
                    _ => Ok(Response::VolumePending { operation: pending }),
                }
            }
            _ => Err(Error::State),
        }
    }
}
