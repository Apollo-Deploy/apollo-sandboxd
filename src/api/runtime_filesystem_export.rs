//! Runtime protocol handling for exporting a bounded immutable OCI layer.
use super::{handlers::now_ms, runtime_service::RuntimeService, state_worker::deadline_error};
use crate::{
    error::{Error, Result},
    security::peer::Peer,
};
use guest_protocol::GuestMessage;
use sandboxd_protocol::{FilesystemExportInfo, Request, Response};
use std::{os::fd::OwnedFd, sync::Arc};
use tokio::{
    sync::mpsc,
    time::{Instant, timeout_at},
};

pub(crate) const OCI_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

impl RuntimeService {
    pub(crate) async fn export_request(
        self: &Arc<Self>,
        request: Request,
        peer: Peer,
        deadline: Instant,
    ) -> Result<(Response, OwnedFd)> {
        let Request::FilesystemExport {
            volume_id,
            operation,
            operation_sequence,
            fence,
            max_bytes,
            max_entries,
        } = request
        else {
            return Err(Error::Path);
        };
        Request::FilesystemExport {
            volume_id: volume_id.clone(),
            operation: operation.clone(),
            operation_sequence,
            fence: fence.clone(),
            max_bytes,
            max_entries,
        }
        .validate()
        .map_err(|_| Error::Path)?;
        let slot = Arc::new(
            timeout_at(
                deadline,
                Arc::clone(&self.filesystem_export_slots).acquire_owned(),
            )
            .await
            .map_err(|_| deadline_error())?
            .map_err(|_| Error::State)?,
        );
        let command = sandboxd_protocol::GuestCommand::FilesystemExport {
            volume_id: volume_id.clone(),
            max_bytes,
            max_entries,
        };
        let digest = crate::state::guest_operation::digest(&fence, &command)?;
        let uid = peer.uid;
        let admission_operation = operation.clone();
        let admission_fence = fence.clone();
        let admission_command = command.clone();
        let admitted_volume = volume_id.clone();
        let admission = self
            .state
            .with_store(move |store| {
                if let Some(id) = &admitted_volume {
                    let key = store.active_session_key(uid, &admission_fence, now_ms()?)?;
                    let intent = store.session_intent(uid, &key)?;
                    if !intent.pins.volumes.iter().any(|volume| {
                        &volume.volume_id == id && volume.owner_uid.is_none_or(|owner| owner == uid)
                    }) {
                        return Err(Error::Path);
                    }
                }
                store.admit_guest_operation_with_sinks(
                    uid,
                    &admission_operation,
                    &admission_fence,
                    &admission_command,
                    0,
                    Some(operation_sequence),
                    now_ms()?,
                )
            })
            .await?;
        let key = match admission {
            crate::state::guest_operation::GuestAdmission::Complete(
                Response::FilesystemExport(info),
            ) => {
                if info.operation != operation
                    || info.media_type != OCI_LAYER_MEDIA_TYPE
                    || info.byte_len > max_bytes
                    || info.entry_count > max_entries
                {
                    return Err(Error::Path);
                }
                let state_path = self.config.state.directory.clone();
                let sha256 = info.sha256.clone();
                let byte_len = info.byte_len;
                let load_slot = Arc::clone(&slot);
                let fd = timeout_at(
                    deadline,
                    tokio::task::spawn_blocking(move || {
                        let _slot = load_slot;
                        crate::storage::load_filesystem_export(
                            &state_path,
                            uid,
                            &sha256,
                            byte_len,
                            max_bytes,
                        )
                    }),
                )
                .await
                .map_err(|_| deadline_error())?
                .map_err(|_| Error::State)??;
                return Ok((Response::FilesystemExport(info), fd));
            }
            crate::state::guest_operation::GuestAdmission::Pending(key) => key,
            crate::state::guest_operation::GuestAdmission::Complete(_) => return Err(Error::Path),
        };
        let vm = self.current(uid, &key).await?;
        let mut guest = vm.guest.lock().await;
        let guest = guest.as_mut().ok_or_else(|| {
            Error::Api(sandboxd_protocol::ApiError::new(
                sandboxd_protocol::ErrorCode::SessionUnavailable,
                "guest control is unavailable",
            ))
        })?;
        let (sha256, byte_len, entry_count) = {
            let initial = timeout_at(
                deadline,
                guest.request(
                    operation.clone(),
                    GuestMessage::FilesystemExportBegin {
                        volume_id: volume_id.clone(),
                        max_bytes,
                        max_entries,
                    },
                ),
            )
            .await
            .map_err(|_| deadline_error())??;
            match initial.message {
                GuestMessage::FilesystemExportReady {
                    sha256,
                    byte_len,
                    entry_count,
                } => (sha256, byte_len, entry_count),
                _ => return Err(Error::Path),
            }
        };
        if byte_len == 0 || byte_len > max_bytes || entry_count > max_entries {
            return Err(Error::Path);
        }
        let (chunk_sender, mut chunk_receiver) = mpsc::channel::<Vec<u8>>(2);
        let stage_state = self.config.state.directory.clone();
        let stage_sha256 = sha256.clone();
        // Blocking filesystem work survives an RPC timeout. Keep its admission
        // permit until the task exits so abandoned requests cannot bypass the cap.
        let stage_slot = Arc::clone(&slot);
        let stage_writer = tokio::task::spawn_blocking(move || {
            let _slot = stage_slot;
            let mut stager =
                crate::storage::FilesystemExportStager::new(&stage_state, uid, max_bytes)?;
            while let Some(chunk) = chunk_receiver.blocking_recv() {
                stager.append(&chunk)?;
            }
            stager.finish(byte_len, &stage_sha256)
        });
        let mut offset = 0u64;
        while offset < byte_len {
            let remaining = byte_len - offset;
            let max_chunk = remaining.min(60 * 1024) as u32;
            let chunk = timeout_at(
                deadline,
                guest.request(
                    operation.clone(),
                    GuestMessage::FilesystemExportRead {
                        offset,
                        max_bytes: max_chunk,
                    },
                ),
            )
            .await
            .map_err(|_| deadline_error())??;
            let GuestMessage::FilesystemExportChunk {
                offset: echoed,
                data,
                eof,
            } = chunk.message
            else {
                return Err(Error::Path);
            };
            if echoed != offset
                || data.is_empty()
                || data.len() > max_chunk as usize
                || eof != (offset + data.len() as u64 == byte_len)
            {
                return Err(Error::Path);
            }
            let data_len = data.len() as u64;
            timeout_at(deadline, chunk_sender.send(data))
                .await
                .map_err(|_| deadline_error())?
                .map_err(|_| Error::State)?;
            offset += data_len;
        }
        drop(chunk_sender);
        let (sha256, byte_len) = timeout_at(deadline, stage_writer)
            .await
            .map_err(|_| deadline_error())?
            .map_err(|_| Error::State)??;
        let state_path = self.config.state.directory.clone();
        let response_sha256 = sha256.clone();
        let load_slot = Arc::clone(&slot);
        let fd = timeout_at(
            deadline,
            tokio::task::spawn_blocking(move || {
                let _slot = load_slot;
                crate::storage::load_filesystem_export(
                    &state_path,
                    uid,
                    &response_sha256,
                    byte_len,
                    max_bytes,
                )
            }),
        )
        .await
        .map_err(|_| deadline_error())?
        .map_err(|_| Error::State)??;
        let receipt = FilesystemExportInfo {
            operation,
            base_digest: vm.intent.pins.base_image.clone(),
            media_type: OCI_LAYER_MEDIA_TYPE.to_owned(),
            sha256,
            byte_len,
            entry_count,
        };
        let response = Response::FilesystemExport(receipt);
        let saved = response.clone();
        let operation = match &response {
            Response::FilesystemExport(info) => info.operation.clone(),
            _ => return Err(Error::State),
        };
        self.state
            .with_store(move |store| {
                store.complete_guest_operation(uid, &operation, digest, &saved)
            })
            .await?;
        Ok((response, fd))
    }
}
