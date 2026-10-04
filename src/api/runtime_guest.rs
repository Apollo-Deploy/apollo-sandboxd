//! Guest file effects retain their original operation ID across uncertain replies.
use super::{handlers::now_ms, runtime_service::RuntimeService, state_worker::deadline_error};
use crate::{
    error::{Error, Result},
    exec::{JournalItem, OutputJournal},
    security::peer::Peer,
    state::guest_operation::{self, GuestAdmission},
};
use guest_protocol::GuestMessage;
use sandboxd_protocol::exec::{ExecOutputItem, ExecOutputPage, OutputPolicy};
use sandboxd_protocol::{
    ApiError, ErrorCode, Fence, GuestCommand, GuestReply, OperationId, Response,
};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use tokio::{
    sync::oneshot,
    time::{Instant, timeout_at},
};

impl RuntimeService {
    async fn router_ready(
        &self,
        vm: &Arc<super::runtime_service::LiveVm>,
        exec: &sandboxd_protocol::ExecId,
        command: &GuestCommand,
        request_digest: [u8; 32],
        sink_fds: Vec<OwnedFd>,
    ) -> Result<bool> {
        let root = self
            .config
            .state
            .directory
            .join("output")
            .join(vm.intent.key.sandbox.as_str())
            .join(format!(
                "g{}-s{}",
                vm.intent.key.sandbox_generation.get(),
                vm.intent.key.generation.get()
            ));
        if vm.exec_router.contains(exec)? {
            super::runtime_exec_identity::validate_existing(&root, exec, command, request_digest)?;
            return Ok(true);
        }
        let GuestCommand::ExecStart { spec } = command else {
            return Ok(false);
        };
        if spec.id != *exec {
            return Err(Error::State);
        }
        let path = root.join(exec.as_str());
        crate::security::path::SecureDir::open(&self.config.state.directory)?
            .open_child("output")?
            .ensure_private_directory(vm.intent.key.sandbox.as_str())?
            .ensure_private_directory(&format!(
                "g{}-s{}",
                vm.intent.key.sandbox_generation.get(),
                vm.intent.key.generation.get()
            ))?
            .ensure_private_directory(exec.as_str())?;
        crate::exec::ExecEventRouter::prepare_manifest(
            &path,
            exec,
            request_digest,
            spec.output_policy,
        )?;
        let journal = OutputJournal::open(&path, exec.clone(), 256 << 20)?;
        let (stdout, stderr) = match sink_fds.len() {
            0 => (None, None),
            2 => {
                let mut fds = sink_fds.into_iter();
                (
                    Some(crate::exec::OutputSink::new(
                        fds.next().ok_or(Error::Path)?,
                        spec.output_policy,
                    )?),
                    Some(crate::exec::OutputSink::new(
                        fds.next().ok_or(Error::Path)?,
                        spec.output_policy,
                    )?),
                )
            }
            _ => return Err(Error::Path),
        };
        vm.exec_router
            .register(exec.clone(), journal, stdout, stderr, spec.output_policy)?;
        Ok(true)
    }

    pub async fn guest_command(
        self: &Arc<Self>,
        peer: Peer,
        operation: OperationId,
        operation_sequence: u64,
        fence: Fence,
        command: GuestCommand,
        sink_fds: Vec<OwnedFd>,
        deadline: Instant,
    ) -> Result<Response> {
        // Required output must be admitted with both role-ordered sink FDs.
        if matches!(
            command,
            GuestCommand::ExecStart {
                spec: ref value
            } if matches!(value.output_policy, OutputPolicy::Required)
        ) && sink_fds.len() != 2
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "required output sinks require two SCM_RIGHTS descriptors",
            )
            .into());
        }
        let (reply, receive) = oneshot::channel();
        let sink_count = u8::try_from(sink_fds.len()).map_err(|_| Error::Path)?;
        let digest = guest_operation::digest_with_sinks(&fence, &command, sink_count)?;
        let runtime = Arc::clone(self);
        let completed = self
            .queue
            .submit(fence.sandbox.clone(), async move {
                if reply.is_closed() || Instant::now() >= deadline {
                    let _ = reply.send(Err(deadline_error()));
                    return Ok(());
                }
                let (owned_operation, owned_command) = (operation.clone(), command.clone());
                let admitted = runtime
                    .state
                    .with_store(move |store| {
                        // The durable-state queue may outlive the request deadline.
                        // Recheck at the actual admission boundary, before intent.
                        if reply.is_closed() || Instant::now() >= deadline {
                            let _ = reply.send(Err(deadline_error()));
                            return Ok(None);
                        }
                        let admission = store.admit_guest_operation_with_sinks(
                            peer.uid,
                            &owned_operation,
                            &fence,
                            &owned_command,
                            sink_count,
                            Some(operation_sequence),
                            now_ms()?,
                        );
                        Ok(Some((reply, admission)))
                    })
                    .await?;
                let Some((reply, admission)) = admitted else {
                    return Ok(());
                };
                let result = match admission {
                    Ok(GuestAdmission::Complete(response)) => Ok(response),
                    Ok(GuestAdmission::Pending(key)) => {
                        runtime
                            .apply_guest(peer.uid, operation, key, command, digest, sink_fds)
                            .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
                Ok(())
            })
            .await?;
        drop(completed);
        timeout_at(deadline, receive)
            .await
            .map_err(|_| deadline_error())?
            .map_err(|_| Error::State)?
    }

    async fn apply_guest(
        &self,
        uid: u32,
        operation: OperationId,
        key: crate::state::SessionKey,
        mut command: GuestCommand,
        digest: [u8; 32],
        sink_fds: Vec<OwnedFd>,
    ) -> Result<Response> {
        let vm = self.current(uid, &key).await?;
        vm.process.verify()?;
        if let GuestCommand::ExecStart { spec } = &mut command {
            self.authority
                .apply_exec_defaults(&vm.intent.pins.base_image, spec)?;
            spec.validate().map_err(|_| {
                ApiError::new(
                    ErrorCode::InvalidRequest,
                    "image execution defaults are empty or invalid",
                )
            })?;
        }
        if let GuestCommand::ExecList { after, limit } = &command {
            // Journal/index reads may fsync or touch SQLite-backed files. Keep
            // them off the Tokio worker so a slow disk cannot stall all VM
            // control traffic.
            let router = vm.exec_router.clone();
            let cursor = after.clone();
            let page_size = *limit;
            let entries =
                tokio::task::spawn_blocking(move || router.list(cursor.as_ref(), page_size))
                    .await
                    .map_err(|_| Error::State)??;
            let response = Response::Guest(GuestReply::ExecList(entries));
            let saved = response.clone();
            self.state
                .with_store(move |store| {
                    store.complete_guest_operation(uid, &operation, digest, &saved)
                })
                .await?;
            return Ok(response);
        }
        let requested_exec = match &command {
            GuestCommand::ExecStart { spec } => Some(spec.id.clone()),
            GuestCommand::ExecStdin { exec, .. }
            | GuestCommand::ExecResizePty { exec, .. }
            | GuestCommand::ExecSignal { exec, .. }
            | GuestCommand::ExecCancel { exec }
            | GuestCommand::ExecWait { exec }
            | GuestCommand::ExecAttach { exec, .. }
            | GuestCommand::ExecReplay { exec, .. } => Some(exec.clone()),
            GuestCommand::ExecList { .. } | GuestCommand::File { .. } => None,
        };
        if let Some(exec) = requested_exec.as_ref()
            && matches!(
                &command,
                GuestCommand::ExecAttach { .. } | GuestCommand::ExecReplay { .. }
            )
        {
            if !vm.exec_router.contains(exec)? {
                return Err(
                    ApiError::new(ErrorCode::ExecNotFound, "execution is not admitted").into(),
                );
            }
            let page =
                vm.exec_router
                    .replay(exec, replay_from(&command), replay_limit(&command))?;
            let response = Response::Guest(GuestReply::ExecOutput(ExecOutputPage {
                exec: exec.clone(),
                items: page.items.into_iter().map(output_item).collect(),
                high_watermark: page.high_watermark,
                transport_gaps: page.transport_gaps,
            }));
            let saved = response.clone();
            self.state
                .with_store(move |store| {
                    store.complete_guest_operation(uid, &operation, digest, &saved)
                })
                .await?;
            return Ok(response);
        }
        let guest = vm.guest.lock().await;
        let guest = guest.as_ref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::SessionUnavailable,
                "guest control is unavailable",
            )
        })?;
        if let Some(exec) = requested_exec.clone()
            && !self
                .router_ready(&vm, &exec, &command, digest, sink_fds)
                .await?
        {
            return Err(ApiError::new(ErrorCode::ExecNotFound, "execution is not admitted").into());
        }
        let message = guest_message(command.clone());
        let peer = guest.request(operation.clone(), message).await?;
        let response = match peer.message {
            GuestMessage::Ready => Response::Guest(GuestReply::Acknowledged),
            GuestMessage::ExecExit {
                exec,
                exit_code,
                signal,
                timed_out,
            } => {
                if Some(&exec) != requested_exec.as_ref() {
                    return Err(ApiError::new(
                        ErrorCode::GuestProtocolMismatch,
                        "guest exit identity does not match request",
                    )
                    .into());
                }
                Response::Guest(GuestReply::ExecExit {
                    exec,
                    exit_code,
                    signal,
                    timed_out,
                })
            }
            GuestMessage::FileResult {
                data,
                offset,
                eof,
                metadata,
                entries,
                link_target,
            } => Response::Guest(GuestReply::File {
                data,
                offset,
                eof,
                metadata,
                entries,
                link_target,
            }),
            GuestMessage::Error { .. } => Response::Error(ApiError::new(
                if requested_exec.is_some() {
                    ErrorCode::ExecFailed
                } else {
                    ErrorCode::FileTransferFailed
                },
                if requested_exec.is_some() {
                    "guest execution failed"
                } else {
                    "guest file operation failed"
                },
            )),
            _ => {
                return Err(ApiError::new(
                    ErrorCode::GuestProtocolMismatch,
                    "unexpected file operation response",
                )
                .into());
            }
        };
        let (saved_operation, saved_response) = (operation.clone(), response.clone());
        self.state
            .with_store(move |store| {
                store.complete_guest_operation(uid, &saved_operation, digest, &saved_response)
            })
            .await?;
        // A failed retirement loses no result: the host receipt was committed first.
        let retired = OperationId::new(format!("retire-{}", &hex::encode(digest)[..24]))
            .map_err(|_| Error::State)?;
        let _ = guest
            .request(retired, GuestMessage::RetireOperation { operation })
            .await;
        let key = key.clone();
        self.state
            .with_store(move |store| store.touch_activity(uid, &key, now_ms()?, 0))
            .await?;
        Ok(response)
    }
}

fn guest_message(command: GuestCommand) -> GuestMessage {
    match command {
        GuestCommand::ExecStart { spec } => GuestMessage::ExecStart { spec },
        GuestCommand::ExecStdin { exec, data, eof } => GuestMessage::ExecStdin { exec, data, eof },
        GuestCommand::ExecResizePty { exec, size } => GuestMessage::ExecResizePty { exec, size },
        GuestCommand::ExecSignal { exec, signal } => GuestMessage::ExecSignal { exec, signal },
        GuestCommand::ExecCancel { exec } => GuestMessage::ExecCancel { exec },
        GuestCommand::ExecWait { exec } => GuestMessage::ExecWait { exec },
        GuestCommand::ExecAttach { .. } | GuestCommand::ExecReplay { .. } => {
            unreachable!("host-only output replay command")
        }
        GuestCommand::ExecList { .. } => unreachable!("host-only execution list command"),
        GuestCommand::File { request } => GuestMessage::File { request },
    }
}

fn replay_from(command: &GuestCommand) -> u64 {
    match command {
        GuestCommand::ExecAttach { from_sequence, .. }
        | GuestCommand::ExecReplay { from_sequence, .. } => *from_sequence,
        _ => unreachable!(),
    }
}

fn replay_limit(command: &GuestCommand) -> u16 {
    match command {
        GuestCommand::ExecAttach { limit, .. } | GuestCommand::ExecReplay { limit, .. } => *limit,
        _ => unreachable!(),
    }
}

fn output_item(item: crate::exec::JournalItem) -> ExecOutputItem {
    match item {
        JournalItem::Record(record) => {
            ExecOutputItem::Record(sandboxd_protocol::exec::OutputRecord {
                exec: record.exec,
                stream: record.stream,
                sequence: record.sequence,
                timestamp_unix_ms: record.timestamp_unix_ms,
                flags: record.flags,
                payload: record.payload,
            })
        }
        JournalItem::Gap {
            from_sequence,
            to_sequence,
        } => ExecOutputItem::Gap {
            from_sequence,
            to_sequence,
        },
    }
}
