#[path = "supervisor_config.rs"]
mod config;
pub use config::Config;
#[path = "supervisor_retirement.rs"]
mod retirement;

use crate::{exec::Manager, files, protocol};
use guest_protocol::{GuestEnvelope, GuestMessage, SessionIdentity};
use sandboxd_protocol::OperationId;
use sha2::{Digest, Sha256};
use socket2::Socket;
#[cfg(target_os = "linux")]
use socket2::{Domain, SockAddr, Type};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;
use std::{
    fs::File,
    io::{Read, Write},
};

#[cfg(target_os = "linux")]
const VSOCK_CID_ANY: u32 = u32::MAX;
#[cfg(target_os = "linux")]
const VSOCK_CID_HOST: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("guest configuration error: {0}")]
    Config(String),
    #[error("guest transport error: {0}")]
    Io(#[from] std::io::Error),
    #[error("guest protocol error: {0}")]
    Protocol(#[from] protocol::ProtocolError),
}

enum ConnectionResult {
    Closed,
    Rebind(SessionIdentity),
}

struct ConnectionContext<'a> {
    identity: SessionIdentity,
    outgoing_rx: Receiver<GuestMessage>,
    outgoing_tx: SyncSender<GuestMessage>,
    manager: &'a mut Manager,
    operations: &'a mut HashMap<OperationId, ([u8; 32], GuestMessage)>,
    state: Option<&'a File>,
    network_tool: Option<&'a File>,
}

pub fn run(config: Config) -> Result<(), Error> {
    let listener = bind_vsock()?;
    let mut identity = config.identity.clone();
    let (initial_tx, _) = sync_channel::<GuestMessage>(1);
    let state = config.state;
    let network_tool = config.network_tool;
    let mut manager = Manager::new(initial_tx);
    let mut operations = HashMap::new();
    loop {
        let (stream, _peer) = listener.accept()?;
        // Firecracker's host endpoint is the only trusted control peer.  The
        // guest can connect to this listener too, and the envelope identity is
        // intentionally not a secret, so reject guest-local connections before
        // they reach the protocol handshake.
        #[cfg(target_os = "linux")]
        if !is_host_peer(&_peer) {
            continue;
        }
        stream.set_write_timeout(Some(std::time::Duration::from_secs(1)))?;
        let reader = stream.try_clone()?;
        let (incoming_tx, incoming_rx) = sync_channel::<(u64, GuestEnvelope)>(128);
        let (outgoing_tx, outgoing_rx) = sync_channel::<GuestMessage>(512);
        manager.disconnect_events();
        let reader_identity = identity.clone();
        thread::Builder::new()
            .name("guest-control-reader".into())
            .spawn(move || read_loop(reader, reader_identity, incoming_tx))
            .map_err(|e| Error::Config(format!("control reader spawn failed: {e}")))?;
        match serve_connection(
            stream,
            incoming_rx,
            ConnectionContext {
                identity: identity.clone(),
                outgoing_rx,
                outgoing_tx,
                manager: &mut manager,
                operations: &mut operations,
                state: state.as_ref(),
                network_tool: network_tool.as_ref(),
            },
        ) {
            Ok(ConnectionResult::Rebind(next)) => identity = next,
            Ok(ConnectionResult::Closed) | Err(_) => {}
        }
    }
}

#[cfg(target_os = "linux")]
fn is_host_peer(peer: &SockAddr) -> bool {
    peer.as_vsock_address()
        .is_some_and(|(cid, _port)| cid == VSOCK_CID_HOST)
}

#[cfg(target_os = "linux")]
fn bind_vsock() -> Result<Socket, Error> {
    let socket = Socket::new(Domain::VSOCK, Type::STREAM, None)?;
    socket.set_reuse_address(false)?;
    socket.bind(&SockAddr::vsock(VSOCK_CID_ANY, guest_protocol::GUEST_PORT))?;
    socket.listen(16)?;
    Ok(socket)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn only_host_cid_is_an_accepted_control_peer() {
        assert!(is_host_peer(&SockAddr::vsock(VSOCK_CID_HOST, 1234)));
        assert!(!is_host_peer(&SockAddr::vsock(3, 1234)));
        assert!(!is_host_peer(&SockAddr::vsock(VSOCK_CID_ANY, 1234)));
    }
}

#[cfg(not(target_os = "linux"))]
fn bind_vsock() -> Result<Socket, Error> {
    Err(Error::Config("virtio-vsock requires a Linux guest".into()))
}

fn read_loop<R: Read>(
    mut reader: R,
    expected: SessionIdentity,
    sender: SyncSender<(u64, GuestEnvelope)>,
) {
    loop {
        let (id, envelope) = match protocol::read(&mut reader) {
            Ok(value) => value,
            Err(_) => break,
        };
        if envelope.validate(&expected).is_err() {
            break;
        }
        if sender.send((id, envelope)).is_err() {
            break;
        }
    }
}

fn serve_connection<S: Read + Write + Send + 'static>(
    mut stream: S,
    incoming: Receiver<(u64, GuestEnvelope)>,
    context: ConnectionContext<'_>,
) -> Result<ConnectionResult, Error> {
    let ConnectionContext {
        identity,
        outgoing_rx,
        outgoing_tx,
        manager,
        operations,
        state,
        network_tool,
    } = context;
    let mut freeze = crate::freeze::FreezeGuard::new(state);
    let boot_op = OperationId::new(protocol::BOOT_OPERATION)
        .map_err(|_| Error::Config("boot operation ID invalid".into()))?;
    let mut hello_seen = false;
    loop {
        freeze.expire().map_err(Error::Config)?;
        if hello_seen && let Ok(message) = outgoing_rx.try_recv() {
            if let GuestMessage::ExecExit { exec, .. } = &message {
                manager.finish(exec, &message);
            }
            let envelope = protocol::envelope(&identity, boot_op.clone(), message);
            protocol::write(&mut stream, 0, &envelope)?;
            continue;
        }
        let (request_id, envelope) =
            match incoming.recv_timeout(std::time::Duration::from_millis(25)) {
                Ok(value) => value,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            };
        if !hello_seen && !matches!(envelope.message, GuestMessage::Hello) {
            let operation = envelope.operation.clone();
            protocol::write(
                &mut stream,
                request_id,
                &protocol::envelope(
                    &identity,
                    operation,
                    GuestMessage::Error {
                        code: "HELLO required".into(),
                    },
                ),
            )?;
            continue;
        }
        let operation = envelope.operation.clone();
        let authenticating = !hello_seen && matches!(envelope.message, GuestMessage::Hello);
        let rebind_identity = match &envelope.message {
            GuestMessage::SessionRebind { identity } => Some(identity.clone()),
            _ => None,
        };
        let request = envelope.message;
        let receipt = hello_seen && is_receipted(&request);
        let request_fingerprint = receipt.then(|| fingerprint_message(&request)).transpose()?;
        let cached = request_fingerprint.as_ref().and_then(|fingerprint| {
            operations
                .get(&operation)
                .and_then(|(known, response)| (known == fingerprint).then(|| response.clone()))
        });
        let operation_conflict = request_fingerprint.as_ref().is_some_and(|fingerprint| {
            operations
                .get(&operation)
                .is_some_and(|(known, _)| known != fingerprint)
        });
        let capacity_exhausted =
            receipt && !operations.contains_key(&operation) && operations.len() >= 1024;
        let should_store =
            receipt && cached.is_none() && !operation_conflict && !capacity_exhausted;
        let response = if operation_conflict {
            GuestMessage::Error {
                code: "operation ID conflict".into(),
            }
        } else if matches!(request, GuestMessage::FilesystemQuiesce)
            && cached.is_some()
            && !freeze.frozen()
        {
            GuestMessage::Error {
                code: "quiesce expired; use a fresh operation".into(),
            }
        } else if let Some(cached) = cached {
            cached
        } else if freeze.frozen()
            && !matches!(
                request,
                GuestMessage::FilesystemUnquiesce
                    | GuestMessage::Ping
                    | GuestMessage::Health
                    | GuestMessage::Metrics
                    | GuestMessage::ProcessList
                    | GuestMessage::RetireOperation { .. }
                    | GuestMessage::SessionRebind { .. }
            )
        {
            GuestMessage::Error {
                code: "filesystem is quiesced".into(),
            }
        } else if capacity_exhausted {
            GuestMessage::Error {
                code: "operation receipt capacity exhausted; retire completed receipts".into(),
            }
        } else {
            match request {
                GuestMessage::Hello if !hello_seen => {
                    hello_seen = true;
                    GuestMessage::Ready
                }
                GuestMessage::Hello => GuestMessage::Error {
                    code: "duplicate HELLO".into(),
                },
                GuestMessage::SessionRebind { .. } if hello_seen => {
                    GuestMessage::SessionRebindReady
                }
                GuestMessage::Ping => GuestMessage::Ready,
                GuestMessage::ExecStart { spec } if hello_seen => match manager.start(*spec) {
                    Ok(()) => GuestMessage::Ready,
                    Err(code) => GuestMessage::Error {
                        code: bounded_error(code),
                    },
                },
                GuestMessage::ExecStdin { exec, data, eof } => {
                    result(manager.stdin(&exec, &data, eof))
                }
                GuestMessage::ExecResizePty { exec, size } => result(manager.resize(&exec, size)),
                GuestMessage::ExecSignal { exec, signal } => result(manager.signal(&exec, signal)),
                GuestMessage::ExecCancel { exec } => result(manager.cancel(&exec)),
                GuestMessage::ExecWait { exec } => manager.wait(&exec),
                GuestMessage::File { request } => match files::handle(request) {
                    Ok(message) => message,
                    Err(code) => GuestMessage::Error {
                        code: bounded_error(code),
                    },
                },
                GuestMessage::FilesystemSync => state.as_ref().map_or_else(
                    || GuestMessage::Error {
                        code: "filesystem sync unavailable".into(),
                    },
                    |file| sync_filesystems(file),
                ),
                GuestMessage::FilesystemExportBegin {
                    volume_id,
                    max_bytes,
                    max_entries,
                } => {
                    if !manager.process_list().is_empty() {
                        GuestMessage::Error {
                            code: "customer processes are still running".into(),
                        }
                    } else if let Some(state) = state {
                        match volume_id
                            .as_ref()
                            .map(crate::volumes::selected)
                            .transpose()
                            .and_then(|selected| {
                                crate::filesystem_export::create_selected(
                                    state,
                                    &operation,
                                    selected.as_ref(),
                                    max_bytes,
                                    max_entries,
                                )
                            }) {
                            Ok(receipt) => GuestMessage::FilesystemExportReady {
                                sha256: receipt.sha256,
                                byte_len: receipt.byte_len,
                                entry_count: receipt.entry_count,
                            },
                            Err(code) => GuestMessage::Error {
                                code: bounded_error(code),
                            },
                        }
                    } else {
                        GuestMessage::Error {
                            code: "filesystem export unavailable".into(),
                        }
                    }
                }
                GuestMessage::FilesystemExportRead { offset, max_bytes } => {
                    let admitted_export = operations.get(&operation).is_some_and(|(_, receipt)| {
                        matches!(receipt, GuestMessage::FilesystemExportReady { .. })
                    });
                    if !admitted_export {
                        GuestMessage::Error {
                            code: "filesystem export receipt not found".into(),
                        }
                    } else {
                        state.as_ref().map_or_else(
                            || GuestMessage::Error {
                                code: "filesystem export unavailable".into(),
                            },
                            |state| match crate::filesystem_export::read(
                                state, &operation, offset, max_bytes,
                            ) {
                                Ok((data, eof)) => {
                                    GuestMessage::FilesystemExportChunk { offset, data, eof }
                                }
                                Err(code) => GuestMessage::Error {
                                    code: bounded_error(code),
                                },
                            },
                        )
                    }
                }
                GuestMessage::FilesystemQuiesce => result(freeze.freeze()),
                GuestMessage::FilesystemUnquiesce => result(freeze.thaw()),
                GuestMessage::ConfigureNetwork { config } => {
                    result(crate::network::configure(&config, network_tool))
                }
                GuestMessage::ConfigureVolumes { volumes } if hello_seen => {
                    result(crate::volumes::configure(&volumes))
                }
                GuestMessage::Health => GuestMessage::HealthResult {
                    health: manager.health(),
                },
                GuestMessage::Metrics => GuestMessage::MetricsResult {
                    metrics: manager.metrics(),
                },
                GuestMessage::ProcessList => GuestMessage::ProcessListResult {
                    processes: manager.process_list(),
                },
                GuestMessage::Shutdown => {
                    let _ = protocol::write(
                        &mut stream,
                        request_id,
                        &protocol::envelope(&identity, operation, GuestMessage::Ready),
                    );
                    break;
                }
                GuestMessage::RetireOperation { operation: target } => {
                    retirement::retire(state, operations, &target)
                }
                GuestMessage::RetireExec { exec } => result(manager.retire(&exec)),
                _ if !hello_seen => GuestMessage::Error {
                    code: "HELLO required".into(),
                },
                _ => GuestMessage::Error {
                    code: "unsupported guest message".into(),
                },
            }
        };
        if should_store && let Some(fingerprint) = request_fingerprint {
            operations.insert(operation.clone(), (fingerprint, response.clone()));
        }
        protocol::write(
            &mut stream,
            request_id,
            &protocol::envelope(&identity, operation, response),
        )?;
        if let Some(next) = rebind_identity {
            return Ok(ConnectionResult::Rebind(next));
        }
        if authenticating {
            manager.set_events(outgoing_tx.clone());
        }
        while hello_seen && let Ok(message) = outgoing_rx.try_recv() {
            if let GuestMessage::ExecExit { exec, .. } = &message {
                manager.finish(exec, &message);
            }
            let envelope = protocol::envelope(&identity, boot_op.clone(), message);
            protocol::write(&mut stream, 0, &envelope)?;
        }
    }
    Ok(ConnectionResult::Closed)
}

fn result(value: Result<(), String>) -> GuestMessage {
    value
        .map(|()| GuestMessage::Ready)
        .unwrap_or_else(|code| GuestMessage::Error {
            code: bounded_error(code),
        })
}
fn sync_filesystems(state: &File) -> GuestMessage {
    match crate::fsync::sync_state(state) {
        Ok(()) => GuestMessage::Ready,
        Err(code) => GuestMessage::Error {
            code: bounded_error(code),
        },
    }
}
fn bounded_error(mut value: String) -> String {
    value.truncate(128);
    value
}

fn fingerprint_message(message: &GuestMessage) -> Result<[u8; 32], Error> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(message, &mut bytes)
        .map_err(|e| Error::Config(format!("operation fingerprint failed: {e}")))?;
    Ok(Sha256::digest(bytes).into())
}

fn is_receipted(message: &GuestMessage) -> bool {
    matches!(
        message,
        GuestMessage::ExecStart { .. }
            | GuestMessage::ExecStdin { .. }
            | GuestMessage::ExecResizePty { .. }
            | GuestMessage::ExecSignal { .. }
            | GuestMessage::ExecCancel { .. }
            | GuestMessage::File { .. }
            | GuestMessage::FilesystemSync
            | GuestMessage::FilesystemQuiesce
            | GuestMessage::FilesystemUnquiesce
            | GuestMessage::FilesystemExportBegin { .. }
            | GuestMessage::ConfigureVolumes { .. }
    )
}
