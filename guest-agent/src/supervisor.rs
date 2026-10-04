use crate::{exec::Manager, files, protocol};
use guest_protocol::{BootNonce, GuestEnvelope, GuestMessage, SessionIdentity};
use sandboxd_protocol::{OperationId, SandboxGeneration, SandboxId, SessionGeneration, SessionId};
use sha2::{Digest, Sha256};
use socket2::Socket;
#[cfg(target_os = "linux")]
use socket2::{Domain, SockAddr, Type};
use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::PathBuf,
};

#[cfg(target_os = "linux")]
const VSOCK_CID_ANY: u32 = u32::MAX;

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

pub struct Config {
    pub identity: SessionIdentity,
    pub state: Option<File>,
    pub network_tool: Option<File>,
}

impl Config {
    pub fn from_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Self, Error> {
        let mut values = HashMap::new();
        let mut iterator = args.into_iter();
        let _program = iterator.next();
        while let Some(arg) = iterator.next() {
            let key = arg
                .to_str()
                .ok_or_else(|| Error::Config("argument is not UTF-8".into()))?;
            let key = key
                .strip_prefix("--")
                .ok_or_else(|| Error::Config("arguments must use --key value".into()))?;
            let value = iterator
                .next()
                .ok_or_else(|| Error::Config(format!("missing value for --{key}")))?;
            let value = value
                .into_string()
                .map_err(|_| Error::Config(format!("value for --{key} is not UTF-8")))?;
            if values.insert(key.to_owned(), value).is_some() {
                return Err(Error::Config(format!("duplicate --{key}")));
            }
        }
        let required = |name: &str| {
            values
                .get(name)
                .cloned()
                .ok_or_else(|| Error::Config(format!("missing --{name}")))
        };
        let nonce = required("boot-nonce")?;
        let nonce =
            hex::decode(nonce).map_err(|_| Error::Config("boot nonce must be hex".into()))?;
        let boot_nonce: [u8; 32] = nonce
            .try_into()
            .map_err(|_| Error::Config("boot nonce must contain 32 bytes".into()))?;
        let identity = SessionIdentity {
            sandbox: SandboxId::new(required("sandbox")?)
                .map_err(|_| Error::Config("invalid sandbox ID".into()))?,
            sandbox_generation: parse_generation(&required("sandbox-generation")?)?,
            session: SessionId::new(required("session")?)
                .map_err(|_| Error::Config("invalid session ID".into()))?,
            session_generation: parse_session_generation(&required("session-generation")?)?,
            boot_nonce: BootNonce(boot_nonce),
            vsock_cid: parse_u32(&required("vsock-cid")?)?,
            protocol_version: guest_protocol::GUEST_PROTOCOL_VERSION,
        };
        identity
            .authenticate(&identity)
            .map_err(|_| Error::Config("invalid guest identity".into()))?;
        let state = values
            .get("state-fd")
            .map(|value| {
                let fd: i32 = value
                    .parse()
                    .map_err(|_| Error::Config("state fd is invalid".into()))?;
                if fd < 0 {
                    return Err(Error::Config("state fd is negative".into()));
                }
                let path = PathBuf::from(format!("/proc/self/fd/{fd}"));
                let file = File::open(path)?;
                let meta = file.metadata()?;
                if !meta.is_dir() || meta.uid() != 0 {
                    return Err(Error::Config(
                        "state fd is not a root-owned directory".into(),
                    ));
                }
                #[cfg(target_os = "linux")]
                {
                    let fs_type = nix::sys::statfs::fstatfs(&file)
                        .map_err(|e| Error::Config(format!("inspect state filesystem: {e}")))?;
                    if fs_type.filesystem_type() != nix::sys::statfs::EXT4_SUPER_MAGIC {
                        return Err(Error::Config("state fd is not ext4".into()));
                    }
                }
                Ok(file)
            })
            .transpose()?;
        let network_tool = values
            .get("network-tool-fd")
            .map(|value| {
                let fd: i32 = value
                    .parse()
                    .map_err(|_| Error::Config("network tool fd is invalid".into()))?;
                if fd < 0 {
                    return Err(Error::Config("network tool fd is negative".into()));
                }
                let file = File::open(format!("/proc/self/fd/{fd}"))?;
                let meta = file.metadata()?;
                if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                    return Err(Error::Config(
                        "network tool fd is not a trusted regular file".into(),
                    ));
                }
                Ok(file)
            })
            .transpose()?;
        Ok(Self {
            identity,
            state,
            network_tool,
        })
    }
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
        let (stream, _) = listener.accept()?;
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
            identity.clone(),
            incoming_rx,
            outgoing_rx,
            outgoing_tx,
            &mut manager,
            &mut operations,
            state.as_ref(),
            network_tool.as_ref(),
        ) {
            Ok(ConnectionResult::Rebind(next)) => identity = next,
            Ok(ConnectionResult::Closed) | Err(_) => {}
        }
    }
}

#[cfg(target_os = "linux")]
fn bind_vsock() -> Result<Socket, Error> {
    let socket = Socket::new(Domain::VSOCK, Type::STREAM, None)?;
    socket.set_reuse_address(false)?;
    socket.bind(&SockAddr::vsock(VSOCK_CID_ANY, guest_protocol::GUEST_PORT))?;
    socket.listen(16)?;
    Ok(socket)
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
    identity: SessionIdentity,
    incoming: Receiver<(u64, GuestEnvelope)>,
    outgoing_rx: Receiver<GuestMessage>,
    outgoing_tx: SyncSender<GuestMessage>,
    manager: &mut Manager,
    operations: &mut HashMap<OperationId, ([u8; 32], GuestMessage)>,
    state: Option<&File>,
    network_tool: Option<&File>,
) -> Result<ConnectionResult, Error> {
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
            operations.get(&operation).map(|(known, response)| {
                if known == fingerprint {
                    Ok(response.clone())
                } else {
                    Err(GuestMessage::Error {
                        code: "operation ID conflict".into(),
                    })
                }
            })
        });
        let capacity_exhausted =
            receipt && !operations.contains_key(&operation) && operations.len() >= 1024;
        let should_store = receipt && cached.is_none() && !capacity_exhausted;
        let response = if matches!(request, GuestMessage::FilesystemQuiesce)
            && cached.is_some()
            && !freeze.frozen()
        {
            GuestMessage::Error {
                code: "quiesce expired; use a fresh operation".into(),
            }
        } else if let Some(cached) = cached {
            cached.unwrap_or_else(|response| response)
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
                    if operations.remove(&target).is_some() {
                        GuestMessage::Ready
                    } else {
                        GuestMessage::Error {
                            code: "operation receipt not found".into(),
                        }
                    }
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
            | GuestMessage::ConfigureVolumes { .. }
    )
}
fn parse_u32(value: &str) -> Result<u32, Error> {
    value
        .parse()
        .map_err(|_| Error::Config("numeric identity value is invalid".into()))
}
fn parse_generation(value: &str) -> Result<sandboxd_protocol::SandboxGeneration, Error> {
    SandboxGeneration::new(
        value
            .parse()
            .map_err(|_| Error::Config("generation is invalid".into()))?,
    )
    .map_err(|e| Error::Config(e.into()))
}

fn parse_session_generation(value: &str) -> Result<SessionGeneration, Error> {
    SessionGeneration::new(
        value
            .parse()
            .map_err(|_| Error::Config("generation is invalid".into()))?,
    )
    .map_err(|e| Error::Config(e.into()))
}
