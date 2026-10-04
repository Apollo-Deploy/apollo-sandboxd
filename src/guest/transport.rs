use super::endpoint::GuestEndpoint;
use super::framing;
use crate::error::{Error, Result};
use guest_protocol::{GuestEnvelope, GuestMessage, SessionIdentity};
use sandboxd_protocol::OperationId;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncWriteExt, WriteHalf},
    net::UnixStream,
    sync::{Mutex, broadcast, oneshot},
    time::timeout,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING: usize = 64;
const MAX_EVENTS: usize = 128;

#[derive(Clone, Debug)]
pub struct GuestPeer {
    pub request_id: u64,
    pub operation: OperationId,
    pub message: GuestMessage,
}
struct Pending {
    operation: OperationId,
    sender: oneshot::Sender<GuestPeer>,
}
type PendingMap = Arc<StdMutex<HashMap<u64, Pending>>>;

struct PendingGuard {
    map: PendingMap,
    id: u64,
    armed: bool,
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.map.lock().map(|mut map| map.remove(&self.id));
        }
    }
}

pub struct GuestConnection {
    writer: Mutex<WriteHalf<UnixStream>>,
    pending: PendingMap,
    events: Mutex<broadcast::Receiver<GuestPeer>>,
    event_tx: broadcast::Sender<GuestPeer>,
    next_request: AtomicU64,
    closed: Arc<AtomicBool>,
    expected: SessionIdentity,
    reader_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl GuestConnection {
    pub async fn connect(
        endpoint: &GuestEndpoint,
        expected: SessionIdentity,
        operation: OperationId,
    ) -> Result<Self> {
        Self::connect_with_timeout(endpoint, expected, operation, DEFAULT_TIMEOUT).await
    }

    /// Couples endpoint adoption to a previously captured VMM identity. Unix
    /// stream peer credentials do not expose a Firecracker PID, so callers
    /// must supply the pinned process identity explicitly when available.
    #[cfg(target_os = "linux")]
    pub async fn connect_with_process(
        endpoint: &GuestEndpoint,
        expected: SessionIdentity,
        operation: OperationId,
        process: &crate::process::ProcessIdentity,
    ) -> Result<Self> {
        process.verify()?;
        Self::connect_with_process_timeout(endpoint, expected, operation, DEFAULT_TIMEOUT, process)
            .await
    }

    pub async fn connect_with_process_timeout(
        endpoint: &GuestEndpoint,
        expected: SessionIdentity,
        operation: OperationId,
        duration: Duration,
        process: &crate::process::ProcessIdentity,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            process.verify()?;
            let connection =
                Self::connect_internal(endpoint, expected, operation, duration, Some(process))
                    .await?;
            process.verify()?;
            return Ok(connection);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = process;
            Self::connect_with_timeout(endpoint, expected, operation, duration).await
        }
    }
    pub async fn connect_with_timeout(
        endpoint: &GuestEndpoint,
        expected: SessionIdentity,
        operation: OperationId,
        duration: Duration,
    ) -> Result<Self> {
        Self::connect_internal(endpoint, expected, operation, duration, None).await
    }

    /// Rebind an authenticated connection after a full VM restore. The old
    /// transport is quarantined by an authenticated SessionRebind exchange;
    /// only then is the new process/socket endpoint adopted and HELLO/READY
    /// performed with the strictly newer session identity.
    pub async fn rebind_with_process_timeout(
        &self,
        endpoint: &GuestEndpoint,
        old_identity: SessionIdentity,
        new_identity: SessionIdentity,
        operation: OperationId,
        duration: Duration,
        process: &crate::process::ProcessIdentity,
    ) -> Result<Self> {
        if self.expected != old_identity {
            return Err(Error::Config("guest rebind old identity mismatch"));
        }
        old_identity
            .validate_rebind(&new_identity)
            .map_err(Error::Config)?;
        process.verify()?;
        let peer = self
            .request_with_timeout(
                operation,
                GuestMessage::SessionRebind {
                    identity: new_identity.clone(),
                },
                duration,
            )
            .await?;
        if !matches!(peer.message, GuestMessage::SessionRebindReady) {
            return Err(Error::Config("guest rebind acknowledgement invalid"));
        }
        self.shutdown_transport().await;
        process.verify()?;
        Self::connect_with_process_timeout(
            endpoint,
            new_identity,
            OperationId::new("session-rebind-hello")
                .map_err(|_| Error::Config("guest rebind operation invalid"))?,
            duration,
            process,
        )
        .await
    }

    async fn connect_internal(
        endpoint: &GuestEndpoint,
        expected: SessionIdentity,
        operation: OperationId,
        duration: Duration,
        expected_process: Option<&crate::process::ProcessIdentity>,
    ) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        let _ = expected_process;
        let deadline = Instant::now() + duration;
        let mut stream = loop {
            endpoint.verify()?;
            #[cfg(target_os = "linux")]
            if let Some(process) = expected_process {
                process.verify()?;
            }
            let attempt = async {
                let mut stream = timeout(remaining(deadline), UnixStream::connect(&endpoint.path))
                    .await
                    .map_err(|_| Error::Config("guest transport connect timeout"))??;
                #[cfg(target_os = "linux")]
                if let Some(process) = expected_process {
                    let peer_pid = stream
                        .peer_cred()?
                        .pid()
                        .and_then(|pid| u32::try_from(pid).ok())
                        .ok_or(Error::Config("guest peer PID unavailable"))?;
                    if peer_pid != process.pid() {
                        return Err(Error::Config("guest peer process identity mismatch"));
                    }
                }
                endpoint.verify()?;
                vsock_connect(&mut stream, deadline).await?;
                Ok(stream)
            }
            .await;
            match attempt {
                Ok(stream) => break stream,
                Err(Error::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::UnexpectedEof
                    ) && Instant::now() < deadline =>
                {
                    // The host socket exists before the guest has bound its port.
                    // Retry only transport establishment, never HELLO/READY validation.
                    tokio::time::sleep(Duration::from_millis(10).min(remaining(deadline))).await;
                }
                Err(error) => return Err(error),
            }
        };
        let hello = GuestEnvelope {
            identity: expected.clone(),
            operation: operation.clone(),
            message: GuestMessage::Hello,
        };
        timeout(remaining(deadline), framing::write(&mut stream, 1, &hello))
            .await
            .map_err(|_| Error::Config("guest handshake write timeout"))??;
        let (id, ready) = timeout(remaining(deadline), framing::read(&mut stream))
            .await
            .map_err(|_| Error::Config("guest handshake read timeout"))??;
        if id != 1 || ready.operation != operation {
            return Err(Error::Config("guest handshake correlation failed"));
        }
        framing::validate(&ready, &expected)?;
        if !matches!(ready.message, GuestMessage::Ready) {
            return Err(Error::Config("guest did not become ready"));
        }
        let (reader, writer) = tokio::io::split(stream);
        let pending = Arc::new(StdMutex::new(HashMap::new()));
        let (event_tx, event_rx) = broadcast::channel(MAX_EVENTS);
        let closed = Arc::new(AtomicBool::new(false));
        let reader_task = tokio::spawn(reader_loop(
            reader,
            expected.clone(),
            pending.clone(),
            event_tx.clone(),
            closed.clone(),
        ));
        Ok(Self {
            writer: Mutex::new(writer),
            pending,
            events: Mutex::new(event_rx),
            event_tx,
            next_request: AtomicU64::new(2),
            closed,
            expected,
            reader_task: Mutex::new(Some(reader_task)),
        })
    }

    pub async fn request(
        &self,
        operation: OperationId,
        message: GuestMessage,
    ) -> Result<GuestPeer> {
        self.request_with_timeout(operation, message, DEFAULT_TIMEOUT)
            .await
    }
    pub async fn request_with_timeout(
        &self,
        operation: OperationId,
        message: GuestMessage,
        duration: Duration,
    ) -> Result<GuestPeer> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Config("guest transport is closed"));
        }
        let id = self
            .next_request
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| Error::Config("guest request ID exhausted"))?;
        let (sender, receiver) = oneshot::channel();
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| Error::Config("guest pending state poisoned"))?;
            if pending.len() >= MAX_PENDING {
                return Err(Error::Config("guest request capacity exhausted"));
            }
            pending.insert(
                id,
                Pending {
                    operation: operation.clone(),
                    sender,
                },
            );
        }
        let mut guard = PendingGuard {
            map: self.pending.clone(),
            id,
            armed: true,
        };
        let envelope = GuestEnvelope {
            identity: self.expected.clone(),
            operation,
            message,
        };
        let deadline = Instant::now() + duration;
        let wrote = timeout(remaining(deadline), async {
            let mut writer = self.writer.lock().await;
            framing::write(&mut *writer, id, &envelope).await
        })
        .await;
        if !matches!(wrote, Ok(Ok(()))) {
            self.shutdown_transport().await;
            return Err(Error::Config("guest request write failed"));
        }
        match timeout(remaining(deadline), receiver).await {
            Ok(Ok(peer)) => {
                guard.armed = false;
                Ok(peer)
            }
            _ => {
                self.shutdown_transport().await;
                Err(Error::Config("guest request timed out"))
            }
        }
    }
    pub async fn receive(&self, duration: Duration) -> Result<GuestPeer> {
        timeout(duration, self.events.lock().await.recv())
            .await
            .map_err(|_| Error::Config("guest event timeout"))?
            .map_err(|error| match error {
                broadcast::error::RecvError::Closed => Error::Config("guest transport closed"),
                broadcast::error::RecvError::Lagged(_) => {
                    Error::Config("guest event retention exceeded")
                }
            })
    }

    /// Subscribe to unsolicited guest events without stealing the primary
    /// receiver. Each subscriber has the same bounded retention window and is
    /// explicitly told when it falls behind.
    pub fn subscribe_events(&self) -> broadcast::Receiver<GuestPeer> {
        self.event_tx.subscribe()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    async fn shutdown_transport(&self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut task) = self.reader_task.try_lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
        let mut writer = self.writer.lock().await;
        let _ = writer.shutdown().await;
    }
}

impl Drop for GuestConnection {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut task) = self.reader_task.try_lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}

#[path = "io.rs"]
mod io;
use io::{reader_loop, vsock_connect};

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}
