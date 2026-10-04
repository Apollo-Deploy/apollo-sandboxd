use super::framing;
use super::{GuestPeer, PendingMap};
use crate::error::{Error, Result};
use guest_protocol::SessionIdentity;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf},
    net::UnixStream,
    sync::broadcast,
    time::timeout,
};

pub(super) async fn reader_loop(
    mut reader: ReadHalf<UnixStream>,
    expected: SessionIdentity,
    pending: PendingMap,
    events: broadcast::Sender<GuestPeer>,
    closed: Arc<AtomicBool>,
) {
    loop {
        let (request_id, envelope) = match framing::read(&mut reader).await {
            Ok(value) => value,
            Err(_) => break,
        };
        if framing::validate(&envelope, &expected).is_err() {
            break;
        }
        let peer = GuestPeer {
            request_id,
            operation: envelope.operation,
            message: envelope.message,
        };
        if request_id != 0 {
            if let Some(waiter) = pending
                .lock()
                .ok()
                .and_then(|mut map| map.remove(&request_id))
                && waiter.operation == peer.operation
            {
                let _ = waiter.sender.send(peer);
                continue;
            }
            break;
        }
        if events.send(peer).is_err() {
            break;
        }
    }
    closed.store(true, Ordering::Release);
    if let Ok(mut pending) = pending.lock() {
        pending.clear();
    }
}

pub(super) async fn vsock_connect(stream: &mut UnixStream, deadline: Instant) -> Result<()> {
    let request = format!("CONNECT {}\n", guest_protocol::GUEST_PORT);
    timeout(remaining(deadline), stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| Error::Config("vsock connect write timeout"))??;
    let mut response = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        timeout(remaining(deadline), stream.read_exact(&mut byte))
            .await
            .map_err(|_| Error::Config("vsock connect response timeout"))??;
        response.push(byte[0]);
        if response.len() > 64 {
            return Err(Error::Config("vsock connect response exceeds limit"));
        }
        if byte[0] == b'\n' {
            break;
        }
    }
    let text = std::str::from_utf8(&response)
        .map_err(|_| Error::Config("vsock connect response is not ASCII"))?;
    text.strip_prefix("OK ")
        .and_then(|value| value.strip_suffix('\n'))
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|port| *port != 0)
        .ok_or(Error::Config("vsock connect response rejected"))?;
    Ok(())
}
fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}
