use super::handlers;
use crate::{
    config::Config,
    error::{Error, Result},
    security::peer::Peer,
    state::Store,
};
use sandboxd_protocol::{ApiError, ErrorCode, Request, Response};
use std::sync::Arc;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout_at},
};

enum Work {
    Request {
        peer: Peer,
        request: Request,
        deadline: Instant,
        reply: oneshot::Sender<Result<Response>>,
    },
    Expire,
    Invoke {
        operation: Box<dyn FnOnce(&mut Store) -> Result<Box<dyn std::any::Any + Send>> + Send>,
        reply: oneshot::Sender<Result<Box<dyn std::any::Any + Send>>>,
    },
    BlockingInvoke {
        operation: Box<dyn FnOnce(&mut Store) -> Result<Box<dyn std::any::Any + Send>> + Send>,
        reply: std::sync::mpsc::SyncSender<Result<Box<dyn std::any::Any + Send>>>,
    },
}

#[derive(Clone)]
pub struct StateClient(mpsc::Sender<Work>);

/// One daemon-wide SQLite owner. Queue capacity is tied to the connection bound;
/// there is no per-request blocking task or unbounded waiting list.
pub fn start(mut store: Store, config: Arc<Config>) -> (StateClient, JoinHandle<Result<()>>) {
    let (sender, mut receiver) = mpsc::channel(usize::from(config.daemon.max_connections));
    let worker = tokio::task::spawn_blocking(move || {
        while let Some(work) = receiver.blocking_recv() {
            match work {
                Work::Request {
                    peer,
                    request,
                    deadline,
                    reply,
                } => {
                    // Cancellation before dispatch must not create a late side effect.
                    if reply.is_closed() || Instant::now() >= deadline {
                        let _ = reply.send(Err(deadline_error()));
                        continue;
                    }
                    let _ = reply.send(handlers::dispatch(&mut store, &config, peer, request));
                }
                Work::Expire => {
                    store.expire_leases(handlers::now_ms()?)?;
                }
                Work::Invoke { operation, reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let _ = reply.send(operation(&mut store));
                }
                Work::BlockingInvoke { operation, reply } => {
                    let _ = reply.send(operation(&mut store));
                }
            }
        }
        Ok(())
    });
    (StateClient(sender), worker)
}

impl StateClient {
    /// Short durable callbacks from a bounded blocking runtime worker. A native
    /// channel is intentional: boot enters an async runtime, so nesting
    /// Handle::block_on in its synchronous journal callbacks would panic.
    pub(super) fn with_store_blocking<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Store) -> Result<T> + Send + 'static,
    {
        let (reply, receiver) = std::sync::mpsc::sync_channel(1);
        self.0
            .try_send(Work::BlockingInvoke {
                operation: Box::new(move |store| {
                    operation(store).map(|value| Box::new(value) as Box<dyn std::any::Any + Send>)
                }),
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::Api(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "state request queue is full",
                )),
                mpsc::error::TrySendError::Closed(_) => Error::State,
            })?;
        receiver
            .recv()
            .map_err(|_| Error::State)??
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| Error::State)
    }

    /// Execute a short synchronous callback on the exclusive Store worker.
    /// Runtime jobs use this for journal callbacks and observations; the
    /// callback must never wait on async I/O or retain Store across an await.
    pub async fn with_store<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Store) -> Result<T> + Send + 'static,
    {
        let (reply, receiver) = oneshot::channel();
        self.0
            .try_send(Work::Invoke {
                operation: Box::new(move |store| {
                    operation(store).map(|value| Box::new(value) as Box<dyn std::any::Any + Send>)
                }),
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::Api(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "state request queue is full",
                )),
                mpsc::error::TrySendError::Closed(_) => Error::State,
            })?;
        let value = receiver.await.map_err(|_| Error::State)??;
        value
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| Error::State)
    }

    pub async fn dispatch(
        &self,
        peer: Peer,
        request: Request,
        deadline: Instant,
    ) -> Result<Response> {
        let (reply, receiver) = oneshot::channel();
        self.0
            .try_send(Work::Request {
                peer,
                request,
                deadline,
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::Api(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "state request queue is full",
                )),
                mpsc::error::TrySendError::Closed(_) => Error::State,
            })?;
        timeout_at(deadline, receiver)
            .await
            .map_err(|_| deadline_error())?
            .map_err(|_| Error::State)?
    }

    /// A busy queue defers this periodic bounded scan; never block the accept loop.
    pub fn expire(&self) -> Result<()> {
        match self.0.try_send(Work::Expire) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::State),
        }
    }
}

pub fn deadline_error() -> Error {
    ApiError::new(
        ErrorCode::RequestTimeout,
        "request deadline exceeded; replay operation to resolve an uncertain result",
    )
    .into()
}

#[cfg(test)]
#[path = "state_worker_tests.rs"]
mod tests;
