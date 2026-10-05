use super::{
    handlers,
    runtime_service::RuntimeService,
    socket::Socket,
    state_worker::{self, StateClient},
};
use crate::{
    config::Config,
    error::{Error, Result},
    runtime::VerifiedCatalogs,
    security::peer::Peer,
    state::Store,
};
use sandboxd_protocol::SessionId;
use sandboxd_protocol::{Mutation, Request, Response};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::UnixStream,
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval, timeout_at},
};

pub async fn serve(config: Config, store: Store) -> Result<()> {
    run(config, store, None).await
}

/// Production entry point: execution catalogs and recovery must succeed before socket readiness.
pub async fn serve_with_runtime(
    config: Config,
    store: Store,
    catalogs: VerifiedCatalogs,
) -> Result<()> {
    run(config, store, Some(catalogs)).await
}

/// Reconcile and stop sessions owned by one exact durable store without opening an API socket.
pub async fn cleanup_owned_sessions(
    config: Config,
    store: Store,
    catalogs: VerifiedCatalogs,
    session_id: Option<SessionId>,
) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(Error::Config(
            "session cleanup requires Linux process identity",
        ));
    }
    let config = Arc::new(config);
    let (state, worker) = state_worker::start(store, Arc::clone(&config));
    let runtime = RuntimeService::new_for_cleanup(config, state.clone(), catalogs);
    let cleanup = match runtime {
        Ok(runtime) => {
            let result = async {
                if let Some(session_id) = session_id {
                    runtime.cleanup_exact_owned(session_id).await?;
                } else {
                    runtime.cleanup_all_owned().await?;
                }
                runtime.shutdown().await
            }
            .await;
            drop(runtime);
            result
        }
        Err(error) => Err(error),
    };
    drop(state);
    let worker_result = worker.await.map_err(|_| Error::State)?;
    cleanup.and(worker_result)
}

async fn run(config: Config, store: Store, catalogs: Option<VerifiedCatalogs>) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(Error::Config("daemon control requires Linux SO_PEERCRED"));
    }
    let config = Arc::new(config);
    let (state, mut worker) = state_worker::start(store, Arc::clone(&config));
    let runtime = match catalogs {
        Some(catalogs) => {
            let runtime = RuntimeService::new(Arc::clone(&config), state.clone(), catalogs)?;
            runtime.recover().await?;
            Some(runtime)
        }
        None => None,
    };
    let socket = Socket::bind(&config.daemon).await?;
    if runtime.is_some() {
        eprintln!("daemon API ready; native runtime enabled; production qualification incomplete");
    }
    let permits = Arc::new(Semaphore::new(usize::from(config.daemon.max_connections)));
    let mut clients = JoinSet::new();
    let mut ticks = interval(Duration::from_secs(1));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    #[cfg(target_os = "linux")]
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(not(target_os = "linux"))]
    let mut term = ();
    let mut worker_consumed = false;
    let outcome = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = termination(&mut term) => break Ok(()),
            result = &mut worker => {
                worker_consumed = true;
                break result.map_err(|_| Error::State).and_then(|result| result).and(Err(Error::State));
            }
            Some(result) = clients.join_next(), if !clients.is_empty() => {
                if result.is_err() { eprintln!("API connection task failed"); }
            }
            _ = ticks.tick() => {
                if let Some(runtime) = &runtime { runtime.tick_policy(); }
                else if let Err(error) = state.expire() { break Err(error); }
            }
            accepted = socket.listener.accept(), if permits.available_permits() > 0 => {
                let (stream, _) = match accepted { Ok(pair) => pair, Err(error) => break Err(error.into()) };
                let permit = Arc::clone(&permits).try_acquire_owned().map_err(|_| Error::State)?;
                let config = Arc::clone(&config);
                let state = state.clone();
                let runtime = runtime.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    if connection(stream, config, state, runtime).await.is_err() { eprintln!("API connection rejected or closed"); }
                });
            }
        }
    };
    clients.shutdown().await;
    if let Some(runtime) = &runtime {
        runtime.shutdown().await?;
    }
    drop(runtime);
    drop(state);
    if !worker_consumed {
        worker.await.map_err(|_| Error::State)??;
    }
    outcome
}
#[cfg(target_os = "linux")]
async fn termination(term: &mut tokio::signal::unix::Signal) {
    term.recv().await;
}
#[cfg(not(target_os = "linux"))]
async fn termination(_: &mut ()) {
    std::future::pending::<()>().await;
}

async fn connection(
    stream: UnixStream,
    config: Arc<Config>,
    state: StateClient,
    runtime: Option<Arc<RuntimeService>>,
) -> Result<()> {
    let peer = Peer::from_stream(&stream)?.authorize(&config.security)?;
    let deadline =
        Instant::now() + Duration::from_secs(u64::from(config.daemon.request_timeout_seconds));
    // Ancillary descriptors are received only after SO_PEERCRED authorization.
    // The bounded frame and body are read through Tokio readiness; no
    // per-client blocking-pool task can starve state or VM control work.
    let mut stream = stream;
    let (id, request, sink_fds) = timeout_at(deadline, super::ancillary::recv_request(&mut stream))
        .await
        .map_err(|_| Error::State)??;
    request.validate().map_err(|_| Error::Path)?;
    super::ancillary::validate_fd_count(&request, sink_fds.len())?;
    let mut response_fds = Vec::new();
    let result = if let Some(runtime) = &runtime
        && matches!(
            request,
            Request::Volume { .. } | Request::VolumeInspect { .. } | Request::VolumeRelease { .. }
        ) {
        runtime
            .volume_request(peer, request, sink_fds, deadline)
            .await
    } else if let Some(runtime) = &runtime
        && matches!(request, Request::FilesystemExport { .. })
    {
        #[cfg(target_os = "linux")]
        let export = runtime.export_request(request, peer, deadline).await;
        #[cfg(not(target_os = "linux"))]
        let export: Result<(Response, std::os::fd::OwnedFd)> =
            Err(sandboxd_protocol::ApiError::new(
                sandboxd_protocol::ErrorCode::UnsupportedCapability,
                "filesystem export requires Linux",
            )
            .into());
        match export {
            Ok((response, fd)) => {
                response_fds.push(fd);
                Ok(response)
            }
            Err(error) => Err(error),
        }
    } else if let (Some(runtime), Request::ExecStatus { fence, exec }) = (&runtime, &request) {
        runtime
            .exec_status(peer, fence.clone(), exec.clone(), deadline)
            .await
    } else if let (
        Some(runtime),
        Request::Guest {
            operation,
            operation_sequence,
            fence,
            command,
            ..
        },
    ) = (&runtime, &request)
    {
        runtime
            .guest_command(
                peer,
                operation.clone(),
                *operation_sequence,
                fence.clone(),
                *command.clone(),
                sink_fds,
                deadline,
            )
            .await
    } else if let (
        Some(runtime),
        Request::Mutate {
            operation,
            operation_sequence,
            mutation,
            ..
        },
    ) = (&runtime, &request)
        && let Mutation::Session { fence, control } = mutation.as_ref()
    {
        runtime
            .control(
                peer,
                operation.clone(),
                fence.clone(),
                *control,
                *operation_sequence,
                deadline,
            )
            .await
    } else if let Some(runtime) = &runtime
        && matches!(request, Request::Snapshot { .. })
    {
        runtime.snapshot_request(peer, request, deadline).await
    } else if let Some(runtime) = &runtime
        && matches!(request, Request::Checkpoint { .. })
    {
        runtime.checkpoint_request(peer, request, deadline).await
    } else if let Some(runtime) = &runtime
        && matches!(
            request,
            Request::ImageInspect { .. } | Request::ImageList { .. } | Request::Image { .. }
        )
    {
        runtime.image_request(peer, request, deadline).await
    } else {
        match runtime
            .as_ref()
            .and_then(|r| r.stateless(&request))
            .or_else(|| handlers::stateless(&config, &request))
        {
            Some(response) => Ok(response),
            None => state.dispatch(peer, request, deadline).await,
        }
    };
    let response = result.unwrap_or_else(|error| Response::Error(error.api()));
    // Reserve a bounded write window so a deadline error can reach the caller.
    let write_deadline = Instant::now() + Duration::from_secs(1);
    timeout_at(
        write_deadline,
        super::response_transport::send(&mut stream, id, &response, &response_fds),
    )
    .await
    .map_err(|_| Error::State)??;
    Ok(())
}
