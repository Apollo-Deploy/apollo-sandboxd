use super::ancillary;
use super::codec;
use crate::error::{Error, Result};
use sandboxd_protocol::{ApiError, ErrorCode, Request, Response};
use std::os::fd::{AsRawFd, OwnedFd};
use std::{path::Path, time::Duration};
use tokio::{net::UnixStream, time::timeout};

/// CLI and other standalone clients use the same framed API.
pub async fn call(socket: &Path, request: &Request, deadline: Duration) -> Result<Response> {
    if !socket.is_absolute() || deadline.is_zero() || deadline > Duration::from_secs(300) {
        return Err(Error::Path);
    }
    timeout(deadline, async {
        let mut stream = UnixStream::connect(socket).await?;
        codec::write(&mut stream, 1, request).await?;
        let (id, response, fds) = super::response_transport::receive(&mut stream).await?;
        if !fds.is_empty() {
            return Err(Error::Path);
        }
        if id != 1 {
            return Err(Error::State);
        }
        if let Response::Guest(reply) = &response {
            reply.validate().map_err(|_| Error::State)?;
        }
        match response {
            Response::Error(error) => Err(error.into()),
            response => Ok(response),
        }
    })
    .await
    .map_err(|_| {
        Error::Api(ApiError::new(
            ErrorCode::SessionUnavailable,
            "daemon request timed out",
        ))
    })?
}

/// Sends one request with role-ordered stdout/stderr sink descriptors.
pub async fn call_with_sinks(
    socket: &Path,
    request: &Request,
    sinks: Vec<OwnedFd>,
    deadline: Duration,
) -> Result<Response> {
    if sinks.len() != 2 {
        return Err(Error::Path);
    }
    let (response, fds) = call_with_fds(socket, request, sinks, deadline).await?;
    if !fds.is_empty() {
        return Err(Error::Path);
    }
    Ok(response)
}

/// Descriptor-aware image import and immutable filesystem export transport.
pub async fn call_with_fds(
    socket: &Path,
    request: &Request,
    sinks: Vec<OwnedFd>,
    deadline: Duration,
) -> Result<(Response, Vec<OwnedFd>)> {
    ancillary::validate_fd_count(request, sinks.len())?;
    if !socket.is_absolute() || deadline.is_zero() || deadline > Duration::from_secs(300) {
        return Err(Error::Path);
    }
    timeout(deadline, async {
        let stream = UnixStream::connect(socket).await?;
        let std_stream = stream.into_std()?;
        // sendmsg/write may block on a full Unix socket. Keep this bounded
        // operation off the Tokio worker and use a blocking clone so the
        // ancillary rights are attached exactly once.
        std_stream.set_nonblocking(false)?;
        std_stream.set_write_timeout(Some(deadline))?;
        let send_stream = std_stream.try_clone()?;
        let sending_request = request.clone();
        let send_result = tokio::task::spawn_blocking(move || {
            // Own rights until send completes, including after caller timeout.
            let raw: Vec<_> = sinks.iter().map(AsRawFd::as_raw_fd).collect();
            ancillary::send_request(&send_stream, 1, &sending_request, &raw)
        })
        .await
        .map_err(|_| Error::State)?;
        send_result?;
        std_stream.set_nonblocking(true)?;
        let mut stream = UnixStream::from_std(std_stream)?;
        let (id, response, fds) = super::response_transport::receive(&mut stream).await?;
        if id != 1 {
            return Err(Error::State);
        }
        if let Response::Guest(reply) = &response {
            reply.validate().map_err(|_| Error::State)?;
        }
        if let Response::FilesystemExport(info) = &response {
            match request {
                Request::FilesystemExport {
                    operation,
                    max_bytes,
                    max_entries,
                    ..
                } if info.operation == *operation
                    && info.byte_len > 0
                    && info.byte_len <= *max_bytes
                    && info.entry_count <= *max_entries =>
                {
                    ()
                }
                _ => return Err(Error::State),
            }
        }
        match response {
            Response::Error(error) => Err(error.into()),
            response => Ok((response, fds)),
        }
    })
    .await
    .map_err(|_| Error::State)?
}
