//! Narrow Artifactd V3 client used only at image intake.
use crate::error::{Error, Result};
use artifactd_protocol::{Action, OperationId, Request, VERSION};
use rustix::fd::OwnedFd;
use std::{fs::File, path::Path};

pub(crate) fn allocate(socket: &Path, server_uid: u32) -> Result<String> {
    artifactd_protocol::client::Client::new(socket, server_uid)
        .allocate()
        .map(|operation| operation.as_str().to_owned())
        .map_err(Error::Io)
}

pub(crate) fn call(
    socket: &Path,
    server_uid: u32,
    operation_id: &str,
    action: Action,
    input: Option<&File>,
) -> Result<(serde_json::Value, Option<OwnedFd>)> {
    let operation_id = OperationId::try_from(operation_id.to_owned()).map_err(|_| Error::State)?;
    let request = Request {
        version: VERSION,
        operation_id,
        action,
    };
    let (response, fd) = artifactd_protocol::client::Client::new(socket, server_uid)
        .call(&request, input)
        .map_err(Error::Io)?;
    let value = response
        .result
        .map_err(|_| Error::Artifact("artifact service rejected image handoff"))?;
    Ok((value, fd))
}

pub(crate) fn value_string<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::State)
}

pub(crate) fn value_u64(value: &serde_json::Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or(Error::State)
}

pub(crate) fn prepared_fd(fd: Option<OwnedFd>) -> Result<File> {
    fd.map(File::from).ok_or(Error::State)
}
