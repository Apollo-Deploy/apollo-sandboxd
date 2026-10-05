//! Response descriptors are delivered once with the first framed bytes.
use crate::error::{Error, Result};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use sandboxd_protocol::{Response, codec};
use std::{
    io::{self, IoSlice},
    os::fd::{AsRawFd, OwnedFd},
};
use tokio::{
    io::{AsyncWriteExt, Interest},
    net::UnixStream,
};

fn validate(response: &Response, count: usize) -> Result<()> {
    let expected = usize::from(matches!(response, Response::FilesystemExport(_)));
    if count != expected {
        return Err(Error::Path);
    }
    Ok(())
}

pub(super) async fn receive(stream: &mut UnixStream) -> Result<(u64, Response, Vec<OwnedFd>)> {
    let (id, response, fds) = super::ancillary::recv_frame(stream).await?;
    validate(&response, fds.len())?;
    Ok((id, response, fds))
}

pub(super) async fn send(
    stream: &mut UnixStream,
    id: u64,
    response: &Response,
    fds: &[OwnedFd],
) -> Result<()> {
    validate(response, fds.len())?;
    let (header, body) = codec::encode_frame_parts(id, response).map_err(|_| Error::State)?;
    let raw = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
    let controls = if raw.is_empty() {
        Vec::new()
    } else {
        vec![ControlMessage::ScmRights(&raw)]
    };
    let buffers = [IoSlice::new(&header), IoSlice::new(&body)];
    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = MsgFlags::empty();
    let sent = loop {
        stream.writable().await.map_err(|_| Error::State)?;
        match stream.try_io(Interest::WRITABLE, || {
            sendmsg::<()>(stream.as_raw_fd(), &buffers, &controls, flags, None)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))
        }) {
            Ok(0) => return Err(Error::State),
            Ok(sent) => break sent,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(Error::State),
        }
    };
    let total = header.len() + body.len();
    if sent > total {
        return Err(Error::State);
    }
    if sent < header.len() {
        stream
            .write_all(&header[sent..])
            .await
            .map_err(|_| Error::State)?;
    }
    if sent < total {
        let offset = sent.saturating_sub(header.len());
        stream
            .write_all(&body[offset..])
            .await
            .map_err(|_| Error::State)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandboxd_protocol::{
        Fence, FilesystemExportInfo, ImageDigest, LeaseId, OperationId, Request, SandboxGeneration,
        SandboxId, SessionGeneration,
    };
    use std::io::Read;

    // Owns SCM_RIGHTS response delivery, distinct from export persistence and
    // tar semantics. A plain codec reader or repeated ancillary send would lose
    // or duplicate the descriptor. The peer fixture makes no admission claim.
    #[tokio::test]
    async fn descriptor_client_receives_export_bytes_and_rejects_invalid_delivery() {
        for (missing, wrong_operation, entries) in [
            (false, false, 1),
            (false, false, 0),
            (true, false, 1),
            (false, true, 1),
        ] {
            let root = tempfile::tempdir().unwrap();
            let socket = root.path().join("api.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let data = root.path().join("layer");
            std::fs::write(&data, b"transport-payload").unwrap();
            let operation = OperationId::with_sequence(1, "export").unwrap();
            let request = Request::FilesystemExport {
                volume_id: None,
                operation: operation.clone(),
                operation_sequence: 1,
                fence: Fence {
                    sandbox: SandboxId::new("transport").unwrap(),
                    generation: SandboxGeneration::new(1).unwrap(),
                    session_generation: Some(SessionGeneration::new(1).unwrap()),
                    lease: LeaseId::new("lease").unwrap(),
                },
                max_bytes: 1024,
                max_entries: 1,
            };
            let expected = request.clone();
            let response = Response::FilesystemExport(FilesystemExportInfo {
                operation: if wrong_operation {
                    OperationId::with_sequence(2, "other-export").unwrap()
                } else {
                    operation
                },
                base_digest: ImageDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                sha256: "b".repeat(64),
                byte_len: 17,
                entry_count: entries,
            });
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (id, request, input) = super::super::ancillary::recv_request(&mut stream)
                    .await
                    .unwrap();
                assert_eq!(request, expected);
                assert!(input.is_empty());
                if missing {
                    let (header, body) = codec::encode_frame_parts(id, &response).unwrap();
                    stream.write_all(&header).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                } else {
                    let fd: OwnedFd = std::fs::File::open(data).unwrap().into();
                    send(&mut stream, id, &response, &[fd]).await.unwrap();
                }
            });
            let result = super::super::client::call_with_fds(
                &socket,
                &request,
                Vec::new(),
                std::time::Duration::from_secs(2),
            )
            .await;
            server.await.unwrap();
            if missing || wrong_operation {
                assert!(
                    result.is_err(),
                    "export delivery must match request operation and rights"
                );
            } else {
                let (_, mut fds) = result.unwrap();
                assert_eq!(fds.len(), 1);
                let mut payload = Vec::new();
                std::fs::File::from(fds.pop().unwrap())
                    .read_to_end(&mut payload)
                    .unwrap();
                assert_eq!(payload, b"transport-payload");
            }
        }
    }
}
