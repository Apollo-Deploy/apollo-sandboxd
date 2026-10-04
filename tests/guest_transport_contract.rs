use apollo_sandboxd::guest::{GuestConnection, GuestEndpoint};
use guest_protocol::{
    BootNonce, GuestEnvelope, GuestMessage, OutputRecord, SessionIdentity, Stream,
};
use sandboxd_protocol::{OperationId, SandboxGeneration, SandboxId, SessionGeneration, SessionId};
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

fn identity() -> SessionIdentity {
    SessionIdentity {
        sandbox: SandboxId::new("sb").unwrap(),
        sandbox_generation: SandboxGeneration::new(1).unwrap(),
        session: SessionId::new("session").unwrap(),
        session_generation: SessionGeneration::new(2).unwrap(),
        boot_nonce: BootNonce([7; 32]),
        vsock_cid: 33,
        protocol_version: guest_protocol::GUEST_PROTOCOL_VERSION,
    }
}

async fn read_frame(stream: &mut tokio::net::UnixStream) -> (u64, GuestEnvelope) {
    let mut header = [0; 20];
    stream.read_exact(&mut header).await.unwrap();
    let header = sandboxd_protocol::codec::Header::decode(header).unwrap();
    let mut body = vec![0; header.body_len as usize];
    stream.read_exact(&mut body).await.unwrap();
    (
        header.request_id,
        sandboxd_protocol::codec::decode_body(&body).unwrap(),
    )
}

async fn accept_vsock(stream: &mut tokio::net::UnixStream) {
    let mut line = Vec::new();
    loop {
        let mut byte = [0; 1];
        stream.read_exact(&mut byte).await.unwrap();
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    assert_eq!(line, b"CONNECT 1024\n");
    stream.write_all(b"OK 4242\n").await.unwrap();
}

async fn write_frame(stream: &mut tokio::net::UnixStream, id: u64, value: &GuestEnvelope) {
    let (header, body) = sandboxd_protocol::codec::encode_frame_parts(id, value).unwrap();
    stream.write_all(&header).await.unwrap();
    stream.write_all(&body).await.unwrap();
}

#[tokio::test]
async fn handshake_waits_for_guest_listener_then_authenticates_full_session_identity() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("vsock.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let endpoint = GuestEndpoint::observed(&path).unwrap();
    let expected = identity();
    let server_identity = expected.clone();
    let server = tokio::spawn(async move {
        // Firecracker accepts the host socket before the guest binds its port.
        let (mut not_ready, _) = listener.accept().await.unwrap();
        let mut connect = [0; 13];
        not_ready.read_exact(&mut connect).await.unwrap();
        assert_eq!(&connect, b"CONNECT 1024\n");
        drop(not_ready);
        let (mut stream, _) = listener.accept().await.unwrap();
        accept_vsock(&mut stream).await;
        let (_, hello) = read_frame(&mut stream).await;
        assert!(matches!(hello.message, GuestMessage::Hello));
        write_frame(
            &mut stream,
            1,
            &GuestEnvelope {
                identity: server_identity,
                operation: hello.operation,
                message: GuestMessage::Ready,
            },
        )
        .await;
    });
    let connection =
        GuestConnection::connect(&endpoint, expected, OperationId::new("hello").unwrap())
            .await
            .unwrap();
    drop(connection);
    server.await.unwrap();
}

#[tokio::test]
async fn wrong_generation_is_rejected_before_connection_is_ready() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("vsock.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let endpoint = GuestEndpoint::observed(&path).unwrap();
    let expected = identity();
    let mut wrong = expected.clone();
    wrong.session_generation = SessionGeneration::new(3).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        accept_vsock(&mut stream).await;
        let (_, hello) = read_frame(&mut stream).await;
        write_frame(
            &mut stream,
            1,
            &GuestEnvelope {
                identity: wrong,
                operation: hello.operation,
                message: GuestMessage::Ready,
            },
        )
        .await;
    });
    assert!(
        GuestConnection::connect_with_timeout(
            &endpoint,
            expected,
            OperationId::new("hello").unwrap(),
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn oversized_frame_is_rejected_before_body_allocation() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("vsock.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let endpoint = GuestEndpoint::observed(&path).unwrap();
    let expected = identity();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        accept_vsock(&mut stream).await;
        let (_, hello) = read_frame(&mut stream).await;
        let mut header = [0; 20];
        header[..4].copy_from_slice(b"ASD\0");
        header[4..6].copy_from_slice(&1u16.to_be_bytes());
        header[8..12]
            .copy_from_slice(&((guest_protocol::wire::MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
        header[12..20].copy_from_slice(&hello.operation.as_str().len().to_be_bytes());
        stream.write_all(&header).await.unwrap();
    });
    assert!(
        GuestConnection::connect_with_timeout(
            &endpoint,
            expected,
            OperationId::new("hello").unwrap(),
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn unsolicited_output_is_routed_while_request_waits_for_matching_response() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("vsock.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let endpoint = GuestEndpoint::observed(&path).unwrap();
    let expected = identity();
    let server_identity = expected.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        accept_vsock(&mut stream).await;
        let (_, hello) = read_frame(&mut stream).await;
        write_frame(
            &mut stream,
            1,
            &GuestEnvelope {
                identity: server_identity.clone(),
                operation: hello.operation,
                message: GuestMessage::Ready,
            },
        )
        .await;
        let (id, request) = read_frame(&mut stream).await;
        write_frame(
            &mut stream,
            0,
            &GuestEnvelope {
                identity: server_identity.clone(),
                operation: OperationId::new("event").unwrap(),
                message: GuestMessage::Output {
                    record: OutputRecord {
                        exec: sandboxd_protocol::ExecId::new("e").unwrap(),
                        stream: Stream::Stdout,
                        sequence: 1,
                        timestamp_unix_ms: 1,
                        flags: 0,
                        payload: b"x".to_vec(),
                    },
                },
            },
        )
        .await;
        write_frame(
            &mut stream,
            id,
            &GuestEnvelope {
                identity: server_identity,
                operation: request.operation,
                message: GuestMessage::Ready,
            },
        )
        .await;
    });
    let connection =
        GuestConnection::connect(&endpoint, expected, OperationId::new("hello").unwrap())
            .await
            .unwrap();
    let request = connection.request(OperationId::new("ping").unwrap(), GuestMessage::Ping);
    let (response, event) = tokio::join!(request, connection.receive(Duration::from_secs(1)));
    assert!(matches!(response.unwrap().message, GuestMessage::Ready));
    assert!(matches!(
        event.unwrap().message,
        GuestMessage::Output { .. }
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn request_timeout_closes_transport_and_releases_pending_capacity() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("vsock.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let endpoint = GuestEndpoint::observed(&path).unwrap();
    let expected = identity();
    let server_identity = expected.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        accept_vsock(&mut stream).await;
        let (_, hello) = read_frame(&mut stream).await;
        write_frame(
            &mut stream,
            1,
            &GuestEnvelope {
                identity: server_identity,
                operation: hello.operation,
                message: GuestMessage::Ready,
            },
        )
        .await;
        let _ = read_frame(&mut stream).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let connection =
        GuestConnection::connect(&endpoint, expected, OperationId::new("hello").unwrap())
            .await
            .unwrap();
    assert!(
        connection
            .request_with_timeout(
                OperationId::new("slow").unwrap(),
                GuestMessage::Ping,
                Duration::from_millis(20)
            )
            .await
            .is_err()
    );
    assert!(
        connection
            .request(
                OperationId::new("after-timeout").unwrap(),
                GuestMessage::Ping
            )
            .await
            .is_err()
    );
    drop(connection);
    server.await.unwrap();
}
