use firecracker_api::http::{MAX_HEADER, read_response};
use tokio::io::{AsyncWriteExt, duplex};

#[tokio::test]
async fn fragmented_http_bodies_and_empty_success_are_supported() {
    for response in [
        b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(),
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    ] {
        assert_eq!(
            read_response(&mut &*response).await.expect("204"),
            (204, vec![])
        );
    }
    let (mut writer, mut reader) = duplex(1);
    let writing = tokio::spawn(async move {
        writer
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\0\xff\r\n")
            .await
            .expect("write");
    });
    assert_eq!(
        read_response(&mut reader).await.expect("200"),
        (200, vec![0, 255, 13, 10])
    );
    writing.await.expect("writer");
}

#[tokio::test]
async fn ambiguous_oversized_or_truncated_http_is_rejected() {
    for response in [
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\nx",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx",
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
        "HTTP/1.1 200 OK\r\n\r\n",
        "HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
        "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
    ] {
        assert!(
            read_response(&mut response.as_bytes()).await.is_err(),
            "accepted {response:?}"
        );
    }
    let oversized = vec![b'x'; MAX_HEADER + 1];
    assert!(read_response(&mut oversized.as_slice()).await.is_err());
}
