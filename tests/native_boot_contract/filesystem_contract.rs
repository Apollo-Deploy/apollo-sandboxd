//! Real guest overlay -> immutable OCI layer byte contract.
use apollo_sandboxd::guest::GuestConnection;
use guest_protocol::{FileRequest, GuestMessage};
use sandboxd_protocol::OperationId;
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

pub(super) async fn run(guest: &GuestConnection) {
    const LIMIT: u64 = 1024 * 1024;
    let operation = OperationId::new("native-filesystem-export").unwrap();
    let ready = guest
        .request(
            operation.clone(),
            GuestMessage::FilesystemExportBegin {
                volume_id: None,
                max_bytes: LIMIT,
                max_entries: 256,
            },
        )
        .await
        .expect("export completed guest filesystem");
    let (sha256, byte_len, entry_count) = match ready.message {
        GuestMessage::FilesystemExportReady {
            sha256,
            byte_len,
            entry_count,
        } => (sha256, byte_len, entry_count),
        other => panic!("unexpected export response: {other:?}"),
    };
    assert!((1..=LIMIT).contains(&byte_len));
    assert!((1..=256).contains(&entry_count));

    // A later guest write must not alter the already acknowledged layer.
    let changed = guest
        .request(
            OperationId::new("native-post-export-write").unwrap(),
            GuestMessage::File {
                request: FileRequest::Write {
                    transfer_id: "native-post-export".into(),
                    path: "/qualification.txt".into(),
                    offset: 0,
                    data: b"after-export".to_vec(),
                    final_chunk: true,
                    sha256: None,
                    atomic_replace: true,
                },
            },
        )
        .await
        .expect("write after export acknowledgement");
    assert!(matches!(changed.message, GuestMessage::FileResult { .. }));
    let live = guest
        .request(
            OperationId::new("native-post-export-read").unwrap(),
            GuestMessage::File {
                request: FileRequest::Read {
                    path: "/qualification.txt".into(),
                    offset: 0,
                    limit: 1024,
                },
            },
        )
        .await
        .expect("read live file after export");
    match live.message {
        GuestMessage::FileResult { data, .. } => assert_eq!(data, b"after-export"),
        other => panic!("unexpected live file response: {other:?}"),
    }

    let mut bytes = Vec::new();
    loop {
        let offset = bytes.len() as u64;
        let reply = guest
            .request(
                operation.clone(),
                GuestMessage::FilesystemExportRead {
                    offset,
                    max_bytes: 60 * 1024,
                },
            )
            .await
            .expect("read acknowledged immutable layer");
        let GuestMessage::FilesystemExportChunk {
            offset: returned_offset,
            data,
            eof,
        } = reply.message
        else {
            panic!("unexpected layer chunk: {:?}", reply.message);
        };
        assert_eq!(returned_offset, offset);
        assert!(!data.is_empty(), "export must make bounded progress");
        assert!(data.len() <= 60 * 1024);
        assert!(offset + data.len() as u64 <= byte_len);
        bytes.extend_from_slice(&data);
        if eof {
            break;
        }
    }
    assert_eq!(bytes.len() as u64, byte_len);
    assert_eq!(hex::encode(Sha256::digest(&bytes)), sha256);
    let mut archive = tar::Archive::new(bytes.as_slice());
    let mut qualification_files = 0;
    for entry in archive.entries().expect("decode OCI tar layer") {
        let mut entry = entry.expect("decode tar entry");
        let path = entry.path().expect("decode layer path").into_owned();
        assert!(!path.is_absolute());
        if path == Path::new("qualification.txt") {
            qualification_files += 1;
            let mut payload = Vec::new();
            entry.read_to_end(&mut payload).expect("read exported file");
            assert_eq!(payload, b"persistent-state");
        }
    }
    assert_eq!(qualification_files, 1, "exact pre-export file required");

    let retired = guest
        .request(
            OperationId::new("native-retire-filesystem-export").unwrap(),
            GuestMessage::RetireOperation {
                operation: operation.clone(),
            },
        )
        .await
        .expect("retire durably observed export");
    assert!(matches!(retired.message, GuestMessage::Ready));
    let unavailable = guest
        .request(
            operation,
            GuestMessage::FilesystemExportRead {
                offset: 0,
                max_bytes: 1024,
            },
        )
        .await
        .expect("read retired export");
    assert!(matches!(unavailable.message, GuestMessage::Error { .. }));
}
