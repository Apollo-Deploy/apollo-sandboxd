use proptest::prelude::*;
use sandboxd_protocol::{
    codec::{self, CodecError, Header},
    *,
};
use std::io::Cursor;

#[test]
fn header_has_stable_network_byte_order_and_rejects_unknown_features() {
    let header = Header {
        request_id: 0x0102030405060708,
        body_len: 256,
    };
    let bytes = header.encode().expect("header");
    assert_eq!(
        bytes,
        [
            65, 83, 68, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8
        ]
    );
    for index in [0, 1, 2, 3, 4, 5, 6, 7] {
        let mut invalid = bytes;
        invalid[index] ^= 0x80;
        assert!(matches!(Header::decode(invalid), Err(CodecError::Header)));
    }
    for len in [0, MAX_FRAME_BYTES as u32 + 1, u32::MAX] {
        assert!(
            Header {
                request_id: 0,
                body_len: len
            }
            .encode()
            .is_err()
        );
    }
}

#[test]
fn concatenated_frames_and_truncation_obey_declared_boundaries() {
    let mut bytes = Vec::new();
    codec::write_frame(&mut bytes, 7, &Request::Health).expect("frame one");
    let first_end = bytes.len();
    codec::write_frame(&mut bytes, 8, &Request::Capabilities).expect("frame two");
    let mut reader = Cursor::new(&bytes);
    assert_eq!(
        codec::read_frame::<Request>(&mut reader).expect("one"),
        (7, Request::Health)
    );
    assert_eq!(reader.position(), first_end as u64);
    assert_eq!(
        codec::read_frame::<Request>(&mut reader).expect("two"),
        (8, Request::Capabilities)
    );
    for end in 0..first_end {
        assert!(codec::read_frame::<Request>(&bytes[..end]).is_err());
    }
}

#[test]
fn hostile_cbor_is_rejected_before_collection_allocation() {
    for bytes in [
        vec![],
        vec![0x9b, 255, 255, 255, 255, 255, 255, 255, 255],
        vec![0xbf, 0xff],
        vec![0xc0, 0],
        vec![0xa2, 0, 0],
    ] {
        assert!(codec::decode_body::<Request>(&bytes).is_err());
    }
    let mut bytes = codec::encode_body(&Request::Health).expect("body");
    bytes.push(0);
    assert!(codec::decode_body::<Request>(&bytes).is_err());
    let mut nested = vec![0x81; 40];
    nested.push(0);
    assert!(codec::decode_body::<Vec<u8>>(&nested).is_err());
    let mut oversized_map = vec![0xb9, 0x02, 0x01];
    oversized_map.resize(1029, 0);
    assert!(matches!(
        codec::decode_body::<Request>(&oversized_map),
        Err(CodecError::Limit)
    ));
}

proptest! {
    #[test]
    fn header_round_trip_is_exact(id in any::<u64>(), length in 1u32..=MAX_FRAME_BYTES as u32) {
        let header = Header { request_id: id, body_len: length };
        prop_assert_eq!(Header::decode(header.encode().expect("valid header")).expect("decode"), header);
    }
    #[test]
    fn generation_advance_never_rolls_back(value in 1u64..i64::MAX as u64) {
        let generation = SandboxGeneration::new(value).expect("valid generation");
        prop_assert_eq!(generation.next().expect("advance").get(), value + 1);
    }
}
