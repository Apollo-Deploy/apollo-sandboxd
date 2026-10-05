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
            65, 83, 68, 0, 0, 2, 0, 0, 0, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8
        ]
    );
    let mut legacy = bytes;
    legacy[4..6].copy_from_slice(&1u16.to_be_bytes());
    assert!(matches!(Header::decode(legacy), Err(CodecError::Header)));
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

#[test]
fn execution_list_has_an_encodable_tagged_map_contract() {
    use ciborium::value::Value;
    let reply = Response::Guest(GuestReply::ExecList {
        entries: Vec::new(),
    });
    let bytes = codec::encode_body(&reply).expect("execution list must encode on the public wire");
    let wire: Value = ciborium::de::from_reader(bytes.as_slice()).expect("CBOR value");
    let Value::Map(fields) = wire else {
        panic!("response must be a map")
    };
    assert_eq!(fields.len(), 2);
    let field = |fields: &[(Value, Value)], name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == &Value::Text(name.into()))
            .map(|(_, value)| value.clone())
            .expect("required wire field")
    };
    assert_eq!(field(&fields, "response"), Value::Text("guest".into()));
    let Value::Map(body) = field(&fields, "body") else {
        panic!("body must be a map")
    };
    assert_eq!(body.len(), 2);
    assert_eq!(field(&body, "result"), Value::Text("exec_list".into()));
    assert_eq!(field(&body, "entries"), Value::Array(vec![]));
    assert_eq!(
        codec::decode_body::<Response>(&bytes).expect("typed response"),
        reply
    );
}

#[test]
fn receipt_inspection_has_a_read_only_public_wire_contract() {
    use ciborium::value::Value;
    let literal = Value::Map(vec![
        (
            Value::Text("request".into()),
            Value::Text("operation_inspect".into()),
        ),
        (
            Value::Text("operation".into()),
            Value::Text("op-7-inspect".into()),
        ),
        (
            Value::Text("operation_sequence".into()),
            Value::Integer(7.into()),
        ),
    ]);
    let mut wire = Vec::new();
    ciborium::ser::into_writer(&literal, &mut wire).unwrap();
    let request: Request = codec::decode_body(&wire).unwrap();
    request.validate().unwrap();
    assert!(matches!(
        request,
        Request::OperationInspect {
            operation_sequence: 7,
            ..
        }
    ));
    let invalid = Request::OperationInspect {
        operation: OperationId::with_sequence(7, "inspect").unwrap(),
        operation_sequence: 8,
    };
    assert!(invalid.validate().is_err());
    let receipt = Response::OperationReceipt(Box::new(OperationReceipt {
        operation: OperationId::with_sequence(7, "inspect").unwrap(),
        operation_sequence: 7,
        accepted_sequence: 6,
        state: OperationReceiptState::Unknown,
        request_digest: None,
        response: None,
    }));
    let encoded = codec::encode_body(&receipt).unwrap();
    let decoded: Value = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    let Value::Map(fields) = decoded else {
        panic!("response map");
    };
    assert!(fields.contains(&(
        Value::Text("response".into()),
        Value::Text("operation_receipt".into())
    )));
    assert_eq!(codec::decode_body::<Response>(&encoded).unwrap(), receipt);
}
