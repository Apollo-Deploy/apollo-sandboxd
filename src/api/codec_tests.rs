use super::*;
use sandboxd_protocol::{Request, codec as canonical};

#[tokio::test]
async fn async_adapter_and_canonical_parser_agree_on_hostile_frames_and_policy_limits() {
    let mut valid = Vec::new();
    canonical::write_frame(&mut valid, 19, &Request::Health).expect("golden frame");
    let mut cases = vec![(valid.clone(), 131_072), (valid.clone(), 1)];
    for length in 0..valid.len() {
        cases.push((valid[..length].to_vec(), 131_072));
    }
    for index in 0..12 {
        let mut bad = valid.clone();
        bad[index] ^= 0xff;
        cases.push((bad, 131_072));
    }
    // Invalid CBOR and a well-framed body with trailing bytes.
    for body in [
        vec![0x9f, 0xff],
        vec![0xc0, 0],
        vec![0x61, 0xff],
        vec![0, 0],
    ] {
        let mut bytes = canonical::Header {
            request_id: 19,
            body_len: body.len() as u32,
        }
        .encode()
        .expect("header")
        .to_vec();
        bytes.extend(body);
        cases.push((bytes, 131_072));
    }
    for (bytes, limit) in cases {
        let expected = canonical::read_frame_limited::<Request>(&bytes[..], limit);
        let actual = read_limited::<Request>(&mut &bytes[..], limit).await;
        assert_eq!(
            actual.is_ok(),
            expected.is_ok(),
            "frame={bytes:?}, limit={limit}"
        );
        if let (Ok(actual), Ok(expected)) = (actual, expected) {
            assert_eq!(actual, expected);
        }
    }
    let mut emitted = Vec::new();
    write(&mut emitted, 19, &Request::Health)
        .await
        .expect("async writer");
    assert_eq!(emitted, valid, "wire bytes must be canonical");
}
