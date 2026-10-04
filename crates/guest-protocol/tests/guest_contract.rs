use guest_protocol::*;
use proptest::prelude::*;
use sandboxd_protocol::{codec, *};

fn identity() -> SessionIdentity {
    SessionIdentity {
        sandbox: SandboxId::new("sandbox").expect("id"),
        sandbox_generation: SandboxGeneration::new(1).expect("generation"),
        session: SessionId::new("session").expect("id"),
        session_generation: SessionGeneration::new(3).expect("generation"),
        boot_nonce: BootNonce([7; 32]),
        vsock_cid: 4,
        protocol_version: GUEST_PROTOCOL_VERSION,
    }
}
#[test]
fn every_stale_session_identity_is_rejected_and_nonce_is_redacted() {
    let expected = identity();
    assert!(expected.authenticate(&expected).is_ok());
    let mut wrong = expected.clone();
    wrong.session_generation = wrong.session_generation.next().expect("next");
    assert!(expected.authenticate(&wrong).is_err());
    let mut wrong = expected.clone();
    wrong.vsock_cid += 1;
    assert!(expected.authenticate(&wrong).is_err());
    let mut wrong = expected.clone();
    wrong.protocol_version += 1;
    assert!(expected.authenticate(&wrong).is_err());
    assert_eq!(
        format!("{:?}", expected.boot_nonce),
        "BootNonce([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", SecretValue("customer-secret".into())),
        "[REDACTED]"
    );
}

#[test]
fn session_rebind_requires_new_generation_session_and_nonce() {
    let old = identity();
    let mut next = old.clone();
    next.session = SessionId::new("session-next").expect("id");
    next.session_generation = SessionGeneration::new(4).expect("generation");
    next.boot_nonce = BootNonce([8; 32]);
    assert!(old.validate_rebind(&next).is_ok());

    let mut same_generation = next.clone();
    same_generation.session_generation = old.session_generation;
    assert!(old.validate_rebind(&same_generation).is_err());
    let mut zero_nonce = next.clone();
    zero_nonce.boot_nonce = BootNonce([0; 32]);
    assert!(old.validate_rebind(&zero_nonce).is_err());
    let mut different_cid = next.clone();
    different_cid.vsock_cid += 1;
    assert!(old.validate_rebind(&different_cid).is_err());
}
proptest! {
    #[test]
    fn output_encoding_preserves_all_bytes(payload in prop::collection::vec(any::<u8>(), 0..65537)) {
        let record = OutputRecord { exec: ExecId::new("exec").expect("id"), stream: Stream::Stdout,
            sequence: 1, timestamp_unix_ms: 0, flags: 0, payload: payload.clone() };
        let encoded = codec::encode_body(&record).expect("encode");
        let decoded: OutputRecord = codec::decode_body(&encoded).expect("decode");
        prop_assert_eq!(decoded.payload, payload);
    }
    #[test]
    fn changing_any_nonce_byte_is_rejected(index in 0usize..32, change in 1u8..=255) {
        let expected = identity(); let mut received = expected.clone();
        received.boot_nonce.0[index] ^= change;
        prop_assert!(expected.authenticate(&received).is_err());
    }
}
