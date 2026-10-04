#![no_main]
use guest_protocol::GuestEnvelope;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if let Ok(envelope) = sandboxd_protocol::codec::decode_body::<GuestEnvelope>(bytes) {
        let _ = envelope.validate(&envelope.identity);
    }
});
