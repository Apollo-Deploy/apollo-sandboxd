#![no_main]
use libfuzzer_sys::fuzz_target;
use sandboxd_protocol::{Request, codec};
fuzz_target!(|bytes: &[u8]| {
    let _ = codec::read_frame::<Request>(bytes);
    let _ = codec::decode_body::<Request>(bytes);
    if bytes.len() >= codec::HEADER_BYTES {
        if let Ok(header) = <[u8; codec::HEADER_BYTES]>::try_from(&bytes[..codec::HEADER_BYTES]) {
            let _ = codec::Header::decode(header);
        }
    }
});
