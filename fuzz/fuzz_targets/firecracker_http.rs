#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
fuzz_target!(|bytes: &[u8]| {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("fuzzer runtime")
    });
    runtime.block_on(async {
        let _ = firecracker_api::http::read_response(&mut bytes.as_ref()).await;
    });
});
