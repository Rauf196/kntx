#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kntx::tls::passthrough::parse_client_hello(data);
});
