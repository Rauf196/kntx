#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 128 mirrors the hardcoded max_headers at forward.rs:631. Not attacker-controlled in
    // production, so it's fixed here rather than fuzzed - only `data` is the input surface.
    let _ = kntx::proxy::l7::parse::parse_request(data, 128);
});
