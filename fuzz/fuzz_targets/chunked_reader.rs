#![no_main]

use std::sync::OnceLock;

use kntx::proxy::l7::framing::ChunkedReader;
use libfuzzer_sys::fuzz_target;
use tokio::io::BufReader;

// matches production's real scratch size (pool::buffer::BufferPool::DEFAULT_BUFFER_SIZE,
// src/pool/buffer.rs:6). Scratch size is a caller detail, not attacker-controlled, so it's
// fixed rather than fuzzed.
const SCRATCH_LEN: usize = 64 * 1024;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build current-thread tokio runtime for fuzz harness")
    })
}

fuzz_target!(|data: &[u8]| {
    runtime().block_on(async {
        let mut src = BufReader::new(std::io::Cursor::new(data));
        let mut dst: Vec<u8> = Vec::new();
        let mut scratch = [0u8; SCRATCH_LEN];
        let mut cr = ChunkedReader::new();
        while !cr.is_done() {
            // Err is a normal outcome for fuzz input - only panic/hang/OOM (caught by
            // libFuzzer itself) count as bugs.
            if cr.pump_once(&mut src, &mut dst, &mut scratch).await.is_err() {
                break;
            }
        }
    });
});
