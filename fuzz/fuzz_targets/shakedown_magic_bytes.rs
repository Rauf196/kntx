#![no_main]

use libfuzzer_sys::fuzz_target;

// exercises no kntx code - proves the fuzzing pipeline itself works before trusting the
// other targets. per-byte checks, not one comparison, so coverage-guided search finds
// this in seconds instead of a blind 2^64 search.
const MAGIC: &[u8] = b"KNTXFUZZ";

fuzz_target!(|data: &[u8]| {
    if data.len() < MAGIC.len() {
        return;
    }
    if data[0] != MAGIC[0] {
        return;
    }
    if data[1] != MAGIC[1] {
        return;
    }
    if data[2] != MAGIC[2] {
        return;
    }
    if data[3] != MAGIC[3] {
        return;
    }
    if data[4] != MAGIC[4] {
        return;
    }
    if data[5] != MAGIC[5] {
        return;
    }
    if data[6] != MAGIC[6] {
        return;
    }
    if data[7] != MAGIC[7] {
        return;
    }
    panic!("shakedown: full magic matched - pipeline is alive");
});
