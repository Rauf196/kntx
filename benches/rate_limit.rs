//! keyed limiter vs a mutexed token-bucket map, uncontended and under
//! thread contention. criterion has no native multi-thread mode, so the
//! threaded scenarios use iter_custom with scoped threads: wall time for
//! `iters` checks split across 8 threads.

use std::collections::HashMap;
use std::hint::black_box;
use std::num::NonZeroU32;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};

use kntx::rate_limit::{KeyedLimiter, MonotonicClock, Period, Rate};

const THREADS: u64 = 8;

/// comparator: the design keyed.rs exists to refuse. two-word state per
/// key under one map lock, allocating per new key, unbounded memory.
struct MutexBucketMap {
    map: Mutex<HashMap<u64, (f64, Instant)>>,
    rate_per_sec: f64,
    burst: f64,
}

impl MutexBucketMap {
    fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            rate_per_sec,
            burst,
        }
    }

    fn check(&self, key: u64) -> bool {
        let now = Instant::now();
        let mut map = self.map.lock().unwrap();
        let entry = map.entry(key).or_insert((self.burst, now));
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.0 = (entry.0 + elapsed * self.rate_per_sec).min(self.burst);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

fn keyed() -> KeyedLimiter {
    // rate high enough that checks stay on the allow path: the hit-path
    // CAS is what production traffic pays
    let rate = Rate {
        count: NonZeroU32::new(1_000_000_000).unwrap(),
        period: Period::Second,
    };
    KeyedLimiter::new(rate, 1000, 65536, MonotonicClock::new())
}

fn bucket_map() -> MutexBucketMap {
    MutexBucketMap::new(1_000_000_000.0, 1000.0)
}

fn spread_key(thread: u64, i: u64) -> u64 {
    // distinct keys per thread, spread across sets by a large stride
    thread.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (i % 64)
}

fn threaded<F: Fn(u64) + Sync>(iters: u64, op: F) -> Duration {
    let per_thread = iters.div_ceil(THREADS);
    let start = Instant::now();
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let op = &op;
            s.spawn(move || {
                for i in 0..per_thread {
                    op(spread_key(t, i));
                }
            });
        }
    });
    start.elapsed()
}

fn bench_uncontended(c: &mut Criterion) {
    let mut group = c.benchmark_group("uncontended_single_thread");
    let limiter = keyed();
    group.bench_function("keyed_limiter", |b| {
        b.iter(|| black_box(limiter.check(&black_box(42u64))))
    });
    let buckets = bucket_map();
    group.bench_function("mutex_bucket_map", |b| {
        b.iter(|| black_box(buckets.check(black_box(42))))
    });
    group.finish();
}

fn bench_same_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("same_key_8_threads");
    group.bench_function("keyed_limiter", |b| {
        b.iter_custom(|iters| {
            let limiter = keyed();
            threaded(iters, |_| {
                black_box(limiter.check(&42u64));
            })
        })
    });
    group.bench_function("mutex_bucket_map", |b| {
        b.iter_custom(|iters| {
            let buckets = bucket_map();
            threaded(iters, |_| {
                black_box(buckets.check(42));
            })
        })
    });
    group.finish();
}

fn bench_distinct_keys(c: &mut Criterion) {
    let mut group = c.benchmark_group("distinct_keys_8_threads");
    group.bench_function("keyed_limiter", |b| {
        b.iter_custom(|iters| {
            let limiter = keyed();
            threaded(iters, |key| {
                black_box(limiter.check(&key));
            })
        })
    });
    group.bench_function("mutex_bucket_map", |b| {
        b.iter_custom(|iters| {
            let buckets = bucket_map();
            threaded(iters, |key| {
                black_box(buckets.check(key));
            })
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_uncontended,
    bench_same_key,
    bench_distinct_keys
);
criterion_main!(benches);
