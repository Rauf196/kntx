//! backend selection cost per strategy, and hash ring build cost at reload.
//! the threaded scenarios use iter_custom with scoped threads, as in
//! benches/rate_limit.rs: wall time for `iters` selections split over 8 threads.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use kntx::balancer::RoundRobin;
use kntx::balancer::ring::Ring;
use kntx::config::{BalancerStrategy, KeepaliveConfig};
use kntx::health::BackendPool;
use kntx::proxy::l7::matcher::RouteContext;

const THREADS: u64 = 8;
const SIZES: [u16; 3] = [2, 8, 32];

fn addrs(n: u16) -> Vec<SocketAddr> {
    (0..n)
        .map(|i| SocketAddr::from(([10, 0, 0, 1], 3000 + i)))
        .collect()
}

fn balancer(n: u16, strategy: BalancerStrategy) -> RoundRobin {
    let mut pool = BackendPool::new(
        "bench".into(),
        addrs(n),
        3,
        Duration::from_secs(10),
        KeepaliveConfig::default(),
    );
    if strategy == BalancerStrategy::Hash {
        pool = pool.with_hash_ring();
    }
    RoundRobin::with_strategy(Arc::new(pool), strategy)
}

/// a different client per call, so hash lookups walk the whole ring rather
/// than hitting one cached point.
fn select(rr: &RoundRobin, i: u64) -> Option<SocketAddr> {
    let ctx = RouteContext {
        method: None,
        host: None,
        path: None,
        headers: &[],
        sni: None,
        client_ip: IpAddr::V4(Ipv4Addr::from(i as u32)),
    };
    rr.next_backend(&ctx, &[])
}

fn threaded<F: Fn(u64) + Sync>(iters: u64, op: F) -> Duration {
    let per_thread = iters.div_ceil(THREADS);
    let start = Instant::now();
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let op = &op;
            s.spawn(move || {
                for i in 0..per_thread {
                    op(t << 32 | i);
                }
            });
        }
    });
    start.elapsed()
}

const STRATEGIES: [(&str, BalancerStrategy); 2] = [
    ("round_robin", BalancerStrategy::RoundRobin),
    ("hash", BalancerStrategy::Hash),
];

fn bench_select_single_thread(c: &mut Criterion) {
    let mut group = c.benchmark_group("select_single_thread");
    for n in SIZES {
        for (name, strategy) in STRATEGIES {
            let rr = balancer(n, strategy);
            let mut i = 0u64;
            group.bench_with_input(BenchmarkId::new(name, n), &n, |b, _| {
                b.iter(|| {
                    i += 1;
                    black_box(select(&rr, i))
                })
            });
        }
    }
    group.finish();
}

fn bench_select_8_threads(c: &mut Criterion) {
    let mut group = c.benchmark_group("select_8_threads");
    for n in SIZES {
        for (name, strategy) in STRATEGIES {
            let rr = balancer(n, strategy);
            group.bench_with_input(BenchmarkId::new(name, n), &n, |b, _| {
                b.iter_custom(|iters| {
                    threaded(iters, |i| {
                        black_box(select(&rr, i));
                    })
                })
            });
        }
    }
    group.finish();
}

fn bench_ring_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_build");
    // the last case is the weight-sum cap, the largest ring validation allows
    for (label, n, weight) in [("8x1", 8, 1), ("32x1", 32, 1), ("8x125_cap", 8, 125)] {
        let list: Vec<_> = addrs(n).into_iter().map(|a| (a, weight)).collect();
        group.bench_function(label, |b| {
            b.iter(|| black_box(Ring::build(list.iter().copied())))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_select_single_thread,
    bench_select_8_threads,
    bench_ring_build
);
criterion_main!(benches);
