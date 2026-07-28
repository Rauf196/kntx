use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::BalancerStrategy;
use crate::health::{BackendPool, BackendState};
use crate::util::CacheLinePadded;

/// backend selection for one pool.
///
/// enum rather than `Arc<dyn Balancer>`: the set is closed and selection is
/// static dispatch, matching how `l4::forward` picks a forwarding strategy.
/// `Router` is `dyn` because Phase F extends it with user-authored logic; this
/// is not that kind of surface.
pub struct RoundRobin {
    pool: Arc<BackendPool>,
    strategy: BalancerStrategy,
    /// round-robin cursor, also the tiebreak rotation for least-conn.
    index: CacheLinePadded<AtomicUsize>,
}

impl RoundRobin {
    pub fn new(pool: Arc<BackendPool>) -> Self {
        Self::with_strategy(pool, BalancerStrategy::RoundRobin)
    }

    pub fn with_strategy(pool: Arc<BackendPool>, strategy: BalancerStrategy) -> Self {
        Self {
            pool,
            strategy,
            index: CacheLinePadded(AtomicUsize::new(0)),
        }
    }

    pub fn pool(&self) -> Arc<BackendPool> {
        Arc::clone(&self.pool)
    }

    pub fn strategy(&self) -> BalancerStrategy {
        self.strategy
    }

    pub fn current_index(&self) -> usize {
        self.index.0.load(Ordering::Relaxed)
    }

    pub fn next_backend(&self) -> Option<SocketAddr> {
        // one snapshot per selection: len and indexing stay consistent even if a
        // reload swaps the backend set mid-call.
        let backends = self.pool.snapshot();
        if backends.is_empty() {
            return None;
        }

        // is_available has a side effect: it CASes an expired Open circuit to
        // HalfOpen, and only the winner probes. so it must be called at most
        // once per candidate per selection, and only on candidates we would
        // actually return. every strategy below respects that.
        let recovery_timeout = self.pool.recovery_timeout();
        match self.strategy {
            BalancerStrategy::RoundRobin => self.pick_round_robin(&backends, recovery_timeout),
            BalancerStrategy::LeastConn => self.pick_least_conn(&backends, recovery_timeout),
            BalancerStrategy::Weighted => self.pick_weighted(&backends, recovery_timeout),
        }
    }

    fn pick_round_robin(
        &self,
        backends: &[Arc<BackendState>],
        recovery_timeout: std::time::Duration,
    ) -> Option<SocketAddr> {
        let len = backends.len();
        let start = self.index.0.fetch_add(1, Ordering::Relaxed);
        for i in 0..len {
            let backend = &backends[start.wrapping_add(i) % len];
            if backend.is_available(recovery_timeout) {
                return Some(backend.address());
            }
        }
        None // all backends unavailable
    }

    /// fewest in-flight first. ties rotate on the shared cursor so equal-load
    /// backends still spread instead of all landing on the lowest index, which
    /// is the failure mode of a naive min-scan under bursty arrivals.
    fn pick_least_conn(
        &self,
        backends: &[Arc<BackendState>],
        recovery_timeout: std::time::Duration,
    ) -> Option<SocketAddr> {
        let len = backends.len();
        let start = self.index.0.fetch_add(1, Ordering::Relaxed);

        // single pass, no allocation. sorting the candidates would rank the
        // failover order too, but it costs a Vec per selection - once per L4
        // connection and once per L7 request - and this path may not allocate.
        // load is read before any is_available call, so scanning never burns a
        // half-open probe on a backend this selection would not return.
        // strict `<` keeps the rotating start on ties, which is what spreads
        // equal-load backends instead of pinning index 0.
        let mut best = start % len;
        let mut best_load = backends[best].active_count();
        for i in 1..len {
            let idx = start.wrapping_add(i) % len;
            let load = backends[idx].active_count();
            if load < best_load {
                best = idx;
                best_load = load;
            }
        }

        if backends[best].is_available(recovery_timeout) {
            return Some(backends[best].address());
        }

        // least-loaded is circuit-open. fall back to rotation order rather than
        // re-ranking the rest by load: on the failover path availability beats
        // picking the second-lightest, and it keeps one is_available call per
        // backend without a scratch buffer.
        for i in 0..len {
            let idx = start.wrapping_add(i) % len;
            if idx == best {
                continue;
            }
            if backends[idx].is_available(recovery_timeout) {
                return Some(backends[idx].address());
            }
        }
        None
    }

    /// weight-proportional selection: the step counter walks a repeating cycle of
    /// length `sum(weights)`, and each backend owns `weight` consecutive slots.
    ///
    /// ponytail: blocked, not interleaved. weights 5:1 emit aaaaab per cycle, not
    /// ababababa. nginx's smooth WRR interleaves, but it needs a per-backend
    /// accumulator mutated under the worker lock on every pick; here that would
    /// mean either a mutex on the selection path or a racy multi-atomic
    /// read-modify-write. proportions over any window of a full cycle are
    /// identical either way, and at proxy request rates the ordering skew is
    /// sub-millisecond against a backend that has the capacity the weight claims.
    /// upgrade to true smooth WRR if a burst-sensitive workload shows up.
    ///
    /// deriving the pick from the step counter alone keeps this stateless, so a
    /// reload that retunes weights takes effect on the next selection with no
    /// accumulator to reconcile.
    fn pick_weighted(
        &self,
        backends: &[Arc<BackendState>],
        recovery_timeout: std::time::Duration,
    ) -> Option<SocketAddr> {
        let len = backends.len();
        let step = self.index.0.fetch_add(1, Ordering::Relaxed);

        let total: u64 = backends.iter().map(|b| b.weight() as u64).sum();
        if total == 0 {
            return None; // every backend drained
        }

        let mut cursor = (step as u64) % total;
        let mut chosen = None;
        for (idx, backend) in backends.iter().enumerate() {
            let weight = backend.weight() as u64;
            if cursor < weight {
                chosen = Some(idx);
                break;
            }
            cursor -= weight;
        }
        let chosen = chosen?;

        // walk from the weighted pick, skipping unavailable backends but keeping
        // zero-weight ones excluded: a drained backend must not absorb failover.
        for i in 0..len {
            let idx = (chosen + i) % len;
            let backend = &backends[idx];
            if backend.weight() > 0 && backend.is_available(recovery_timeout) {
                return Some(backend.address());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    use crate::config::KeepaliveConfig;

    fn test_pool(addrs: &[&str]) -> Arc<BackendPool> {
        let addrs: Vec<SocketAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
        Arc::new(BackendPool::new(
            "test".into(),
            addrs,
            3,
            Duration::from_secs(10),
            KeepaliveConfig::default(),
        ))
    }

    #[test]
    fn cycles_through_backends() {
        let rr = RoundRobin::new(test_pool(&[
            "127.0.0.1:3001",
            "127.0.0.1:3002",
            "127.0.0.1:3003",
        ]));

        let first_cycle: Vec<_> = (0..3).map(|_| rr.next_backend().unwrap()).collect();
        let second_cycle: Vec<_> = (0..3).map(|_| rr.next_backend().unwrap()).collect();

        assert_eq!(first_cycle, second_cycle);
    }

    #[test]
    fn distributes_evenly() {
        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:3001".parse().unwrap(),
            "127.0.0.1:3002".parse().unwrap(),
        ];
        let pool = Arc::new(BackendPool::new(
            "test".into(),
            addrs.clone(),
            3,
            Duration::from_secs(10),
            KeepaliveConfig::default(),
        ));
        let rr = RoundRobin::new(pool);

        let mut counts = [0u32; 2];
        for _ in 0..1000 {
            let picked = rr.next_backend().unwrap();
            let pos = addrs.iter().position(|a| *a == picked).unwrap();
            counts[pos] += 1;
        }

        assert_eq!(counts[0], 500);
        assert_eq!(counts[1], 500);
    }

    #[test]
    fn single_backend() {
        let rr = RoundRobin::new(test_pool(&["127.0.0.1:3001"]));

        for _ in 0..100 {
            assert_eq!(
                rr.next_backend().unwrap(),
                "127.0.0.1:3001".parse::<SocketAddr>().unwrap(),
            );
        }
    }

    #[test]
    fn empty_backends_returns_none() {
        let pool = Arc::new(BackendPool::new(
            "test".into(),
            vec![],
            3,
            Duration::from_secs(10),
            KeepaliveConfig::default(),
        ));
        let rr = RoundRobin::new(pool);
        assert!(rr.next_backend().is_none());
    }

    #[test]
    fn wraps_around_at_usize_boundary() {
        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:3001".parse().unwrap(),
            "127.0.0.1:3002".parse().unwrap(),
            "127.0.0.1:3003".parse().unwrap(),
        ];
        let pool = Arc::new(BackendPool::new(
            "test".into(),
            addrs.clone(),
            3,
            Duration::from_secs(10),
            KeepaliveConfig::default(),
        ));
        let rr = RoundRobin::new(pool);

        // simulate index near usize::MAX
        rr.index.0.store(usize::MAX - 1, Ordering::Relaxed);

        let a = rr.next_backend().unwrap();
        let b = rr.next_backend().unwrap();
        let c = rr.next_backend().unwrap();

        // usize::MAX - 1, usize::MAX, then wraps to 0
        assert_eq!(a, addrs[(usize::MAX - 1) % 3]);
        assert_eq!(b, addrs[usize::MAX % 3]);
        assert_eq!(c, addrs[0]); // 0 % 3 == 0
    }

    #[test]
    fn concurrent_access() {
        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:3001".parse().unwrap(),
            "127.0.0.1:3002".parse().unwrap(),
        ];
        let pool = Arc::new(BackendPool::new(
            "test".into(),
            addrs.clone(),
            3,
            Duration::from_secs(10),
            KeepaliveConfig::default(),
        ));
        let rr = Arc::new(RoundRobin::new(pool));
        let total_per_thread = 5000;
        let thread_count = 4;

        let handles: Vec<_> = (0..thread_count)
            .map(|_| {
                let rr = Arc::clone(&rr);
                let addrs = addrs.clone();
                std::thread::spawn(move || {
                    let mut counts = [0u32; 2];
                    for _ in 0..total_per_thread {
                        let picked = rr.next_backend().unwrap();
                        let pos = addrs.iter().position(|a| *a == picked).unwrap();
                        counts[pos] += 1;
                    }
                    counts
                })
            })
            .collect();

        let mut total = [0u32; 2];
        for h in handles {
            let counts = h.join().unwrap();
            total[0] += counts[0];
            total[1] += counts[1];
        }

        let grand_total = total_per_thread as u32 * thread_count;
        assert_eq!(total[0] + total[1], grand_total);
        // with 20000 total requests across 2 backends, expect even split
        assert_eq!(total[0], grand_total / 2);
        assert_eq!(total[1], grand_total / 2);
    }

    #[test]
    fn skips_unhealthy_backends() {
        use crate::health::CircuitState;

        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:3001".parse().unwrap(),
            "127.0.0.1:3002".parse().unwrap(),
            "127.0.0.1:3003".parse().unwrap(),
        ];
        let pool = Arc::new(BackendPool::new(
            "test".into(),
            addrs.clone(),
            1,
            Duration::from_secs(60),
            KeepaliveConfig::default(),
        ));
        let rr = RoundRobin::new(Arc::clone(&pool));

        // open the first backend's circuit
        pool.record_failure(addrs[0]);
        assert_eq!(pool.get(0).circuit_state(), CircuitState::Open);

        // all calls should avoid the open-circuit backend
        for _ in 0..10 {
            let next = rr.next_backend().unwrap();
            assert_ne!(next, addrs[0], "should not select open-circuit backend");
        }
    }

    fn strategy_pool(addrs: &[&str], strategy: BalancerStrategy) -> (Arc<BackendPool>, RoundRobin) {
        let pool = test_pool(addrs);
        let rr = RoundRobin::with_strategy(Arc::clone(&pool), strategy);
        (pool, rr)
    }

    /// count selections per address over `n` calls.
    fn tally(rr: &RoundRobin, addrs: &[&str], n: usize) -> Vec<u32> {
        let parsed: Vec<SocketAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
        let mut counts = vec![0u32; parsed.len()];
        for _ in 0..n {
            let picked = rr.next_backend().expect("a backend should be selectable");
            let pos = parsed.iter().position(|a| *a == picked).unwrap();
            counts[pos] += 1;
        }
        counts
    }

    #[test]
    fn least_conn_picks_fewest_active() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"];
        let (pool, rr) = strategy_pool(&addrs, BalancerStrategy::LeastConn);

        // backend 0 carries 5 in-flight, backend 1 carries 2, backend 2 idle
        let _b0: Vec<_> = (0..5).map(|_| pool.get(0).track_active()).collect();
        let _b1: Vec<_> = (0..2).map(|_| pool.get(1).track_active()).collect();

        for _ in 0..20 {
            assert_eq!(
                rr.next_backend().unwrap(),
                addrs[2].parse::<SocketAddr>().unwrap(),
                "idle backend must win while it stays the least loaded",
            );
        }
    }

    #[test]
    fn least_conn_prefers_next_lowest_when_idle_backend_fills_up() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002"];
        let (pool, rr) = strategy_pool(&addrs, BalancerStrategy::LeastConn);

        let _b0: Vec<_> = (0..3).map(|_| pool.get(0).track_active()).collect();
        assert_eq!(rr.next_backend().unwrap(), addrs[1].parse().unwrap());

        // load backend 1 past backend 0 and the preference must invert
        let _b1: Vec<_> = (0..4).map(|_| pool.get(1).track_active()).collect();
        assert_eq!(rr.next_backend().unwrap(), addrs[0].parse().unwrap());
    }

    #[test]
    fn least_conn_guard_drop_restores_availability() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002"];
        let (pool, rr) = strategy_pool(&addrs, BalancerStrategy::LeastConn);

        {
            let _held: Vec<_> = (0..3).map(|_| pool.get(0).track_active()).collect();
            assert_eq!(pool.get(0).active_count(), 3);
            assert_eq!(rr.next_backend().unwrap(), addrs[1].parse().unwrap());
        }

        // guards dropped: the counter must fully unwind, not leak
        assert_eq!(pool.get(0).active_count(), 0);
        assert_eq!(pool.get(1).active_count(), 0);
    }

    #[test]
    fn least_conn_ties_rotate_evenly() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"];
        let (_pool, rr) = strategy_pool(&addrs, BalancerStrategy::LeastConn);

        // all idle - a naive min-scan would return index 0 every time
        let counts = tally(&rr, &addrs, 300);
        assert_eq!(counts, vec![100, 100, 100], "tiebreak must rotate");
    }

    #[test]
    fn least_conn_skips_open_circuit_even_when_least_loaded() {
        use crate::health::CircuitState;

        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002"];
        let pool = Arc::new(BackendPool::new(
            "test".into(),
            addrs.iter().map(|a| a.parse().unwrap()).collect(),
            1,
            Duration::from_secs(60),
            KeepaliveConfig::default(),
        ));
        let rr = RoundRobin::with_strategy(Arc::clone(&pool), BalancerStrategy::LeastConn);

        // backend 0 is idle (so least-loaded) but its circuit is open
        let _b1: Vec<_> = (0..9).map(|_| pool.get(1).track_active()).collect();
        pool.record_failure(addrs[0].parse().unwrap());
        assert_eq!(pool.get(0).circuit_state(), CircuitState::Open);

        for _ in 0..10 {
            assert_eq!(
                rr.next_backend().unwrap(),
                addrs[1].parse::<SocketAddr>().unwrap(),
                "load must never override circuit state",
            );
        }
    }

    #[test]
    fn least_conn_all_unavailable_returns_none() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002"];
        let pool = Arc::new(BackendPool::new(
            "test".into(),
            addrs.iter().map(|a| a.parse().unwrap()).collect(),
            1,
            Duration::from_secs(60),
            KeepaliveConfig::default(),
        ));
        let rr = RoundRobin::with_strategy(Arc::clone(&pool), BalancerStrategy::LeastConn);
        for a in &addrs {
            pool.record_failure(a.parse().unwrap());
        }
        assert!(rr.next_backend().is_none());
    }

    #[test]
    fn weighted_distribution_matches_configured_weights() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"];
        let (pool, rr) = strategy_pool(&addrs, BalancerStrategy::Weighted);
        pool.set_weights(&[
            (addrs[0].parse().unwrap(), 3),
            (addrs[1].parse().unwrap(), 1),
            (addrs[2].parse().unwrap(), 4),
        ]);

        // one full cycle is 8 selections; 1000 cycles keeps the assert exact
        let counts = tally(&rr, &addrs, 8000);
        assert_eq!(counts, vec![3000, 1000, 4000]);
    }

    #[test]
    fn weighted_equal_weights_matches_round_robin() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002"];
        let (_pool, rr) = strategy_pool(&addrs, BalancerStrategy::Weighted);
        // default weight is 1 for every backend
        assert_eq!(tally(&rr, &addrs, 1000), vec![500, 500]);
    }

    #[test]
    fn weighted_zero_weight_drains_backend() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002"];
        let (pool, rr) = strategy_pool(&addrs, BalancerStrategy::Weighted);
        pool.set_weights(&[
            (addrs[0].parse().unwrap(), 0),
            (addrs[1].parse().unwrap(), 5),
        ]);

        let counts = tally(&rr, &addrs, 500);
        assert_eq!(counts, vec![0, 500], "weight 0 must receive nothing");
    }

    #[test]
    fn weighted_drained_backend_does_not_absorb_failover() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002"];
        let pool = Arc::new(BackendPool::new(
            "test".into(),
            addrs.iter().map(|a| a.parse().unwrap()).collect(),
            1,
            Duration::from_secs(60),
            KeepaliveConfig::default(),
        ));
        let rr = RoundRobin::with_strategy(Arc::clone(&pool), BalancerStrategy::Weighted);
        pool.set_weights(&[
            (addrs[0].parse().unwrap(), 0),
            (addrs[1].parse().unwrap(), 5),
        ]);

        // the only weighted backend goes unhealthy. a drained backend is drained
        // on purpose, so failover must not resurrect it.
        pool.record_failure(addrs[1].parse().unwrap());
        assert!(
            rr.next_backend().is_none(),
            "failover must respect weight 0, not treat it as a spare",
        );
    }

    #[test]
    fn weighted_reload_retunes_share_without_rebuild() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002"];
        let (pool, rr) = strategy_pool(&addrs, BalancerStrategy::Weighted);
        pool.set_weights(&[
            (addrs[0].parse().unwrap(), 9),
            (addrs[1].parse().unwrap(), 1),
        ]);
        let before = tally(&rr, &addrs, 1000);
        assert_eq!(before, vec![900, 100]);

        // same balancer instance, new weights - the reload path stores in place
        pool.set_weights(&[
            (addrs[0].parse().unwrap(), 1),
            (addrs[1].parse().unwrap(), 9),
        ]);
        let after = tally(&rr, &addrs, 1000);
        assert_eq!(after, vec![100, 900]);
    }

    #[test]
    fn weighted_concurrent_selection_preserves_proportions() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002"];
        let (pool, rr) = strategy_pool(&addrs, BalancerStrategy::Weighted);
        pool.set_weights(&[
            (addrs[0].parse().unwrap(), 3),
            (addrs[1].parse().unwrap(), 1),
        ]);
        let rr = Arc::new(rr);

        let per_thread = 4000;
        let threads = 4;
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let rr = Arc::clone(&rr);
                let parsed: Vec<SocketAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
                std::thread::spawn(move || {
                    let mut counts = [0u32; 2];
                    for _ in 0..per_thread {
                        let picked = rr.next_backend().unwrap();
                        counts[parsed.iter().position(|a| *a == picked).unwrap()] += 1;
                    }
                    counts
                })
            })
            .collect();

        let mut total = [0u32; 2];
        for h in handles {
            let c = h.join().unwrap();
            total[0] += c[0];
            total[1] += c[1];
        }

        // the shared cursor is a single fetch_add, so every step index is handed
        // out exactly once and the 3:1 split stays exact under contention.
        let grand = per_thread * threads;
        assert_eq!(total[0] + total[1], grand);
        assert_eq!(total[0], grand / 4 * 3);
        assert_eq!(total[1], grand / 4);
    }

    #[test]
    fn does_not_skip_saturated_backend() {
        // saturation is enforced at checkout (KeepaliveCache::checkout), not at RR selection
        use crate::config::KeepaliveConfig;
        use std::sync::atomic::Ordering;

        let addr: std::net::SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let cfg = KeepaliveConfig {
            max_idle: 1,
            idle_conn_ttl_secs: 60,
            max_total: 1,
        };
        let pool = Arc::new(BackendPool::new(
            "test".into(),
            vec![addr],
            3,
            Duration::from_secs(60),
            cfg,
        ));
        let rr = RoundRobin::new(Arc::clone(&pool));

        // set total_count = max_total → backend is saturated
        pool.get(0).total_count.0.store(1, Ordering::Relaxed);
        assert!(
            pool.get(0).is_saturated(),
            "precondition: backend saturated"
        );

        // RR must still return it (saturation is a checkout-level concern, not RR-level)
        let selected = rr.next_backend();
        assert!(
            selected.is_some(),
            "RR must select saturated backend with closed circuit"
        );
        assert_eq!(selected.unwrap(), addr);
    }
}
