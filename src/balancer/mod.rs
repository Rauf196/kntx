use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::config::{BalancerStrategy, HashKey};
use crate::health::{BackendPool, BackendState, Backends};
use crate::proxy::l7::matcher::RouteContext;
use crate::util::{CacheLinePadded, intern_label};

pub mod ring;

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
    hash_key: HashKey,
    pool_label: &'static str,
}

impl RoundRobin {
    pub fn new(pool: Arc<BackendPool>) -> Self {
        Self::with_strategy(pool, BalancerStrategy::RoundRobin)
    }

    pub fn with_strategy(pool: Arc<BackendPool>, strategy: BalancerStrategy) -> Self {
        let pool_label = intern_label(pool.name());
        Self {
            pool,
            strategy,
            index: CacheLinePadded(AtomicUsize::new(0)),
            hash_key: HashKey::ClientIp,
            pool_label,
        }
    }

    pub fn with_hash_key(mut self, key: HashKey) -> Self {
        self.hash_key = key;
        self
    }

    pub fn pool(&self) -> Arc<BackendPool> {
        Arc::clone(&self.pool)
    }

    pub fn strategy(&self) -> BalancerStrategy {
        self.strategy
    }

    /// the key in use, `None` unless the strategy is `hash`.
    pub fn hash_key(&self) -> Option<&HashKey> {
        (self.strategy == BalancerStrategy::Hash).then_some(&self.hash_key)
    }

    pub fn current_index(&self) -> usize {
        self.index.0.load(Ordering::Relaxed)
    }

    /// `tried`: backends this request already failed on. only `hash` needs it.
    pub fn next_backend(&self, ctx: &RouteContext<'_>, tried: &[SocketAddr]) -> Option<SocketAddr> {
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
            BalancerStrategy::Hash => self.pick_hash(&backends, ctx, tried, recovery_timeout),
        }
    }

    #[cfg(test)]
    pub(crate) fn next_backend_any(&self) -> Option<SocketAddr> {
        let ctx = RouteContext {
            method: None,
            host: None,
            path: None,
            headers: &[],
            sni: None,
            client_ip: IpAddr::from([127, 0, 0, 1]),
        };
        self.next_backend(&ctx, &[])
    }

    /// skipping a backend here gives the same owner as removing it from the ring.
    fn pick_hash(
        &self,
        backends: &Backends,
        ctx: &RouteContext<'_>,
        tried: &[SocketAddr],
        recovery_timeout: Duration,
    ) -> Option<SocketAddr> {
        let ring = backends.ring()?;
        let Some(key) = self.key_hash(ctx) else {
            metrics::counter!("kntx_hash_key_missing_total", "pool" => self.pool_label)
                .increment(1);
            return self.pick_weighted(backends, recovery_timeout);
        };

        for idx in ring.walk(key) {
            let backend = &backends[idx];
            if !tried.contains(&backend.address()) && backend.is_available(recovery_timeout) {
                return Some(backend.address());
            }
        }
        // everything untried is down: retrying a tried backend beats a 503,
        // and is the only option in a one-backend pool.
        ring.walk(key)
            .map(|idx| &backends[idx])
            .find(|b| tried.contains(&b.address()) && b.is_available(recovery_timeout))
            .map(|b| b.address())
    }

    fn key_hash(&self, ctx: &RouteContext<'_>) -> Option<u64> {
        match &self.hash_key {
            HashKey::ClientIp => Some(match ctx.client_ip.to_canonical() {
                IpAddr::V4(ip) => ring::hash64(&ip.octets()),
                IpAddr::V6(ip) => ring::hash64(&ip.octets()),
            }),
            HashKey::Header(name) => ctx
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .filter(|h| !h.value.is_empty())
                .map(|h| ring::hash64(&h.value)),
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

        let first_cycle: Vec<_> = (0..3).map(|_| rr.next_backend_any().unwrap()).collect();
        let second_cycle: Vec<_> = (0..3).map(|_| rr.next_backend_any().unwrap()).collect();

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
            let picked = rr.next_backend_any().unwrap();
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
                rr.next_backend_any().unwrap(),
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
        assert!(rr.next_backend_any().is_none());
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

        let a = rr.next_backend_any().unwrap();
        let b = rr.next_backend_any().unwrap();
        let c = rr.next_backend_any().unwrap();

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
                        let picked = rr.next_backend_any().unwrap();
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
            let next = rr.next_backend_any().unwrap();
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
            let picked = rr
                .next_backend_any()
                .expect("a backend should be selectable");
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
                rr.next_backend_any().unwrap(),
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
        assert_eq!(rr.next_backend_any().unwrap(), addrs[1].parse().unwrap());

        // load backend 1 past backend 0 and the preference must invert
        let _b1: Vec<_> = (0..4).map(|_| pool.get(1).track_active()).collect();
        assert_eq!(rr.next_backend_any().unwrap(), addrs[0].parse().unwrap());
    }

    #[test]
    fn least_conn_guard_drop_restores_availability() {
        let addrs = ["127.0.0.1:3001", "127.0.0.1:3002"];
        let (pool, rr) = strategy_pool(&addrs, BalancerStrategy::LeastConn);

        {
            let _held: Vec<_> = (0..3).map(|_| pool.get(0).track_active()).collect();
            assert_eq!(pool.get(0).active_count(), 3);
            assert_eq!(rr.next_backend_any().unwrap(), addrs[1].parse().unwrap());
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
                rr.next_backend_any().unwrap(),
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
        assert!(rr.next_backend_any().is_none());
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
            rr.next_backend_any().is_none(),
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
                        let picked = rr.next_backend_any().unwrap();
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
        let selected = rr.next_backend_any();
        assert!(
            selected.is_some(),
            "RR must select saturated backend with closed circuit"
        );
        assert_eq!(selected.unwrap(), addr);
    }

    use crate::health::CircuitState;
    use crate::proxy::l7::parse::ParsedHeader;
    use std::net::Ipv4Addr;

    fn addrs(n: u16) -> Vec<SocketAddr> {
        (0..n)
            .map(|i| SocketAddr::from(([127, 0, 0, 1], 3001 + i)))
            .collect()
    }

    fn hash_rr(addrs: &[SocketAddr], threshold: u32, recovery: Duration) -> RoundRobin {
        let pool = BackendPool::new(
            "test".into(),
            addrs.to_vec(),
            threshold,
            recovery,
            KeepaliveConfig::default(),
        )
        .with_hash_ring();
        RoundRobin::with_strategy(Arc::new(pool), BalancerStrategy::Hash)
    }

    fn ctx_for(ip: IpAddr, headers: &[ParsedHeader]) -> RouteContext<'_> {
        RouteContext {
            method: None,
            host: None,
            path: None,
            headers,
            sni: None,
            client_ip: ip,
        }
    }

    fn ip(i: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i))
    }

    fn pick(rr: &RoundRobin, i: u32, tried: &[SocketAddr]) -> Option<SocketAddr> {
        rr.next_backend(&ctx_for(ip(i), &[]), tried)
    }

    fn without(addrs: &[SocketAddr], gone: SocketAddr) -> Vec<SocketAddr> {
        addrs.iter().copied().filter(|&a| a != gone).collect()
    }

    const LONG: Duration = Duration::from_secs(60);

    #[test]
    fn hash_same_key_same_backend_and_keys_spread() {
        let a = addrs(3);
        let rr = hash_rr(&a, 3, LONG);
        let first = pick(&rr, 42, &[]).unwrap();
        for _ in 0..1000 {
            assert_eq!(pick(&rr, 42, &[]), Some(first));
        }

        let hit: std::collections::HashSet<_> = (0..300).map(|i| pick(&rr, i, &[])).collect();
        assert_eq!(hit.len(), 3, "distinct keys must reach every backend");
    }

    #[test]
    fn hash_circuit_open_equals_removal() {
        let a = addrs(5);
        let rr = hash_rr(&a, 1, LONG);
        rr.pool.record_failure(a[1]);
        let reference = hash_rr(&without(&a, a[1]), 1, LONG);
        for i in 0..10_000 {
            assert_eq!(pick(&rr, i, &[]), pick(&reference, i, &[]), "key {i}");
        }
    }

    #[test]
    fn hash_weight_zero_equals_removal() {
        let a = addrs(5);
        let rr = hash_rr(&a, 3, LONG);
        rr.pool.set_weights(&[(a[1], 0)]);
        let reference = hash_rr(&without(&a, a[1]), 3, LONG);
        for i in 0..10_000 {
            assert_eq!(pick(&rr, i, &[]), pick(&reference, i, &[]), "key {i}");
        }
    }

    /// the failed attempt's record_failure may or may not open the owner's
    /// circuit before the retry; the retry must land on the same backend either way.
    #[test]
    fn hash_retry_after_failure_equals_removal() {
        let a = addrs(5);
        let references: Vec<_> = a
            .iter()
            .map(|&gone| hash_rr(&without(&a, gone), 1, LONG))
            .collect();
        for threshold in [1, 3] {
            let rr = hash_rr(&a, threshold, LONG);
            for i in 0..10_000 {
                let owner = pick(&rr, i, &[]).unwrap();
                rr.pool.record_failure(owner);
                let owner_idx = a.iter().position(|&x| x == owner).unwrap();
                assert_eq!(
                    pick(&rr, i, &[owner]),
                    pick(&references[owner_idx], i, &[]),
                    "threshold {threshold}, key {i}"
                );
                rr.pool.record_success(owner);
            }
        }
    }

    #[test]
    fn hash_retry_single_backend_returns_it_again() {
        let a = addrs(1);
        let rr = hash_rr(&a, 3, LONG);
        assert_eq!(pick(&rr, 7, &a), Some(a[0]));
    }

    #[test]
    fn hash_retry_after_spent_probe_uses_other_backend() {
        let a = addrs(2);
        let rr = hash_rr(&a, 1, Duration::ZERO);
        let i = (0..).find(|&i| pick(&rr, i, &[]) == Some(a[0])).unwrap();

        rr.pool.record_failure(a[0]);
        // recovery 0: the open circuit is expired, so this pick wins the probe
        assert_eq!(pick(&rr, i, &[]), Some(a[0]));
        assert_eq!(rr.pool.get(0).circuit_state(), CircuitState::HalfOpen);
        rr.pool.record_failure(a[0]);

        assert_eq!(pick(&rr, i, &[a[0]]), Some(a[1]));
    }

    #[test]
    fn hash_skipping_tried_backend_does_not_spend_its_probe() {
        let a = addrs(2);
        let rr = hash_rr(&a, 1, Duration::ZERO);
        let i = (0..).find(|&i| pick(&rr, i, &[]) == Some(a[0])).unwrap();
        rr.pool.record_failure(a[0]);

        assert_eq!(pick(&rr, i, &[a[0]]), Some(a[1]));
        assert_eq!(
            rr.pool.get(0).circuit_state(),
            CircuitState::Open,
            "a tried backend must not have is_available called on it"
        );
    }

    #[test]
    fn hash_all_unavailable_or_empty_returns_none() {
        let a = addrs(3);
        let rr = hash_rr(&a, 1, LONG);
        for &addr in &a {
            rr.pool.record_failure(addr);
        }
        assert_eq!(pick(&rr, 1, &[]), None);
        assert_eq!(pick(&rr, 1, &a), None);

        assert_eq!(pick(&hash_rr(&[], 1, LONG), 1, &[]), None);
    }

    #[test]
    fn hash_header_key_is_case_insensitive() {
        let a = addrs(3);
        let rr = hash_rr(&a, 3, LONG).with_hash_key(HashKey::Header("x-session-id".into()));
        let headers = [ParsedHeader {
            name: "X-Session-ID".into(),
            value: b"u42".to_vec(),
        }];

        let picks: std::collections::HashSet<_> = (0..50)
            .map(|i| rr.next_backend(&ctx_for(ip(i), &headers), &[]))
            .collect();
        assert_eq!(picks.len(), 1, "the header, not the client ip, is the key");
    }

    #[test]
    fn hash_missing_or_empty_header_falls_back_to_weighted() {
        let a = addrs(2);
        let rr = hash_rr(&a, 3, LONG).with_hash_key(HashKey::Header("x-session-id".into()));
        rr.pool.set_weights(&[(a[0], 0), (a[1], 1)]);
        let empty = [ParsedHeader {
            name: "x-session-id".into(),
            value: Vec::new(),
        }];

        for headers in [&[][..], &empty[..]] {
            for i in 0..100 {
                assert_eq!(
                    rr.next_backend(&ctx_for(ip(i), headers), &[]),
                    Some(a[1]),
                    "fallback must respect weight 0"
                );
            }
        }
    }

    #[test]
    fn hash_ipv4_mapped_matches_ipv4() {
        let a = addrs(5);
        let rr = hash_rr(&a, 3, LONG);
        for i in 0..1000 {
            let IpAddr::V4(v4) = ip(i) else {
                unreachable!()
            };
            let mapped = IpAddr::V6(v4.to_ipv6_mapped());
            assert_eq!(
                rr.next_backend(&ctx_for(mapped, &[]), &[]),
                pick(&rr, i, &[]),
            );
        }
    }

    /// sizes differ on purpose: a ring paired with the other list would index
    /// out of bounds instead of quietly returning a member.
    #[test]
    fn hash_concurrent_reload_and_select() {
        use std::sync::atomic::AtomicBool;

        let a = addrs(4);
        let rr = Arc::new(hash_rr(&a, 3, LONG));
        let stop = Arc::new(AtomicBool::new(false));

        let reloader = {
            let (rr, stop, a) = (Arc::clone(&rr), Arc::clone(&stop), a.clone());
            std::thread::spawn(move || {
                let mut big = false;
                while !stop.load(Ordering::Relaxed) {
                    let set = if big { &a[..] } else { &a[..2] };
                    rr.pool.reconcile(set, &[], 3, LONG);
                    big = !big;
                }
            })
        };

        let pickers: Vec<_> = (0..4)
            .map(|t| {
                let (rr, a) = (Arc::clone(&rr), a.clone());
                std::thread::spawn(move || {
                    for i in 0..50_000 {
                        let got = pick(&rr, t * 50_000 + i, &[]).expect("a and b always exist");
                        assert!(a.contains(&got));
                    }
                })
            })
            .collect();
        for p in pickers {
            p.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        reloader.join().unwrap();
    }
}
