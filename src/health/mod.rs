use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::config::KeepaliveConfig;
use crate::proxy::l7::keepalive::KeepaliveCache;
use crate::util::{CacheLinePadded, monotonic_millis};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

impl CircuitState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Closed,
            1 => Self::Open,
            2 => Self::HalfOpen,
            _ => Self::Closed,
        }
    }
}

pub struct BackendState {
    address: SocketAddr,
    pool_name: Arc<str>,
    pub(crate) circuit: AtomicU8,
    pub(crate) consecutive_failures: AtomicU32,
    pub(crate) open_since: AtomicU64,
    pub keepalive: KeepaliveCache,
    pub total_count: CacheLinePadded<AtomicU64>,
}

impl BackendState {
    pub fn new(address: SocketAddr, pool_name: Arc<str>, keepalive_cfg: KeepaliveConfig) -> Self {
        Self {
            address,
            pool_name,
            circuit: AtomicU8::new(CircuitState::Closed as u8),
            consecutive_failures: AtomicU32::new(0),
            open_since: AtomicU64::new(0),
            keepalive: KeepaliveCache::new(keepalive_cfg),
            total_count: CacheLinePadded(AtomicU64::new(0)),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn pool_name(&self) -> &Arc<str> {
        &self.pool_name
    }

    pub fn circuit_state(&self) -> CircuitState {
        CircuitState::from_u8(self.circuit.load(Ordering::Acquire))
    }

    /// check if this backend can accept traffic.
    /// for Open circuits past recovery timeout, attempts CAS to HalfOpen.
    /// only one caller wins the CAS — that connection is the probe.
    pub fn is_available(&self, recovery_timeout: Duration) -> bool {
        match self.circuit_state() {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => false,
            CircuitState::Open => {
                let elapsed =
                    monotonic_millis().saturating_sub(self.open_since.load(Ordering::Relaxed));
                if elapsed >= recovery_timeout.as_millis() as u64 {
                    self.circuit
                        .compare_exchange(
                            CircuitState::Open as u8,
                            CircuitState::HalfOpen as u8,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                } else {
                    false
                }
            }
        }
    }

    /// true when total active+idle conns to this backend has reached max_total.
    /// observability query only — NOT consulted by RoundRobin (saturation is enforced at checkout).
    pub fn is_saturated(&self) -> bool {
        match self.keepalive.max_total {
            None => false,
            Some(cap) => self.total_count.0.load(Ordering::Acquire) >= cap.get() as u64,
        }
    }

    /// pop and drop stale idle conns from this backend's cache, decrementing total_count per drop.
    pub fn sweep_stale_keepalive(&self) {
        let dropped = self.keepalive.sweep_stale(self.keepalive.idle_conn_ttl);
        if dropped > 0 {
            self.total_count
                .0
                .fetch_sub(dropped as u64, Ordering::Release);
            for _ in 0..dropped {
                metrics::gauge!(
                    "kntx_backend_pool_size",
                    "pool" => self.pool_name.to_string(),
                    "backend" => self.address.to_string(),
                )
                .decrement(1.0);
            }
        }
    }
}

pub struct BackendPool {
    pool_name: Arc<str>,
    // Arc-wrapped so checkout sites can hand the state to KeepaliveCache::checkout without
    // re-cloning the heavy BackendState (which owns the keepalive ArrayQueue).
    backends: Vec<Arc<BackendState>>,
    failure_threshold: u32,
    recovery_timeout: Duration,
    keepalive_cfg: KeepaliveConfig,
}

impl BackendPool {
    pub fn new(
        pool_name: Arc<str>,
        addrs: Vec<SocketAddr>,
        failure_threshold: u32,
        recovery_timeout: Duration,
        keepalive: KeepaliveConfig,
    ) -> Self {
        let backends = addrs
            .into_iter()
            .map(|a| {
                Arc::new(BackendState::new(
                    a,
                    Arc::clone(&pool_name),
                    keepalive.clone(),
                ))
            })
            .collect();
        Self {
            pool_name,
            backends,
            failure_threshold,
            recovery_timeout,
            keepalive_cfg: keepalive,
        }
    }

    /// pool-wide keepalive configuration. used by the sweeper to derive its tick interval
    /// and to skip pools with keepalive disabled.
    pub fn keepalive_cfg(&self) -> &KeepaliveConfig {
        &self.keepalive_cfg
    }

    pub fn name(&self) -> &str {
        &self.pool_name
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub fn recovery_timeout(&self) -> Duration {
        self.recovery_timeout
    }

    pub fn get(&self, idx: usize) -> &BackendState {
        self.backends[idx].as_ref()
    }

    pub fn iter(&self) -> impl Iterator<Item = &BackendState> {
        self.backends.iter().map(|a| a.as_ref())
    }

    /// look up an Arc-wrapped BackendState by address. used by L7 checkout to thread
    /// the state into KeepaliveCache::checkout without re-allocating.
    pub fn state_for(&self, addr: SocketAddr) -> Option<Arc<BackendState>> {
        self.backends
            .iter()
            .find(|b| b.address == addr)
            .map(Arc::clone)
    }

    pub fn record_failure(&self, addr: SocketAddr) {
        let Some(backend) = self.find(addr) else {
            return;
        };
        let prev = backend.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        let state = backend.circuit_state();

        match state {
            CircuitState::Closed if prev + 1 >= self.failure_threshold => {
                backend
                    .circuit
                    .store(CircuitState::Open as u8, Ordering::Release);
                backend
                    .open_since
                    .store(monotonic_millis(), Ordering::Relaxed);
                tracing::warn!(%addr, pool = %self.pool_name, "circuit opened after {} failures", prev + 1);
                metrics::gauge!(
                    "kntx_backend_health",
                    "pool" => self.pool_name.to_string(),
                    "backend" => addr.to_string(),
                )
                .set(0.0);
                metrics::gauge!(
                    "kntx_circuit_breaker_state",
                    "pool" => self.pool_name.to_string(),
                    "backend" => addr.to_string(),
                )
                .set(CircuitState::Open as u8 as f64);
                // flush stale idle conns now that the circuit is open;
                // circuit was flipped first so concurrent checkouts skip
                // this backend via is_available() before they pop anything.
                backend
                    .keepalive
                    .flush_all(&backend.total_count, &self.pool_name, addr);
            }
            CircuitState::HalfOpen => {
                backend
                    .circuit
                    .store(CircuitState::Open as u8, Ordering::Release);
                backend
                    .open_since
                    .store(monotonic_millis(), Ordering::Relaxed);
                tracing::warn!(%addr, pool = %self.pool_name, "half-open probe failed, circuit re-opened");
                metrics::gauge!(
                    "kntx_circuit_breaker_state",
                    "pool" => self.pool_name.to_string(),
                    "backend" => addr.to_string(),
                )
                .set(CircuitState::Open as u8 as f64);
                backend
                    .keepalive
                    .flush_all(&backend.total_count, &self.pool_name, addr);
            }
            _ => {}
        }
    }

    pub fn record_success(&self, addr: SocketAddr) {
        let Some(backend) = self.find(addr) else {
            return;
        };
        backend.consecutive_failures.store(0, Ordering::Relaxed);
        let state = backend.circuit_state();

        if state == CircuitState::HalfOpen || state == CircuitState::Open {
            backend
                .circuit
                .store(CircuitState::Closed as u8, Ordering::Release);
            tracing::info!(%addr, pool = %self.pool_name, "circuit closed, backend recovered");
            metrics::gauge!(
                "kntx_backend_health",
                "pool" => self.pool_name.to_string(),
                "backend" => addr.to_string(),
            )
            .set(1.0);
            metrics::gauge!(
                "kntx_circuit_breaker_state",
                "pool" => self.pool_name.to_string(),
                "backend" => addr.to_string(),
            )
            .set(CircuitState::Closed as u8 as f64);
        }
    }

    /// emit initial health metrics for all backends so dashboards show them from startup
    pub fn emit_initial_metrics(&self) {
        for backend in &self.backends {
            let addr = backend.address.to_string();
            metrics::gauge!(
                "kntx_backend_health",
                "pool" => self.pool_name.to_string(),
                "backend" => addr.clone(),
            )
            .set(1.0);
            metrics::gauge!(
                "kntx_circuit_breaker_state",
                "pool" => self.pool_name.to_string(),
                "backend" => addr,
            )
            .set(0.0);
        }
    }

    fn find(&self, addr: SocketAddr) -> Option<&BackendState> {
        self.backends
            .iter()
            .find(|b| b.address == addr)
            .map(|a| a.as_ref())
    }
}

pub struct HealthChecker {
    pool: Arc<BackendPool>,
    interval: Duration,
    connect_timeout: Duration,
}

impl HealthChecker {
    pub fn new(pool: Arc<BackendPool>, interval: Duration, connect_timeout: Duration) -> Self {
        Self {
            pool,
            interval,
            connect_timeout,
        }
    }

    /// spawn the health check loop as a background task.
    /// exits cleanly when the shutdown receiver fires.
    pub fn spawn(self, mut shutdown: watch::Receiver<()>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                self.probe_cycle().await;
                tokio::select! {
                    _ = tokio::time::sleep(self.interval) => {}
                    _ = shutdown.changed() => {
                        tracing::info!(pool = %self.pool.name(), "health checker exiting");
                        return;
                    }
                }
            }
        })
    }

    async fn probe_cycle(&self) {
        for backend in self.pool.iter() {
            let addr = backend.address();
            let start = std::time::Instant::now();

            let result = tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr)).await;

            let duration = start.elapsed();

            match result {
                Ok(Ok(_)) => {
                    self.pool.record_success(addr);
                }
                _ => {
                    self.pool.record_failure(addr);
                }
            }

            metrics::histogram!(
                "kntx_health_check_duration_seconds",
                "pool" => self.pool.name().to_string(),
                "backend" => addr.to_string(),
            )
            .record(duration.as_secs_f64());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    const ADDR: &str = "127.0.0.1:3001";

    fn make_pool(addrs: &[&str], threshold: u32, recovery_secs: u64) -> Arc<BackendPool> {
        let addrs: Vec<SocketAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
        Arc::new(BackendPool::new(
            "test".into(),
            addrs,
            threshold,
            Duration::from_secs(recovery_secs),
            KeepaliveConfig::default(),
        ))
    }

    #[test]
    fn circuit_starts_closed() {
        let pool = make_pool(&[ADDR], 3, 10);
        assert_eq!(pool.get(0).circuit_state(), CircuitState::Closed);
    }

    #[test]
    fn failures_below_threshold_stays_closed() {
        let pool = make_pool(&[ADDR], 3, 10);
        let addr: SocketAddr = ADDR.parse().unwrap();
        pool.record_failure(addr);
        pool.record_failure(addr);
        assert_eq!(pool.get(0).circuit_state(), CircuitState::Closed);
        assert_eq!(pool.get(0).consecutive_failures.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn failures_at_threshold_opens_circuit() {
        let pool = make_pool(&[ADDR], 3, 10);
        let addr: SocketAddr = ADDR.parse().unwrap();
        pool.record_failure(addr);
        pool.record_failure(addr);
        pool.record_failure(addr);
        assert_eq!(pool.get(0).circuit_state(), CircuitState::Open);
    }

    #[test]
    fn open_circuit_not_available() {
        let pool = make_pool(&[ADDR], 1, 10);
        let addr: SocketAddr = ADDR.parse().unwrap();
        pool.record_failure(addr);
        assert_eq!(pool.get(0).circuit_state(), CircuitState::Open);
        assert!(!pool.get(0).is_available(pool.recovery_timeout()));
    }

    #[test]
    fn open_circuit_available_after_recovery_timeout() {
        let pool = make_pool(&[ADDR], 1, 10);
        let addr: SocketAddr = ADDR.parse().unwrap();
        pool.record_failure(addr);
        assert_eq!(pool.get(0).circuit_state(), CircuitState::Open);

        assert!(pool.get(0).is_available(Duration::ZERO));
        assert_eq!(pool.get(0).circuit_state(), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_not_available() {
        let pool = make_pool(&[ADDR], 1, 10);
        pool.get(0)
            .circuit
            .store(CircuitState::HalfOpen as u8, Ordering::Relaxed);
        assert!(!pool.get(0).is_available(pool.recovery_timeout()));
    }

    #[test]
    fn only_one_half_open_probe() {
        let pool: Arc<BackendPool> = Arc::new(BackendPool::new(
            "test".into(),
            vec![ADDR.parse().unwrap()],
            1,
            Duration::from_secs(10),
            KeepaliveConfig::default(),
        ));

        pool.get(0)
            .circuit
            .store(CircuitState::Open as u8, Ordering::Release);

        let wins = Arc::new(std::sync::atomic::AtomicU32::new(0));

        std::thread::scope(|s| {
            for _ in 0..16 {
                let pool = Arc::clone(&pool);
                let wins = Arc::clone(&wins);
                s.spawn(move || {
                    if pool.get(0).is_available(Duration::ZERO) {
                        wins.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });

        assert_eq!(
            wins.load(Ordering::Relaxed),
            1,
            "exactly one thread should win the CAS"
        );
        assert_eq!(pool.get(0).circuit_state(), CircuitState::HalfOpen);
    }

    #[test]
    fn success_on_half_open_closes_circuit() {
        let pool = make_pool(&[ADDR], 3, 10);
        let addr: SocketAddr = ADDR.parse().unwrap();
        pool.get(0)
            .circuit
            .store(CircuitState::HalfOpen as u8, Ordering::Release);
        pool.get(0).consecutive_failures.store(3, Ordering::Relaxed);

        pool.record_success(addr);

        assert_eq!(pool.get(0).circuit_state(), CircuitState::Closed);
        assert_eq!(pool.get(0).consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn failure_on_half_open_reopens() {
        let pool = make_pool(&[ADDR], 3, 10);
        let addr: SocketAddr = ADDR.parse().unwrap();
        pool.get(0)
            .circuit
            .store(CircuitState::HalfOpen as u8, Ordering::Release);

        let before = monotonic_millis();
        pool.record_failure(addr);
        let after = monotonic_millis();

        assert_eq!(pool.get(0).circuit_state(), CircuitState::Open);
        let ts = pool.get(0).open_since.load(Ordering::Relaxed);
        assert!(ts >= before && ts <= after + 1);
    }

    #[test]
    fn record_success_resets_failures() {
        let pool = make_pool(&[ADDR], 3, 10);
        let addr: SocketAddr = ADDR.parse().unwrap();
        pool.record_failure(addr);
        pool.record_failure(addr);
        assert_eq!(pool.get(0).consecutive_failures.load(Ordering::Relaxed), 2);

        pool.record_success(addr);
        assert_eq!(pool.get(0).consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn all_backends_unavailable() {
        let pool = make_pool(&["127.0.0.1:3001", "127.0.0.1:3002"], 1, 60);
        let addr1: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        pool.record_failure(addr1);
        pool.record_failure(addr2);

        let recovery = pool.recovery_timeout();
        let any_available = pool.iter().any(|b| b.is_available(recovery));
        assert!(!any_available);
    }

    #[test]
    fn record_success_on_open_closes_directly() {
        let pool = make_pool(&[ADDR], 3, 10);
        let addr: SocketAddr = ADDR.parse().unwrap();
        pool.get(0)
            .circuit
            .store(CircuitState::Open as u8, Ordering::Release);

        pool.record_success(addr);

        assert_eq!(pool.get(0).circuit_state(), CircuitState::Closed);
    }

    #[test]
    fn not_saturated_when_max_total_zero() {
        let cfg = KeepaliveConfig {
            max_idle: 4,
            idle_conn_ttl_secs: 60,
            max_total: 0,
        };
        let addr: SocketAddr = ADDR.parse().unwrap();
        let state = BackendState::new(addr, "test".into(), cfg);
        state.total_count.0.store(999, Ordering::SeqCst);
        assert!(
            !state.is_saturated(),
            "max_total=0 means unlimited, never saturated"
        );
    }

    #[test]
    fn not_saturated_below_cap() {
        let cfg = KeepaliveConfig {
            max_idle: 4,
            idle_conn_ttl_secs: 60,
            max_total: 5,
        };
        let addr: SocketAddr = ADDR.parse().unwrap();
        let state = BackendState::new(addr, "test".into(), cfg);
        state.total_count.0.store(4, Ordering::SeqCst);
        assert!(!state.is_saturated());
    }

    #[test]
    fn saturated_at_cap() {
        let cfg = KeepaliveConfig {
            max_idle: 4,
            idle_conn_ttl_secs: 60,
            max_total: 5,
        };
        let addr: SocketAddr = ADDR.parse().unwrap();
        let state = BackendState::new(addr, "test".into(), cfg);
        state.total_count.0.store(5, Ordering::SeqCst);
        assert!(state.is_saturated());
    }

    #[test]
    fn is_available_ignores_saturation() {
        // saturated but circuit closed → is_available must return true;
        // saturation enforcement lives at the checkout layer, not in RR selection.
        let cfg = KeepaliveConfig {
            max_idle: 1,
            idle_conn_ttl_secs: 60,
            max_total: 1,
        };
        let addr: SocketAddr = ADDR.parse().unwrap();
        let state = BackendState::new(addr, "test".into(), cfg);
        state.total_count.0.store(1, Ordering::SeqCst); // at cap
        assert!(state.is_saturated(), "precondition: backend is saturated");
        assert!(
            state.is_available(Duration::from_secs(60)),
            "is_available must be circuit-only, not consult saturation"
        );
    }

    #[test]
    fn sweep_stale_keepalive_decrements_count() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let cfg = KeepaliveConfig {
                max_idle: 4,
                idle_conn_ttl_secs: 1,
                max_total: 0,
            };
            let state = Arc::new(BackendState::new(addr, "test".into(), cfg));

            // push a stale idle (last_used far in the past)
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let _s = listener.accept().await.unwrap();
            state
                .keepalive
                .push_test_idle(stream, std::time::Instant::now() - Duration::from_secs(10));
            state.total_count.0.store(1, Ordering::SeqCst);

            state.sweep_stale_keepalive();

            assert_eq!(
                state.total_count.0.load(Ordering::SeqCst),
                0,
                "stale conn must be dropped and counter decremented"
            );
            assert_eq!(state.keepalive.queue_len(), 0);
        });
    }

    #[test]
    fn flush_on_circuit_open_clears_cache() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_addr = listener.local_addr().unwrap();

            let cfg = KeepaliveConfig {
                max_idle: 5,
                idle_conn_ttl_secs: 60,
                max_total: 0,
            };
            let pool = Arc::new(BackendPool::new(
                "flush_test".into(),
                vec![backend_addr],
                1, // circuit opens after 1 failure
                Duration::from_secs(60),
                cfg,
            ));

            // manually fill the keepalive cache with 3 idle conns
            for _ in 0..3 {
                let stream = tokio::net::TcpStream::connect(backend_addr).await.unwrap();
                let _s = listener.accept().await.unwrap();
                pool.get(0)
                    .keepalive
                    .push_test_idle(stream, std::time::Instant::now());
            }
            pool.get(0).total_count.0.store(3, Ordering::Relaxed);
            assert_eq!(pool.get(0).keepalive.queue_len(), 3);

            // trigger circuit open via record_failure
            pool.record_failure(backend_addr);
            assert_eq!(pool.get(0).circuit_state(), CircuitState::Open);

            // cache must be flushed and total_count zeroed
            assert_eq!(
                pool.get(0).total_count.0.load(Ordering::Relaxed),
                0,
                "flush_all must decrement total_count for each drained idle"
            );
            assert_eq!(
                pool.get(0).keepalive.queue_len(),
                0,
                "cache must be empty after circuit opens"
            );
        });
    }
}
