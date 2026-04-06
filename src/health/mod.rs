use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;

use crate::util::monotonic_millis;

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
            _ => Self::Closed, // defensive fallback
        }
    }
}

pub struct BackendState {
    address: SocketAddr,
    pub(crate) circuit: AtomicU8,
    pub(crate) consecutive_failures: AtomicU32,
    pub(crate) open_since: AtomicU64,
}

impl BackendState {
    fn new(address: SocketAddr) -> Self {
        Self {
            address,
            circuit: AtomicU8::new(CircuitState::Closed as u8),
            consecutive_failures: AtomicU32::new(0),
            open_since: AtomicU64::new(0),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
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
            CircuitState::HalfOpen => false, // probe in flight
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
}

pub struct BackendPool {
    backends: Vec<BackendState>,
    failure_threshold: u32,
    recovery_timeout: Duration,
}

impl BackendPool {
    pub fn new(addrs: Vec<SocketAddr>, failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            backends: addrs.into_iter().map(BackendState::new).collect(),
            failure_threshold,
            recovery_timeout,
        }
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
        &self.backends[idx]
    }

    pub fn iter(&self) -> impl Iterator<Item = &BackendState> {
        self.backends.iter()
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
                tracing::warn!(%addr, "circuit opened after {} failures", prev + 1);
                metrics::gauge!("kntx_backend_health", "backend" => addr.to_string()).set(0.0);
                metrics::gauge!("kntx_circuit_breaker_state", "backend" => addr.to_string())
                    .set(CircuitState::Open as u8 as f64);
            }
            CircuitState::HalfOpen => {
                backend
                    .circuit
                    .store(CircuitState::Open as u8, Ordering::Release);
                backend
                    .open_since
                    .store(monotonic_millis(), Ordering::Relaxed);
                tracing::warn!(%addr, "half-open probe failed, circuit re-opened");
                metrics::gauge!("kntx_circuit_breaker_state", "backend" => addr.to_string())
                    .set(CircuitState::Open as u8 as f64);
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
            tracing::info!(%addr, "circuit closed, backend recovered");
            metrics::gauge!("kntx_backend_health", "backend" => addr.to_string()).set(1.0);
            metrics::gauge!("kntx_circuit_breaker_state", "backend" => addr.to_string())
                .set(CircuitState::Closed as u8 as f64);
        }
    }

    /// emit initial health metrics for all backends so dashboards show them from startup
    pub fn emit_initial_metrics(&self) {
        for backend in &self.backends {
            let addr = backend.address.to_string();
            metrics::gauge!("kntx_backend_health", "backend" => addr.clone()).set(1.0);
            metrics::gauge!("kntx_circuit_breaker_state", "backend" => addr).set(0.0);
        }
    }

    fn find(&self, addr: SocketAddr) -> Option<&BackendState> {
        self.backends.iter().find(|b| b.address == addr)
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
    /// cancelled automatically when the tokio runtime shuts down.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run().await })
    }

    async fn run(&self) {
        loop {
            for backend in self.pool.iter() {
                let addr = backend.address();
                let start = std::time::Instant::now();

                let result =
                    tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr)).await;

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
                    "backend" => addr.to_string(),
                )
                .record(duration.as_secs_f64());
            }

            tokio::time::sleep(self.interval).await;
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
            addrs,
            threshold,
            Duration::from_secs(recovery_secs),
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
        // recovery timeout = 10s, has not elapsed
        assert!(!pool.get(0).is_available(pool.recovery_timeout()));
    }

    #[test]
    fn open_circuit_available_after_recovery_timeout() {
        let pool = make_pool(&[ADDR], 1, 10);
        let addr: SocketAddr = ADDR.parse().unwrap();
        pool.record_failure(addr);
        assert_eq!(pool.get(0).circuit_state(), CircuitState::Open);

        // use Duration::ZERO as the recovery timeout: elapsed >= 0 is always true
        // for u64, so the CAS will fire regardless of how long the process has run.
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
            vec![ADDR.parse().unwrap()],
            1,
            Duration::from_secs(10),
        ));

        pool.get(0)
            .circuit
            .store(CircuitState::Open as u8, Ordering::Release);

        // Duration::ZERO: elapsed (u64) >= 0 is always true, so all 16 threads
        // reach the CAS — exactly one wins, the rest get the failure result.
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
}
