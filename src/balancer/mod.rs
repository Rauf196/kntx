use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::health::BackendPool;
use crate::util::CacheLinePadded;

pub struct RoundRobin {
    pool: Arc<BackendPool>,
    index: CacheLinePadded<AtomicUsize>,
}

impl RoundRobin {
    pub fn new(pool: Arc<BackendPool>) -> Self {
        Self {
            pool,
            index: CacheLinePadded(AtomicUsize::new(0)),
        }
    }

    pub fn pool(&self) -> Arc<BackendPool> {
        Arc::clone(&self.pool)
    }

    pub fn current_index(&self) -> usize {
        self.index.0.load(Ordering::Relaxed)
    }

    pub fn next_backend(&self) -> Option<SocketAddr> {
        let len = self.pool.len();
        if len == 0 {
            return None;
        }

        let start = self.index.0.fetch_add(1, Ordering::Relaxed);
        let recovery_timeout = self.pool.recovery_timeout();

        for i in 0..len {
            let idx = (start.wrapping_add(i)) % len;
            let backend = self.pool.get(idx);
            if backend.is_available(recovery_timeout) {
                return Some(backend.address());
            }
        }

        None // all backends unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn test_pool(addrs: &[&str]) -> Arc<BackendPool> {
        let addrs: Vec<SocketAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
        Arc::new(BackendPool::new("test".into(), addrs, 3, Duration::from_secs(10)))
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
        let pool = Arc::new(BackendPool::new("test".into(), addrs.clone(), 3, Duration::from_secs(10)));
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
        let pool = Arc::new(BackendPool::new("test".into(), vec![], 3, Duration::from_secs(10)));
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
        let pool = Arc::new(BackendPool::new("test".into(), addrs.clone(), 3, Duration::from_secs(10)));
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
        let pool = Arc::new(BackendPool::new("test".into(), addrs.clone(), 3, Duration::from_secs(10)));
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
        let pool = Arc::new(BackendPool::new("test".into(), addrs.clone(), 1, Duration::from_secs(60)));
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
}
