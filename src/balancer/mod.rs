use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::util::CacheLinePadded;

pub struct RoundRobin {
    backends: Vec<SocketAddr>,
    index: CacheLinePadded<AtomicUsize>,
}

impl RoundRobin {
    pub fn new(backends: Vec<SocketAddr>) -> Self {
        Self {
            backends,
            index: CacheLinePadded(AtomicUsize::new(0)),
        }
    }

    pub fn next_backend(&self) -> Option<SocketAddr> {
        if self.backends.is_empty() {
            return None;
        }

        let idx = self.index.0.fetch_add(1, Ordering::Relaxed);
        Some(self.backends[idx % self.backends.len()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backends(addrs: &[&str]) -> Vec<SocketAddr> {
        addrs.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn cycles_through_backends() {
        let rr = RoundRobin::new(backends(&[
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
        let addrs = backends(&["127.0.0.1:3001", "127.0.0.1:3002"]);
        let rr = RoundRobin::new(addrs.clone());

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
        let rr = RoundRobin::new(backends(&["127.0.0.1:3001"]));

        for _ in 0..100 {
            assert_eq!(
                rr.next_backend().unwrap(),
                "127.0.0.1:3001".parse::<SocketAddr>().unwrap(),
            );
        }
    }

    #[test]
    fn empty_backends_returns_none() {
        let rr = RoundRobin::new(vec![]);
        assert!(rr.next_backend().is_none());
    }

    #[test]
    fn wraps_around_at_usize_boundary() {
        let addrs = backends(&["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"]);
        let rr = RoundRobin::new(addrs.clone());

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
        use std::sync::Arc;

        let addrs = backends(&["127.0.0.1:3001", "127.0.0.1:3002"]);
        let rr = Arc::new(RoundRobin::new(addrs.clone()));
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
}
