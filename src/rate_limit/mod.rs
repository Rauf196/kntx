//! GCRA-based rate limiting.
//!
//! self-contained: std imports only, no kntx types cross this boundary
//! in either direction. inputs are a key, a [`Clock`], and scalar params;
//! output is a [`Decision`]. config mapping and metric emission belong
//! to call sites.

mod gcra;
mod keyed;

pub use gcra::{Gcra, Verdict};
pub use keyed::KeyedLimiter;

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// admission rate: `count` events per `period`, sustained.
#[derive(Clone, Copy, Debug)]
pub struct Rate {
    pub count: NonZeroU32,
    pub period: Period,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Period {
    Second,
    Minute,
}

/// outcome of a limit check. `retry_after` is the shortest wait after
/// which the same key would be admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { retry_after: Duration },
}

/// monotonic time source, nanos since an arbitrary fixed origin.
/// injected so tests drive time explicitly instead of sleeping.
/// u64 nanos covers 584 years, no wrap handling.
pub trait Clock: Send + Sync {
    fn now_nanos(&self) -> u64;
}

/// production clock: Instant anchored at construction.
pub struct MonotonicClock {
    origin: Instant,
}

/// unkeyed limiter: one budget shared by every caller.
pub struct Limiter<C: Clock = MonotonicClock> {
    gcra: Gcra,
    tat: AtomicU64,
    clock: C,
}

/// one configured zone: a single shared budget, or one budget per client IP.
pub enum ZoneLimiter<C: Clock = MonotonicClock> {
    Global(Limiter<C>),
    PerIp(KeyedLimiter<C>),
}

/// a named reference to a shared zone, resolved once at startup. the name
/// labels metrics at deny sites; the limiter is the shared budget.
pub struct ZoneHandle {
    pub name: Arc<str>,
    pub limiter: Arc<ZoneLimiter>,
}

impl Period {
    fn as_nanos(self) -> u64 {
        match self {
            Period::Second => NANOS_PER_SEC,
            Period::Minute => 60 * NANOS_PER_SEC,
        }
    }
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now_nanos(&self) -> u64 {
        // u128 -> u64 truncation unreachable inside the 584-year range
        self.origin.elapsed().as_nanos() as u64
    }
}

impl<C: Clock> Limiter<C> {
    pub fn new(rate: Rate, burst: u32, clock: C) -> Self {
        Self {
            gcra: Gcra::new(rate, burst),
            tat: AtomicU64::new(0),
            clock,
        }
    }

    pub fn check(&self) -> Decision {
        let now = self.clock.now_nanos();
        // relaxed: the TAT word is the only state, nothing else is
        // published through it
        let mut tat = self.tat.load(Ordering::Relaxed);
        loop {
            match self.gcra.decide(tat, now) {
                Verdict::Deny { retry_after_nanos } => {
                    return Decision::Deny {
                        retry_after: Duration::from_nanos(retry_after_nanos),
                    };
                }
                Verdict::Allow { new_tat } => match self.tat.compare_exchange_weak(
                    tat,
                    new_tat,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return Decision::Allow,
                    Err(observed) => tat = observed,
                },
            }
        }
    }
}

impl<C: Clock> ZoneLimiter<C> {
    pub fn check(&self, client_ip: IpAddr) -> Decision {
        match self {
            ZoneLimiter::Global(limiter) => limiter.check(),
            ZoneLimiter::PerIp(limiter) => limiter.check(&client_ip),
        }
    }
}

/// test clock: advances only when told. atomic so shared references can
/// move time mid-test.
#[cfg(test)]
pub struct ManualClock {
    nanos: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl ManualClock {
    pub fn new(start_nanos: u64) -> Self {
        Self {
            nanos: std::sync::atomic::AtomicU64::new(start_nanos),
        }
    }

    pub fn set(&self, nanos: u64) {
        // relaxed: a single test-controlled value, no ordering dependencies
        self.nanos
            .store(nanos, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn advance(&self, nanos: u64) {
        self.nanos
            .fetch_add(nanos, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn now_nanos(&self) -> u64 {
        self.nanos.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_clock_non_decreasing() {
        let clock = MonotonicClock::new();
        let a = clock.now_nanos();
        let b = clock.now_nanos();
        assert!(b >= a);
    }

    #[test]
    fn manual_clock_set_and_advance() {
        let clock = ManualClock::new(5);
        assert_eq!(clock.now_nanos(), 5);
        clock.advance(10);
        assert_eq!(clock.now_nanos(), 15);
        clock.set(3);
        assert_eq!(clock.now_nanos(), 3);
    }

    fn rate_10s() -> Rate {
        Rate {
            count: NonZeroU32::new(10).unwrap(),
            period: Period::Second,
        }
    }

    const T: u64 = 100_000_000; // rate 10/s emission interval

    #[test]
    fn global_limiter_burst_deny_refill() {
        let limiter = Limiter::new(rate_10s(), 2, ManualClock::new(0));
        for _ in 0..3 {
            assert_eq!(limiter.check(), Decision::Allow);
        }
        assert_eq!(
            limiter.check(),
            Decision::Deny {
                retry_after: Duration::from_nanos(T)
            }
        );
        limiter.clock.advance(T);
        assert_eq!(limiter.check(), Decision::Allow);
        assert!(matches!(limiter.check(), Decision::Deny { .. }));
    }

    #[test]
    fn global_limiter_concurrent_admits_exactly_burst_plus_one() {
        // frozen clock: no refill, so the admitted total is exact
        let limiter = Limiter::new(rate_10s(), 16, ManualClock::new(0));
        let admitted = std::sync::atomic::AtomicU32::new(0);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..300 {
                        if limiter.check() == Decision::Allow {
                            admitted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        assert_eq!(admitted.load(Ordering::Relaxed), 17);
    }

    #[test]
    fn zone_global_shares_budget_across_ips() {
        let zone = ZoneLimiter::Global(Limiter::new(rate_10s(), 0, ManualClock::new(0)));
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert_eq!(zone.check(ip1), Decision::Allow);
        assert!(matches!(zone.check(ip2), Decision::Deny { .. }));
    }

    #[test]
    fn zone_per_ip_budgets_are_independent() {
        let zone = ZoneLimiter::PerIp(KeyedLimiter::new(rate_10s(), 0, 64, ManualClock::new(0)));
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert_eq!(zone.check(ip1), Decision::Allow);
        assert!(matches!(zone.check(ip1), Decision::Deny { .. }));
        assert_eq!(zone.check(ip2), Decision::Allow);
    }
}
