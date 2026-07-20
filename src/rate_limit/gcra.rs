//! pure GCRA math on u64 nanos. no atomics and no clock: callers pass
//! timestamps in, new state comes back by value. the CAS loops live in
//! callers, which keeps every admission sequence testable with plain
//! integers.

use super::Rate;

/// generic cell rate algorithm. per-key state is one word, the TAT
/// (theoretical arrival time), so callers can CAS it; token-bucket state
/// is two words and would need a lock.
///
/// behaves as a token bucket of depth `burst + 1` refilling at `rate`.
/// `burst = 0` means strict pacing: arrivals closer than one emission
/// interval apart are denied.
#[derive(Clone, Copy, Debug)]
pub struct Gcra {
    /// emission interval: period / rate
    t_nanos: u64,
    /// tolerance: burst * t. a TAT no more than tau ahead of now is
    /// inside the burst allowance.
    tau_nanos: u64,
}

/// deny carries no new TAT: denials don't advance state, so retry_after
/// stays exact under repeated over-limit attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow { new_tat: u64 },
    Deny { retry_after_nanos: u64 },
}

impl Gcra {
    pub fn new(rate: Rate, burst: u32) -> Self {
        // div_ceil, not floor: floor reaches t = 0 at extreme rates, which
        // disables pacing entirely. rounding up errs toward strict.
        let t_nanos = rate.period.as_nanos().div_ceil(u64::from(rate.count.get()));
        // saturating: u32::MAX burst at minute scale overflows u64; a
        // saturated tau just admits everything.
        let tau_nanos = t_nanos.saturating_mul(u64::from(burst));
        Self { t_nanos, tau_nanos }
    }

    /// rule on an arrival at `now` given the key's stored `tat`.
    /// fresh keys start at tat = 0: `max(tat, now)` treats any past tat
    /// as now, so idle never accumulates credit beyond tau.
    pub fn decide(&self, tat: u64, now: u64) -> Verdict {
        let tat = tat.max(now);
        let ahead = tat - now;
        if ahead > self.tau_nanos {
            Verdict::Deny {
                retry_after_nanos: ahead - self.tau_nanos,
            }
        } else {
            Verdict::Allow {
                new_tat: tat.saturating_add(self.t_nanos),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Period, Rate};
    use super::*;
    use std::num::NonZeroU32;

    fn per_second(count: u32, burst: u32) -> Gcra {
        Gcra::new(
            Rate {
                count: NonZeroU32::new(count).unwrap(),
                period: Period::Second,
            },
            burst,
        )
    }

    fn per_minute(count: u32, burst: u32) -> Gcra {
        Gcra::new(
            Rate {
                count: NonZeroU32::new(count).unwrap(),
                period: Period::Minute,
            },
            burst,
        )
    }

    /// run arrivals at a fixed instant with the caller protocol (store tat
    /// only on allow); returns (admitted count, final tat).
    fn admit_until_deny(gcra: &Gcra, mut tat: u64, now: u64, max_attempts: u32) -> (u32, u64) {
        let mut admitted = 0;
        for _ in 0..max_attempts {
            match gcra.decide(tat, now) {
                Verdict::Allow { new_tat } => {
                    tat = new_tat;
                    admitted += 1;
                }
                Verdict::Deny { .. } => break,
            }
        }
        (admitted, tat)
    }

    const T: u64 = 100_000_000; // rate 10/s emission interval

    #[test]
    fn burst_plus_one_admitted_back_to_back() {
        for burst in [0, 1, 5, 100] {
            let gcra = per_second(10, burst);
            let (admitted, tat) = admit_until_deny(&gcra, 0, 0, burst + 2);
            assert_eq!(admitted, burst + 1, "burst {burst}");
            assert!(matches!(gcra.decide(tat, 0), Verdict::Deny { .. }));
        }
    }

    #[test]
    fn retry_after_exact_at_deny_boundary() {
        let gcra = per_second(10, 5);
        let (_, tat) = admit_until_deny(&gcra, 0, 0, 10);
        // 6 admitted, tat = 6T; ahead - tau = 6T - 5T = T
        assert_eq!(
            gcra.decide(tat, 0),
            Verdict::Deny {
                retry_after_nanos: T
            }
        );
    }

    #[test]
    fn allow_at_exactly_retry_after() {
        let gcra = per_second(10, 5);
        let (_, tat) = admit_until_deny(&gcra, 0, 0, 10);
        let Verdict::Deny { retry_after_nanos } = gcra.decide(tat, 0) else {
            panic!("expected deny at saturation");
        };
        // one nano early still denied, with exactly one nano left to wait
        assert_eq!(
            gcra.decide(tat, retry_after_nanos - 1),
            Verdict::Deny {
                retry_after_nanos: 1
            }
        );
        assert!(matches!(
            gcra.decide(tat, retry_after_nanos),
            Verdict::Allow { .. }
        ));
    }

    #[test]
    fn idle_does_not_accumulate_credit() {
        let gcra = per_second(10, 5);
        let (_, tat) = admit_until_deny(&gcra, 0, 0, 10);
        // an hour idle refills the burst allowance and not one arrival more
        let later = 3_600 * 1_000_000_000;
        let (admitted, _) = admit_until_deny(&gcra, tat, later, 100);
        assert_eq!(admitted, 6);
    }

    #[test]
    fn burst_zero_enforces_spacing() {
        let gcra = per_second(10, 0);
        let Verdict::Allow { new_tat: tat } = gcra.decide(0, 0) else {
            panic!("first arrival must be admitted");
        };
        assert_eq!(
            gcra.decide(tat, 0),
            Verdict::Deny {
                retry_after_nanos: T
            }
        );
        assert_eq!(
            gcra.decide(tat, T - 1),
            Verdict::Deny {
                retry_after_nanos: 1
            }
        );
        assert_eq!(gcra.decide(tat, T), Verdict::Allow { new_tat: 2 * T });
    }

    #[test]
    fn per_minute_interval_math() {
        // 6/min = one arrival per 10s
        let ten_secs = 10 * 1_000_000_000;
        let gcra = per_minute(6, 0);
        let Verdict::Allow { new_tat: tat } = gcra.decide(0, 0) else {
            panic!("first arrival must be admitted");
        };
        assert_eq!(tat, ten_secs);
        assert_eq!(
            gcra.decide(tat, ten_secs - 1),
            Verdict::Deny {
                retry_after_nanos: 1
            }
        );
        assert!(matches!(gcra.decide(tat, ten_secs), Verdict::Allow { .. }));
    }

    #[test]
    fn deny_is_pure_and_leaves_tat_unchanged() {
        let gcra = per_second(10, 2);
        let (_, tat) = admit_until_deny(&gcra, 0, 0, 10);
        // repeated over-limit arrivals: same ruling every time, and the
        // stored tat (unchanged by denies) still admits at the promised time
        let first = gcra.decide(tat, 0);
        for _ in 0..10 {
            assert_eq!(gcra.decide(tat, 0), first);
        }
        let Verdict::Deny { retry_after_nanos } = first else {
            panic!("expected deny at saturation");
        };
        assert!(matches!(
            gcra.decide(tat, retry_after_nanos),
            Verdict::Allow { .. }
        ));
    }

    #[test]
    fn rate_one_burst_zero() {
        let one_sec = 1_000_000_000;
        let gcra = per_second(1, 0);
        let Verdict::Allow { new_tat: tat } = gcra.decide(0, 0) else {
            panic!("first arrival must be admitted");
        };
        assert_eq!(
            gcra.decide(tat, one_sec / 2),
            Verdict::Deny {
                retry_after_nanos: one_sec / 2
            }
        );
        assert!(matches!(gcra.decide(tat, one_sec), Verdict::Allow { .. }));
    }

    #[test]
    fn u32_max_rate_still_paces() {
        // div_ceil keeps t at 1 nano instead of 0, so pacing survives
        let gcra = per_second(u32::MAX, 0);
        let Verdict::Allow { new_tat: tat } = gcra.decide(0, 0) else {
            panic!("first arrival must be admitted");
        };
        assert_eq!(tat, 1);
        assert_eq!(
            gcra.decide(tat, 0),
            Verdict::Deny {
                retry_after_nanos: 1
            }
        );
        assert!(matches!(gcra.decide(tat, 1), Verdict::Allow { .. }));
    }

    #[test]
    fn saturation_does_not_overflow() {
        // tau = 60e9 * u32::MAX overflows u64 and saturates: admit everything
        let gcra = per_minute(1, u32::MAX);
        assert!(matches!(gcra.decide(u64::MAX, 0), Verdict::Allow { .. }));
        // tat + t at the top of the range saturates instead of wrapping
        assert_eq!(
            gcra.decide(u64::MAX, u64::MAX),
            Verdict::Allow { new_tat: u64::MAX }
        );
    }
}
