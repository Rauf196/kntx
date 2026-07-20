//! lock-free keyed limiter: GCRA states in a set-associative cache.
//!
//! memory is fixed at construction and never grows with key cardinality:
//! a key landing in a full set evicts the way with the oldest TAT instead
//! of allocating, so an attacker spraying keys degrades those keys to
//! sharing set capacity and nothing else. keys are stored only as 64-bit
//! fingerprints from a per-limiter seeded siphash; a full-fingerprint
//! collision inside one set makes two keys share a budget, and at 4 ways
//! per 2^64 fingerprints that risk is accepted.
//!
//! accuracy at eviction boundaries: a way's fp and TAT are two atomics,
//! not one unit, so a reader can pair a freshly claimed fp with the
//! victim's not-yet-reset TAT. a past TAT decides like a fresh key
//! (correct); a future TAT gives early denies carrying the old key's
//! retry_after until the claimer's TAT CAS lands. concurrent claims can
//! still duplicate a key across two ways when the set has no empty way
//! and churn diverges the claimants' oldest-TAT reads; the copy the scan
//! stops reaching becomes the set's oldest TAT and ages out. exactness
//! would need a per-set lock on every check; shedding load tolerates the
//! approximation.

use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::{Clock, Decision, Gcra, MonotonicClock, Rate, Verdict};

const WAYS_PER_SET: usize = 4;

/// keyed GCRA states in fixed memory, indexed by the low bits of the key
/// hash, evicting within 4-way sets.
pub struct KeyedLimiter<C: Clock = MonotonicClock> {
    gcra: Gcra,
    // seeded per limiter: hash-flood resistant, and fingerprints never
    // need to survive a restart or match across limiters
    hasher: RandomState,
    sets: Box<[Set]>,
    set_mask: u64,
    clock: C,
}

// one cache line: 4 ways * 16 bytes. the alignment keeps a set from
// straddling two lines
#[repr(align(64))]
#[derive(Default)]
struct Set {
    ways: [Way; WAYS_PER_SET],
}

#[derive(Default)]
struct Way {
    /// key fingerprint, 0 = empty
    fp: AtomicU64,
    tat: AtomicU64,
}

const _: () = assert!(std::mem::size_of::<Set>() == 64);

impl<C: Clock> KeyedLimiter<C> {
    /// capacity is `max_keys` rounded up to a whole power-of-two number
    /// of sets, 64 bytes per set. values below one set floor to one;
    /// config validation owns rejecting them.
    pub fn new(rate: Rate, burst: u32, max_keys: u32, clock: C) -> Self {
        let set_count = (max_keys as usize)
            .div_ceil(WAYS_PER_SET)
            .next_power_of_two();
        Self {
            gcra: Gcra::new(rate, burst),
            hasher: RandomState::new(),
            sets: (0..set_count).map(|_| Set::default()).collect(),
            set_mask: (set_count - 1) as u64,
            clock,
        }
    }

    /// effective key capacity after rounding.
    pub fn capacity(&self) -> usize {
        self.sets.len() * WAYS_PER_SET
    }

    pub fn check<K: Hash + ?Sized>(&self, key: &K) -> Decision {
        let hash = self.hasher.hash_one(key);
        let fp = fingerprint(hash);
        let set = &self.sets[(hash & self.set_mask) as usize];
        let now = self.clock.now_nanos();

        'scan: loop {
            // one pass both finds a resident key and selects the claim
            // victim: first empty way, else oldest TAT. first empty, not
            // any empty, so concurrent claimants of a new key converge on
            // the same way and the fp CAS arbitrates, instead of landing
            // duplicates on different empties
            let mut victim: Option<(&Way, u64, u64)> = None;
            let mut oldest = u64::MAX;
            let mut have_empty = false;
            for way in &set.ways {
                // acquire pairs with the claim's fp CAS: a matching fp
                // reads TAT values written for this key
                let way_fp = way.fp.load(Ordering::Acquire);
                if way_fp == fp {
                    let mut tat = way.tat.load(Ordering::Acquire);
                    loop {
                        match self.gcra.decide(tat, now) {
                            Verdict::Deny { retry_after_nanos } => {
                                return Decision::Deny {
                                    retry_after: Duration::from_nanos(retry_after_nanos),
                                };
                            }
                            Verdict::Allow { new_tat } => {
                                match way.tat.compare_exchange_weak(
                                    tat,
                                    new_tat,
                                    Ordering::AcqRel,
                                    Ordering::Acquire,
                                ) {
                                    Ok(_) => return Decision::Allow,
                                    Err(observed) => {
                                        // lost the race. if the fp moved on, the way
                                        // was evicted mid-loop and holds another key
                                        if way.fp.load(Ordering::Acquire) != fp {
                                            continue 'scan;
                                        }
                                        tat = observed;
                                    }
                                }
                            }
                        }
                    }
                }
                if way_fp == 0 {
                    if !have_empty {
                        have_empty = true;
                        // fp never returns to 0 once claimed, so an empty
                        // way still holds its initial TAT of 0
                        victim = Some((way, 0, 0));
                    }
                } else if !have_empty {
                    // relaxed: a stale value misroutes the heuristic or fails
                    // the claim CAS below, both end in a rescan
                    let tat = way.tat.load(Ordering::Relaxed);
                    if tat <= oldest {
                        oldest = tat;
                        victim = Some((way, way_fp, tat));
                    }
                }
            }

            // miss: claim the selected way
            let Some((way, expected_fp, expected_tat)) = victim else {
                unreachable!("the <= comparison always selects a way");
            };

            if way
                .fp
                .compare_exchange(expected_fp, fp, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                // another thread claimed this way first; rescan, the key
                // may even be resident now
                continue 'scan;
            }

            let Verdict::Allow { new_tat } = self.gcra.decide(0, now) else {
                unreachable!("a fresh key's first arrival is always admitted");
            };
            // CAS, not a store: readers that saw the new fp before this
            // line may have already advanced the TAT from the victim's
            // value, and a blind store would roll their admits back
            if way
                .tat
                .compare_exchange(expected_tat, new_tat, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                // rescan into the hit path for an honest verdict on this
                // arrival instead
                continue 'scan;
            }
            return Decision::Allow;
        }
    }
}

// 0 marks an empty way, so a real hash of 0 shifts to 1
fn fingerprint(hash: u64) -> u64 {
    if hash == 0 { 1 } else { hash }
}

#[cfg(test)]
mod tests {
    use super::super::{ManualClock, Period};
    use super::*;
    use std::num::NonZeroU32;
    use std::sync::atomic::AtomicU32;

    const MINUTE: u64 = 60_000_000_000;

    fn limiter(
        count: u32,
        period: Period,
        burst: u32,
        max_keys: u32,
        start_nanos: u64,
    ) -> KeyedLimiter<ManualClock> {
        KeyedLimiter::new(
            Rate {
                count: NonZeroU32::new(count).unwrap(),
                period,
            },
            burst,
            max_keys,
            ManualClock::new(start_nanos),
        )
    }

    fn deny_nanos(decision: Decision) -> u64 {
        match decision {
            Decision::Deny { retry_after } => retry_after.as_nanos() as u64,
            Decision::Allow => panic!("expected deny"),
        }
    }

    #[test]
    fn keys_have_independent_budgets() {
        let l = limiter(10, Period::Second, 2, 1024, 0);
        for _ in 0..3 {
            assert_eq!(l.check("a"), Decision::Allow);
        }
        assert!(matches!(l.check("a"), Decision::Deny { .. }));
        for _ in 0..3 {
            assert_eq!(l.check("b"), Decision::Allow);
        }
        assert!(matches!(l.check("b"), Decision::Deny { .. }));
        assert!(matches!(l.check("a"), Decision::Deny { .. }));
    }

    #[test]
    fn full_set_evicts_oldest_tat() {
        // max_keys 4 = one set: every key contends for the same 4 ways
        let l = limiter(1, Period::Minute, 0, 4, 0);
        for (t, key) in ["k1", "k2", "k3", "k4"].into_iter().enumerate() {
            l.clock.set(t as u64);
            assert_eq!(l.check(key), Decision::Allow, "{key}");
        }
        l.clock.set(4);
        // set is full: k5 claims the oldest way, which is k1's
        assert_eq!(l.check("k5"), Decision::Allow);
        // survivors keep their state: strict pacing still denies each,
        // with retry_after anchored to their original arrival times
        assert_eq!(deny_nanos(l.check("k2")), MINUTE - 3);
        assert_eq!(deny_nanos(l.check("k3")), MINUTE - 2);
        assert_eq!(deny_nanos(l.check("k4")), MINUTE - 1);
        assert_eq!(deny_nanos(l.check("k5")), MINUTE);
        // k1 lost its way, so it re-enters as a fresh key
        assert_eq!(l.check("k1"), Decision::Allow);
    }

    #[test]
    fn evicted_key_reinserts_cleanly_after_idle() {
        let l = limiter(1, Period::Minute, 0, 4, 0);
        for (t, key) in ["k1", "k2", "k3", "k4"].into_iter().enumerate() {
            l.clock.set(t as u64);
            assert_eq!(l.check(key), Decision::Allow);
        }
        l.clock.set(4);
        assert_eq!(l.check("k5"), Decision::Allow);
        // long idle: no stale state, k1 admits fresh and paces from scratch
        l.clock.set(10 * MINUTE);
        assert_eq!(l.check("k1"), Decision::Allow);
        assert_eq!(deny_nanos(l.check("k1")), MINUTE);
    }

    #[test]
    fn fingerprint_zero_remaps_to_one() {
        assert_eq!(fingerprint(0), 1);
        assert_eq!(fingerprint(1), 1);
        assert_eq!(fingerprint(u64::MAX), u64::MAX);
    }

    #[test]
    fn concurrent_same_key_admits_exactly_burst_plus_one() {
        // frozen clock: no refill, so the admitted total is exact, not a bound
        let l = limiter(10, Period::Second, 16, 1024, 0);
        let admitted = AtomicU32::new(0);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..500 {
                        if l.check("shared") == Decision::Allow {
                            admitted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        assert_eq!(admitted.load(Ordering::Relaxed), 17);
    }

    #[test]
    fn concurrent_distinct_keys_do_not_interfere() {
        let l = limiter(10, Period::Second, 4, 4096, 0);
        let l = &l;
        std::thread::scope(|s| {
            for key in ["k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"] {
                s.spawn(move || {
                    let mut admitted = 0;
                    for _ in 0..200 {
                        if l.check(key) == Decision::Allow {
                            admitted += 1;
                        }
                    }
                    assert_eq!(admitted, 5, "{key}");
                });
            }
        });
    }
}
