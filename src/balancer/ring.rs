use std::fmt::Write;
use std::net::SocketAddr;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// nginx's `hash ... consistent` value.
pub const POINTS_PER_WEIGHT: u32 = 160;

/// caps the ring at 160k points, and the member count at 1000 so `Walk` can
/// dedupe on a stack bitset.
pub const MAX_WEIGHT_SUM: u64 = 1000;

const SEEN_WORDS: usize = (MAX_WEIGHT_SUM as usize).div_ceil(64);

pub struct Ring {
    /// (position, member). ties sort by address so config order never picks an owner.
    points: Vec<(u64, u32)>,
    /// member -> list index. weight-0 backends are not members.
    members: Vec<usize>,
}

/// distinct list indices clockwise from a key, owner first.
pub struct Walk<'a> {
    ring: &'a Ring,
    next: usize,
    seen: [u64; SEEN_WORDS],
    found: usize,
}

impl Ring {
    /// points are named from the address, not the list index, so reordering the
    /// list moves no keys.
    ///
    /// # Panics
    ///
    /// if the weight sum exceeds `MAX_WEIGHT_SUM`. config validation rejects that.
    pub fn build(backends: impl IntoIterator<Item = (SocketAddr, u32)>) -> Self {
        let mut points = Vec::new();
        let mut members = Vec::new();
        let mut member_addrs = Vec::new();
        let mut weight_sum = 0u64;
        let mut prefix = String::new();

        for (idx, (addr, weight)) in backends.into_iter().enumerate() {
            if weight == 0 {
                continue;
            }
            weight_sum += u64::from(weight);
            assert!(
                weight_sum <= MAX_WEIGHT_SUM,
                "hash ring weight sum {weight_sum} exceeds {MAX_WEIGHT_SUM}",
            );
            let member = members.len() as u32;
            members.push(idx);
            member_addrs.push(addr);
            // each point hashes "<addr>-<i>". FNV streams, so the prefix state is
            // computed once and only the digits are fed per point: formatting
            // every name was a fifth of the build time at the weight cap.
            prefix.clear();
            write!(prefix, "{addr}-").expect("writing to a String cannot fail");
            let prefix_state = fnv1a(FNV_OFFSET, prefix.as_bytes());
            let mut digits = [0u8; 10];
            for i in 0..weight * POINTS_PER_WEIGHT {
                let pos = fmix64(fnv1a(prefix_state, decimal(i, &mut digits)));
                points.push((pos, member));
            }
        }

        // address tiebreak only on equal positions: comparing addresses in the
        // main sort doubled the build time at the weight cap
        points.sort_unstable_by_key(|&(pos, _)| pos);
        for run in points.chunk_by_mut(|a, b| a.0 == b.0) {
            if run.len() > 1 {
                run.sort_unstable_by_key(|&(_, member)| member_addrs[member as usize]);
            }
        }
        Self { points, members }
    }

    pub fn owner(&self, key_hash: u64) -> Option<usize> {
        self.walk(key_hash).next()
    }

    pub fn walk(&self, key_hash: u64) -> Walk<'_> {
        Walk {
            ring: self,
            next: self.points.partition_point(|&(pos, _)| pos < key_hash),
            seen: [0; SEEN_WORDS],
            found: 0,
        }
    }
}

impl Iterator for Walk<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let points = &self.ring.points;
        while self.found < self.ring.members.len() {
            let (_, member) = points[self.next % points.len()];
            self.next += 1;
            let (word, bit) = (member as usize / 64, 1u64 << (member % 64));
            if self.seen[word] & bit == 0 {
                self.seen[word] |= bit;
                self.found += 1;
                return Some(self.ring.members[member as usize]);
            }
        }
        None
    }
}

/// FNV-1a, then murmur3's fmix64. must stay stable across instances and releases,
/// which rules out `DefaultHasher`. without the finalizer, near-identical point
/// names clump on the ring.
pub fn hash64(bytes: &[u8]) -> u64 {
    fmix64(fnv1a(FNV_OFFSET, bytes))
}

fn fnv1a(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// ascii decimal of `n`, written into the tail of `buf`.
fn decimal(mut n: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut start = buf.len();
    loop {
        start -= 1;
        buf[start] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &buf[start..];
        }
    }
}

fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: u64 = 100_000;

    fn addrs(n: u8) -> Vec<SocketAddr> {
        (1..=n)
            .map(|i| SocketAddr::from(([10, 0, 0, i], 8080)))
            .collect()
    }

    fn weighted(addrs: &[SocketAddr], weight: u32) -> Vec<(SocketAddr, u32)> {
        addrs.iter().map(|&a| (a, weight)).collect()
    }

    fn key(i: u64) -> u64 {
        hash64(&i.to_le_bytes())
    }

    fn owners(list: &[(SocketAddr, u32)]) -> Vec<SocketAddr> {
        let ring = Ring::build(list.iter().copied());
        (0..KEYS)
            .map(|i| list[ring.owner(key(i)).expect("ring has members")].0)
            .collect()
    }

    fn share(owners: &[SocketAddr], addr: SocketAddr) -> f64 {
        owners.iter().filter(|&&o| o == addr).count() as f64 / owners.len() as f64
    }

    /// a change here remaps every deployed key. the fmix64 inputs are the
    /// published FNV-1a 64 vectors for "" and "a".
    #[test]
    fn hash64_golden_values() {
        assert_eq!(fmix64(0xcbf2_9ce4_8422_2325), hash64(b""));
        assert_eq!(fmix64(0xaf63_dc4c_8601_ec8c), hash64(b"a"));

        assert_eq!(hash64(b""), 0xefd0_1f60_ba99_2926);
        assert_eq!(hash64(b"a"), 0x82a2_a958_a9be_ce5b);
        assert_eq!(hash64(b"10.0.0.1:8080-0"), 0x0c47_a627_e1f4_cf2d);
    }

    /// point positions are part of the wire contract, like the golden values.
    #[test]
    fn ring_points_are_named_hashes() {
        let addr = SocketAddr::from(([10, 0, 0, 1], 8080));
        let ring = Ring::build([(addr, 2)]);
        let mut expected: Vec<u64> = (0..2 * POINTS_PER_WEIGHT)
            .map(|i| hash64(format!("{addr}-{i}").as_bytes()))
            .collect();
        expected.sort_unstable();
        let built: Vec<u64> = ring.points.iter().map(|&(pos, _)| pos).collect();
        assert_eq!(built, expected);
    }

    #[test]
    fn decimal_matches_display_at_digit_boundaries() {
        let mut buf = [0u8; 10];
        for n in [0, 1, 9, 10, 99, 100, 159_999, u32::MAX] {
            assert_eq!(decimal(n, &mut buf), n.to_string().as_bytes());
        }
    }

    /// share deviates ~1/sqrt(160) = 8%, so ±25% is past 3 sigma.
    #[test]
    fn ring_balance_equal_weights() {
        let a = addrs(4);
        let owners = owners(&weighted(&a, 1));
        for &addr in &a {
            let s = share(&owners, addr);
            assert!((0.1875..=0.3125).contains(&s), "{addr} share {s}");
        }
    }

    #[test]
    fn ring_add_remaps_only_to_new_backend() {
        let a = addrs(5);
        let before = owners(&weighted(&a[..4], 1));
        let after = owners(&weighted(&a, 1));

        let mut moved = 0;
        for (b, n) in before.iter().zip(&after) {
            if b != n {
                assert_eq!(*n, a[4], "a moved key must go to the new backend");
                moved += 1;
            }
        }
        let frac = moved as f64 / KEYS as f64;
        assert!(
            (0.15..=0.25).contains(&frac),
            "moved {frac}, expected ~0.20"
        );
    }

    #[test]
    fn ring_remove_remaps_only_removed_keys() {
        let a = addrs(5);
        let removed = a[2];
        let before = owners(&weighted(&a, 1));
        let rest: Vec<_> = a.iter().copied().filter(|&x| x != removed).collect();
        let after = owners(&weighted(&rest, 1));

        for (b, n) in before.iter().zip(&after) {
            assert_eq!(
                b != n,
                *b == removed,
                "only the removed backend's keys move"
            );
        }
    }

    #[test]
    fn ring_reorder_moves_nothing() {
        let a = addrs(5);
        let mut reversed = a.clone();
        reversed.reverse();
        assert_eq!(owners(&weighted(&a, 1)), owners(&weighted(&reversed, 1)));
    }

    #[test]
    fn ring_weight_increase_only_gains() {
        let a = addrs(4);
        let before = owners(&weighted(&a, 1));
        let mut list = weighted(&a, 1);
        list[0].1 = 2;
        let after = owners(&list);

        let mut moved = 0;
        for (b, n) in before.iter().zip(&after) {
            if b != n {
                assert_eq!(*n, a[0], "a heavier backend only gains keys");
                moved += 1;
            }
        }
        assert!(moved > 0);
    }

    #[test]
    fn ring_weight_proportional() {
        let a = addrs(2);
        let owners = owners(&[(a[0], 1), (a[1], 3)]);
        let s = share(&owners, a[1]);
        assert!((0.65..=0.85).contains(&s), "weight 3 of 4 got {s}");
    }

    #[test]
    fn ring_zero_weight_is_never_selected() {
        let a = addrs(2);
        let ring = Ring::build([(a[0], 0), (a[1], 1)]);
        for i in 0..1000 {
            assert_eq!(ring.walk(key(i)).collect::<Vec<_>>(), vec![1]);
        }
    }

    #[test]
    fn ring_without_members_has_no_owner() {
        assert_eq!(Ring::build([]).owner(key(0)), None);
        let a = addrs(2);
        assert_eq!(Ring::build(weighted(&a, 0)).owner(key(0)), None);
    }

    /// failover and retries rely on this.
    #[test]
    fn ring_walk_order_equals_successive_removal() {
        let a = addrs(5);
        let list = [(a[0], 1), (a[1], 3), (a[2], 1), (a[3], 2), (a[4], 1)];
        let ring = Ring::build(list);
        // keyed by removed set, a rebuild per key is too slow in debug
        let mut rings = std::collections::HashMap::new();

        for i in 0..10_000 {
            let walk: Vec<SocketAddr> = ring.walk(key(i)).map(|idx| list[idx].0).collect();
            assert_eq!(walk.len(), 5, "every member exactly once");
            for k in 1..walk.len() {
                let mut removed = walk[..k].to_vec();
                removed.sort();
                let (rest, reduced) = rings.entry(removed).or_insert_with_key(|removed| {
                    let rest: Vec<_> = list
                        .iter()
                        .copied()
                        .filter(|(addr, _)| !removed.contains(addr))
                        .collect();
                    let reduced = Ring::build(rest.iter().copied());
                    (rest, reduced)
                });
                let owner = reduced.owner(key(i)).unwrap();
                assert_eq!(rest[owner].0, walk[k], "key {i}, candidate {k}");
            }
        }
    }

    #[test]
    fn ring_weight_sum_at_cap_builds() {
        let a = addrs(2);
        let ring = Ring::build([(a[0], 999), (a[1], 1)]);
        assert_eq!(ring.walk(key(0)).count(), 2);
    }

    #[test]
    #[should_panic(expected = "exceeds 1000")]
    fn ring_weight_sum_over_cap_panics() {
        let a = addrs(2);
        Ring::build([(a[0], 1000), (a[1], 1)]);
    }
}
