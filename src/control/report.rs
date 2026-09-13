//! Runtime state as plain data, built once and either serialized to JSON or
//! rendered as HTML. The panel takes these types rather than a `Snapshot`, so a
//! field added here and forgotten in the panel is a missing column, never two
//! routes disagreeing about a value.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

use serde::Serialize;

use crate::config::BalancerStrategy;
use crate::runtime::Snapshot;

pub struct ServerInfo {
    pub version: &'static str,
    pub uptime_secs: u64,
    pub config_version: u64,
    pub pools: usize,
    pub state: &'static str,
}

impl ServerInfo {
    /// hand-built rather than derived: the shape shipped before serde reached this
    /// module and there is nothing to gain from changing it.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"version\":\"{}\",\"uptime_secs\":{},\"config_version\":{},\"pools\":{},\"state\":\"{}\"}}\n",
            self.version, self.uptime_secs, self.config_version, self.pools, self.state,
        )
    }
}

pub fn server_info(snapshot: &Snapshot, started: Instant, draining: bool) -> ServerInfo {
    ServerInfo {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: started.elapsed().as_secs(),
        config_version: snapshot.version,
        pools: snapshot.pools.len(),
        state: if draining { "draining" } else { "serving" },
    }
}

#[derive(Serialize)]
pub struct PoolsReport<'a> {
    pub config_version: u64,
    pub pools: Vec<PoolReport<'a>>,
}

#[derive(Serialize)]
pub struct PoolReport<'a> {
    pub name: &'a str,
    pub strategy: BalancerStrategy,
    pub failure_threshold: u32,
    pub recovery_timeout_secs: u64,
    pub backends: Vec<BackendReport>,
}

#[derive(Serialize)]
pub struct BackendReport {
    pub address: SocketAddr,
    pub circuit: &'static str,
    pub weight: u32,
    pub active: u64,
    pub consecutive_failures: u32,
    pub keepalive_idle: usize,
    pub total_conns: u64,
}

/// reads `circuit_state`, never `is_available`: the latter CASes an expired Open
/// circuit into HalfOpen, and reading a status page must not spend the one recovery
/// probe a real request is waiting for.
///
/// pools are sorted by name because `Snapshot.pools` is a `HashMap` and unsorted
/// output shuffles between calls. backends keep config order, which is what
/// round-robin rotates through.
pub fn pools_report(snapshot: &Snapshot) -> PoolsReport<'_> {
    let mut pools: Vec<_> = snapshot
        .pools
        .iter()
        .map(|(name, (pool, balancer))| PoolReport {
            name,
            strategy: balancer.strategy(),
            failure_threshold: pool.failure_threshold(),
            recovery_timeout_secs: pool.recovery_timeout().as_secs(),
            backends: pool
                .snapshot()
                .iter()
                .map(|b| BackendReport {
                    address: b.address(),
                    circuit: b.circuit_state().as_str(),
                    weight: b.weight(),
                    active: b.active_count(),
                    consecutive_failures: b.consecutive_failures(),
                    keepalive_idle: b.keepalive.queue_len(),
                    total_conns: b.total_count.0.load(Ordering::Relaxed),
                })
                .collect(),
        })
        .collect();
    pools.sort_by_key(|p| p.name);

    PoolsReport {
        config_version: snapshot.version,
        pools,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use crate::config::Config;
    use crate::health::{BackendPool, CircuitState};
    use crate::runtime::build_snapshot;

    use super::*;

    const CONFIG: &str = "\
[[listeners]]
address = \"127.0.0.1:19997\"
mode = \"l4\"
pool = \"zeta\"

[[pools]]
name = \"zeta\"
backends = [{ address = \"127.0.0.1:3001\" }]

[[pools]]
name = \"alpha\"
strategy = \"least_conn\"
backends = [{ address = \"127.0.0.1:3002\", weight = 5 }, { address = \"127.0.0.1:3003\" }]

[health]
failure_threshold = 2
recovery_timeout_secs = 30
";

    fn snapshot() -> crate::runtime::Snapshot {
        build_snapshot(Arc::new(Config::from_toml(CONFIG, "<test>").unwrap()))
    }

    fn empty_config() -> Arc<Config> {
        Arc::new(Config::from_toml(CONFIG, "<test>").unwrap())
    }

    #[test]
    fn pools_are_sorted_and_backends_keep_config_order() {
        let snap = snapshot();
        let report = pools_report(&snap);

        // HashMap iteration order is arbitrary, so an unsorted report shuffles
        // between calls and the panel's rows jump on every refresh
        let names: Vec<_> = report.pools.iter().map(|p| p.name).collect();
        assert_eq!(names, ["alpha", "zeta"]);

        let alpha = &report.pools[0];
        let addrs: Vec<_> = alpha.backends.iter().map(|b| b.address.port()).collect();
        assert_eq!(
            addrs,
            [3002, 3003],
            "backend order is round-robin's rotation"
        );
    }

    #[test]
    fn report_carries_per_pool_runtime_state() {
        let snap = snapshot();
        let report = pools_report(&snap);
        let alpha = &report.pools[0];

        assert_eq!(alpha.strategy, BalancerStrategy::LeastConn);
        assert_eq!(alpha.failure_threshold, 2);
        assert_eq!(alpha.recovery_timeout_secs, 30);
        assert_eq!(alpha.backends[0].weight, 5);
        assert_eq!(alpha.backends[1].weight, 1);
        assert_eq!(report.pools[1].strategy, BalancerStrategy::RoundRobin);

        for backend in &alpha.backends {
            assert_eq!(backend.circuit, "closed");
            assert_eq!(backend.active, 0);
            assert_eq!(backend.consecutive_failures, 0);
        }
    }

    #[test]
    fn reading_the_report_never_spends_the_recovery_probe() {
        // zero recovery timeout, built past config validation which rejects it: the
        // circuit is Open and instantly eligible, so a stray is_available() call
        // inside the report would CAS it to HalfOpen and the assert below would fail.
        // with a non-zero timeout the test would pass whether or not the bug existed.
        let pool = Arc::new(BackendPool::new(
            "probe".into(),
            vec!["127.0.0.1:3001".parse().unwrap()],
            1,
            Duration::ZERO,
            Default::default(),
        ));
        let balancer = Arc::new(crate::balancer::RoundRobin::new(Arc::clone(&pool)));
        let mut pools = std::collections::HashMap::new();
        pools.insert("probe".to_owned(), (Arc::clone(&pool), balancer));
        let snap = crate::runtime::Snapshot {
            pools,
            zones: Default::default(),
            version: 0,
            config: empty_config(),
        };

        let backend = pool.get(0);
        pool.record_failure(backend.address());
        assert_eq!(backend.circuit_state(), CircuitState::Open);

        for _ in 0..5 {
            let report = pools_report(&snap);
            assert_eq!(report.pools[0].backends[0].circuit, "open");
        }
        assert_eq!(
            backend.circuit_state(),
            CircuitState::Open,
            "the report consumed the recovery probe"
        );

        // a real request still wins that CAS, which is the slot being protected
        assert!(backend.is_available(Duration::ZERO));
        assert_eq!(backend.circuit_state(), CircuitState::HalfOpen);
    }

    #[test]
    fn serializes_with_the_documented_field_names() {
        let snap = snapshot();
        let json = serde_json::to_string(&pools_report(&snap)).unwrap();
        for field in [
            "config_version",
            "\"name\":\"alpha\"",
            "\"strategy\":\"least_conn\"",
            "failure_threshold",
            "recovery_timeout_secs",
            "\"address\":\"127.0.0.1:3002\"",
            "\"circuit\":\"closed\"",
            "keepalive_idle",
            "total_conns",
        ] {
            assert!(json.contains(field), "{field} missing from {json}");
        }
        // Arc<Vec<..>> and CacheLinePadded must not leak into the wire shape
        assert!(!json.contains("CacheLinePadded"), "{json}");
    }

    #[test]
    fn empty_snapshot_serializes_as_an_empty_list() {
        let snap = crate::runtime::Snapshot {
            pools: Default::default(),
            zones: Default::default(),
            version: 4,
            config: empty_config(),
        };
        let json = serde_json::to_string(&pools_report(&snap)).unwrap();
        assert_eq!(json, "{\"config_version\":4,\"pools\":[]}");
    }
}
