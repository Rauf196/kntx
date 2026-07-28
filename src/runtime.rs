use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::access_log::AccessLogSink;
use crate::balancer::RoundRobin;
use crate::config::{
    self, Config, ForwardingStrategy, ListenerConfig, RateLimitConfig, ResolvedHealth, ZoneConfig,
};
use crate::health::{BackendPool, HealthChecker};
use crate::listener::{self, ListenerRuntime, RuntimeCell, ServeConfig};
use crate::pool::buffer::BufferPool;
use crate::proxy::l4::Resources;
use crate::proxy::l7::ErrorPages;
use crate::proxy::l7::keepalive::KeepaliveSweeper;
use crate::proxy::l7::router::{Router, RouterBuildError, build_router};
use crate::rate_limit::{
    KeyedLimiter, Limiter, MonotonicClock, Period, Rate, ZoneHandle, ZoneLimiter,
};
use crate::tls::TlsError;

/// health probes get a fixed connect timeout; per-pool tuning has no demand yet (D7).
const HEALTH_PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// a bound listener the reload manager can reconfigure or retire.
pub struct ListenerHandle {
    pub runtime: RuntimeCell,
    /// makes `serve` stop accepting, close the listen socket and drain. process
    /// shutdown fans out through these too, so `serve` needs only the one signal.
    pub drain: watch::Sender<()>,
}

/// every bound listener, keyed by listen address. reload mutates membership, so
/// it is behind a lock - never read on the connection path, which holds the
/// `RuntimeCell` it was spawned with.
pub type ListenerRegistry = Arc<Mutex<HashMap<SocketAddr, ListenerHandle>>>;

/// background tasks owned per pool. a pool a reload drops has these aborted:
/// they are timer loops with no in-flight state to drain, unlike a listener.
pub type PoolTasks = Arc<Mutex<HashMap<String, Vec<JoinHandle<()>>>>>;

/// a bound-but-not-yet-running listener handed to the supervision loop, which is
/// the sole owner of listener task lifecycle. carries the address so a panic can
/// still be attributed to a port.
pub type ListenerSpawn = (SocketAddr, Pin<Box<dyn Future<Output = ()> + Send>>);

#[derive(Debug, Error)]
pub enum ReloadError {
    #[error("invalid configuration")]
    Config(#[from] config::ConfigError),
    #[error("listener {address}: routing table rejected")]
    Router {
        address: SocketAddr,
        #[source]
        source: RouterBuildError,
    },
    #[error("listener {address}: TLS certificates rejected")]
    Tls {
        address: SocketAddr,
        #[source]
        source: TlsError,
    },
    #[error("listener {address}: references unknown rate limit zone '{zone}'")]
    UnknownZone { address: SocketAddr, zone: String },
    #[error("failed to bind new listener")]
    Bind(#[from] listener::ListenerError),
}

/// serve ingredients fixed for the process lifetime. shared by startup and reload
/// so a listener bound by a reload is wired exactly like one bound at boot.
pub struct SharedServe {
    pub strategy: ForwardingStrategy,
    pub resources: Resources,
    pub error_pages: Arc<ErrorPages>,
    pub access_log: Arc<AccessLogSink>,
    pub buffer_pool: Arc<BufferPool>,
}

/// everything the SIGHUP handler needs to reconcile the running process.
pub struct ReloadContext {
    pub state: Arc<ArcSwap<Snapshot>>,
    pub listeners: ListenerRegistry,
    pub pool_tasks: PoolTasks,
    pub shared: Arc<SharedServe>,
    pub spawn_tx: mpsc::UnboundedSender<ListenerSpawn>,
    /// handed to background tasks a reload starts, so they stop with the process.
    pub shutdown: watch::Receiver<()>,
}

/// the effective running configuration: the reconcilable, swappable runtime
/// state derived from a `Config`. built fresh by `build_snapshot`; on reload the
/// manager diffs the current snapshot against a freshly built desired one and
/// applies the difference at commit time.
///
/// listeners are not here yet - they carry bound sockets and running tasks and
/// are reconciled by the listener manager, added in a later step.
pub struct Snapshot {
    pub pools: HashMap<String, (Arc<BackendPool>, Arc<RoundRobin>)>,
    pub zones: HashMap<String, ZoneSlot>,
    /// monotonic reload counter; startup is 0, each committed reload increments it.
    pub version: u64,
}

/// a live rate-limit zone plus the config it was built from. the config is the
/// reconcile key: an unchanged zone keeps its limiter (and its accumulated GCRA
/// state), so a reload that touches an unrelated zone can't hand a flooding client
/// a fresh burst by resetting counters.
pub struct ZoneSlot {
    pub config: ZoneConfig,
    pub limiter: Arc<ZoneLimiter>,
}

/// build a fresh `Snapshot` from a validated config. pure: no sockets bound, no
/// tasks spawned, no metrics emitted, no shared state mutated. reload builds a
/// desired snapshot with this, then reconciles the running state toward it - so
/// keeping this side-effect-free is what lets a failed reload abort cleanly.
///
/// the config MUST be validated first (`Config::from_file`/`from_toml`): zone rate
/// is unwrapped as NonZero on that guarantee.
pub fn build_snapshot(config: &Config) -> Snapshot {
    let mut pools = HashMap::with_capacity(config.pools.len());
    for pool_cfg in &config.pools {
        pools.insert(pool_cfg.name.clone(), build_pool(pool_cfg, &config.health));
    }

    let mut zones = HashMap::with_capacity(config.rate_limit.zones.len());
    for (name, zone) in &config.rate_limit.zones {
        zones.insert(name.clone(), build_zone_slot(name, zone));
    }

    Snapshot {
        pools,
        zones,
        version: 0,
    }
}

fn build_zone_slot(name: &str, zone: &ZoneConfig) -> ZoneSlot {
    ZoneSlot {
        config: zone.clone(),
        limiter: Arc::new(build_zone(name, zone)),
    }
}

/// reconcile the running zones toward `new`. a zone whose config is byte-identical
/// keeps its limiter (live GCRA state intact); a changed one is rebuilt, resetting
/// its budget; a removed one is dropped. pure - no commit, safe to abort after.
fn reconcile_zones(
    current: &HashMap<String, ZoneSlot>,
    new: &RateLimitConfig,
) -> HashMap<String, ZoneSlot> {
    let mut zones = HashMap::with_capacity(new.zones.len());
    for (name, cfg) in &new.zones {
        match current.get(name) {
            Some(slot) if slot.config == *cfg => {
                zones.insert(
                    name.clone(),
                    ZoneSlot {
                        config: slot.config.clone(),
                        limiter: Arc::clone(&slot.limiter),
                    },
                );
            }
            _ => {
                zones.insert(name.clone(), build_zone_slot(name, cfg));
            }
        }
    }
    zones
}

/// resolve a listener's optional rate-limit zone reference into a shared handle.
/// fallible: a listener may name a zone a reload removed. config validation
/// guarantees this at boot, so startup passes the built snapshot and unwraps.
pub fn build_zone_handle(
    cfg: &ListenerConfig,
    zones: &HashMap<String, ZoneSlot>,
) -> Result<Option<ZoneHandle>, ReloadError> {
    let Some(ref name) = cfg.rate_limit else {
        return Ok(None);
    };
    let slot = zones.get(name).ok_or_else(|| ReloadError::UnknownZone {
        address: cfg.address,
        zone: name.clone(),
    })?;
    Ok(Some(ZoneHandle {
        name: name.as_str().into(),
        limiter: Arc::clone(&slot.limiter),
    }))
}

fn build_pool(
    pool_cfg: &config::PoolConfig,
    defaults: &config::HealthConfig,
) -> (Arc<BackendPool>, Arc<RoundRobin>) {
    let health = pool_cfg.effective_health(defaults);
    let addrs: Vec<_> = pool_cfg.backends.iter().map(|b| b.address).collect();
    let pool = Arc::new(BackendPool::new(
        pool_cfg.name.as_str().into(),
        addrs,
        health.failure_threshold,
        Duration::from_secs(health.recovery_timeout_secs),
        pool_cfg.keepalive.clone(),
    ));
    pool.set_weights(&weights_of(pool_cfg));
    let balancer = Arc::new(RoundRobin::with_strategy(
        Arc::clone(&pool),
        pool_cfg.strategy,
    ));
    (pool, balancer)
}

fn weights_of(pool_cfg: &config::PoolConfig) -> Vec<(std::net::SocketAddr, u32)> {
    pool_cfg
        .backends
        .iter()
        .map(|b| (b.address, b.weight))
        .collect()
}

/// assemble a listener's `ServeConfig` - the process-lifetime half of its serve
/// state, built once and never swapped. the router, TLS acceptor and rate-limit
/// zone are the reloadable half and live on `ListenerRuntime`, not here.
pub fn build_serve_config(shared: &SharedServe, cfg: &ListenerConfig) -> ServeConfig {
    ServeConfig {
        strategy: shared.strategy,
        resources: shared.resources.clone(),
        max_connections: cfg.max_connections,
        idle_timeout: cfg.idle_timeout_secs.map(Duration::from_secs),
        drain_timeout: Duration::from_secs(cfg.drain_timeout_secs),
        connect_timeout: Duration::from_secs(cfg.connect_timeout_secs),
        max_connect_attempts: cfg.max_connect_attempts,
        tls_handshake_timeout: cfg
            .tls
            .as_ref()
            .map(|t| Duration::from_secs(t.handshake_timeout_secs))
            .unwrap_or(Duration::from_secs(5)),
        listener_label: cfg.address.to_string().into(),
        error_pages: Arc::clone(&shared.error_pages),
        access_log: Arc::clone(&shared.access_log),
        buffer_pool: Arc::clone(&shared.buffer_pool),
    }
}

/// start the background tasks a pool needs: an active health checker when the
/// pool has a probe interval, and a keepalive sweeper when backend keepalive is
/// on. shared by startup and reload.
pub fn spawn_pool_tasks(
    pool: &Arc<BackendPool>,
    health: &ResolvedHealth,
    shutdown: &watch::Receiver<()>,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();
    if let Some(interval_secs) = health.check_interval_secs {
        let checker = HealthChecker::new(
            Arc::clone(pool),
            Duration::from_secs(interval_secs),
            HEALTH_PROBE_CONNECT_TIMEOUT,
        );
        handles.push(checker.spawn(shutdown.clone()));
        tracing::info!(pool = %pool.name(), interval_secs, "health checker started");
    }
    if let Some(sweeper) = KeepaliveSweeper::new(Arc::clone(pool)) {
        handles.push(sweeper.spawn(shutdown.clone()));
        tracing::info!(pool = %pool.name(), "keepalive sweeper started");
    }
    handles
}

/// tell every listener to stop accepting and drain. process shutdown reaches
/// listeners this way so `serve` has a single drain signal to select on.
pub fn drain_all(listeners: &ListenerRegistry) {
    for handle in listeners.lock().expect("registry lock").values() {
        let _ = handle.drain.send(());
    }
}

/// re-read + validate the config file, then apply the reload. emits reload metrics
/// and logs the outcome. a parse/validation failure aborts with the current config
/// fully intact - nothing is mutated before validation passes.
pub async fn reload_from_file(ctx: &ReloadContext, path: &str) {
    tracing::info!(config = %path, "SIGHUP received, reloading config");
    let result = match Config::from_file(path) {
        Ok(new) => apply_reload(ctx, &new).await,
        Err(e) => Err(ReloadError::from(e)),
    };
    match result {
        Ok(version) => {
            metrics::counter!("kntx_config_reload_total", "result" => "success").increment(1);
            metrics::gauge!("kntx_config_last_reload_success").set(1.0);
            metrics::gauge!("kntx_config_last_reload_timestamp_seconds").set(now_unix_secs());
            metrics::gauge!("kntx_config_version").set(version as f64);
            tracing::info!(version, "config reloaded");
        }
        Err(e) => {
            metrics::counter!("kntx_config_reload_total", "result" => "failure").increment(1);
            metrics::gauge!("kntx_config_last_reload_success").set(0.0);
            metrics::gauge!("kntx_config_last_reload_timestamp_seconds").set(now_unix_secs());
            tracing::error!(error = %e, "config reload rejected, keeping current config");
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                tracing::error!(cause = %s);
                src = s.source();
            }
        }
    }
}

/// a listener's desired state, assembled in the build phase and applied at commit.
struct Prepared {
    address: SocketAddr,
    runtime: ListenerRuntime,
    /// set only for a listener this reload introduces: its bound socket and the
    /// config its serve task starts with.
    fresh: Option<(tokio::net::TcpListener, ServeConfig)>,
}

/// reconcile the running process toward `new` and commit a version-bumped snapshot.
/// pools are stable Arcs reconciled in place, so running connections pick up the
/// new backend set on their next selection; routes and TLS certs are pushed into
/// each listener's runtime cell and take effect for connections accepted after
/// the swap. `new` MUST be validated. returns the committed version.
///
/// everything that can fail - router build, cert load, bind - runs before anything
/// mutates, so a rejected reload leaves the running config fully intact.
pub async fn apply_reload(ctx: &ReloadContext, new: &Config) -> Result<u64, ReloadError> {
    let current = ctx.state.load();

    // pools in both configs keep their Arc, so circuit state, warm keepalive conns
    // and counters survive. new ones are built cold here and started at commit.
    let mut pools = HashMap::with_capacity(new.pools.len());
    let mut added_pools = Vec::new();
    for pool_cfg in &new.pools {
        match current.pools.get(&pool_cfg.name) {
            Some(existing) => {
                pools.insert(pool_cfg.name.clone(), existing.clone());
            }
            None => {
                let entry = build_pool(pool_cfg, &new.health);
                added_pools.push((pool_cfg, Arc::clone(&entry.0)));
                pools.insert(pool_cfg.name.clone(), entry);
            }
        }
    }

    // zones reconcile by name+params: an unchanged zone keeps its live limiter,
    // a changed one is rebuilt (budget reset). routers and listener runtimes below
    // resolve against this desired set, so a route or listener may reference a zone
    // this reload adds, and a retuned limit reaches both paths at commit.
    let zones = reconcile_zones(&current.zones, &new.rate_limit);

    let bound: Vec<SocketAddr> = ctx
        .listeners
        .lock()
        .expect("registry lock")
        .keys()
        .copied()
        .collect();

    let mut prepared = Vec::with_capacity(new.listeners.len());
    for cfg in &new.listeners {
        // routers resolve against the desired pool set, so a route may point at a
        // pool this same reload introduces. they hold the stable pool Arcs;
        // membership is swapped underneath at commit.
        let router: Arc<dyn Router> = Arc::new(build_router(cfg, &pools, &zones).map_err(
            |source| ReloadError::Router {
                address: cfg.address,
                source,
            },
        )?);
        // acceptors are rebuilt unconditionally: a rotation writes new bytes to the
        // same paths, so comparing config text would miss the case this exists for.
        let tls_acceptor = match cfg.tls {
            Some(ref tls_cfg) => {
                Some(
                    crate::tls::build_acceptor(tls_cfg).map_err(|source| ReloadError::Tls {
                        address: cfg.address,
                        source,
                    })?,
                )
            }
            None => None,
        };
        let rate_limit = build_zone_handle(cfg, &zones)?;
        // bind last of the fallible steps: a listening socket is the only build-phase
        // product visible outside the process, so keep the window before abort short.
        let fresh = if bound.contains(&cfg.address) {
            None
        } else {
            Some((
                listener::bind(cfg.address).await?,
                build_serve_config(&ctx.shared, cfg),
            ))
        };
        prepared.push(Prepared {
            address: cfg.address,
            runtime: ListenerRuntime {
                router,
                listener_cfg: Arc::new(cfg.clone()),
                tls_acceptor,
                rate_limit,
            },
            fresh,
        });
    }

    // commit. every step below is infallible; pools go first so a router published
    // in this reload never points at a pool whose membership or tasks lag behind it.
    for pool_cfg in &new.pools {
        let (pool, balancer) = &pools[&pool_cfg.name];
        let health = pool_cfg.effective_health(&new.health);
        let addrs: Vec<_> = pool_cfg.backends.iter().map(|b| b.address).collect();
        let diff = pool.reconcile(
            &addrs,
            health.failure_threshold,
            Duration::from_secs(health.recovery_timeout_secs),
        );
        // after reconcile, so weights land on the surviving states and on any
        // backend this reload just added. weight 0 drains a backend without
        // removing it, which is the whole reason weights are live.
        pool.set_weights(&weights_of(pool_cfg));
        if !diff.added.is_empty() || !diff.removed.is_empty() {
            tracing::info!(
                pool = %pool_cfg.name,
                added = ?diff.added,
                removed = ?diff.removed,
                "pool membership reconciled",
            );
        }
        // a surviving pool keeps its balancer Arc, so the strategy it was built
        // with is the strategy it keeps. same treatment as the other
        // restart-only knobs: say so rather than half-applying.
        if balancer.strategy() != pool_cfg.strategy {
            tracing::warn!(
                pool = %pool_cfg.name,
                running = ?balancer.strategy(),
                configured = ?pool_cfg.strategy,
                "pool strategy is restart-only, keeping the running strategy",
            );
        }
    }

    {
        let mut tasks = ctx.pool_tasks.lock().expect("pool task lock");
        for (pool_cfg, pool) in &added_pools {
            if new.metrics.is_some() {
                pool.emit_initial_metrics();
            }
            let health = pool_cfg.effective_health(&new.health);
            tracing::info!(pool = %pool_cfg.name, backends = pool.len(), "pool added");
            tasks.insert(
                pool_cfg.name.clone(),
                spawn_pool_tasks(pool, &health, &ctx.shutdown),
            );
        }
        // a dropped pool stops being probed and swept. its Arc lives on until the
        // last connection pinned to a route that named it releases it.
        tasks.retain(|name, handles| {
            if pools.contains_key(name) {
                return true;
            }
            for handle in handles.iter() {
                handle.abort();
            }
            tracing::info!(pool = %name, "pool removed, background tasks stopped");
            false
        });
    }

    let mut registry = ctx.listeners.lock().expect("registry lock");
    for entry in prepared {
        let address = entry.address;
        let Some((socket, serve_config)) = entry.fresh else {
            registry[&address].runtime.store(Arc::new(entry.runtime));
            continue;
        };
        let (drain_tx, drain_rx) = watch::channel(());
        let cell: RuntimeCell = Arc::new(ArcSwap::from_pointee(entry.runtime));
        let task = Box::pin(listener::serve(
            socket,
            Arc::clone(&cell),
            serve_config,
            drain_rx,
        ));
        if ctx.spawn_tx.send((address, task)).is_err() {
            // supervision loop is gone, so the process is on its way out
            tracing::warn!(%address, "listener not started, process is shutting down");
            continue;
        }
        registry.insert(
            address,
            ListenerHandle {
                runtime: cell,
                drain: drain_tx,
            },
        );
        tracing::info!(%address, "listener added");
    }
    registry.retain(|address, handle| {
        if new.listeners.iter().any(|l| l.address == *address) {
            return true;
        }
        let _ = handle.drain.send(());
        tracing::info!(%address, "listener removed, draining in-flight connections");
        false
    });
    drop(registry);

    let version = current.version + 1;
    ctx.state.store(Arc::new(Snapshot {
        pools,
        zones,
        version,
    }));
    Ok(version)
}

fn now_unix_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// construct one zone limiter from its config. keyed zones round max_keys up to a
/// power-of-two set count and log when the effective capacity differs.
fn build_zone(name: &str, zone: &config::ZoneConfig) -> ZoneLimiter {
    let rate = Rate {
        count: NonZeroU32::new(zone.rate).expect("validation rejects rate = 0"),
        period: match zone.per {
            config::RatePeriod::Second => Period::Second,
            config::RatePeriod::Minute => Period::Minute,
        },
    };
    match zone.key {
        config::ZoneKey::Global => {
            ZoneLimiter::Global(Limiter::new(rate, zone.burst, MonotonicClock::new()))
        }
        config::ZoneKey::ClientIp => {
            let requested = zone.max_keys.unwrap_or(config::DEFAULT_ZONE_MAX_KEYS);
            let keyed = KeyedLimiter::new(rate, zone.burst, requested, MonotonicClock::new());
            if keyed.capacity() != requested as usize {
                tracing::info!(
                    zone = %name,
                    requested,
                    effective = keyed.capacity(),
                    "rate limit zone max_keys rounded up to a power-of-two set count",
                );
            }
            ZoneLimiter::PerIp(keyed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> Config {
        Config::from_toml(toml, "<test>").expect("valid test config")
    }

    /// what main::run wires up at startup, minus the bound sockets: listeners are
    /// registered so a reload treats them as survivors, and the only listener that
    /// actually binds is one a test's reload introduces.
    struct Harness {
        ctx: ReloadContext,
        spawn_rx: mpsc::UnboundedReceiver<ListenerSpawn>,
        /// held so the drain senders in the registry stay live and observable.
        drains: HashMap<SocketAddr, watch::Receiver<()>>,
        _shutdown: watch::Sender<()>,
    }

    fn harness(config: &Config) -> Harness {
        let snapshot = build_snapshot(config);
        let mut registry = HashMap::new();
        let mut drains = HashMap::new();
        for l in &config.listeners {
            let router: Arc<dyn Router> = Arc::new(
                build_router(l, &snapshot.pools, &snapshot.zones)
                    .expect("test config is buildable"),
            );
            let (drain, rx) = watch::channel(());
            drains.insert(l.address, rx);
            registry.insert(
                l.address,
                ListenerHandle {
                    runtime: ListenerRuntime::cell(
                        router,
                        Arc::new(l.clone()),
                        None,
                        build_zone_handle(l, &snapshot.zones).expect("zone refs valid"),
                    ),
                    drain,
                },
            );
        }

        let (shutdown_tx, shutdown) = watch::channel(());
        let (spawn_tx, spawn_rx) = mpsc::unbounded_channel();
        let mut pool_tasks = HashMap::new();
        for pool_cfg in &config.pools {
            let (pool, _) = &snapshot.pools[&pool_cfg.name];
            let health = pool_cfg.effective_health(&config.health);
            pool_tasks.insert(
                pool_cfg.name.clone(),
                spawn_pool_tasks(pool, &health, &shutdown),
            );
        }

        Harness {
            ctx: ReloadContext {
                state: Arc::new(ArcSwap::from_pointee(snapshot)),
                listeners: Arc::new(Mutex::new(registry)),
                pool_tasks: Arc::new(Mutex::new(pool_tasks)),
                shared: Arc::new(test_shared_serve()),
                spawn_tx,
                shutdown,
            },
            spawn_rx,
            drains,
            _shutdown: shutdown_tx,
        }
    }

    fn test_shared_serve() -> SharedServe {
        let buffer_pool = BufferPool::new(4, 4096);
        SharedServe {
            strategy: ForwardingStrategy::Userspace,
            buffer_pool: Arc::new(buffer_pool.clone()),
            resources: Resources {
                buffer_pool,
                #[cfg(target_os = "linux")]
                pipe_pool: crate::pool::pipe::PipePool::new(2).expect("pipe pool"),
                socket_buffer_size: None,
            },
            error_pages: Arc::new(
                ErrorPages::load(&config::ErrorPagesConfig::default()).expect("no error pages"),
            ),
            access_log: Arc::new(AccessLogSink::Off),
        }
    }

    /// a free loopback port, released before the caller binds it. good enough for a
    /// single-process test; nothing else here races for ports.
    fn free_port() -> SocketAddr {
        let sock = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        sock.local_addr().expect("local addr")
    }

    const TWO_POOLS: &str = r#"
[[listeners]]
address = "127.0.0.1:8080"
pool = "web"

[[pools]]
name = "web"
backends = [{ address = "127.0.0.1:3001" }, { address = "127.0.0.1:3002" }]

[[pools]]
name = "api"
backends = [{ address = "127.0.0.1:4001" }]
"#;

    #[test]
    fn builds_pools_with_correct_membership() {
        let snap = build_snapshot(&cfg(TWO_POOLS));
        assert_eq!(snap.version, 0);
        assert_eq!(snap.pools.len(), 2);
        assert_eq!(snap.pools.get("web").unwrap().0.len(), 2);
        assert_eq!(snap.pools.get("api").unwrap().0.len(), 1);
        // the RoundRobin is wired to its own pool
        assert!(snap.pools.get("web").unwrap().1.next_backend().is_some());
    }

    #[test]
    fn builds_zones_and_dispatches_on_key() {
        let toml = format!(
            "{TWO_POOLS}\n\
             [rate_limit.zones.per_ip]\nkey = \"client_ip\"\nrate = 100\nburst = 10\n\n\
             [rate_limit.zones.global_cap]\nkey = \"global\"\nrate = 50\n"
        );
        let snap = build_snapshot(&cfg(&toml));
        assert_eq!(snap.zones.len(), 2);
        assert!(matches!(
            &*snap.zones.get("per_ip").unwrap().limiter,
            ZoneLimiter::PerIp(_)
        ));
        assert!(matches!(
            &*snap.zones.get("global_cap").unwrap().limiter,
            ZoneLimiter::Global(_)
        ));
    }

    #[test]
    fn no_rate_limit_section_yields_no_zones() {
        let snap = build_snapshot(&cfg(TWO_POOLS));
        assert!(snap.zones.is_empty());
    }

    /// one L4 listener + one "web" pool with the given backends; failure_threshold=1
    /// so a single recorded failure opens a circuit deterministically.
    fn one_pool_cfg(addrs: &[&str]) -> Config {
        let backends = addrs
            .iter()
            .map(|a| format!("{{ address = \"{a}\" }}"))
            .collect::<Vec<_>>()
            .join(", ");
        cfg(&format!(
            "[health]\nfailure_threshold = 1\n\n\
             [[listeners]]\naddress = \"127.0.0.1:8080\"\npool = \"web\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{backends}]\n"
        ))
    }

    fn addr(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn reload_reconciles_backend_membership() {
        let start = one_pool_cfg(&["127.0.0.1:3001", "127.0.0.1:3002"]);
        let h = harness(&start);
        let v = apply_reload(&h.ctx, &one_pool_cfg(&["127.0.0.1:3001", "127.0.0.1:3003"]))
            .await
            .expect("reload succeeds");
        assert_eq!(v, 1);
        let snap = h.ctx.state.load();
        let (pool, _) = snap.pools.get("web").unwrap();
        let addrs: Vec<_> = pool.snapshot().iter().map(|b| b.address()).collect();
        assert!(addrs.contains(&addr("127.0.0.1:3001")));
        assert!(addrs.contains(&addr("127.0.0.1:3003")));
        assert!(
            !addrs.contains(&addr("127.0.0.1:3002")),
            "removed backend must be gone from the running pool"
        );
    }

    fn weighted_pool_cfg(strategy: &str, w1: u32, w2: u32) -> Config {
        cfg(&format!(
            r#"
            [[listeners]]
            address = "127.0.0.1:18080"
            pool = "web"

            [[pools]]
            name = "web"
            strategy = "{strategy}"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            weight = {w1}

            [[pools.backends]]
            address = "127.0.0.1:3002"
            weight = {w2}
            "#
        ))
    }

    #[test]
    fn build_snapshot_wires_strategy_and_weights_from_config() {
        let snapshot = build_snapshot(&weighted_pool_cfg("weighted", 3, 1));
        let (pool, balancer) = snapshot.pools.get("web").unwrap();

        assert_eq!(balancer.strategy(), config::BalancerStrategy::Weighted);
        assert_eq!(pool.state_for(addr("127.0.0.1:3001")).unwrap().weight(), 3);
        assert_eq!(pool.state_for(addr("127.0.0.1:3002")).unwrap().weight(), 1);

        // and the wiring actually steers selection, not just the stored fields
        let mut first = 0;
        for _ in 0..400 {
            if balancer.next_backend().unwrap() == addr("127.0.0.1:3001") {
                first += 1;
            }
        }
        assert_eq!(first, 300);
    }

    #[tokio::test]
    async fn reload_retunes_weights_but_keeps_strategy() {
        let h = harness(&weighted_pool_cfg("weighted", 3, 1));
        let balancer_before = h.ctx.state.load().pools.get("web").unwrap().1.clone();

        // weight moves to drain 3001; strategy change in the same reload is
        // restart-only and must be ignored rather than half-applied.
        apply_reload(&h.ctx, &weighted_pool_cfg("least_conn", 0, 5))
            .await
            .expect("reload succeeds");

        let (pool, balancer_after) = h.ctx.state.load().pools.get("web").unwrap().clone();
        assert!(
            Arc::ptr_eq(&balancer_before, &balancer_after),
            "surviving pool keeps its balancer",
        );
        assert_eq!(
            balancer_after.strategy(),
            config::BalancerStrategy::Weighted,
            "strategy is restart-only",
        );
        assert_eq!(pool.state_for(addr("127.0.0.1:3001")).unwrap().weight(), 0);
        assert_eq!(pool.state_for(addr("127.0.0.1:3002")).unwrap().weight(), 5);

        // the drained backend must stop receiving traffic immediately
        for _ in 0..100 {
            assert_eq!(
                balancer_after.next_backend().unwrap(),
                addr("127.0.0.1:3002")
            );
        }
    }

    #[tokio::test]
    async fn reload_applies_weight_to_a_backend_it_adds() {
        let h = harness(&weighted_pool_cfg("weighted", 1, 1));
        apply_reload(&h.ctx, &weighted_pool_cfg("weighted", 1, 4))
            .await
            .expect("reload succeeds");

        // set_weights runs after reconcile, so a weight lands even on a backend
        // that only exists as of this reload
        let pool = h.ctx.state.load().pools.get("web").unwrap().0.clone();
        assert_eq!(pool.state_for(addr("127.0.0.1:3002")).unwrap().weight(), 4);
    }

    #[tokio::test]
    async fn reload_preserves_pool_arc_and_circuit() {
        use crate::health::CircuitState;
        let start = one_pool_cfg(&["127.0.0.1:3001", "127.0.0.1:3002"]);
        let h = harness(&start);
        let pool_before = h.ctx.state.load().pools.get("web").unwrap().0.clone();
        pool_before.record_failure(addr("127.0.0.1:3001"));
        assert_eq!(
            pool_before
                .state_for(addr("127.0.0.1:3001"))
                .unwrap()
                .circuit_state(),
            CircuitState::Open
        );

        // reload with an unrelated change (a third backend added)
        apply_reload(
            &h.ctx,
            &one_pool_cfg(&["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"]),
        )
        .await
        .expect("reload succeeds");

        let pool_after = h.ctx.state.load().pools.get("web").unwrap().0.clone();
        assert!(
            Arc::ptr_eq(&pool_before, &pool_after),
            "pool Arc must stay stable across reload so in-flight conns and drain work"
        );
        assert_eq!(
            pool_after
                .state_for(addr("127.0.0.1:3001"))
                .unwrap()
                .circuit_state(),
            CircuitState::Open,
            "a live circuit breaker must survive an unrelated reload"
        );
    }

    #[tokio::test]
    async fn reload_version_increments() {
        let h = harness(&one_pool_cfg(&["127.0.0.1:3001"]));
        assert_eq!(h.ctx.state.load().version, 0);
        assert_eq!(
            apply_reload(&h.ctx, &one_pool_cfg(&["127.0.0.1:3001"]))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            apply_reload(&h.ctx, &one_pool_cfg(&["127.0.0.1:3002"]))
                .await
                .unwrap(),
            2
        );
        assert_eq!(h.ctx.state.load().version, 2);
    }

    /// one L7 listener with an `/api` route and a catch-all; `api_target` names the
    /// pool the `/api` route points at, so a reload can move it.
    fn routed_cfg(api_target: &str) -> Config {
        cfg(&format!(
            "[[listeners]]\naddress = \"127.0.0.1:8080\"\nmode = \"l7\"\n\n\
             [[listeners.routes]]\npath_prefix = \"/api\"\npool = \"{api_target}\"\n\n\
             [[listeners.routes]]\npool = \"web\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{{ address = \"127.0.0.1:3001\" }}]\n\n\
             [[pools]]\nname = \"api\"\nbackends = [{{ address = \"127.0.0.1:4001\" }}]\n"
        ))
    }

    fn routed_pool_for(h: &Harness, path: &str) -> String {
        let cell = h.ctx.listeners.lock().unwrap()[&addr("127.0.0.1:8080")]
            .runtime
            .clone();
        let ctx = crate::proxy::l7::matcher::RouteContext {
            method: Some("GET"),
            host: None,
            path: Some(path),
            headers: &[],
            sni: None,
            client_ip: "127.0.0.1".parse().unwrap(),
        };
        cell.load()
            .router
            .route(&ctx)
            .expect("catch-all always matches")
            .pool
            .name
            .to_string()
    }

    #[tokio::test]
    async fn reload_swaps_the_route_table() {
        let h = harness(&routed_cfg("api"));
        assert_eq!(routed_pool_for(&h, "/api/v1"), "api");

        apply_reload(&h.ctx, &routed_cfg("web"))
            .await
            .expect("reload succeeds");

        assert_eq!(
            routed_pool_for(&h, "/api/v1"),
            "web",
            "the listener must serve the reloaded route table"
        );
        assert_eq!(routed_pool_for(&h, "/other"), "web");
    }

    /// a route may point at a pool the same reload introduces: routers are built
    /// against the desired pool set, not the running one. this was an abort until
    /// pool add landed.
    #[tokio::test]
    async fn reload_adds_a_pool_and_routes_to_it() {
        let h = harness(&routed_cfg("api"));
        let with_new_pool = cfg(
            "[[listeners]]\naddress = \"127.0.0.1:8080\"\nmode = \"l7\"\n\n\
             [[listeners.routes]]\npath_prefix = \"/api\"\npool = \"fallback\"\n\n\
             [[listeners.routes]]\npool = \"web\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{ address = \"127.0.0.1:3001\" }]\n\n\
             [[pools]]\nname = \"fallback\"\nbackends = [{ address = \"127.0.0.1:5001\" }]\n",
        );

        apply_reload(&h.ctx, &with_new_pool)
            .await
            .expect("a route may reference a pool this reload adds");

        assert_eq!(routed_pool_for(&h, "/api/v1"), "fallback");
        let snap = h.ctx.state.load();
        assert_eq!(
            snap.pools["fallback"].0.snapshot()[0].address(),
            addr("127.0.0.1:5001")
        );
        assert!(
            h.ctx.pool_tasks.lock().unwrap().contains_key("fallback"),
            "an added pool must get its own health checker and sweeper"
        );
        assert!(
            !snap.pools.contains_key("api"),
            "a pool no config references must leave the snapshot"
        );
    }

    /// a dropped pool stops being probed, but its Arc outlives the snapshot so
    /// connections pinned to the old route table finish on it.
    #[tokio::test]
    async fn reload_removes_a_pool_and_stops_its_tasks() {
        let h = harness(&routed_cfg("api"));
        let pinned = h.ctx.state.load().pools["api"].0.clone();

        // "web" catch-all only: nothing references "api" any more
        let without_api = cfg(
            "[[listeners]]\naddress = \"127.0.0.1:8080\"\nmode = \"l7\"\n\n\
             [[listeners.routes]]\npool = \"web\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{ address = \"127.0.0.1:3001\" }]\n",
        );
        apply_reload(&h.ctx, &without_api)
            .await
            .expect("reload succeeds");

        assert!(!h.ctx.state.load().pools.contains_key("api"));
        assert!(!h.ctx.pool_tasks.lock().unwrap().contains_key("api"));
        assert_eq!(
            pinned.snapshot()[0].address(),
            addr("127.0.0.1:4001"),
            "a pinned connection must still reach the pool it routed to"
        );
    }

    #[tokio::test]
    async fn reload_adds_and_removes_listeners() {
        let extra = free_port();
        let mut h = harness(&routed_cfg("api"));
        let old = addr("127.0.0.1:8080");

        let moved = cfg(&format!(
            "[[listeners]]\naddress = \"{extra}\"\nmode = \"l7\"\n\n\
             [[listeners.routes]]\npool = \"web\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{{ address = \"127.0.0.1:3001\" }}]\n"
        ));
        apply_reload(&h.ctx, &moved).await.expect("reload succeeds");

        let (spawned, _task) = h.spawn_rx.try_recv().expect("added listener handed over");
        assert_eq!(spawned, extra);
        {
            let registry = h.ctx.listeners.lock().unwrap();
            assert!(registry.contains_key(&extra));
            assert!(
                !registry.contains_key(&old),
                "removed listener must deregister"
            );
        }
        // serve() selects on exactly this receiver, so its resolving is what makes
        // the removed listener stop accepting and drain
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                h.drains.get_mut(&old).unwrap().changed(),
            )
            .await
            .is_ok(),
            "removed listener must be told to drain"
        );
    }

    /// abort safety: certs are loaded in the build phase, so a rotation that lands
    /// half-written leaves the old acceptor, routes, pools and version untouched.
    #[tokio::test]
    async fn reload_aborts_on_unreadable_certs() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\ntruncated\n").unwrap();
        std::fs::write(&key, b"not a key").unwrap();

        let h = harness(&routed_cfg("api"));
        let with_tls = cfg(&format!(
            "[[listeners]]\naddress = \"127.0.0.1:8080\"\nmode = \"l7\"\n\n\
             [[listeners.tls.certificates]]\ncert = \"{}\"\nkey = \"{}\"\n\n\
             [[listeners.routes]]\npath_prefix = \"/api\"\npool = \"web\"\n\n\
             [[listeners.routes]]\npool = \"web\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{{ address = \"127.0.0.1:3001\" }}]\n",
            cert.display(),
            key.display(),
        ));

        let err = apply_reload(&h.ctx, &with_tls).await.unwrap_err();
        assert!(matches!(err, ReloadError::Tls { .. }), "got {err:?}");
        assert_eq!(
            h.ctx.state.load().version,
            0,
            "aborted reload must not bump"
        );
        assert_eq!(routed_pool_for(&h, "/api/v1"), "api");
        assert!(
            h.ctx.state.load().pools.contains_key("api"),
            "an aborted reload must not drop a pool"
        );
    }

    /// one L4 listener with a listener-level `edge` zone at the given rate.
    fn zoned_cfg(rate: u32) -> Config {
        cfg(&format!(
            "[[listeners]]\naddress = \"127.0.0.1:8080\"\npool = \"web\"\nrate_limit = \"edge\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{{ address = \"127.0.0.1:3001\" }}]\n\n\
             [rate_limit.zones.edge]\nkey = \"global\"\nrate = {rate}\n"
        ))
    }

    fn zone_limiter(snap: &Snapshot, name: &str) -> Arc<ZoneLimiter> {
        Arc::clone(&snap.zones.get(name).expect("zone present").limiter)
    }

    /// the reset-attack guard: reloading an unrelated change must not rebuild a
    /// zone whose params are identical, or a flooding client gets a fresh budget
    /// on every SIGHUP.
    #[tokio::test]
    async fn reload_preserves_unchanged_zone_limiter() {
        let h = harness(&zoned_cfg(100));
        let before = zone_limiter(&h.ctx.state.load(), "edge");

        // reload an unrelated backend change; the zone params are byte-identical
        let with_backend = cfg(
            "[[listeners]]\naddress = \"127.0.0.1:8080\"\npool = \"web\"\nrate_limit = \"edge\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{ address = \"127.0.0.1:3002\" }]\n\n\
             [rate_limit.zones.edge]\nkey = \"global\"\nrate = 100\n",
        );
        apply_reload(&h.ctx, &with_backend)
            .await
            .expect("reload succeeds");

        let after = zone_limiter(&h.ctx.state.load(), "edge");
        assert!(
            Arc::ptr_eq(&before, &after),
            "an unchanged zone must keep its live limiter across reload"
        );
    }

    /// changing a zone's rate rebuilds its limiter (budget reset) and the new
    /// limiter reaches the listener's pinned runtime cell.
    #[tokio::test]
    async fn reload_rebuilds_changed_zone_and_relinks_listener() {
        let h = harness(&zoned_cfg(100));
        let before = zone_limiter(&h.ctx.state.load(), "edge");

        apply_reload(&h.ctx, &zoned_cfg(500))
            .await
            .expect("reload succeeds");

        let after = zone_limiter(&h.ctx.state.load(), "edge");
        assert!(
            !Arc::ptr_eq(&before, &after),
            "a changed zone must be rebuilt, resetting its budget"
        );
        // the listener runtime's handle must point at the rebuilt limiter, not the old one
        let handle_limiter = h.ctx.listeners.lock().unwrap()[&addr("127.0.0.1:8080")]
            .runtime
            .load()
            .rate_limit
            .as_ref()
            .map(|z| Arc::clone(&z.limiter))
            .expect("listener has a zone");
        assert!(
            Arc::ptr_eq(&handle_limiter, &after),
            "the reloaded listener must enforce the rebuilt zone"
        );
    }

    /// a zone no config references leaves the snapshot; a listener that stops
    /// referencing it drops its handle.
    #[tokio::test]
    async fn reload_removes_unreferenced_zone() {
        let h = harness(&zoned_cfg(100));
        assert!(h.ctx.state.load().zones.contains_key("edge"));

        let no_zone = cfg(
            "[[listeners]]\naddress = \"127.0.0.1:8080\"\npool = \"web\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{ address = \"127.0.0.1:3001\" }]\n",
        );
        apply_reload(&h.ctx, &no_zone)
            .await
            .expect("reload succeeds");

        assert!(!h.ctx.state.load().zones.contains_key("edge"));
        assert!(
            h.ctx.listeners.lock().unwrap()[&addr("127.0.0.1:8080")]
                .runtime
                .load()
                .rate_limit
                .is_none(),
            "a listener that dropped its zone reference must have no handle"
        );
    }

    /// a listener referencing a zone this reload adds must resolve against the
    /// desired zone set, not the running one (the pool-add analog for zones).
    #[tokio::test]
    async fn reload_adds_a_zone_a_listener_references() {
        let h = harness(&routed_cfg("api"));

        let with_zone = cfg(
            "[[listeners]]\naddress = \"127.0.0.1:8080\"\npool = \"web\"\nrate_limit = \"edge\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{ address = \"127.0.0.1:3001\" }]\n\n\
             [rate_limit.zones.edge]\nkey = \"client_ip\"\nrate = 10\n",
        );
        apply_reload(&h.ctx, &with_zone)
            .await
            .expect("a listener may reference a zone this reload adds");

        assert!(h.ctx.state.load().zones.contains_key("edge"));
        assert!(
            h.ctx.listeners.lock().unwrap()[&addr("127.0.0.1:8080")]
                .runtime
                .load()
                .rate_limit
                .is_some()
        );
    }
}
