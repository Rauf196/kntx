//! End-to-end reload tests: a real served listener reconciled through the real
//! `apply_reload` path, then hit with real HTTP requests. The unit tests in
//! `runtime.rs` prove the reconcile logic at the data-structure level; these prove
//! the serve loop actually picks up a committed reload.

mod helpers;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};

use helpers::http_backend::{HttpBackend, ResponseSpec};
use kntx::access_log::AccessLogSink;
use kntx::config::Config;
use kntx::listener::{self, ListenerRuntime};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::proxy::l7::ErrorPages;
use kntx::proxy::l7::router::{Router, build_router};
use kntx::runtime::{
    ListenerHandle, ListenerRegistry, PoolTasks, ReloadContext, SharedServe, apply_reload,
    build_serve_config, build_snapshot, build_zone_handle, spawn_pool_tasks,
};

/// a running proxy wired exactly like `main::run`, driveable through `reload`.
struct TestProxy {
    ctx: ReloadContext,
    _shutdown: watch::Sender<()>,
}

impl TestProxy {
    async fn start(config: &Config) -> Self {
        let state = Arc::new(ArcSwap::from_pointee(build_snapshot(config)));
        let snap = state.load_full();

        let buffer_pool = BufferPool::with_defaults();
        let shared = Arc::new(SharedServe {
            strategy: kntx::config::ForwardingStrategy::Userspace,
            buffer_pool: Arc::new(buffer_pool.clone()),
            resources: Resources {
                buffer_pool,
                #[cfg(target_os = "linux")]
                pipe_pool: kntx::pool::pipe::PipePool::with_defaults().unwrap(),
                socket_buffer_size: None,
            },
            error_pages: Arc::new(ErrorPages::load(&Default::default()).unwrap()),
            access_log: Arc::new(AccessLogSink::Off),
        });

        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let listeners: ListenerRegistry = Arc::new(Mutex::new(HashMap::new()));
        let pool_tasks: PoolTasks = Arc::new(Mutex::new(HashMap::new()));

        for pool_cfg in &config.pools {
            let (pool, _) = &snap.pools[&pool_cfg.name];
            let health = pool_cfg.effective_health(&config.health);
            pool_tasks.lock().unwrap().insert(
                pool_cfg.name.clone(),
                spawn_pool_tasks(pool, &health, &shutdown_rx),
            );
        }

        // ReloadContext needs the sender; no test here adds a *served* listener
        // (the bind-abort test fails at bind, before any handoff), so there is
        // nothing to adopt and no consumer task.
        let (spawn_tx, _spawn_rx) = mpsc::unbounded_channel();
        for cfg in &config.listeners {
            let router: Arc<dyn Router> =
                Arc::new(build_router(cfg, &snap.pools, &snap.zones).unwrap());
            let rate_limit = build_zone_handle(cfg, &snap.zones).unwrap();
            let runtime = ListenerRuntime::cell(router, Arc::new(cfg.clone()), None, rate_limit);
            let (drain_tx, drain_rx) = watch::channel(());
            let tcp = listener::bind(cfg.address).await.unwrap();
            tokio::spawn(listener::serve(
                tcp,
                Arc::clone(&runtime),
                build_serve_config(&shared, cfg),
                drain_rx,
            ));
            listeners.lock().unwrap().insert(
                cfg.address,
                ListenerHandle {
                    runtime,
                    drain: drain_tx,
                },
            );
        }

        Self {
            ctx: ReloadContext {
                state,
                listeners,
                pool_tasks,
                shared,
                spawn_tx,
                shutdown: shutdown_rx,
            },
            _shutdown: shutdown_tx,
        }
    }

    async fn reload(&self, cfg: &Config) -> Result<u64, kntx::runtime::ReloadError> {
        apply_reload(&self.ctx, cfg).await
    }

    fn version(&self) -> u64 {
        self.ctx.state.load().version
    }
}

/// a free loopback port, released before use. single-process test, nothing else
/// races for it.
fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// one GET on a fresh connection; returns (status, body).
async fn get(addr: SocketAddr) -> (u16, String) {
    let mut conn = TcpStream::connect(addr).await.unwrap();
    conn.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    (status, body)
}

fn l7_single_pool(listen: SocketAddr, backend: SocketAddr) -> Config {
    Config::from_toml(
        &format!(
            "[[listeners]]\naddress = \"{listen}\"\nmode = \"l7\"\npool = \"web\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{{ address = \"{backend}\" }}]\n"
        ),
        "<test>",
    )
    .unwrap()
}

/// 8.6: swapping a pool's backend set routes new connections to the new backend.
#[tokio::test]
async fn reload_backend_swap_routes_new_requests() {
    let alpha = HttpBackend::start(ResponseSpec::ok("alpha")).await;
    let beta = HttpBackend::start(ResponseSpec::ok("beta")).await;
    let listen = free_port();

    let proxy = TestProxy::start(&l7_single_pool(listen, alpha.addr)).await;
    let (status, body) = get(listen).await;
    assert_eq!((status, body.as_str()), (200, "alpha"));

    let v = proxy
        .reload(&l7_single_pool(listen, beta.addr))
        .await
        .expect("reload succeeds");
    assert_eq!(v, 1);

    let (status, body) = get(listen).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "beta"),
        "a new connection must hit the reloaded backend"
    );
    assert_eq!(beta.accept_count(), 1);
}

/// 8.8: a reload that fails a build-phase step (here: binding an added listener on
/// an occupied port) is rejected whole - the running listener keeps serving and the
/// version does not move.
#[tokio::test]
async fn reload_bind_failure_keeps_old_config_serving() {
    let alpha = HttpBackend::start(ResponseSpec::ok("alpha")).await;
    let listen = free_port();
    let proxy = TestProxy::start(&l7_single_pool(listen, alpha.addr)).await;
    assert_eq!(get(listen).await, (200, "alpha".to_owned()));

    // occupy a port, then reload a config that adds a second listener on it
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = occupied.local_addr().unwrap();
    let adds_busy_listener = Config::from_toml(
        &format!(
            "[[listeners]]\naddress = \"{listen}\"\nmode = \"l7\"\npool = \"web\"\n\n\
             [[listeners]]\naddress = \"{busy}\"\nmode = \"l7\"\npool = \"web\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{{ address = \"{}\" }}]\n",
            alpha.addr
        ),
        "<test>",
    )
    .unwrap();

    let err = proxy.reload(&adds_busy_listener).await.unwrap_err();
    assert!(
        matches!(err, kntx::runtime::ReloadError::Bind(_)),
        "got {err:?}"
    );
    assert_eq!(
        proxy.version(),
        0,
        "aborted reload must not bump the version"
    );
    assert_eq!(
        get(listen).await,
        (200, "alpha".to_owned()),
        "the original listener must keep serving after a rejected reload"
    );
}

fn l7_rate_limited(listen: SocketAddr, backend: SocketAddr, rate: u32, burst: u32) -> Config {
    Config::from_toml(
        &format!(
            "[[listeners]]\naddress = \"{listen}\"\nmode = \"l7\"\n\n\
             [[listeners.routes]]\npool = \"web\"\nrate_limit = \"z\"\n\n\
             [[pools]]\nname = \"web\"\nbackends = [{{ address = \"{backend}\" }}]\n\n\
             [rate_limit.zones.z]\nkey = \"global\"\nrate = {rate}\nburst = {burst}\n"
        ),
        "<test>",
    )
    .unwrap()
}

/// step-6 headline: tightening a zone's rate takes effect on reload. A lenient zone
/// admits everything; after a reload to rate=1/burst=0 the rebuilt zone starts
/// rejecting with 429.
#[tokio::test]
async fn reload_tightening_zone_starts_rejecting() {
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let listen = free_port();

    let proxy = TestProxy::start(&l7_rate_limited(listen, backend.addr, 1000, 100)).await;
    for _ in 0..5 {
        assert_eq!(get(listen).await.0, 200, "lenient zone admits everything");
    }

    proxy
        .reload(&l7_rate_limited(listen, backend.addr, 1, 0))
        .await
        .expect("reload succeeds");

    // rebuilt zone: budget reset, so the first request is admitted and the burst of
    // rapid ones behind it is denied. at least one 429 proves the tighter limit is live.
    let mut denied = 0;
    for _ in 0..4 {
        if get(listen).await.0 == 429 {
            denied += 1;
        }
    }
    assert!(
        denied >= 1,
        "a tightened zone must reject after reload, got {denied} rejects"
    );
}
