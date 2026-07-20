mod helpers;

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use kntx::access_log::AccessLogSink;
use kntx::balancer::RoundRobin;
use kntx::config::{
    ErrorPagesConfig, ForwardingStrategy, KeepaliveConfig, ListenerConfig, ListenerMode,
};
use kntx::health::BackendPool;
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::proxy::l7::ErrorPages;
use kntx::rate_limit::{
    KeyedLimiter, Limiter, MonotonicClock, Period, Rate, ZoneHandle, ZoneLimiter,
};

use helpers::http_backend::{HttpBackend, ResponseSpec};
use helpers::{EchoServer, make_single_pool_router};
use kntx::proxy::l7::matcher::{CompositeMatcher, Matcher, PathPrefixMatcher};
use kntx::proxy::l7::router::{ConfigRouter, PoolHandle, RouteEntry, Router};

fn rate(count: u32, period: Period) -> Rate {
    Rate {
        count: NonZeroU32::new(count).unwrap(),
        period,
    }
}

fn per_ip_zone(count: u32, period: Period, burst: u32) -> Arc<ZoneLimiter> {
    Arc::new(ZoneLimiter::PerIp(KeyedLimiter::new(
        rate(count, period),
        burst,
        1024,
        MonotonicClock::new(),
    )))
}

fn global_zone(count: u32, period: Period, burst: u32) -> Arc<ZoneLimiter> {
    Arc::new(ZoneLimiter::Global(Limiter::new(
        rate(count, period),
        burst,
        MonotonicClock::new(),
    )))
}

fn test_resources() -> Resources {
    Resources {
        buffer_pool: BufferPool::new(64, 64 * 1024),
        #[cfg(target_os = "linux")]
        pipe_pool: kntx::pool::pipe::PipePool::new(32).unwrap(),
        socket_buffer_size: None,
    }
}

fn test_pool(addrs: &[SocketAddr]) -> Arc<BackendPool> {
    Arc::new(BackendPool::new(
        "test".into(),
        addrs.to_vec(),
        3,
        Duration::from_secs(10),
        KeepaliveConfig::default(),
    ))
}

fn test_serve_config(mode: ListenerMode, rate_limit: Option<ZoneHandle>) -> ServeConfig {
    ServeConfig {
        rate_limit,
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: "test-listener".into(),
        listener_cfg: Arc::new(ListenerConfig {
            address: "127.0.0.1:0".parse().unwrap(),
            mode,
            pool: Some("test".to_owned()),
            ..Default::default()
        }),
        error_pages: Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap()),
        access_log: Arc::new(AccessLogSink::Off),
        buffer_pool: Arc::new(BufferPool::new(64, 64 * 1024)),
    }
}

async fn start_proxy(
    backend_addrs: &[SocketAddr],
    zone_name: &str,
    zone: Option<Arc<ZoneLimiter>>,
) -> (SocketAddr, tokio::sync::watch::Sender<()>) {
    let pool = test_pool(backend_addrs);
    let rr = Arc::new(RoundRobin::new(pool.clone()));
    let router = make_single_pool_router(pool, rr);
    let config = test_serve_config(
        ListenerMode::L4,
        zone.map(|limiter| ZoneHandle {
            name: zone_name.into(),
            limiter,
        }),
    );

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    tokio::spawn(listener::serve(tcp_listener, router, config, shutdown_rx));

    (proxy_addr, shutdown_tx)
}

async fn assert_echo_ok(conn: &mut TcpStream, payload: &[u8]) {
    conn.write_all(payload).await.expect("write to echo");
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut buf))
        .await
        .expect("echo read timed out")
        .expect("echo read failed");
    assert_eq!(buf, payload);
}

/// a rate-limited conn must die with an RST, not a clean FIN: a clean EOF
/// here means the linger-0 path regressed to a plain close. the RST races
/// the client's handshake completion, so it can surface either as a
/// connect error or as an error on the first read.
async fn assert_rejected_with_rst(proxy_addr: SocketAddr) {
    let connected = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(proxy_addr))
        .await
        .expect("connect should resolve quickly, not hang");
    let err = match connected {
        Err(e) => e,
        Ok(mut conn) => {
            let result = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut [0u8; 16]))
                .await
                .expect("reset should arrive quickly, not hang");
            result.expect_err("expected RST, got data or clean EOF")
        }
    };
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
}

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

fn init_metrics() -> &'static PrometheusHandle {
    METRICS_HANDLE.get_or_init(|| {
        PrometheusBuilder::new()
            .install_recorder()
            .expect("install prometheus recorder")
    })
}

fn counter_value(render: &str, metric: &str, labels: &[&str]) -> f64 {
    render
        .lines()
        .find(|line| line.starts_with(metric) && labels.iter().all(|l| line.contains(l)))
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .unwrap_or(0.0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l4_flood_excess_reset_healthy_conns_unaffected() {
    let handle = init_metrics();
    let backend = EchoServer::start().await;
    // 1/min burst 4 = budget of 5, no refill within the test
    let zone = per_ip_zone(1, Period::Minute, 4);
    let (proxy_addr, _shutdown) = start_proxy(&[backend.addr], "flood", Some(zone)).await;

    // first admit, held open across the flood
    let mut held = TcpStream::connect(proxy_addr).await.unwrap();
    assert_echo_ok(&mut held, b"held-1").await;

    for i in 0..4 {
        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        assert_echo_ok(&mut conn, format!("burst-{i}").as_bytes()).await;
    }

    for _ in 0..3 {
        assert_rejected_with_rst(proxy_addr).await;
    }

    // the held admitted conn is untouched by the flood rejections
    assert_echo_ok(&mut held, b"held-2").await;

    let rejected = counter_value(
        handle.render().as_str(),
        "kntx_rate_limit_rejected_total",
        &["zone=\"flood\"", "scope=\"listener\""],
    );
    assert!(rejected >= 3.0, "expected >= 3 rejections, got {rejected}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l4_limiter_recovers_after_window() {
    let backend = EchoServer::start().await;
    // 2/s burst 0: strict pacing at 500ms, wide margin against test jitter
    let zone = per_ip_zone(2, Period::Second, 0);
    let (proxy_addr, _shutdown) = start_proxy(&[backend.addr], "recover", Some(zone)).await;

    let mut first = TcpStream::connect(proxy_addr).await.unwrap();
    assert_echo_ok(&mut first, b"first").await;

    assert_rejected_with_rst(proxy_addr).await;

    tokio::time::sleep(Duration::from_millis(600)).await;

    let mut recovered = TcpStream::connect(proxy_addr).await.unwrap();
    assert_echo_ok(&mut recovered, b"recovered").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l4_global_zone_caps_two_listeners_jointly() {
    let backend = EchoServer::start().await;
    // budget of 3 shared by both listeners through one limiter instance
    let zone = global_zone(1, Period::Minute, 2);
    let (proxy_a, _shutdown_a) = start_proxy(&[backend.addr], "shared", Some(zone.clone())).await;
    let (proxy_b, _shutdown_b) = start_proxy(&[backend.addr], "shared", Some(zone)).await;

    for (i, addr) in [proxy_a, proxy_b, proxy_a].into_iter().enumerate() {
        let mut conn = TcpStream::connect(addr).await.unwrap();
        assert_echo_ok(&mut conn, format!("joint-{i}").as_bytes()).await;
    }

    // budget spent: both listeners now reject
    assert_rejected_with_rst(proxy_b).await;
    assert_rejected_with_rst(proxy_a).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l4_per_ip_budgets_isolated_across_source_ips() {
    let backend = EchoServer::start().await;
    // 1/min burst 0 = one admit per source IP
    let zone = per_ip_zone(1, Period::Minute, 0);
    let (proxy_addr, _shutdown) = start_proxy(&[backend.addr], "per-ip", Some(zone)).await;

    let mut from_one = TcpStream::connect(proxy_addr).await.unwrap();
    assert_echo_ok(&mut from_one, b"ip1").await;

    assert_rejected_with_rst(proxy_addr).await;

    // second loopback address: a fresh key with its own budget
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let mut from_two = socket.connect(proxy_addr).await.unwrap();
    assert_echo_ok(&mut from_two, b"ip2").await;
}

fn route_entry(
    path_prefix: Option<&str>,
    backend: SocketAddr,
    zone: Option<(&str, Arc<ZoneLimiter>)>,
) -> RouteEntry {
    let pool = test_pool(&[backend]);
    let rr = Arc::new(RoundRobin::new(pool.clone()));
    let matchers: Vec<Box<dyn Matcher + Send + Sync>> = match path_prefix {
        Some(prefix) => vec![Box::new(PathPrefixMatcher::new(prefix).unwrap())],
        None => vec![],
    };
    RouteEntry {
        matcher: CompositeMatcher::new(matchers),
        pool: PoolHandle {
            backends: pool,
            rr,
            name: "test".into(),
        },
        route_id: Arc::from(
            path_prefix
                .map_or("default".to_owned(), |p| format!("path={p}"))
                .as_str(),
        ),
        rate_limit: zone.map(|(name, limiter)| ZoneHandle {
            name: name.into(),
            limiter,
        }),
    }
}

async fn start_l7_proxy(routes: Vec<RouteEntry>) -> (SocketAddr, tokio::sync::watch::Sender<()>) {
    let router: Arc<dyn Router> = Arc::new(ConfigRouter::new(routes));
    let config = test_serve_config(ListenerMode::L7, None);

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    tokio::spawn(listener::serve(tcp_listener, router, config, shutdown_rx));

    (proxy_addr, shutdown_tx)
}

async fn http_get(addr: SocketAddr, path: &str, accept: Option<&str>) -> (u16, String) {
    let mut conn = TcpStream::connect(addr).await.unwrap();
    let accept_header = accept
        .map(|a| format!("Accept: {a}\r\n"))
        .unwrap_or_default();
    let req =
        format!("GET {path} HTTP/1.1\r\nHost: test\r\n{accept_header}Connection: close\r\n\r\n");
    conn.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut buf))
        .await
        .expect("response timed out")
        .unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text.split(' ').nth(1).unwrap().parse().unwrap();
    (status, text)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l7_route_zone_429_retry_after_negotiated_metric() {
    let handle = init_metrics();
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    // 1/min burst 1 = two requests admitted, then deny with ~60s retry
    let zone = per_ip_zone(1, Period::Minute, 1);
    let (addr, _shutdown) =
        start_l7_proxy(vec![route_entry(None, backend.addr, Some(("login", zone)))]).await;

    assert_eq!(http_get(addr, "/", None).await.0, 200);
    assert_eq!(http_get(addr, "/", None).await.0, 200);

    let (status, body) = http_get(addr, "/", None).await;
    assert_eq!(status, 429);
    assert!(body.contains("429 Too Many Requests"), "{body}");
    let retry: u64 = body
        .lines()
        .find_map(|line| line.strip_prefix("Retry-After: "))
        .expect("Retry-After header present")
        .trim()
        .parse()
        .unwrap();
    assert!((58..=60).contains(&retry), "retry_after {retry}");

    // content negotiation flows through the 429 path unchanged
    let (status, body) = http_get(addr, "/", Some("application/json")).await;
    assert_eq!(status, 429);
    assert!(
        body.contains(r#""error":"Too Many Requests","status":429"#),
        "{body}"
    );

    let rejected = counter_value(
        handle.render().as_str(),
        "kntx_rate_limit_rejected_total",
        &["zone=\"login\"", "scope=\"route\""],
    );
    assert!(
        rejected >= 2.0,
        "expected >= 2 route rejections, got {rejected}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l7_two_routes_distinct_zones_isolated() {
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let zone_a = per_ip_zone(1, Period::Minute, 0);
    let zone_b = per_ip_zone(1, Period::Minute, 0);
    let (addr, _shutdown) = start_l7_proxy(vec![
        route_entry(Some("/a"), backend.addr, Some(("zone-a", zone_a))),
        route_entry(Some("/b"), backend.addr, Some(("zone-b", zone_b))),
    ])
    .await;

    assert_eq!(http_get(addr, "/a", None).await.0, 200);
    assert_eq!(http_get(addr, "/a", None).await.0, 429);
    // the sibling route's budget is untouched
    assert_eq!(http_get(addr, "/b", None).await.0, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l7_two_routes_shared_zone_share_budget() {
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let zone = per_ip_zone(1, Period::Minute, 0);
    let (addr, _shutdown) = start_l7_proxy(vec![
        route_entry(
            Some("/a"),
            backend.addr,
            Some(("shared-route", zone.clone())),
        ),
        route_entry(Some("/b"), backend.addr, Some(("shared-route", zone))),
    ])
    .await;

    assert_eq!(http_get(addr, "/a", None).await.0, 200);
    assert_eq!(http_get(addr, "/b", None).await.0, 429);
}
