mod helpers;

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use tokio::sync::watch;

use helpers::EchoServer;
use helpers::http_backend::{HttpBackend, ResponseSpec};
use helpers::tls::{client_config_trusting, generate_cert, write_cert_to_tempdir};
use kntx::access_log::AccessLogSink;
use kntx::balancer::RoundRobin;
use kntx::config::{AccessLogConfig, AccessLogOutput};
use kntx::config::{
    CertificateConfig, ErrorPagesConfig, ForwardingStrategy, KeepaliveConfig, ListenerConfig,
    ListenerMode, TlsConfig,
};
use kntx::health::BackendPool;
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::proxy::l7::ErrorPages;
use kntx::proxy::l7::matcher::{
    CompositeMatcher, HostMatcher, Matcher, PathPrefixMatcher, SniMatcher,
};
use kntx::proxy::l7::router::{ConfigRouter, PoolHandle, RouteEntry, Router};
use kntx::tls::build_acceptor;

fn test_resources() -> Resources {
    Resources {
        buffer_pool: BufferPool::new(64, 64 * 1024),
        #[cfg(target_os = "linux")]
        pipe_pool: kntx::pool::pipe::PipePool::new(32).unwrap(),
        socket_buffer_size: None,
    }
}

fn make_pool(name: &str, addr: SocketAddr) -> (Arc<BackendPool>, Arc<RoundRobin>) {
    let pool = Arc::new(BackendPool::new(
        Arc::from(name),
        vec![addr],
        3,
        Duration::from_secs(10),
        KeepaliveConfig::default(),
    ));
    let rr = Arc::new(RoundRobin::new(pool.clone()));
    (pool, rr)
}

fn pool_handle(name: &str, pool: Arc<BackendPool>, rr: Arc<RoundRobin>) -> PoolHandle {
    PoolHandle {
        name: Arc::from(name),
        backends: pool,
        rr,
    }
}

fn route(
    matchers: Vec<Box<dyn Matcher + Send + Sync>>,
    handle: PoolHandle,
    route_id: &str,
) -> RouteEntry {
    RouteEntry {
        matcher: CompositeMatcher::new(matchers),
        pool: handle,
        route_id: Arc::from(route_id),
    }
}

fn catch_all(handle: PoolHandle) -> RouteEntry {
    route(vec![], handle, "default")
}

struct RoutingProxy {
    addr: SocketAddr,
    _shutdown: watch::Sender<()>,
}

async fn start_routing_proxy(router: Arc<dyn Router>) -> RoutingProxy {
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: Some("test".to_owned()),
        routes: vec![],
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
        ..Default::default()
    });

    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let error_pages = Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap());
    let access_log = Arc::new(AccessLogSink::Off);

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let serve_cfg = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: Some(Duration::from_secs(10)),
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(2),
        max_connect_attempts: 1,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };

    tokio::spawn(listener::serve(listener, router, serve_cfg, shutdown_rx));

    RoutingProxy {
        addr,
        _shutdown: shutdown_tx,
    }
}

async fn get(proxy_addr: SocketAddr, host: &str, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut resp = Vec::new();
    let _ = stream.read_to_end(&mut resp).await;

    let text = String::from_utf8_lossy(&resp).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let body = if let Some(pos) = text.find("\r\n\r\n") {
        text[pos + 4..].to_owned()
    } else {
        String::new()
    };

    (status, body)
}

/// two hosts, each routes to a different pool.
#[tokio::test]
async fn host_routing_two_hosts_two_pools() {
    let backend_a = HttpBackend::start(ResponseSpec::ok("pool-a")).await;
    let backend_b = HttpBackend::start(ResponseSpec::ok("pool-b")).await;

    let (pool_a, rr_a) = make_pool("pool-a", backend_a.addr);
    let (pool_b, rr_b) = make_pool("pool-b", backend_b.addr);

    let router = Arc::new(ConfigRouter::new(vec![
        route(
            vec![Box::new(HostMatcher::new("a.example.com").unwrap())],
            pool_handle("pool-a", pool_a, rr_a),
            "host=a.example.com",
        ),
        route(
            vec![Box::new(HostMatcher::new("b.example.com").unwrap())],
            pool_handle("pool-b", pool_b, rr_b),
            "host=b.example.com",
        ),
    ]));

    let proxy = start_routing_proxy(router).await;

    let (status_a, body_a) = get(proxy.addr, "a.example.com", "/").await;
    assert_eq!(status_a, 200);
    assert_eq!(body_a.trim(), "pool-a");

    let (status_b, body_b) = get(proxy.addr, "b.example.com", "/").await;
    assert_eq!(status_b, 200);
    assert_eq!(body_b.trim(), "pool-b");
}

/// /api → pool-a, /static → pool-b, catch-all → pool-c.
#[tokio::test]
async fn path_prefix_routing_three_pools() {
    let backend_a = HttpBackend::start(ResponseSpec::ok("pool-a")).await;
    let backend_b = HttpBackend::start(ResponseSpec::ok("pool-b")).await;
    let backend_c = HttpBackend::start(ResponseSpec::ok("pool-c")).await;

    let (pool_a, rr_a) = make_pool("pool-a", backend_a.addr);
    let (pool_b, rr_b) = make_pool("pool-b", backend_b.addr);
    let (pool_c, rr_c) = make_pool("pool-c", backend_c.addr);

    let router = Arc::new(ConfigRouter::new(vec![
        route(
            vec![Box::new(PathPrefixMatcher::new("/api").unwrap())],
            pool_handle("pool-a", pool_a, rr_a),
            "path=/api",
        ),
        route(
            vec![Box::new(PathPrefixMatcher::new("/static").unwrap())],
            pool_handle("pool-b", pool_b, rr_b),
            "path=/static",
        ),
        catch_all(pool_handle("pool-c", pool_c, rr_c)),
    ]));

    let proxy = start_routing_proxy(router).await;

    let (_, body) = get(proxy.addr, "example.com", "/api/v1").await;
    assert_eq!(body.trim(), "pool-a");

    let (_, body) = get(proxy.addr, "example.com", "/static/style.css").await;
    assert_eq!(body.trim(), "pool-b");

    let (_, body) = get(proxy.addr, "example.com", "/other").await;
    assert_eq!(body.trim(), "pool-c");
}

/// more specific route listed first wins.
#[tokio::test]
async fn declaration_order_specific_first_wins() {
    let backend_a = HttpBackend::start(ResponseSpec::ok("specific")).await;
    let backend_b = HttpBackend::start(ResponseSpec::ok("general")).await;

    let (pool_a, rr_a) = make_pool("specific", backend_a.addr);
    let (pool_b, rr_b) = make_pool("general", backend_b.addr);

    let router = Arc::new(ConfigRouter::new(vec![
        route(
            vec![Box::new(PathPrefixMatcher::new("/api/v1").unwrap())],
            pool_handle("specific", pool_a, rr_a),
            "path=/api/v1",
        ),
        route(
            vec![Box::new(PathPrefixMatcher::new("/api").unwrap())],
            pool_handle("general", pool_b, rr_b),
            "path=/api",
        ),
    ]));

    let proxy = start_routing_proxy(router).await;

    let (_, body) = get(proxy.addr, "example.com", "/api/v1/foo").await;
    assert_eq!(body.trim(), "specific");

    let (_, body) = get(proxy.addr, "example.com", "/api/v2").await;
    assert_eq!(body.trim(), "general");
}

/// more specific listed second never matches when general is first.
#[tokio::test]
async fn declaration_order_specific_after_general_never_matches() {
    let backend_a = HttpBackend::start(ResponseSpec::ok("specific")).await;
    let backend_b = HttpBackend::start(ResponseSpec::ok("general")).await;

    let (pool_a, rr_a) = make_pool("specific", backend_a.addr);
    let (pool_b, rr_b) = make_pool("general", backend_b.addr);

    // general listed before specific - specific never gets traffic
    let router = Arc::new(ConfigRouter::new(vec![
        route(
            vec![Box::new(PathPrefixMatcher::new("/api").unwrap())],
            pool_handle("general", pool_b, rr_b),
            "path=/api",
        ),
        route(
            vec![Box::new(PathPrefixMatcher::new("/api/v1").unwrap())],
            pool_handle("specific", pool_a, rr_a),
            "path=/api/v1",
        ),
    ]));

    let proxy = start_routing_proxy(router).await;

    // /api/v1/foo matches /api first - specific route never reached
    let (_, body) = get(proxy.addr, "example.com", "/api/v1/foo").await;
    assert_eq!(body.trim(), "general");
}

/// composite host+path: both conditions must hold.
#[tokio::test]
async fn composite_host_and_path_required_both() {
    let backend_a = HttpBackend::start(ResponseSpec::ok("matched")).await;
    let backend_b = HttpBackend::start(ResponseSpec::ok("fallback")).await;

    let (pool_a, rr_a) = make_pool("matched", backend_a.addr);
    let (pool_b, rr_b) = make_pool("fallback", backend_b.addr);

    let router = Arc::new(ConfigRouter::new(vec![
        route(
            vec![
                Box::new(HostMatcher::new("api.example.com").unwrap()),
                Box::new(PathPrefixMatcher::new("/v1").unwrap()),
            ],
            pool_handle("matched", pool_a, rr_a),
            "host=api.example.com,path=/v1",
        ),
        catch_all(pool_handle("fallback", pool_b, rr_b)),
    ]));

    let proxy = start_routing_proxy(router).await;

    // both host and path match
    let (_, body) = get(proxy.addr, "api.example.com", "/v1/users").await;
    assert_eq!(body.trim(), "matched");

    // host matches but path doesn't
    let (_, body) = get(proxy.addr, "api.example.com", "/v2/users").await;
    assert_eq!(body.trim(), "fallback");

    // path matches but host doesn't
    let (_, body) = get(proxy.addr, "other.com", "/v1/users").await;
    assert_eq!(body.trim(), "fallback");
}

/// *.example.com matches single-label and multi-label subdomains.
#[tokio::test]
async fn wildcard_host_routes_subdomain() {
    let backend_a = HttpBackend::start(ResponseSpec::ok("wildcard")).await;
    let backend_b = HttpBackend::start(ResponseSpec::ok("fallback")).await;

    let (pool_a, rr_a) = make_pool("wildcard", backend_a.addr);
    let (pool_b, rr_b) = make_pool("fallback", backend_b.addr);

    let router = Arc::new(ConfigRouter::new(vec![
        route(
            vec![Box::new(HostMatcher::new("*.example.com").unwrap())],
            pool_handle("wildcard", pool_a, rr_a),
            "host=*.example.com",
        ),
        catch_all(pool_handle("fallback", pool_b, rr_b)),
    ]));

    let proxy = start_routing_proxy(router).await;

    // single-label subdomain matches
    let (_, body) = get(proxy.addr, "api.example.com", "/").await;
    assert_eq!(
        body.trim(),
        "wildcard",
        "api.example.com must match *.example.com"
    );

    // multi-label subdomain also matches (cloud-native semantics)
    let (_, body) = get(proxy.addr, "a.b.example.com", "/").await;
    assert_eq!(
        body.trim(),
        "wildcard",
        "a.b.example.com must match *.example.com"
    );

    // apex does NOT match wildcard
    let (_, body) = get(proxy.addr, "example.com", "/").await;
    assert_eq!(
        body.trim(),
        "fallback",
        "example.com must NOT match *.example.com"
    );
}

/// no matching route and no catch-all returns 503.
#[tokio::test]
async fn no_match_returns_503() {
    let backend = HttpBackend::start(ResponseSpec::ok("pool-a")).await;
    let (pool, rr) = make_pool("pool-a", backend.addr);

    // only one specific route, no catch-all
    let router = Arc::new(ConfigRouter::new(vec![route(
        vec![Box::new(HostMatcher::new("api.example.com").unwrap())],
        pool_handle("pool-a", pool, rr),
        "host=api.example.com",
    )]));

    let proxy = start_routing_proxy(router).await;

    let (status, _) = get(proxy.addr, "other.com", "/").await;
    assert_eq!(status, 503, "no-match route must return 503");
}

/// catch-all as last route serves unmatched requests.
#[tokio::test]
async fn catch_all_route_serves_unmatched() {
    let backend_a = HttpBackend::start(ResponseSpec::ok("specific")).await;
    let backend_b = HttpBackend::start(ResponseSpec::ok("catch-all")).await;

    let (pool_a, rr_a) = make_pool("specific", backend_a.addr);
    let (pool_b, rr_b) = make_pool("catch-all", backend_b.addr);

    let router = Arc::new(ConfigRouter::new(vec![
        route(
            vec![Box::new(HostMatcher::new("api.example.com").unwrap())],
            pool_handle("specific", pool_a, rr_a),
            "host=api.example.com",
        ),
        catch_all(pool_handle("catch-all", pool_b, rr_b)),
    ]));

    let proxy = start_routing_proxy(router).await;

    // specific route
    let (status, body) = get(proxy.addr, "api.example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body.trim(), "specific");

    // unmatched falls to catch-all
    let (status, body) = get(proxy.addr, "unknown.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body.trim(), "catch-all");
}

/// regression - single-pool listener (old pool = "X" style) still works.
#[tokio::test]
async fn existing_single_pool_listener_unchanged() {
    let backend = HttpBackend::start(ResponseSpec::ok("single-pool")).await;
    let (pool, rr) = make_pool("test", backend.addr);

    let router = helpers::make_single_pool_router(pool, rr);
    let proxy = start_routing_proxy(router).await;

    let (status, body) = get(proxy.addr, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body.trim(), "single-pool");
}

/// route_id appears in the access log for matched routes.
#[tokio::test]
async fn route_id_in_access_log() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let log_path = tmp.path().to_path_buf();

    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let (pool, rr) = make_pool("pool-a", backend.addr);

    let router = Arc::new(ConfigRouter::new(vec![route(
        vec![Box::new(HostMatcher::new("api.example.com").unwrap())],
        pool_handle("pool-a", pool, rr),
        "host=api.example.com",
    )]));

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: Some("test".to_owned()),
        routes: vec![],
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
        ..Default::default()
    });

    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let error_pages = Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap());
    let access_log = Arc::new(
        AccessLogSink::from_config(&AccessLogConfig {
            output: AccessLogOutput::File {
                file: log_path.clone(),
            },
            format: None,
            file_channel_capacity: 64,
        })
        .unwrap(),
    );

    let serve_cfg = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: Some(Duration::from_secs(10)),
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(2),
        max_connect_attempts: 1,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };

    tokio::spawn(listener::serve(listener, router, serve_cfg, shutdown_rx));
    tokio::time::sleep(Duration::from_millis(10)).await;

    get(addr, "api.example.com", "/test").await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = shutdown_tx.send(());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(!content.is_empty(), "access log must have content");
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(
        parsed["route_id"].as_str().unwrap_or(""),
        "host=api.example.com",
        "route_id in access log must match derived route_id"
    );
    assert_eq!(parsed["status"], 200);
}

/// L7+TLS: SNI steers two hostnames to two separate pools.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_sni_routes_two_pools() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend_a = HttpBackend::start(ResponseSpec::ok("pool-a")).await;
    let backend_b = HttpBackend::start(ResponseSpec::ok("pool-b")).await;

    let tc_a = generate_cert(&["a.test"]);
    let tc_b = generate_cert(&["b.test"]);
    let (_dir_a, cert_a, key_a) = write_cert_to_tempdir(&tc_a);
    let (_dir_b, cert_b, key_b) = write_cert_to_tempdir(&tc_b);

    let tls_config = TlsConfig {
        handshake_timeout_secs: 5,
        min_version: "1.2".to_owned(),
        certificates: vec![
            CertificateConfig {
                cert: cert_a,
                key: key_a,
                sni_names: vec!["a.test".to_owned()],
            },
            CertificateConfig {
                cert: cert_b,
                key: key_b,
                sni_names: vec!["b.test".to_owned()],
            },
        ],
    };
    let acceptor = build_acceptor(&tls_config).unwrap();

    let (pool_a, rr_a) = make_pool("pool-a", backend_a.addr);
    let (pool_b, rr_b) = make_pool("pool-b", backend_b.addr);

    let router: Arc<dyn Router> = Arc::new(ConfigRouter::new(vec![
        route(
            vec![Box::new(SniMatcher::new("a.test").unwrap())],
            pool_handle("pool-a", pool_a, rr_a),
            "sni=a.test",
        ),
        route(
            vec![Box::new(SniMatcher::new("b.test").unwrap())],
            pool_handle("pool-b", pool_b, rr_b),
            "sni=b.test",
        ),
    ]));

    let proxy = start_tls_l7_proxy(router, acceptor).await;

    // SNI a.test → pool-a
    let cfg_a = client_config_trusting(&tc_a.cert_der);
    let mut stream_a = helpers::tls::tls_connect(proxy.addr, "a.test", cfg_a).await;
    stream_a
        .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream_a.read_to_end(&mut buf).await;
    let resp_a = String::from_utf8_lossy(&buf);
    assert!(
        resp_a.contains("pool-a"),
        "SNI a.test must route to pool-a, got: {resp_a}"
    );

    // SNI b.test → pool-b
    let cfg_b = client_config_trusting(&tc_b.cert_der);
    let mut stream_b = helpers::tls::tls_connect(proxy.addr, "b.test", cfg_b).await;
    stream_b
        .write_all(b"GET / HTTP/1.1\r\nHost: b.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream_b.read_to_end(&mut buf).await;
    let resp_b = String::from_utf8_lossy(&buf);
    assert!(
        resp_b.contains("pool-b"),
        "SNI b.test must route to pool-b, got: {resp_b}"
    );
}

/// composite SNI+path: both conditions must hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_sni_with_l7_path_composite() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend_matched = HttpBackend::start(ResponseSpec::ok("matched")).await;
    let backend_fallback = HttpBackend::start(ResponseSpec::ok("fallback")).await;

    let tc = generate_cert(&["api.test"]);
    let (_dir, cert_path, key_path) = write_cert_to_tempdir(&tc);

    let tls_config = TlsConfig {
        handshake_timeout_secs: 5,
        min_version: "1.2".to_owned(),
        certificates: vec![CertificateConfig {
            cert: cert_path,
            key: key_path,
            sni_names: vec!["api.test".to_owned()],
        }],
    };
    let acceptor = build_acceptor(&tls_config).unwrap();

    let (pool_m, rr_m) = make_pool("matched", backend_matched.addr);
    let (pool_f, rr_f) = make_pool("fallback", backend_fallback.addr);

    let router: Arc<dyn Router> = Arc::new(ConfigRouter::new(vec![
        route(
            vec![
                Box::new(SniMatcher::new("api.test").unwrap()),
                Box::new(PathPrefixMatcher::new("/v1").unwrap()),
            ],
            pool_handle("matched", pool_m, rr_m),
            "path=/v1,sni=api.test",
        ),
        catch_all(pool_handle("fallback", pool_f, rr_f)),
    ]));

    let proxy = start_tls_l7_proxy(router, acceptor).await;
    let cfg = client_config_trusting(&tc.cert_der);

    // SNI api.test + path /v1 → matched
    let mut stream = helpers::tls::tls_connect(proxy.addr, "api.test", cfg.clone()).await;
    stream
        .write_all(b"GET /v1/users HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    assert!(
        String::from_utf8_lossy(&buf).contains("matched"),
        "sni=api.test + path=/v1 must route to matched"
    );

    // SNI api.test + path /other → fallback
    let mut stream = helpers::tls::tls_connect(proxy.addr, "api.test", cfg).await;
    stream
        .write_all(b"GET /other HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    assert!(
        String::from_utf8_lossy(&buf).contains("fallback"),
        "sni=api.test + path=/other must fall through to fallback"
    );
}

/// regression - TLS listener without routes (single pool) works as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_passthrough_listener_unchanged() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend = HttpBackend::start(ResponseSpec::ok("single-pool")).await;
    let tc = generate_cert(&["localhost"]);
    let (_dir, cert_path, key_path) = write_cert_to_tempdir(&tc);

    let tls_config = TlsConfig {
        handshake_timeout_secs: 5,
        min_version: "1.2".to_owned(),
        certificates: vec![CertificateConfig {
            cert: cert_path,
            key: key_path,
            sni_names: vec![],
        }],
    };
    let acceptor = build_acceptor(&tls_config).unwrap();

    let (pool, rr) = make_pool("test", backend.addr);
    let router = helpers::make_single_pool_router(pool, rr);

    let proxy = start_tls_l7_proxy(router, acceptor).await;

    let cfg = client_config_trusting(&tc.cert_der);
    let mut stream = helpers::tls::tls_connect(proxy.addr, "localhost", cfg).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    assert!(
        String::from_utf8_lossy(&buf).contains("single-pool"),
        "single-pool TLS regression failed"
    );
}

/// L4+TLS with SNI routing: two SNIs routed to two echo pools.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l4_tls_sni_routes_two_pools() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend_a = HttpBackend::start(ResponseSpec::ok("pool-a")).await;
    let backend_b = HttpBackend::start(ResponseSpec::ok("pool-b")).await;

    let tc_a = generate_cert(&["a.test"]);
    let tc_b = generate_cert(&["b.test"]);
    let (_dir_a, cert_a, key_a) = write_cert_to_tempdir(&tc_a);
    let (_dir_b, cert_b, key_b) = write_cert_to_tempdir(&tc_b);

    let tls_config = TlsConfig {
        handshake_timeout_secs: 5,
        min_version: "1.2".to_owned(),
        certificates: vec![
            CertificateConfig {
                cert: cert_a,
                key: key_a,
                sni_names: vec!["a.test".to_owned()],
            },
            CertificateConfig {
                cert: cert_b,
                key: key_b,
                sni_names: vec!["b.test".to_owned()],
            },
        ],
    };
    let acceptor = build_acceptor(&tls_config).unwrap();

    let (pool_a, rr_a) = make_pool("pool-a", backend_a.addr);
    let (pool_b, rr_b) = make_pool("pool-b", backend_b.addr);

    let router: Arc<dyn Router> = Arc::new(ConfigRouter::new(vec![
        route(
            vec![Box::new(SniMatcher::new("a.test").unwrap())],
            pool_handle("pool-a", pool_a, rr_a),
            "sni=a.test",
        ),
        route(
            vec![Box::new(SniMatcher::new("b.test").unwrap())],
            pool_handle("pool-b", pool_b, rr_b),
            "sni=b.test",
        ),
    ]));

    let proxy = start_tls_l4_proxy(router, acceptor).await;

    // client connects with SNI "a.test", sends HTTP (forwarded as raw bytes to backend)
    let cfg_a = client_config_trusting(&tc_a.cert_der);
    let mut stream_a = helpers::tls::tls_connect(proxy.addr, "a.test", cfg_a).await;
    stream_a
        .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream_a.read_to_end(&mut buf).await;
    let resp_a = String::from_utf8_lossy(&buf);
    assert!(
        resp_a.contains("pool-a"),
        "L4 SNI a.test must route to pool-a, got: {resp_a}"
    );

    let cfg_b = client_config_trusting(&tc_b.cert_der);
    let mut stream_b = helpers::tls::tls_connect(proxy.addr, "b.test", cfg_b).await;
    stream_b
        .write_all(b"GET / HTTP/1.1\r\nHost: b.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream_b.read_to_end(&mut buf).await;
    let resp_b = String::from_utf8_lossy(&buf);
    assert!(
        resp_b.contains("pool-b"),
        "L4 SNI b.test must route to pool-b, got: {resp_b}"
    );
}

async fn start_tls_l7_proxy(
    router: Arc<dyn Router>,
    acceptor: tokio_rustls::TlsAcceptor,
) -> RoutingProxy {
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: Some("test".to_owned()),
        routes: vec![],
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
        ..Default::default()
    });

    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let error_pages = Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap());
    let access_log = Arc::new(AccessLogSink::Off);

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let serve_cfg = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: Some(Duration::from_secs(10)),
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(2),
        max_connect_attempts: 1,
        tls_acceptor: Some(acceptor),
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };

    tokio::spawn(listener::serve(listener, router, serve_cfg, shutdown_rx));

    RoutingProxy {
        addr,
        _shutdown: shutdown_tx,
    }
}

async fn start_tls_l4_proxy(
    router: Arc<dyn Router>,
    acceptor: tokio_rustls::TlsAcceptor,
) -> RoutingProxy {
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L4,
        pool: Some("test".to_owned()),
        routes: vec![],
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
        ..Default::default()
    });

    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let error_pages = Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap());
    let access_log = Arc::new(AccessLogSink::Off);

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let serve_cfg = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: Some(Duration::from_secs(10)),
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(2),
        max_connect_attempts: 1,
        tls_acceptor: Some(acceptor),
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };

    tokio::spawn(listener::serve(listener, router, serve_cfg, shutdown_rx));

    RoutingProxy {
        addr,
        _shutdown: shutdown_tx,
    }
}

// silence dead_code on EchoServer import
#[allow(dead_code)]
fn _use_echo_server(_: EchoServer) {}

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

fn init_metrics() -> &'static PrometheusHandle {
    METRICS_HANDLE.get_or_init(|| {
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .expect("install prometheus recorder");
        metrics::describe_counter!(
            "kntx_route_matches_total",
            "Requests that resolved to a configured route, labeled by listener and route_id."
        );
        metrics::describe_counter!(
            "kntx_route_no_match_total",
            "Requests that did not match any configured route."
        );
        handle
    })
}

/// route_matches counter emitted with route_id label after a matched request.
#[tokio::test]
async fn metrics_emit_route_matches_with_route_id_label() {
    let handle = init_metrics();

    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let (pool, rr) = make_pool("metrics-match-pool", backend.addr);
    let router = Arc::new(ConfigRouter::new(vec![route(
        vec![Box::new(HostMatcher::new("metrics.example.com").unwrap())],
        pool_handle("metrics-match-pool", pool, rr),
        "host=metrics.example.com",
    )]));
    let proxy = start_routing_proxy(router).await;

    let (status, _) = get(proxy.addr, "metrics.example.com", "/").await;
    assert_eq!(status, 200);

    let output = handle.render();
    let listener = proxy.addr.to_string();
    assert!(
        output.contains(&format!("listener=\"{listener}\""))
            && output.contains("route_id=\"host=metrics.example.com\""),
        "expected kntx_route_matches_total with listener={listener} and route_id in:\n{output}"
    );
}

/// route_no_match counter emitted when no route resolves.
#[tokio::test]
async fn metrics_emit_route_no_match_on_unmatched_request() {
    let handle = init_metrics();

    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let (pool, rr) = make_pool("metrics-nomatch-pool", backend.addr);
    let router = Arc::new(ConfigRouter::new(vec![route(
        vec![Box::new(HostMatcher::new("other.example.com").unwrap())],
        pool_handle("metrics-nomatch-pool", pool, rr),
        "host=other.example.com",
    )]));
    let proxy = start_routing_proxy(router).await;

    // send a request with a host that doesn't match any route
    let (status, _) = get(proxy.addr, "unmatched.example.com", "/").await;
    assert_eq!(status, 503);

    let output = handle.render();
    let listener = proxy.addr.to_string();
    assert!(
        output.contains("kntx_route_no_match_total")
            && output.contains(&format!("listener=\"{listener}\"")),
        "expected kntx_route_no_match_total with listener={listener} in:\n{output}"
    );
}

/// HELP lines for both route metrics appear in /metrics output.
#[tokio::test]
async fn describe_metrics_present() {
    let handle = init_metrics();
    // ensure both counters have been emitted at least once so HELP lines render
    metrics::counter!(
        "kntx_route_matches_total",
        "listener" => "describe-test",
        "route_id" => "default"
    )
    .increment(1);
    metrics::counter!("kntx_route_no_match_total", "listener" => "describe-test").increment(1);

    let output = handle.render();
    assert!(
        output.contains("# HELP kntx_route_matches_total"),
        "missing HELP line for kntx_route_matches_total in:\n{output}"
    );
    assert!(
        output.contains("# HELP kntx_route_no_match_total"),
        "missing HELP line for kntx_route_no_match_total in:\n{output}"
    );
}
