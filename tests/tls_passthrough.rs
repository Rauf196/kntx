mod helpers;

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

use helpers::tls::{
    SinkBackend, TlsEchoBackend, client_config_trusting, client_hello_bytes, generate_cert,
    tls_connect, tls_connect_no_sni,
};
use kntx::balancer::RoundRobin;
use kntx::config::{ForwardingStrategy, KeepaliveConfig, ListenerConfig, ListenerMode};
use kntx::health::BackendPool;
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::proxy::l7::ErrorPages;
use kntx::proxy::l7::matcher::{CompositeMatcher, Matcher, SniMatcher};
use kntx::proxy::l7::router::{ConfigRouter, PoolHandle, RouteEntry, Router};

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

fn init_metrics() -> &'static PrometheusHandle {
    METRICS_HANDLE.get_or_init(|| {
        PrometheusBuilder::new()
            .install_recorder()
            .expect("install prometheus recorder")
    })
}

/// true when the rendered metrics contain a line with all given fragments.
fn metric_line_present(handle: &PrometheusHandle, fragments: &[&str]) -> bool {
    handle
        .render()
        .lines()
        .any(|line| fragments.iter().all(|f| line.contains(f)))
}

fn test_resources() -> Resources {
    Resources {
        buffer_pool: BufferPool::new(64, 64 * 1024),
        #[cfg(target_os = "linux")]
        pipe_pool: kntx::pool::pipe::PipePool::new(32).unwrap(),
        socket_buffer_size: None,
    }
}

fn make_pool(name: &str, addr: SocketAddr) -> PoolHandle {
    let pool = Arc::new(BackendPool::new(
        Arc::from(name),
        vec![addr],
        3,
        Duration::from_secs(10),
        KeepaliveConfig::default(),
    ));
    let rr = Arc::new(RoundRobin::new(pool.clone()));
    PoolHandle {
        name: Arc::from(name),
        backends: pool,
        rr,
    }
}

fn sni_route(pattern: &str, handle: PoolHandle) -> RouteEntry {
    RouteEntry {
        matcher: CompositeMatcher::new(vec![
            Box::new(SniMatcher::new(pattern).unwrap()) as Box<dyn Matcher + Send + Sync>
        ]),
        pool: handle,
        route_id: Arc::from(format!("sni={pattern}").as_str()),
    }
}

fn catch_all(handle: PoolHandle) -> RouteEntry {
    RouteEntry {
        matcher: CompositeMatcher::new(vec![]),
        pool: handle,
        route_id: Arc::from("default"),
    }
}

struct PassthroughProxy {
    addr: SocketAddr,
    _shutdown: watch::Sender<()>,
}

async fn start_passthrough_proxy(
    router: Arc<dyn Router>,
    strategy: ForwardingStrategy,
    clienthello_timeout_secs: u64,
    idle_timeout: Option<Duration>,
) -> PassthroughProxy {
    init_metrics();

    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::TlsPassthrough,
        pool: Some("test".to_owned()),
        clienthello_timeout_secs,
        idle_timeout_secs: idle_timeout.map(|d| d.as_secs()),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        ..Default::default()
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let serve_cfg = ServeConfig {
        strategy,
        resources: test_resources(),
        max_connections: None,
        idle_timeout,
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(2),
        max_connect_attempts: 1,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages: Arc::new(ErrorPages::load(&Default::default()).unwrap()),
        access_log: Arc::new(kntx::access_log::AccessLogSink::Off),
        buffer_pool: Arc::new(BufferPool::with_defaults()),
    };

    tokio::spawn(listener::serve(listener, router, serve_cfg, shutdown_rx));

    PassthroughProxy {
        addr,
        _shutdown: shutdown_tx,
    }
}

/// full TLS session through the proxy: the client verifies the backend's
/// cert (the proxy owns no certs) and echoes over the session.
async fn verify_echo_roundtrip(proxy_addr: SocketAddr, server_name: &str, cert_der: &[u8]) {
    let config = client_config_trusting(cert_der);
    let mut tls = tls_connect(proxy_addr, server_name, config).await;
    tls.write_all(b"hello through passthrough").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tls.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello through passthrough");
}

/// client establishes TLS with the backend through the proxy; the
/// cert it verifies belongs to the backend, not the proxy.
#[tokio::test]
async fn passthrough_client_sees_backend_cert() {
    let cert = generate_cert(&["a.test"]);
    let backend = TlsEchoBackend::start(&cert).await;
    let router = Arc::new(ConfigRouter::new(vec![catch_all(make_pool(
        "pt-basic",
        backend.addr,
    ))]));
    let proxy = start_passthrough_proxy(router, ForwardingStrategy::Userspace, 10, None).await;

    verify_echo_roundtrip(proxy.addr, "a.test", &cert.cert_der).await;
}

/// two SNIs steer to different pools.
#[tokio::test]
async fn passthrough_sni_routes_two_pools() {
    let handle = init_metrics();

    let cert_a = generate_cert(&["a.test"]);
    let cert_b = generate_cert(&["b.test"]);
    let backend_a = TlsEchoBackend::start(&cert_a).await;
    let backend_b = TlsEchoBackend::start(&cert_b).await;

    let router = Arc::new(ConfigRouter::new(vec![
        sni_route("a.test", make_pool("pt-pool-a", backend_a.addr)),
        sni_route("b.test", make_pool("pt-pool-b", backend_b.addr)),
    ]));
    let proxy = start_passthrough_proxy(router, ForwardingStrategy::Userspace, 10, None).await;

    // each client trusts only its own backend's cert, so a successful
    // handshake is the routing assertion
    verify_echo_roundtrip(proxy.addr, "a.test", &cert_a.cert_der).await;
    verify_echo_roundtrip(proxy.addr, "b.test", &cert_b.cert_der).await;

    let label = proxy.addr.to_string();
    assert!(
        metric_line_present(
            handle,
            &[
                "kntx_tls_passthrough_connections_total",
                &label,
                "route_id=\"sni=a.test\"",
            ],
        ),
        "expected connections_total with route_id=sni=a.test"
    );
}

/// shared body for the strategy matrix below.
async fn verify_strategy(strategy: ForwardingStrategy) {
    let cert = generate_cert(&["strat.test"]);
    let backend = TlsEchoBackend::start(&cert).await;
    let router = Arc::new(ConfigRouter::new(vec![catch_all(make_pool(
        "pt-strategy",
        backend.addr,
    ))]));
    let proxy = start_passthrough_proxy(router, strategy, 10, None).await;

    verify_echo_roundtrip(proxy.addr, "strat.test", &cert.cert_der).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passthrough_strategy_userspace() {
    verify_strategy(ForwardingStrategy::Userspace).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passthrough_strategy_vectored() {
    verify_strategy(ForwardingStrategy::Vectored).await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passthrough_strategy_splice() {
    verify_strategy(ForwardingStrategy::Splice).await;
}

/// non-TLS input closes promptly and the listener stays healthy.
#[tokio::test]
async fn passthrough_non_tls_input_rejected() {
    let handle = init_metrics();

    let cert = generate_cert(&["healthy.test"]);
    let backend = TlsEchoBackend::start(&cert).await;
    let router = Arc::new(ConfigRouter::new(vec![catch_all(make_pool(
        "pt-nontls",
        backend.addr,
    ))]));
    let proxy = start_passthrough_proxy(router, ForwardingStrategy::Userspace, 10, None).await;

    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("proxy must close promptly, not hang")
        .unwrap();
    assert_eq!(n, 0, "expected clean EOF, got {n} bytes");

    assert!(
        metric_line_present(
            handle,
            &[
                "kntx_tls_passthrough_rejects_total",
                &proxy.addr.to_string(),
                "reason=\"not_tls\"",
            ],
        ),
        "expected rejects_total with reason=not_tls"
    );

    // proxy still serves real TLS traffic afterwards
    verify_echo_roundtrip(proxy.addr, "healthy.test", &cert.cert_der).await;
}

/// a hello without SNI lands in the catch-all pool when one exists.
#[tokio::test]
async fn passthrough_no_sni_catchall() {
    let handle = init_metrics();

    // cert with an IP SAN so a no-SNI client can still verify it
    let cert_ip = generate_cert(&["127.0.0.1"]);
    let cert_a = generate_cert(&["a.test"]);
    let backend_a = TlsEchoBackend::start(&cert_a).await;
    let backend_default = TlsEchoBackend::start(&cert_ip).await;

    let router = Arc::new(ConfigRouter::new(vec![
        sni_route("a.test", make_pool("pt-sni-a", backend_a.addr)),
        catch_all(make_pool("pt-default", backend_default.addr)),
    ]));
    let proxy = start_passthrough_proxy(router, ForwardingStrategy::Userspace, 10, None).await;

    // no-SNI client lands in the catch-all pool and verifies its cert
    let config = client_config_trusting(&cert_ip.cert_der);
    let mut tls = tls_connect_no_sni(proxy.addr, config).await;
    tls.write_all(b"no sni here").await.unwrap();
    let mut buf = [0u8; 32];
    let n = tls.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"no sni here");

    assert!(
        metric_line_present(
            handle,
            &["kntx_tls_passthrough_no_sni_total", &proxy.addr.to_string(),],
        ),
        "expected no_sni_total for this listener"
    );
}

/// without a catch-all, a no-SNI hello matches nothing and closes.
#[tokio::test]
async fn passthrough_no_sni_no_catchall_rejected() {
    let handle = init_metrics();

    let cert_a = generate_cert(&["a.test"]);
    let backend_a = TlsEchoBackend::start(&cert_a).await;
    let router = Arc::new(ConfigRouter::new(vec![sni_route(
        "a.test",
        make_pool("pt-sni-only", backend_a.addr),
    )]));
    let proxy = start_passthrough_proxy(router, ForwardingStrategy::Userspace, 10, None).await;

    // raw no-SNI hello: no route matches, proxy closes without a ServerHello
    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    stream.write_all(&client_hello_bytes(None)).await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("proxy must close promptly")
        .unwrap();
    assert_eq!(n, 0, "expected clean EOF for unroutable no-SNI hello");

    assert!(
        metric_line_present(
            handle,
            &["kntx_route_no_match_total", &proxy.addr.to_string()],
        ),
        "expected route_no_match_total for this listener"
    );
}

/// a hello dribbled across several TCP segments still parses, and the
/// backend receives the peeked bytes plus everything after them byte-exact.
#[tokio::test]
async fn passthrough_fragmented_hello_byte_exact() {
    let sink = SinkBackend::start().await;
    let router = Arc::new(ConfigRouter::new(vec![catch_all(make_pool(
        "pt-sink", sink.addr,
    ))]));
    let proxy = start_passthrough_proxy(router, ForwardingStrategy::Userspace, 10, None).await;

    let hello = client_hello_bytes(Some("frag.test"));
    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();

    // three chunks with pauses, so the peek loop needs multiple reads
    let third = hello.len() / 3;
    for chunk in [
        &hello[..third],
        &hello[third..2 * third],
        &hello[2 * third..],
    ] {
        stream.write_all(chunk).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // backend-to-client path is live: sink wrote PONG on accept
    let mut pong = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut pong))
        .await
        .expect("PONG must arrive")
        .unwrap();
    assert_eq!(&pong, b"PONG");

    // bytes after the hello flow through the normal forwarding path
    stream.write_all(b"AFTER-HELLO").await.unwrap();
    stream.shutdown().await.unwrap();

    let mut expected = hello.clone();
    expected.extend_from_slice(b"AFTER-HELLO");
    // poll until the proxy has flushed everything through to the sink
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        {
            let received = sink.received.lock().unwrap();
            if *received == expected {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "backend received {} bytes, expected {} (hello + AFTER-HELLO), content mismatch",
                received.len(),
                expected.len(),
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// clienthello_timeout_secs closes a client that stalls mid-hello.
#[tokio::test]
async fn passthrough_clienthello_timeout() {
    let handle = init_metrics();

    let cert = generate_cert(&["slow.test"]);
    let backend = TlsEchoBackend::start(&cert).await;
    let router = Arc::new(ConfigRouter::new(vec![catch_all(make_pool(
        "pt-slow",
        backend.addr,
    ))]));
    let proxy = start_passthrough_proxy(router, ForwardingStrategy::Userspace, 1, None).await;

    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    // 3 valid-looking bytes, then stall
    stream.write_all(&[22, 3, 1]).await.unwrap();

    let start = std::time::Instant::now();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut buf))
        .await
        .expect("proxy must enforce the ClientHello timeout")
        .unwrap();
    assert_eq!(n, 0, "expected EOF after timeout");
    assert!(
        start.elapsed() >= Duration::from_millis(900),
        "closed too early: {:?}",
        start.elapsed()
    );

    assert!(
        metric_line_present(
            handle,
            &[
                "kntx_tls_passthrough_rejects_total",
                &proxy.addr.to_string(),
                "reason=\"timeout\"",
            ],
        ),
        "expected rejects_total with reason=timeout"
    );
}

/// the idle watchdog still governs the connection after the peek hand-off.
#[tokio::test]
async fn passthrough_idle_timeout_after_handoff() {
    let cert = generate_cert(&["idle.test"]);
    let backend = TlsEchoBackend::start(&cert).await;
    let router = Arc::new(ConfigRouter::new(vec![catch_all(make_pool(
        "pt-idle",
        backend.addr,
    ))]));
    let proxy = start_passthrough_proxy(
        router,
        ForwardingStrategy::Userspace,
        10,
        Some(Duration::from_secs(1)),
    )
    .await;

    let config = client_config_trusting(&cert.cert_der);
    let mut tls = tls_connect(proxy.addr, "idle.test", config).await;
    tls.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 16];
    let n = tls.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ping");

    // go silent; the idle watchdog must close the tunnel
    let result = tokio::time::timeout(Duration::from_secs(4), tls.read(&mut buf))
        .await
        .expect("idle watchdog must close the connection");
    // clean EOF and connection reset are both valid close forms
    match result {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("unexpected {n} bytes on an idle connection"),
    }
}
