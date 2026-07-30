mod helpers;

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

use kntx::access_log::AccessLogSink;
use kntx::balancer::RoundRobin;
use kntx::config::{
    ErrorPagesConfig, ForwardingStrategy, KeepaliveConfig, ListenerConfig, ListenerMode,
};
use kntx::health::BackendPool;
use kntx::listener::{self, ListenerRuntime, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::proxy::l7::ErrorPages;
use kntx::proxy_protocol::TrustedCidr;
use kntx::rate_limit::{KeyedLimiter, MonotonicClock, Period, Rate, ZoneHandle, ZoneLimiter};

use helpers::http_backend::{HttpBackend, ResponseSpec};
use helpers::{EchoServer, make_single_pool_router};

struct Proxy {
    addr: SocketAddr,
    _shutdown: watch::Sender<()>,
}

/// every listener here requires the header; the point of the feature is that a
/// bare connection on the same port is not an option.
async fn start_proxy(
    backend: SocketAddr,
    mode: ListenerMode,
    label: &'static str,
    trusted: Vec<TrustedCidr>,
    rate_limit: Option<ZoneHandle>,
) -> Proxy {
    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![backend],
        3,
        Duration::from_secs(10),
        KeepaliveConfig::default(),
    ));
    let router = make_single_pool_router(
        Arc::clone(&pool),
        Arc::new(RoundRobin::new(Arc::clone(&pool))),
    );

    let tcp_listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = tcp_listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode,
        pool: Some("test".to_owned()),
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        proxy_protocol: true,
        proxy_protocol_from: trusted,
        ..Default::default()
    });

    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let serve_cfg = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: Resources {
            buffer_pool: (*buffer_pool).clone(),
            #[cfg(target_os = "linux")]
            pipe_pool: kntx::pool::pipe::PipePool::with_defaults().unwrap(),
            socket_buffer_size: None,
        },
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(2),
        max_connect_attempts: 1,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: label.into(),
        error_pages: Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap()),
        access_log: Arc::new(AccessLogSink::Off),
        buffer_pool,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    tokio::spawn(listener::serve(
        tcp_listener,
        ListenerRuntime::cell(router, listener_cfg, None, rate_limit),
        serve_cfg,
        shutdown_rx,
    ));

    Proxy {
        addr,
        _shutdown: shutdown_tx,
    }
}

fn v1_header(source: &str, port: u16) -> Vec<u8> {
    format!("PROXY TCP4 {source} 198.51.100.1 {port} 443\r\n").into_bytes()
}

fn v2_header(command: u8, family: u8, block: &[u8]) -> Vec<u8> {
    let mut out = b"\r\n\r\n\x00\r\nQUIT\n".to_vec();
    out.push(0x20 | command);
    out.push(family << 4 | 1);
    out.extend_from_slice(&(block.len() as u16).to_be_bytes());
    out.extend_from_slice(block);
    out
}

fn v2_proxy_inet(source: [u8; 4], port: u16) -> Vec<u8> {
    let mut block = source.to_vec();
    block.extend_from_slice(&[198, 51, 100, 1]);
    block.extend_from_slice(&port.to_be_bytes());
    block.extend_from_slice(&443u16.to_be_bytes());
    v2_header(1, 1, &block)
}

const REQUEST: &[u8] = b"GET /probe HTTP/1.1\r\nHost: example.test\r\n\r\n";

async fn read_some(conn: &mut TcpStream) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut buf))
        .await
        .expect("response should arrive, not hang")
        .expect("read failed");
    buf.truncate(n);
    buf
}

/// a refused connection is dropped without a response - at rejection time the
/// proxy has no idea whether the peer speaks HTTP, so there is nothing to say.
async fn assert_refused(conn: &mut TcpStream) {
    let mut buf = [0u8; 64];
    let result = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut buf))
        .await
        .expect("refusal should be prompt, not a hang");
    match result {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!(
            "expected a refused connection, got {n} bytes: {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
    }
}

async fn echo_through(conn: &mut TcpStream, payload: &[u8]) {
    conn.write_all(payload).await.expect("write payload");
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut buf))
        .await
        .expect("echo should arrive, not hang")
        .expect("echo read failed");
    assert_eq!(buf, payload, "payload must survive the header strip");
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

#[tokio::test]
async fn v1_header_recovers_the_client_address() {
    init_metrics();
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let proxy = start_proxy(backend.addr, ListenerMode::L7, "pp-v1", vec![], None).await;

    let mut conn = TcpStream::connect(proxy.addr).await.unwrap();
    conn.write_all(&v1_header("192.0.2.7", 51234))
        .await
        .unwrap();
    conn.write_all(REQUEST).await.unwrap();

    let response = read_some(&mut conn).await;
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let req = backend.last_request().expect("backend saw the request");
    assert_eq!(req.header("x-forwarded-for"), Some("192.0.2.7"));
    assert_eq!(req.header("x-real-ip"), Some("192.0.2.7"));

    let render = init_metrics().render();
    assert_eq!(
        counter_value(
            &render,
            "kntx_proxy_protocol_headers_total",
            &["listener=\"pp-v1\"", "version=\"v1\""]
        ),
        1.0
    );
}

#[tokio::test]
async fn v2_header_recovers_the_client_address() {
    init_metrics();
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let proxy = start_proxy(backend.addr, ListenerMode::L7, "pp-v2", vec![], None).await;

    let mut conn = TcpStream::connect(proxy.addr).await.unwrap();
    conn.write_all(&v2_proxy_inet([203, 0, 113, 9], 40000))
        .await
        .unwrap();
    conn.write_all(REQUEST).await.unwrap();

    let response = read_some(&mut conn).await;
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let req = backend.last_request().expect("backend saw the request");
    assert_eq!(req.header("x-forwarded-for"), Some("203.0.113.9"));

    let render = init_metrics().render();
    assert_eq!(
        counter_value(
            &render,
            "kntx_proxy_protocol_headers_total",
            &["listener=\"pp-v2\"", "version=\"v2\""]
        ),
        1.0
    );
}

/// LOCAL is the balancer speaking for itself, typically its own health check.
/// Reading it as a client address would attribute the probe to whatever the
/// address block happened to contain.
#[tokio::test]
async fn v2_local_command_keeps_the_socket_peer_as_the_client() {
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let proxy = start_proxy(backend.addr, ListenerMode::L7, "pp-local", vec![], None).await;

    let mut conn = TcpStream::connect(proxy.addr).await.unwrap();
    conn.write_all(&v2_header(0, 0, &[])).await.unwrap();
    conn.write_all(REQUEST).await.unwrap();

    let response = read_some(&mut conn).await;
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let req = backend.last_request().expect("backend saw the request");
    assert_eq!(req.header("x-forwarded-for"), Some("127.0.0.1"));
}

#[tokio::test]
async fn a_bare_connection_is_refused_when_the_header_is_required() {
    init_metrics();
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let proxy = start_proxy(backend.addr, ListenerMode::L7, "pp-bare", vec![], None).await;

    let mut conn = TcpStream::connect(proxy.addr).await.unwrap();
    conn.write_all(REQUEST).await.unwrap();
    assert_refused(&mut conn).await;
    assert!(
        backend.last_request().is_none(),
        "a spoofable connection must never reach a backend"
    );

    let render = init_metrics().render();
    assert_eq!(
        counter_value(
            &render,
            "kntx_proxy_protocol_rejects_total",
            &["listener=\"pp-bare\"", "reason=\"not_proxy_protocol\""]
        ),
        1.0
    );
}

#[tokio::test]
async fn an_untrusted_peer_is_refused_before_its_header_is_read() {
    init_metrics();
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let trusted = vec!["10.0.0.0/8".parse::<TrustedCidr>().unwrap()];
    let proxy = start_proxy(backend.addr, ListenerMode::L7, "pp-trust", trusted, None).await;

    let mut conn = TcpStream::connect(proxy.addr).await.unwrap();
    // a well-formed header from the wrong peer is still a spoof
    conn.write_all(&v1_header("192.0.2.7", 51234))
        .await
        .unwrap();
    conn.write_all(REQUEST).await.unwrap();
    assert_refused(&mut conn).await;
    assert!(backend.last_request().is_none());

    let render = init_metrics().render();
    assert_eq!(
        counter_value(
            &render,
            "kntx_proxy_protocol_rejects_total",
            &["listener=\"pp-trust\"", "reason=\"untrusted\""]
        ),
        1.0
    );
}

/// the header shares a segment with the payload here, which is what a real
/// balancer does. Over-reading it would eat the first bytes of the connection.
#[tokio::test]
async fn l4_strips_the_header_and_forwards_the_payload_byte_exact() {
    let echo = EchoServer::start().await;
    let proxy = start_proxy(echo.addr, ListenerMode::L4, "pp-l4", vec![], None).await;

    let payload = b"the header must not reach the backend";
    let mut coalesced = v1_header("192.0.2.7", 51234);
    coalesced.extend_from_slice(payload);

    let mut conn = TcpStream::connect(proxy.addr).await.unwrap();
    conn.write_all(&coalesced).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut echoed))
        .await
        .expect("echo should arrive, not hang")
        .expect("echo read failed");
    assert_eq!(&echoed, payload);
}

/// a header split across segments makes the read loop drain what it has and
/// wait for the rest. The byte after the split must still survive.
#[tokio::test]
async fn a_fragmented_header_is_consumed_exactly() {
    let echo = EchoServer::start().await;
    let proxy = start_proxy(echo.addr, ListenerMode::L4, "pp-frag", vec![], None).await;

    let header = v2_proxy_inet([192, 0, 2, 7], 51234);
    let mut conn = TcpStream::connect(proxy.addr).await.unwrap();
    for chunk in header.chunks(5) {
        conn.write_all(chunk).await.unwrap();
        conn.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    echo_through(&mut conn, b"payload after a dribbled header").await;
}

/// the bug Phase 12 exists to fix: behind an L4 balancer every connection has
/// the same socket peer, so keying on it puts the whole internet in one budget.
#[tokio::test]
async fn per_ip_rate_limiting_keys_on_the_recovered_address() {
    let echo = EchoServer::start().await;
    // burst 1 admits burst+1 = 2 per key before the first denial
    let zone = ZoneHandle {
        name: "pp-zone".into(),
        limiter: Arc::new(ZoneLimiter::PerIp(KeyedLimiter::new(
            Rate {
                count: NonZeroU32::new(1).unwrap(),
                period: Period::Second,
            },
            1,
            1024,
            MonotonicClock::new(),
        ))),
    };
    let proxy = start_proxy(echo.addr, ListenerMode::L4, "pp-rl", vec![], Some(zone)).await;

    async fn attempt(proxy: SocketAddr, source: &str) -> Result<TcpStream, std::io::Error> {
        let mut conn = TcpStream::connect(proxy).await.unwrap();
        conn.write_all(&v1_header(source, 51234)).await.unwrap();
        conn.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        match tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut buf))
            .await
            .expect("verdict should be prompt, not a hang")
        {
            Ok(_) => {
                assert_eq!(&buf, b"ping");
                Ok(conn)
            }
            Err(e) => Err(e),
        }
    }

    // held open so each attempt is a distinct connection through one peer
    let _a1 = attempt(proxy.addr, "192.0.2.7")
        .await
        .expect("first admitted");
    let _a2 = attempt(proxy.addr, "192.0.2.7")
        .await
        .expect("second admitted, inside burst");
    let denied = attempt(proxy.addr, "192.0.2.7")
        .await
        .expect_err("third exceeds the budget for this client");
    assert_eq!(
        denied.kind(),
        std::io::ErrorKind::ConnectionReset,
        "a denied conn must die with an RST, not a clean FIN"
    );

    // keying on the socket peer would have spent this client's budget too
    let _b1 = attempt(proxy.addr, "192.0.2.8")
        .await
        .expect("a different client has its own budget");
}
