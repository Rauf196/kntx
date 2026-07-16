//! Integration tests for L7 WebSocket upgrade detection and L1 tunnel
//! forwarding. Tunnels are opaque byte pipes after the 101 — these tests
//! verify the handshake gating, the bidirectional copy, the close-time
//! access log emission, and the buffer-pool exhaustion contract.

mod helpers;

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use helpers::ws_backend::{WebSocketBackend, WsBackendMode};
use helpers::{EchoServer, make_single_pool_router};
use kntx::access_log::AccessLogSink;
use kntx::balancer::RoundRobin;
use kntx::config::{
    AccessLogConfig, AccessLogOutput, ErrorPagesConfig, KeepaliveConfig, ListenerConfig,
    ListenerMode,
};
use kntx::health::BackendPool;
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::proxy::l7::ErrorPages;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

#[allow(dead_code)]
fn _silence_echo_server(_: EchoServer) {}

const VALID_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

struct Proxy {
    addr: SocketAddr,
    shutdown_tx: watch::Sender<()>,
}

#[derive(Default)]
struct ProxyOpts {
    access_log_file: Option<std::path::PathBuf>,
    idle_timeout_secs: Option<u64>,
    buffer_pool: Option<BufferPool>,
}

async fn start_proxy(backend_addr: SocketAddr, opts: ProxyOpts) -> Proxy {
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let pool = Arc::new(BackendPool::new(
        "ws-test".into(),
        vec![backend_addr],
        3,
        Duration::from_secs(10),
        KeepaliveConfig::default(),
    ));
    let router = make_single_pool_router(
        Arc::clone(&pool),
        Arc::new(RoundRobin::new(Arc::clone(&pool))),
    );

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: Some("ws-test".to_owned()),
        routes: vec![],
        max_connections: None,
        idle_timeout_secs: opts.idle_timeout_secs,
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
        keepalive_idle_timeout_secs: None,
        keepalive_max_requests: None,
        client_header_timeout_secs: None,
        client_body_timeout_secs: None,
        proxy_send_timeout_secs: None,
        proxy_read_timeout_secs: None,
        request_timeout_secs: None,
        max_body_size_bytes: None,
    });

    let buffer_pool = Arc::new(opts.buffer_pool.unwrap_or_else(BufferPool::with_defaults));
    let error_pages = Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap());
    let access_log = Arc::new(
        AccessLogSink::from_config(&AccessLogConfig {
            output: match opts.access_log_file {
                Some(path) => AccessLogOutput::File { file: path },
                None => AccessLogOutput::Named("off".to_owned()),
            },
            format: None,
            file_channel_capacity: 256,
        })
        .unwrap(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let serve_cfg = ServeConfig {
        strategy: kntx::config::ForwardingStrategy::Userspace,
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
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };

    tokio::spawn(listener::serve(listener, router, serve_cfg, shutdown_rx));

    Proxy { addr, shutdown_tx }
}

fn upgrade_request(host: &str, extra: &str) -> String {
    format!(
        "GET /chat HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {VALID_KEY}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         {extra}\
         \r\n"
    )
}

async fn read_until_double_crlf(stream: &mut TcpStream, buf: &mut Vec<u8>) -> usize {
    loop {
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            return 0;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return pos + 4;
        }
        if buf.len() > 65536 {
            return 0;
        }
    }
}

fn parse_status(head: &[u8]) -> u16 {
    let s = std::str::from_utf8(head).unwrap_or("");
    let first_line = s.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let _version = parts.next();
    parts.next().and_then(|s| s.parse().ok()).unwrap_or(0)
}

async fn wait_for_log_lines(path: &std::path::Path, want: usize) -> Vec<serde_json::Value> {
    for _ in 0..50 {
        if let Ok(content) = std::fs::read_to_string(path) {
            let lines: Vec<serde_json::Value> = content
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            if lines.len() >= want {
                return lines;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("access log did not reach {want} lines in time");
}

#[tokio::test]
async fn websocket_echo_tunnel() {
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(upgrade_request("example.com", "").as_bytes())
        .await
        .unwrap();

    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_ne!(head_end, 0, "no response head");
    let status = parse_status(&buf[..head_end]);
    assert_eq!(status, 101, "expected 101 from proxy, got {status}");
    let head_str = std::str::from_utf8(&buf[..head_end]).unwrap();
    assert!(
        head_str.to_ascii_lowercase().contains("upgrade: websocket"),
        "Upgrade header missing or not preserved: {head_str:?}"
    );
    assert!(
        head_str
            .to_ascii_lowercase()
            .contains("connection: upgrade"),
        "Connection: Upgrade missing or not preserved: {head_str:?}"
    );

    // payload after the handshake — opaque bytes, echoed by backend.
    let payload = b"this-is-not-a-real-ws-frame-just-bytes";
    client.write_all(payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload, "echo mismatch through tunnel");

    let _ = client.shutdown().await;
    drop(proxy);
}

#[tokio::test]
async fn websocket_bidirectional_independence() {
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(upgrade_request("example.com", "").as_bytes())
        .await
        .unwrap();

    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_eq!(parse_status(&buf[..head_end]), 101);

    // hammer the tunnel with several small writes; expect every byte echoed
    // back independently of how it was chunked on the wire.
    for round in 0..5u8 {
        let chunk = [round; 64];
        client.write_all(&chunk).await.unwrap();
        let mut echo = vec![0u8; 64];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, chunk, "round {round} echo mismatch");
    }

    let _ = client.shutdown().await;
    drop(proxy);
}

#[tokio::test]
async fn websocket_backend_rejects_upgrade() {
    let backend = WebSocketBackend::start(WsBackendMode::Reject200).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(upgrade_request("example.com", "").as_bytes())
        .await
        .unwrap();

    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_ne!(head_end, 0);
    let status = parse_status(&buf[..head_end]);
    assert_eq!(
        status, 200,
        "non-101 from backend should pass through; got {status}"
    );
    // Status came from backend, not synthesized — body should follow.
    drop(proxy);
}

#[tokio::test]
async fn websocket_method_not_get_400() {
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    let req = format!(
        "POST /chat HTTP/1.1\r\n\
         Host: example.com\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {VALID_KEY}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_eq!(parse_status(&buf[..head_end]), 400);
    drop(proxy);
}

#[tokio::test]
async fn websocket_missing_sec_key_400() {
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    let req = "GET /chat HTTP/1.1\r\n\
        Host: example.com\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Version: 13\r\n\
        \r\n";
    client.write_all(req.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_eq!(parse_status(&buf[..head_end]), 400);
    drop(proxy);
}

#[tokio::test]
async fn websocket_request_with_body_400() {
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    let req = format!(
        "GET /chat HTTP/1.1\r\n\
         Host: example.com\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {VALID_KEY}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Content-Length: 4\r\n\
         \r\n\
         data"
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_eq!(parse_status(&buf[..head_end]), 400);
    drop(proxy);
}

#[tokio::test]
async fn websocket_subprotocol_passthrough() {
    let backend = WebSocketBackend::start(WsBackendMode::EchoWithSubprotocol).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    let req = format!(
        "GET /chat HTTP/1.1\r\n\
         Host: example.com\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {VALID_KEY}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: chat.v1\r\n\
         \r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_eq!(parse_status(&buf[..head_end]), 101);
    let head_str = std::str::from_utf8(&buf[..head_end]).unwrap();
    assert!(
        head_str.contains("Sec-WebSocket-Protocol: chat.v1"),
        "subprotocol must round-trip through proxy: {head_str:?}"
    );
    drop(proxy);
}

#[tokio::test]
async fn websocket_idle_timeout_closes_tunnel() {
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            idle_timeout_secs: Some(1),
            ..Default::default()
        },
    )
    .await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(upgrade_request("example.com", "").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_eq!(parse_status(&buf[..head_end]), 101);

    // tunnel up. Stay silent — neither side writes. After ~1s the proxy's
    // idle watchdog must close the tunnel; the client's next read sees EOF.
    let start = std::time::Instant::now();
    let mut trash = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut trash))
        .await
        .expect("tunnel did not close within 3s")
        .unwrap();
    assert_eq!(n, 0, "expected EOF after idle timeout");
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(800),
        "closed too early: {elapsed:?}"
    );
    drop(proxy);
}

#[tokio::test]
async fn websocket_graceful_shutdown_closes_tunnel() {
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(upgrade_request("example.com", "").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_eq!(parse_status(&buf[..head_end]), 101);

    // confirm tunnel is live via a round-trip
    client.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");

    // signal shutdown — tunnel must close at the proxy
    proxy.shutdown_tx.send(()).unwrap();

    let mut trash = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut trash))
        .await
        .expect("tunnel did not close within 3s")
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn websocket_buffer_pool_exhausted_returns_503() {
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    // pool capacity 1: the serve_l7_conn body buffer takes the only slot,
    // leaving zero for the tunnel's `try_checkout_pair`.
    let tiny_pool = BufferPool::new(1, 4096);
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            buffer_pool: Some(tiny_pool),
            ..Default::default()
        },
    )
    .await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(upgrade_request("example.com", "").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_eq!(
        parse_status(&buf[..head_end]),
        503,
        "buffer-pool exhaustion before 101 must surface as 503"
    );
    drop(proxy);
}

#[tokio::test]
async fn websocket_access_log_at_close() {
    let logfile = tempfile::NamedTempFile::new().unwrap();
    let logpath = logfile.path().to_path_buf();
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            access_log_file: Some(logpath.clone()),
            ..Default::default()
        },
    )
    .await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(upgrade_request("example.com", "").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_eq!(parse_status(&buf[..head_end]), 101);

    // push a known volume of bytes both directions
    let payload = vec![0xAB; 4096];
    client.write_all(&payload).await.unwrap();
    let mut echo = vec![0u8; payload.len()];
    client.read_exact(&mut echo).await.unwrap();

    // client closes — backend reads EOF and closes too, tunnel exits, log fires
    let _ = client.shutdown().await;
    drop(client);

    let lines = wait_for_log_lines(&logpath, 1).await;
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert_eq!(line["status"], 101);
    assert_eq!(line["method"], "GET");
    assert_eq!(line["tunnel"], true);
    assert!(line.get("outcome").is_some(), "outcome field must be set");
    let bytes_in = line["bytes_in"].as_u64().unwrap_or(0);
    let bytes_out = line["bytes_out"].as_u64().unwrap_or(0);
    assert!(
        bytes_in >= payload.len() as u64,
        "bytes_in ({bytes_in}) should include the {} payload bytes",
        payload.len()
    );
    assert!(
        bytes_out >= payload.len() as u64,
        "bytes_out ({bytes_out}) should include the echo + 101 head"
    );
    drop(proxy);
}

#[tokio::test]
async fn websocket_force_close_emits_access_log() {
    let logfile = tempfile::NamedTempFile::new().unwrap();
    let logpath = logfile.path().to_path_buf();
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            access_log_file: Some(logpath.clone()),
            ..Default::default()
        },
    )
    .await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(upgrade_request("example.com", "").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut buf).await;
    assert_eq!(parse_status(&buf[..head_end]), 101);

    // some traffic so byte counts are non-zero
    client.write_all(&[0xCD; 256]).await.unwrap();
    let mut echo = [0u8; 256];
    client.read_exact(&mut echo).await.unwrap();

    proxy.shutdown_tx.send(()).unwrap();
    let mut trash = [0u8; 16];
    let _ = tokio::time::timeout(Duration::from_secs(3), client.read(&mut trash)).await;

    let lines = wait_for_log_lines(&logpath, 1).await;
    let line = &lines[0];
    assert_eq!(line["status"], 101);
    assert_eq!(line["tunnel"], true);
    let outcome = line["outcome"].as_str().unwrap_or("");
    assert_eq!(
        outcome, "shutdown",
        "tunnel forced-closed via shutdown should record outcome=shutdown"
    );
}

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

fn init_metrics() -> &'static PrometheusHandle {
    METRICS_HANDLE.get_or_init(|| {
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .expect("install prometheus recorder");
        metrics::describe_gauge!(
            "kntx_websocket_tunnels_active",
            "Currently active WebSocket tunnels (labels: listener)."
        );
        metrics::describe_counter!(
            "kntx_websocket_tunnels_total",
            "WebSocket tunnels opened (labels: listener)."
        );
        handle
    })
}

// Parses `metric{labels...} value` lines from the Prometheus text exposition
// and returns the floating-point value for the most recent sample whose
// metric name matches `name` and whose label set contains `(label, value)`.
// Returns None if no matching sample is found.
fn metric_value(rendered: &str, name: &str, label: (&str, &str)) -> Option<f64> {
    let key = format!("{}=\"{}\"", label.0, label.1);
    rendered
        .lines()
        .rfind(|l| l.starts_with(name) && l.contains(&key))
        .and_then(|l| l.rsplit_once(' ').and_then(|(_, v)| v.parse().ok()))
}

/// `kntx_websocket_tunnels_active` rises to 1 once the 101 has been
/// relayed and falls back to 0 when the tunnel exits. The total counter
/// records the opened tunnel exactly once. The gauge sample is taken
/// while traffic is flowing through the tunnel — racing the open/close
/// would let a buggy implementation pass without observing the live
/// gauge value.
#[tokio::test]
async fn websocket_metrics_gauge() {
    let handle = init_metrics();
    let backend = WebSocketBackend::start(WsBackendMode::EchoTunnel).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;
    let listener_label = proxy.addr.to_string();

    let before_active = metric_value(
        &handle.render(),
        "kntx_websocket_tunnels_active",
        ("listener", &listener_label),
    )
    .unwrap_or(0.0);
    let before_total = metric_value(
        &handle.render(),
        "kntx_websocket_tunnels_total",
        ("listener", &listener_label),
    )
    .unwrap_or(0.0);

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(upgrade_request("example.com", "").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    let head_end = read_until_double_crlf(&mut client, &mut head).await;
    assert_ne!(head_end, 0, "no response head");
    assert_eq!(parse_status(&head[..head_end]), 101);

    // Exchange one frame so the tunnel is unambiguously in the bidirectional
    // copy phase by the time the gauge is sampled.
    client.write_all(&[0xAB; 64]).await.unwrap();
    let mut echo = [0u8; 64];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(echo, [0xAB; 64]);

    let active = metric_value(
        &handle.render(),
        "kntx_websocket_tunnels_active",
        ("listener", &listener_label),
    )
    .unwrap_or(0.0);
    assert!(
        (active - (before_active + 1.0)).abs() < 0.001,
        "active gauge must read {} during the tunnel, got {}",
        before_active + 1.0,
        active
    );
    let total = metric_value(
        &handle.render(),
        "kntx_websocket_tunnels_total",
        ("listener", &listener_label),
    )
    .unwrap_or(0.0);
    assert!(
        (total - (before_total + 1.0)).abs() < 0.001,
        "total counter must increment by 1 when the tunnel opens, got {} -> {}",
        before_total,
        total
    );

    drop(client);

    // wait briefly for the tunnel task to observe the FIN and decrement.
    let mut after = before_active;
    for _ in 0..40 {
        after = metric_value(
            &handle.render(),
            "kntx_websocket_tunnels_active",
            ("listener", &listener_label),
        )
        .unwrap_or(0.0);
        if (after - before_active).abs() < 0.001 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        (after - before_active).abs() < 0.001,
        "active gauge must return to {} after tunnel close, got {}",
        before_active,
        after
    );
}
