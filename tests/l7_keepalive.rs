//! Integration tests for the L7 client keep-alive request loop, backend
//! connection cache, phase-specific timeouts, request body size enforcement,
//! and the broken-keepalive retry rule.

mod helpers;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use helpers::http_backend::{BackendRequest, HttpBackend, ResponseSpec};
use helpers::keepalive_client::KeepAliveClient;
use helpers::tls::{client_config_trusting, generate_cert, write_cert_to_tempdir};
use helpers::{BlackholeBackend, SlowResponseBackend, make_single_pool_router};
use kntx::access_log::AccessLogSink;
use kntx::balancer::RoundRobin;
use kntx::config::{
    AccessLogConfig, AccessLogOutput, CertificateConfig, ErrorPagesConfig, KeepaliveConfig,
    ListenerConfig, ListenerMode, TlsConfig,
};
use kntx::health::BackendPool;
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::proxy::l7::ErrorPages;
use kntx::tls::build_acceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

struct Proxy {
    addr: SocketAddr,
    _shutdown: watch::Sender<()>,
}

#[derive(Default)]
struct ProxyOpts {
    keepalive_idle_secs: Option<u64>,
    keepalive_max_requests: Option<u32>,
    access_log_file: Option<std::path::PathBuf>,
    // phase timeouts - all None by default (resolve to 60s); set per test.
    client_header_timeout_secs: Option<u64>,
    client_body_timeout_secs: Option<u64>,
    proxy_send_timeout_secs: Option<u64>,
    proxy_read_timeout_secs: Option<u64>,
    request_timeout_secs: Option<u64>,
    // max request body size - None inherits the production default (1 MiB);
    // Some(0) opts into unlimited; Some(N) sets an explicit cap.
    max_body_size_bytes: Option<u64>,
}

async fn start_proxy(backend_addr: SocketAddr, opts: ProxyOpts) -> Proxy {
    let (proxy, _) = start_proxy_pool(vec![backend_addr], KeepaliveConfig::default(), opts).await;
    proxy
}

/// Variant that returns the underlying pool so backend-pool integration tests
/// can inspect circuit/saturation state directly.
async fn start_proxy_pool(
    backends: Vec<SocketAddr>,
    ka_cfg: KeepaliveConfig,
    opts: ProxyOpts,
) -> (Proxy, Arc<BackendPool>) {
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let pool = Arc::new(BackendPool::new(
        "test".into(),
        backends,
        3,
        Duration::from_secs(10),
        ka_cfg,
    ));
    let router = make_single_pool_router(
        Arc::clone(&pool),
        Arc::new(RoundRobin::new(Arc::clone(&pool))),
    );

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: Some("test".to_owned()),
        routes: vec![],
        max_connections: None,
        // no listener watchdog: the in-loop keepalive_idle select governs
        // between-request idle so these tests measure the in-loop path directly.
        idle_timeout_secs: None,
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
        keepalive_idle_timeout_secs: opts.keepalive_idle_secs,
        keepalive_max_requests: opts.keepalive_max_requests,
        client_header_timeout_secs: opts.client_header_timeout_secs,
        client_body_timeout_secs: opts.client_body_timeout_secs,
        proxy_send_timeout_secs: opts.proxy_send_timeout_secs,
        proxy_read_timeout_secs: opts.proxy_read_timeout_secs,
        request_timeout_secs: opts.request_timeout_secs,
        max_body_size_bytes: opts.max_body_size_bytes,
        clienthello_timeout_secs: 10,
        rate_limit: None,
    });

    let buffer_pool = Arc::new(BufferPool::with_defaults());
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
        rate_limit: None,
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

    (
        Proxy {
            addr,
            _shutdown: shutdown_tx,
        },
        pool,
    )
}

/// Backend that records every request it receives. Tests that verify
/// per-request identifier independence need the full sequence, not just the
/// last request.
async fn backend_recording() -> (HttpBackend, Arc<Mutex<Vec<BackendRequest>>>) {
    let log: Arc<Mutex<Vec<BackendRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let log2 = Arc::clone(&log);
    let handler = Arc::new(move |req: BackendRequest| {
        log2.lock().unwrap().push(req);
        ResponseSpec::ok("ok")
    });
    let backend = HttpBackend::start_with_handler(handler).await;
    (backend, log)
}

async fn wait_for_log_lines(path: &std::path::Path, want: usize) -> Vec<serde_json::Value> {
    for _ in 0..40 {
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

// sequential requests on one connection

#[tokio::test]
async fn client_keepalive_10_sequential() {
    let logfile = tempfile::NamedTempFile::new().unwrap();
    let logpath = logfile.path().to_path_buf();
    let backend = HttpBackend::start(ResponseSpec::ok("hello")).await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            access_log_file: Some(logpath.clone()),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    for i in 0..10 {
        let resp = client
            .request(b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap_or_else(|e| panic!("request {i} failed: {e}"));
        assert_eq!(resp.status, 200, "request {i}");
        assert_eq!(resp.body_str(), "hello", "request {i} body");
        // HTTP/1.1 keep-alive is the default; the proxy still advertises it
        // explicitly for the benefit of older intermediaries.
        assert!(
            resp.connection_has("keep-alive"),
            "request {i} must advertise keep-alive, headers={:?}",
            resp.headers
        );
    }

    // keepalive_index is emitted with the CURRENT request's index, then
    // incremented after the log line. Ten requests log 0..=9, not 1..=10.
    let lines = wait_for_log_lines(&logpath, 10).await;
    let indices: Vec<u64> = lines
        .iter()
        .filter_map(|l| l.get("keepalive_index").and_then(|v| v.as_u64()))
        .collect();
    assert_eq!(
        indices,
        (0..10).collect::<Vec<_>>(),
        "keepalive_index must be 0..=9 (off-by-one if 1..=10)"
    );
}

// request cap closes the conn after N requests and advertises Connection: close

#[tokio::test]
async fn client_keepalive_request_cap() {
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            keepalive_max_requests: Some(3),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    // requests 1 and 2: keep-alive advertised
    for i in 0..2 {
        let r = client
            .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert!(r.connection_has("keep-alive"), "req {i} keep-alive");
    }
    // request 3: index 2, 2+1>=3 → close advertised, conn closes after
    let r3 = client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r3.status, 200);
    assert!(
        r3.connection_has("close"),
        "3rd (cap) response must advertise close, headers={:?}",
        r3.headers
    );
    // conn must now be closed by the proxy
    let trailing = client.read_to_eof().await;
    assert!(
        trailing.is_empty(),
        "proxy must close after the cap; got {} trailing bytes",
        trailing.len()
    );
}

// between-request idle timeout closes the conn

#[tokio::test]
async fn client_keepalive_idle_timeout() {
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            keepalive_idle_secs: Some(1),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let r = client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert!(r.connection_has("keep-alive"));

    // do not send a second request; proxy must close after ~1s idle
    let start = std::time::Instant::now();
    let trailing = tokio::time::timeout(Duration::from_secs(5), client.read_to_eof())
        .await
        .expect("proxy did not close idle conn within 5s");
    assert!(trailing.is_empty());
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(800) && elapsed < Duration::from_secs(4),
        "idle close timing off: {elapsed:?}"
    );
}

// request with Connection: close terminates the keep-alive loop

#[tokio::test]
async fn client_keepalive_close_header_terminates_loop() {
    let backend = HttpBackend::start(ResponseSpec::ok("body")).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    // request 1: normal keep-alive
    let r1 = client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r1.status, 200);
    assert!(r1.connection_has("keep-alive"));

    // request 2 explicitly asks to close: response completes, then conn closes
    let r2 = client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r2.status, 200);
    assert_eq!(r2.body_str(), "body");
    assert!(
        r2.connection_has("close"),
        "response to a Connection: close request must advertise close"
    );
    let trailing = client.read_to_eof().await;
    assert!(
        trailing.is_empty(),
        "proxy must close after Connection: close"
    );
}

// HTTP/1.0 keep-alive is opt-in via Connection: keep-alive

#[tokio::test]
async fn client_http10_explicit_keepalive_opt_in() {
    let backend = HttpBackend::start(ResponseSpec::ok("v0")).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    // HTTP/1.0 WITH explicit keep-alive → loop continues, mixed-case header
    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let r1 = client
        .request(b"GET / HTTP/1.0\r\nHost: e.com\r\nConnection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r1.status, 200);
    assert!(
        r1.connection_has("keep-alive"),
        "HTTP/1.0 opt-in must advertise keep-alive (mixed-case), headers={:?}",
        r1.headers
    );
    // HTTP/1.0 historically uses the mixed-case `Keep-Alive` spelling; some
    // legacy intermediaries still match case-sensitively despite RFC 7230.
    assert_eq!(r1.header("connection"), Some("Keep-Alive"));
    // a second request must still be served on the same conn
    let r2 = client
        .request(b"GET / HTTP/1.0\r\nHost: e.com\r\nConnection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r2.status, 200);

    // HTTP/1.0 WITHOUT keep-alive → close after first response
    let mut c2 = KeepAliveClient::connect(proxy.addr).await;
    let r = c2
        .request(b"GET / HTTP/1.0\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert!(
        r.connection_has("close"),
        "HTTP/1.0 without opt-in must close, headers={:?}",
        r.headers
    );
    let trailing = c2.read_to_eof().await;
    assert!(trailing.is_empty(), "HTTP/1.0 default must close");
}

// clean EOF between requests is not an error

#[tokio::test]
async fn client_keepalive_clean_eof_between_requests() {
    let backend = HttpBackend::start(ResponseSpec::ok("done")).await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let r = client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body_str(), "done");

    // half-close write: proxy's between-request fill_buf sees EOF and must
    // exit serve_l7_conn cleanly (no panic, prompt close - not a 60s hang).
    client.shutdown_write().await.unwrap();
    let trailing = tokio::time::timeout(Duration::from_secs(3), client.read_to_eof())
        .await
        .expect("clean EOF must close conn promptly, not hang on keepalive_idle");
    assert!(trailing.is_empty());
}

// the final allowed response advertises Connection: close

#[tokio::test]
async fn client_keepalive_connection_close_header_advertised_on_last_response() {
    let backend = HttpBackend::start(ResponseSpec::ok("x")).await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            keepalive_max_requests: Some(2),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let r1 = client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    // index 0: 0+1 >= 2? no → keep-alive
    assert!(
        r1.connection_has("keep-alive"),
        "first of 2 must keep-alive, headers={:?}",
        r1.headers
    );
    let r2 = client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    // index 1: 1+1 >= 2? yes → close advertised up front
    assert!(
        r2.connection_has("close"),
        "second (final) must advertise close, headers={:?}",
        r2.headers
    );
    let trailing = client.read_to_eof().await;
    assert!(trailing.is_empty());
}

// request_id is recomputed per request, never carried over between iterations

#[tokio::test]
async fn client_keepalive_request_id_independent_per_request() {
    let (backend, log) = backend_recording().await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    client
        .request(b"GET /1 HTTP/1.1\r\nHost: e.com\r\nX-Request-ID: alpha-1\r\n\r\n")
        .await
        .unwrap();
    client
        .request(b"GET /2 HTTP/1.1\r\nHost: e.com\r\nX-Request-ID: alpha-2\r\n\r\n")
        .await
        .unwrap();

    // small grace for the 2nd backend request to be recorded
    tokio::time::sleep(Duration::from_millis(100)).await;
    let reqs = log.lock().unwrap().clone();
    assert_eq!(reqs.len(), 2, "backend must see two distinct requests");
    assert_eq!(reqs[0].header("x-request-id"), Some("alpha-1"));
    assert_eq!(
        reqs[1].header("x-request-id"),
        Some("alpha-2"),
        "request 2 must carry its own id, not request 1's (no loop-state bleed)"
    );
}

// X-Forwarded-For chain is rebuilt per request, never accumulated across the loop

#[tokio::test]
async fn client_keepalive_xff_independent_per_request() {
    let (backend, log) = backend_recording().await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    client
        .request(b"GET /1 HTTP/1.1\r\nHost: e.com\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n")
        .await
        .unwrap();
    client
        .request(b"GET /2 HTTP/1.1\r\nHost: e.com\r\nX-Forwarded-For: 5.6.7.8\r\n\r\n")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    let reqs = log.lock().unwrap().clone();
    assert_eq!(reqs.len(), 2);
    let xff1 = reqs[0].header("x-forwarded-for").unwrap();
    let xff2 = reqs[1].header("x-forwarded-for").unwrap();
    assert!(
        xff1.starts_with("1.2.3.4,") && !xff1.contains("5.6.7.8"),
        "req1 XFF must be `1.2.3.4, <ip>`, got {xff1:?}"
    );
    assert!(
        xff2.starts_with("5.6.7.8,") && !xff2.contains("1.2.3.4"),
        "req2 XFF must be `5.6.7.8, <ip>` - NOT accumulated with req1, got {xff2:?}"
    );
}

// phase-specific timeouts (header, body, proxy_send, proxy_read, request)

/// `client_header_timeout`: a slowloris client that dribbles an incomplete
/// request head past the budget gets a 408 and the conn closes. The total
/// request deadline is large, so 408 (not 504) is the right status. Backend
/// is never contacted.
#[tokio::test]
async fn phase_timeout_header() {
    let backend = BlackholeBackend::start().await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            client_header_timeout_secs: Some(1),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    // dribble: partial head, never sending the terminating CRLFCRLF.
    client.send_only(b"GET / HTTP/1.1\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    client.send_only(b"Host: slow.example\r\n").await.unwrap();
    // exceed the 1s header budget without completing the head.
    tokio::time::sleep(Duration::from_millis(1400)).await;

    let out = tokio::time::timeout(Duration::from_secs(5), client.read_to_eof())
        .await
        .expect("proxy must respond + close within 5s");
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.starts_with("HTTP/1.1 408"),
        "slowloris head must get 408, got: {text:?}"
    );
}

/// `client_body_timeout`: client sends a complete head (already forwarded to
/// the backend) then stalls mid-body. The proxy cannot synthesize an error
/// response without desyncing the backend's view of the request stream, so
/// it closes the client conn with no status line.
#[tokio::test]
async fn phase_timeout_body() {
    let backend = BlackholeBackend::start().await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            client_body_timeout_secs: Some(1),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    // full head announcing a 100-byte body, then send zero body bytes.
    client
        .send_only(b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n")
        .await
        .unwrap();

    let out = tokio::time::timeout(Duration::from_secs(5), client.read_to_eof())
        .await
        .expect("proxy must close within 5s");
    assert!(
        out.is_empty(),
        "Body timeout must close with no response line, got {} bytes: {:?}",
        out.len(),
        String::from_utf8_lossy(&out),
    );
}

/// `proxy_send_timeout`: backend accepts but never reads. A large request
/// body fills the socket buffers; the proxy's write to the backend blocks
/// past the budget and yields 504 (response head not yet sent). Raw split
/// socket because the client write side blocks once the proxy stops draining
/// it.
#[tokio::test]
async fn phase_timeout_proxy_send() {
    let backend = BlackholeBackend::start().await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            proxy_send_timeout_secs: Some(1),
            // need a 32 MiB body to defeat socket buffers below; opt out of
            // the production 1 MiB cap so the proxy reaches the body-write
            // phase the test is actually probing.
            max_body_size_bytes: Some(0),
            ..Default::default()
        },
    )
    .await;

    let stream = TcpStream::connect(proxy.addr).await.unwrap();
    let (mut rd, mut wr) = stream.into_split();

    tokio::spawn(async move {
        // 32 MiB body: larger than any plausible autotuned socket-buffer sum
        // so the proxy's write to the never-reading backend blocks while the
        // client still has data queued (otherwise the proxy drains it all and
        // stalls on the body-read phase instead of proxy_send).
        let mut req = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 33554432\r\n\r\n".to_vec();
        req.resize(req.len() + 32 * 1024 * 1024, b'a');
        // expected to block/error once the proxy stops draining - ignore.
        let _ = wr.write_all(&req).await;
    });

    let mut buf = Vec::new();
    let got = tokio::time::timeout(Duration::from_secs(8), async {
        let mut tmp = [0u8; 1024];
        loop {
            match rd.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    })
    .await;
    assert!(got.is_ok(), "proxy_send must produce a response within 8s");
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.starts_with("HTTP/1.1 504"),
        "backend stalling on our write must yield 504, got: {text:?}"
    );
}

/// `proxy_read_timeout`: backend accepts (head write succeeds into the
/// kernel buffer) but never sends a response. The proxy's response-head read
/// trips the budget and yields 504 (response head not yet sent to client).
#[tokio::test]
async fn phase_timeout_proxy_read() {
    let backend = BlackholeBackend::start().await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            proxy_read_timeout_secs: Some(1),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        client.request(b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n"),
    )
    .await
    .expect("proxy must respond within 5s")
    .expect("response parse");
    assert_eq!(
        resp.status, 504,
        "silent backend must yield 504 on proxy_read timeout"
    );
}

/// Total `request_timeout`: per-phase budgets are large (default 60s); only
/// the overall cycle deadline clamps. The backend would respond, but not
/// until after the 1s total deadline - the clamped proxy_read call trips
/// with deadline_hit and yields 504. Fires well before the backend's own 5s
/// delay, proving the total cap (not any individual phase) is what tripped.
#[tokio::test]
async fn request_timeout_overall() {
    let backend = SlowResponseBackend::start(Duration::from_secs(5)).await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            request_timeout_secs: Some(1),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let started = Instant::now();
    let resp = tokio::time::timeout(
        Duration::from_secs(4),
        client.request(b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n"),
    )
    .await
    .expect("total deadline must fire well within 4s")
    .expect("response parse");
    let elapsed = started.elapsed();

    assert_eq!(resp.status, 504, "total request_timeout must yield 504");
    assert!(
        elapsed < Duration::from_secs(3),
        "must trip on the 1s total deadline, not wait on the 5s backend; elapsed={elapsed:?}"
    );
}

const KA_DEFAULT: KeepaliveConfig = KeepaliveConfig {
    max_idle: 32,
    idle_conn_ttl_secs: 60,
    max_total: 0,
};

fn ka_cfg(max_idle: usize, max_total: u64) -> KeepaliveConfig {
    KeepaliveConfig {
        max_idle,
        idle_conn_ttl_secs: 60,
        max_total,
    }
}

/// short helper: send GET on the same client conn and unwrap the response.
async fn get_one(client: &mut KeepAliveClient) -> helpers::keepalive_client::ParsedResponse {
    client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .expect("request")
}

/// Five sequential client requests over a single keep-alive client conn
/// reuse one backend conn - `accept_count == 1` proves the cache is being
/// returned to and re-checked-out.
#[tokio::test]
async fn backend_pool_reuses_connection() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("hi")).await;
    let (proxy, _pool) =
        start_proxy_pool(vec![backend.addr], KA_DEFAULT, ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    for i in 0..5 {
        let r = get_one(&mut client).await;
        assert_eq!(r.status, 200, "request {i}");
        assert_eq!(r.body_str(), "hi");
    }
    assert_eq!(
        backend.accept_count(),
        1,
        "5 requests should reuse one backend conn; saw {} accepts",
        backend.accept_count()
    );
}

/// Checkout ordering canary: `max_idle == max_total`, cache fully populated.
/// A subsequent request must hit the cache, not trip saturation. If the
/// implementation regresses to checking saturation before draining the cache,
/// this test fails with a 503 or an unwanted failover.
#[tokio::test]
async fn backend_pool_max_total_equals_max_idle_reuses_cache() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("ok")).await;
    let (proxy, _pool) =
        start_proxy_pool(vec![backend.addr], ka_cfg(4, 4), ProxyOpts::default()).await;

    // populate cache by launching 4 concurrent client conns, each sending one request
    let mut handles = Vec::new();
    for _ in 0..4 {
        let addr = proxy.addr;
        handles.push(tokio::spawn(async move {
            let mut c = KeepAliveClient::connect(addr).await;
            let r = get_one(&mut c).await;
            assert_eq!(r.status, 200);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    // give the proxy a beat to finish returning conns to the cache
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        backend.accept_count(),
        4,
        "warmup must open exactly 4 conns"
    );

    // fifth request: cache has 4 idles, total_count == 4. checkout must pop
    // an idle (Phase 1) and NOT enter the fresh-connect path (Phase 2) where
    // the saturation gate would refuse it.
    let mut c5 = KeepAliveClient::connect(proxy.addr).await;
    let r5 = get_one(&mut c5).await;
    assert_eq!(r5.status, 200, "fifth request must succeed via cache");
    assert_eq!(
        backend.accept_count(),
        4,
        "fifth request must reuse a cached idle; a new accept means the \
         saturation gate fires before cache drain"
    );
}

/// `max_idle = 0` disables the cache: every request opens a fresh backend conn.
#[tokio::test]
async fn keepalive_disabled_via_max_idle_zero() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("ok")).await;
    let (proxy, _pool) =
        start_proxy_pool(vec![backend.addr], ka_cfg(0, 0), ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    for _ in 0..4 {
        let r = get_one(&mut client).await;
        assert_eq!(r.status, 200);
    }
    assert_eq!(
        backend.accept_count(),
        4,
        "max_idle=0 must force fresh connect per request"
    );
}

/// Backend responds with `Connection: close`. Proxy must NOT return the conn
/// to its cache; the next request opens a fresh backend conn.
#[tokio::test]
async fn backend_close_header_drops_from_pool() {
    let backend = HttpBackend::start_keepalive(
        ResponseSpec::ok("bye").with_header("Connection", "close".to_owned()),
    )
    .await;
    let (proxy, _pool) =
        start_proxy_pool(vec![backend.addr], KA_DEFAULT, ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    for i in 0..3 {
        let r = get_one(&mut client).await;
        assert_eq!(r.status, 200, "request {i}");
    }
    assert_eq!(
        backend.accept_count(),
        3,
        "Connection: close from backend must discard each conn; saw {} accepts",
        backend.accept_count()
    );
}

/// Backend closes the idle conn after one response without advertising
/// `Connection: close`. Proxy caches the conn, then on the next checkout the
/// dead-conn probe detects EOF and falls through to fresh connect.
#[tokio::test]
async fn backend_pool_dead_recovery() {
    let backend = HttpBackend::start_keepalive_then_die(ResponseSpec::ok("once"), 1).await;
    let (proxy, _pool) =
        start_proxy_pool(vec![backend.addr], KA_DEFAULT, ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let r1 = get_one(&mut client).await;
    assert_eq!(r1.status, 200);
    // give the backend's FIN time to land in the cached conn before we pop it
    tokio::time::sleep(Duration::from_millis(50)).await;

    let r2 = get_one(&mut client).await;
    assert_eq!(
        r2.status, 200,
        "second request must transparently recover from dead idle"
    );
    assert_eq!(
        backend.accept_count(),
        2,
        "expected fresh reconnect after dead idle; saw {} accepts",
        backend.accept_count()
    );
}

/// Fresh-connect succeeds, but the backend FINs before sending any byte of the
/// response. `reused = false` so the broken-keepalive retry rule does NOT
/// engage. Result: 502.
#[tokio::test]
async fn fresh_backend_immediate_disconnect_returns_502() {
    use tokio::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    if let Ok((stream, _)) = accept {
                        drop(stream); // immediate FIN; no bytes written
                    }
                }
                _ = &mut stop_rx => return,
            }
        }
    });

    let (proxy, _pool) = start_proxy_pool(vec![addr], KA_DEFAULT, ProxyOpts::default()).await;
    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let r = client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        r.status, 502,
        "fresh-connect followed by immediate FIN must yield 502"
    );

    let _ = stop_tx.send(());
}

/// `max_idle = 2`: a burst that opens 4 backend conns then returns them all
/// loses 2 (queue cap). A second burst of 4 then reuses only the 2 cached
/// idles + opens 2 fresh, yielding 6 total accepts.
#[tokio::test]
async fn backend_pool_max_idle_enforced() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("ok")).await;
    let (proxy, _pool) =
        start_proxy_pool(vec![backend.addr], ka_cfg(2, 0), ProxyOpts::default()).await;

    let burst = |n: usize, addr: SocketAddr| async move {
        let mut handles = Vec::new();
        for _ in 0..n {
            handles.push(tokio::spawn(async move {
                let mut c = KeepAliveClient::connect(addr).await;
                let r = get_one(&mut c).await;
                assert_eq!(r.status, 200);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    };

    burst(4, proxy.addr).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(backend.accept_count(), 4, "first burst opens 4 conns");

    burst(4, proxy.addr).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        backend.accept_count(),
        6,
        "second burst reuses 2 cached + opens 2 fresh; saw {} total",
        backend.accept_count()
    );
}

/// Two backends; first hits `max_total = 1` on a long-lived request, second
/// must serve a concurrent request via failover. Saturation does NOT trip
/// the circuit breaker - saturation is "operating at capacity", not failing.
#[tokio::test]
async fn backend_pool_max_total_failover() {
    let slow = SlowResponseBackend::start(Duration::from_secs(2)).await;
    let fast = HttpBackend::start_keepalive(ResponseSpec::ok("fast")).await;
    let (proxy, pool) = start_proxy_pool(
        vec![slow.addr, fast.addr],
        ka_cfg(4, 1),
        ProxyOpts {
            request_timeout_secs: Some(5),
            ..Default::default()
        },
    )
    .await;

    // hold slow backend at its cap with a request in flight
    let slow_addr = proxy.addr;
    let slow_task = tokio::spawn(async move {
        let mut c = KeepAliveClient::connect(slow_addr).await;
        let _ = c.request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // concurrent request must NOT 503; round-robin should land on slow (saturated)
    // then failover to fast. either ordering is acceptable as long as one of the
    // two backends responds.
    let mut c2 = KeepAliveClient::connect(proxy.addr).await;
    let r = c2
        .request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        r.status, 200,
        "concurrent request during saturation must fail over, not 503"
    );

    // saturation is not a backend failure; every backend's circuit stays Closed.
    for state in pool.iter() {
        assert!(
            matches!(state.circuit_state(), kntx::health::CircuitState::Closed),
            "saturation must not open any circuit; saw {:?}",
            state.circuit_state(),
        );
    }

    let _ = tokio::time::timeout(Duration::from_secs(4), slow_task).await;
}

/// All backends saturated → the third client request waits in the queue
/// until a permit frees, then is served. This is the nginx-style
/// queue-on-saturation behaviour added when the per-backend semaphore was
/// introduced; the previous immediate-503 behaviour was the failure mode it
/// replaced.
#[tokio::test]
async fn backend_pool_all_saturated_clients_wait_for_capacity() {
    let slow1 = SlowResponseBackend::start(Duration::from_secs(1)).await;
    let slow2 = SlowResponseBackend::start(Duration::from_secs(1)).await;
    let (proxy, _pool) = start_proxy_pool(
        vec![slow1.addr, slow2.addr],
        ka_cfg(4, 1),
        ProxyOpts {
            request_timeout_secs: Some(10),
            ..Default::default()
        },
    )
    .await;

    // pin both backends with in-flight requests
    let addr = proxy.addr;
    let h1 = tokio::spawn(async move {
        let mut c = KeepAliveClient::connect(addr).await;
        c.request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await
    });
    let h2 = tokio::spawn(async move {
        let mut c = KeepAliveClient::connect(addr).await;
        c.request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // third request: waits for one of the two pinned slows to release its
    // permit (~1s into the test), then is served (another ~1s on the slow
    // backend). Total elapsed is at least the wait, well within the 10s
    // request_timeout.
    let started = Instant::now();
    let mut c3 = KeepAliveClient::connect(proxy.addr).await;
    let r = c3
        .request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(
        r.status, 200,
        "queued request should be served once capacity frees; saw {}",
        r.status
    );
    assert!(
        elapsed >= Duration::from_millis(500),
        "the request should have queued for a real period; elapsed = {:?}",
        elapsed
    );

    let _ = tokio::time::timeout(Duration::from_secs(5), h1).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), h2).await;
}

/// `max_idle = 0` (cache disabled) but `max_total = 1` still caps concurrency
/// per backend: a second concurrent request to the same backend fails over to
/// a peer.
#[tokio::test]
async fn max_idle_zero_with_max_total_caps_concurrent_actives() {
    let slow = SlowResponseBackend::start(Duration::from_secs(2)).await;
    let fast = HttpBackend::start_keepalive(ResponseSpec::ok("fast")).await;
    let (proxy, _pool) = start_proxy_pool(
        vec![slow.addr, fast.addr],
        ka_cfg(0, 1),
        ProxyOpts {
            request_timeout_secs: Some(5),
            ..Default::default()
        },
    )
    .await;

    let slow_addr = proxy.addr;
    let slow_task = tokio::spawn(async move {
        let mut c = KeepAliveClient::connect(slow_addr).await;
        let _ = c.request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut c2 = KeepAliveClient::connect(proxy.addr).await;
    let r = c2
        .request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        r.status, 200,
        "max_total caps concurrency even with caching disabled"
    );

    let _ = tokio::time::timeout(Duration::from_secs(4), slow_task).await;
}

/// Idle sweeper drops cached conns whose age exceeds `idle_conn_ttl`. Test
/// triggers sweep manually to avoid sleeping past the 5s sweeper-interval
/// clamp.
#[tokio::test]
async fn idle_sweeper_drops_stale() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("ok")).await;
    let cfg = KeepaliveConfig {
        max_idle: 4,
        idle_conn_ttl_secs: 1,
        max_total: 0,
    };
    let (proxy, pool) = start_proxy_pool(vec![backend.addr], cfg, ProxyOpts::default()).await;

    let mut c = KeepAliveClient::connect(proxy.addr).await;
    let _ = get_one(&mut c).await;
    drop(c);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let state = pool.state_for(backend.addr).unwrap();
    use std::sync::atomic::Ordering;
    assert_eq!(
        state.total_count.0.load(Ordering::Acquire),
        1,
        "after one request returned to cache, total_count should be 1"
    );

    // wait past the 1s TTL, then sweep manually
    tokio::time::sleep(Duration::from_millis(1200)).await;
    state.sweep_stale_keepalive();
    assert_eq!(
        state.total_count.0.load(Ordering::Acquire),
        0,
        "sweep must drop the stale idle conn",
    );

    // next request fresh-connects (cache empty)
    let mut c2 = KeepAliveClient::connect(proxy.addr).await;
    let _ = get_one(&mut c2).await;
    assert_eq!(
        backend.accept_count(),
        2,
        "post-sweep request must be a fresh accept"
    );
}

/// Stress test: many concurrent client tasks churn checkout/return. After
/// drain, `total_count` for the backend equals the number of idle conns in
/// the queue - no leaked counter slots.
#[tokio::test]
async fn keepalive_concurrent_checkout_return_no_leak() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("ok")).await;
    let cfg = ka_cfg(8, 0);
    let (proxy, pool) = start_proxy_pool(vec![backend.addr], cfg, ProxyOpts::default()).await;

    let mut handles = Vec::new();
    for _ in 0..20 {
        let addr = proxy.addr;
        handles.push(tokio::spawn(async move {
            let mut c = KeepAliveClient::connect(addr).await;
            for _ in 0..5 {
                let r = get_one(&mut c).await;
                assert_eq!(r.status, 200);
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // give the proxy a beat to finish returning conns to the cache
    tokio::time::sleep(Duration::from_millis(200)).await;

    let state = pool.state_for(backend.addr).unwrap();
    use std::sync::atomic::Ordering;
    let total = state.total_count.0.load(Ordering::Acquire);
    // total = idle queue length (no active checkouts left); both ≤ max_idle.
    assert!(
        total <= 8,
        "total_count must be ≤ max_idle after drain; got {}",
        total,
    );
}

/// Backend returns 502 with `Connection: close`. Proxy must (a) pass the 502
/// through to the client, (b) discard the backend conn from the cache, but
/// (c) keep the client conn alive - the proxy-emitted Connection header on
/// the client response is independent of the backend's.
#[tokio::test]
async fn client_keepalive_backend_502_keeps_client_alive() {
    let backend = HttpBackend::start_keepalive(
        ResponseSpec::ok("oops")
            .with_status(502, "Bad Gateway")
            .with_header("Connection", "close".to_owned()),
    )
    .await;
    let (proxy, _pool) =
        start_proxy_pool(vec![backend.addr], KA_DEFAULT, ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let r1 = get_one(&mut client).await;
    assert_eq!(r1.status, 502, "backend's 502 must reach the client");
    assert!(
        r1.connection_has("keep-alive"),
        "client conn must stay alive; got headers={:?}",
        r1.headers,
    );

    let r2 = get_one(&mut client).await;
    assert_eq!(
        r2.status, 502,
        "second request on the kept-alive client conn"
    );
    assert_eq!(
        backend.accept_count(),
        2,
        "backend conn was discarded after 502+close; second request fresh-connects",
    );
}

/// Filling the cache, then forcibly tripping the circuit, must flush the
/// per-backend queue and reset `total_count` to zero.
#[tokio::test]
async fn keepalive_cache_flushed_on_circuit_open() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("ok")).await;
    let cfg = ka_cfg(4, 0);
    let (proxy, pool) = start_proxy_pool(vec![backend.addr], cfg, ProxyOpts::default()).await;

    // warm the cache: 3 concurrent → 3 idle
    let mut handles = Vec::new();
    for _ in 0..3 {
        let addr = proxy.addr;
        handles.push(tokio::spawn(async move {
            let mut c = KeepAliveClient::connect(addr).await;
            let _ = get_one(&mut c).await;
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let state = pool.state_for(backend.addr).unwrap();
    use std::sync::atomic::Ordering;
    assert_eq!(
        state.total_count.0.load(Ordering::Acquire),
        3,
        "cache must contain 3 idle conns"
    );

    // trip circuit Closed → Open via passive failure threshold (3 failures)
    for _ in 0..3 {
        pool.record_failure(backend.addr);
    }
    assert_eq!(
        state.circuit_state(),
        kntx::health::CircuitState::Open,
        "3 failures must open the circuit"
    );
    assert_eq!(
        state.total_count.0.load(Ordering::Acquire),
        0,
        "circuit-open transition must flush the cache",
    );
}

/// Backend that reads exactly `read_total_bytes` bytes off the wire then drops
/// the connection (FIN). Used by the mid-body-failure tests: by the time the
/// proxy reaches the failure, request body bytes have already been flushed to
/// the backend socket, so the cycle is past the retry boundary and the
/// poisoned conn must never be re-pooled.
struct DieAfterBytesBackend {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start_die_after_bytes(read_total_bytes: usize) -> DieAfterBytesBackend {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    if let Ok((mut s, _)) = accept {
                        tokio::spawn(async move {
                            let mut total = 0usize;
                            let mut buf = [0u8; 4096];
                            while total < read_total_bytes {
                                match s.read(&mut buf).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => total += n,
                                }
                            }
                            // explicit drop sends FIN to the proxy mid-stream
                            drop(s);
                        });
                    }
                }
                _ = &mut shutdown_rx => return,
            }
        }
    });

    DieAfterBytesBackend {
        addr,
        _shutdown: shutdown_tx,
    }
}

/// CL pre-check: a Content-Length larger than the listener's limit is rejected
/// up front with 413; the backend is never contacted. No half-state, no cache
/// pollution.
#[tokio::test]
async fn body_cl_exceeds_limit_413() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("ok")).await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            max_body_size_bytes: Some(1024),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let r = client
        .request(b"POST /x HTTP/1.1\r\nHost: e.com\r\nContent-Length: 2048\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r.status, 413, "CL > limit must be rejected with 413");
    // backend untouched
    assert_eq!(
        backend.accept_count(),
        0,
        "CL pre-check must NOT contact the backend"
    );
    // close after 413
    let trailing = client.read_to_eof().await;
    assert!(trailing.is_empty(), "proxy must close after 413");
}

/// Chunked body that exceeds the limit during streaming. The response head
/// has not been written to the client yet in this sequential request/response
/// model, so a 413 is emitted. The backend conn is poisoned by the partial
/// body and must be discarded, not returned to the keepalive cache.
#[tokio::test]
async fn body_chunked_exceeds_pre_response_413() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("ok")).await;
    let (proxy, pool) = start_proxy_pool(
        vec![backend.addr],
        KA_DEFAULT,
        ProxyOpts {
            max_body_size_bytes: Some(512),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let mut req = Vec::new();
    req.extend_from_slice(b"POST /x HTTP/1.1\r\nHost: e.com\r\nTransfer-Encoding: chunked\r\n\r\n");
    // single 1024-byte chunk exceeds the 512-byte cap.
    req.extend_from_slice(b"400\r\n");
    req.extend_from_slice(&[b'x'; 1024]);
    req.extend_from_slice(b"\r\n0\r\n\r\n");
    let r = client.request(&req).await.unwrap();
    assert_eq!(
        r.status, 413,
        "chunked body > limit must be rejected with 413"
    );

    // poisoned conn must not survive in the cache - Drop on the KeepaliveConn
    // decrements total_count without re-pooling.
    tokio::time::sleep(Duration::from_millis(50)).await;
    use std::sync::atomic::Ordering;
    let state = pool.state_for(backend.addr).unwrap();
    assert_eq!(
        state.total_count.0.load(Ordering::Acquire),
        0,
        "chunked-trip conn must be discarded, not returned to cache"
    );
}

/// `max_body_size_bytes = 0` opts out of the cap entirely: a body well past
/// the production 1 MiB default is accepted end-to-end.
#[tokio::test]
async fn body_unlimited_zero_setting() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("ok")).await;
    let proxy = start_proxy(
        backend.addr,
        ProxyOpts {
            max_body_size_bytes: Some(0),
            ..Default::default()
        },
    )
    .await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let body_size = 5 * 1024 * 1024usize; // 5 MiB, well over the 1 MiB default
    let mut req = Vec::new();
    req.extend_from_slice(
        format!("POST /x HTTP/1.1\r\nHost: e.com\r\nContent-Length: {body_size}\r\n\r\n")
            .as_bytes(),
    );
    req.resize(req.len() + body_size, b'x');
    let r = client.request(&req).await.unwrap();
    assert_eq!(
        r.status, 200,
        "unlimited (max_body_size_bytes = 0) must accept arbitrarily large bodies"
    );
}

/// Broken-keepalive safety contract: cached idles that die silently must
/// never cause client-visible failures and must never trip the backend's
/// circuit. Either the dead-conn probe catches the FIN before the proxy
/// writes (and the request fresh-connects), or the head-write itself fails
/// and an idempotent retry lands on a peer. Both paths satisfy the contract.
#[tokio::test]
async fn retry_get_on_broken_keepalive() {
    let b1 = HttpBackend::start_keepalive_then_die(ResponseSpec::ok("b1"), 1).await;
    let b2 = HttpBackend::start_keepalive(ResponseSpec::ok("b2")).await;
    let (proxy, pool) =
        start_proxy_pool(vec![b1.addr, b2.addr], KA_DEFAULT, ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    for i in 0..6 {
        let r = get_one(&mut client).await;
        assert_eq!(
            r.status, 200,
            "request {i} must succeed via retry or fresh-connect"
        );
    }

    // Broken-keepalive races are TCP-level - no backend output was observed,
    // so they do not count as backend failures. B1's circuit must remain
    // Closed even though its cached idles routinely die.
    let b1_state = pool.state_for(b1.addr).unwrap();
    assert!(
        matches!(b1_state.circuit_state(), kntx::health::CircuitState::Closed),
        "B1's circuit must stay Closed across broken-keepalive races"
    );
}

/// PUT (idempotent by spec) with body - once any body byte has been flushed
/// to the backend socket, retry is structurally blocked: pass-through
/// forwarding cannot replay body bytes it has already consumed from the
/// client. Expected: 502 to client, broken backend conn discarded.
#[tokio::test]
async fn no_retry_put_mid_body() {
    let backend = start_die_after_bytes(800).await;
    let (proxy, pool) =
        start_proxy_pool(vec![backend.addr], ka_cfg(2, 0), ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let body_size = 4096usize;
    let mut req = Vec::new();
    req.extend_from_slice(
        format!("PUT /x HTTP/1.1\r\nHost: e.com\r\nContent-Length: {body_size}\r\n\r\n").as_bytes(),
    );
    req.resize(req.len() + body_size, b'a');
    let r = client.request(&req).await.unwrap();
    assert_eq!(
        r.status, 502,
        "PUT with body bytes already sent must NOT retry - pass-through can't replay"
    );

    // backend conn poisoned by partial body → discarded, never re-pooled.
    tokio::time::sleep(Duration::from_millis(50)).await;
    use std::sync::atomic::Ordering;
    let state = pool.state_for(backend.addr).unwrap();
    assert_eq!(
        state.total_count.0.load(Ordering::Acquire),
        0,
        "broken-body conn must be discarded"
    );
}

/// POST (non-idempotent) with body - never retried in any case. With body
/// bytes already sent the backend conn is poisoned and must be discarded.
#[tokio::test]
async fn no_retry_post_with_body_started() {
    let backend = start_die_after_bytes(800).await;
    let (proxy, pool) =
        start_proxy_pool(vec![backend.addr], ka_cfg(2, 0), ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let body_size = 4096usize;
    let mut req = Vec::new();
    req.extend_from_slice(
        format!("POST /x HTTP/1.1\r\nHost: e.com\r\nContent-Length: {body_size}\r\n\r\n")
            .as_bytes(),
    );
    req.resize(req.len() + body_size, b'a');
    let r = client.request(&req).await.unwrap();
    assert_eq!(r.status, 502, "POST mid-body fail must NOT retry");

    tokio::time::sleep(Duration::from_millis(50)).await;
    use std::sync::atomic::Ordering;
    let state = pool.state_for(backend.addr).unwrap();
    assert_eq!(state.total_count.0.load(Ordering::Acquire), 0);
}

/// PATCH (non-idempotent) is not retry-eligible even when no body has been
/// sent yet - the method gate alone blocks retry. Sending PATCH against a
/// single backend that always FINs without responding routes through the
/// "ineligible" branch and consistently yields 502, never 200.
#[tokio::test]
async fn no_retry_patch_zero_bytes() {
    // backend that accepts then immediately drops (FIN with zero bytes back).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    if let Ok((s, _)) = accept {
                        drop(s);
                    }
                }
                _ = &mut stop_rx => return,
            }
        }
    });

    let (proxy, _pool) = start_proxy_pool(vec![addr], KA_DEFAULT, ProxyOpts::default()).await;
    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let r = client
        .request(b"PATCH /x HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        r.status, 502,
        "PATCH (non-idempotent) on a backend that always FINs must 502 - never retried"
    );

    let _ = stop_tx.send(());
}

/// Backend-conn poisoning canary: a backend that FINs mid-body must NOT
/// have its broken conn returned to the cache. After the failure,
/// `total_count` for the backend reads 0 - the broken conn was discarded.
/// An implementation that re-pools the conn would leave `total_count >= 1`
/// here, and subsequent requests would pop the broken conn and pay an extra
/// round-trip.
#[tokio::test]
async fn error_after_body_streamed_discards_backend_conn_not_cached() {
    let backend = start_die_after_bytes(800).await;
    let (proxy, pool) =
        start_proxy_pool(vec![backend.addr], ka_cfg(2, 0), ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    let body_size = 4096usize;
    let mut req = Vec::new();
    req.extend_from_slice(
        format!("POST /x HTTP/1.1\r\nHost: e.com\r\nContent-Length: {body_size}\r\n\r\n")
            .as_bytes(),
    );
    req.resize(req.len() + body_size, b'a');
    let r = client.request(&req).await.unwrap();
    assert_eq!(r.status, 502, "mid-body backend FIN must yield 502");

    tokio::time::sleep(Duration::from_millis(100)).await;
    use std::sync::atomic::Ordering;
    let state = pool.state_for(backend.addr).unwrap();
    assert_eq!(
        state.total_count.0.load(Ordering::Acquire),
        0,
        "broken-body backend conn must be discarded, never returned to cache"
    );
}

/// Broken-keepalive race must never increment `consecutive_failures` or
/// trip the circuit. Send a burst of requests against a pool whose cached
/// idles die routinely; the broken backend's circuit stays Closed well past
/// the failure threshold (default 3).
#[tokio::test]
async fn broken_keepalive_does_not_trip_circuit() {
    let b1 = HttpBackend::start_keepalive_then_die(ResponseSpec::ok("b1"), 1).await;
    let b2 = HttpBackend::start_keepalive(ResponseSpec::ok("b2")).await;
    let (proxy, pool) =
        start_proxy_pool(vec![b1.addr, b2.addr], KA_DEFAULT, ProxyOpts::default()).await;

    let mut client = KeepAliveClient::connect(proxy.addr).await;
    // ten sequential requests - well past failure_threshold of 3. If any path
    // mis-attributed a broken-keepalive race as a backend failure, the circuit
    // would have flipped Open before iteration 10.
    for i in 0..10 {
        let r = get_one(&mut client).await;
        assert_eq!(r.status, 200, "request {i} must succeed");
    }

    let b1_state = pool.state_for(b1.addr).unwrap();
    assert!(
        matches!(b1_state.circuit_state(), kntx::health::CircuitState::Closed),
        "B1's circuit must stay Closed; broken-keepalive races are not health signals"
    );
}

// A keep-alive backend that honors HEAD: for HEAD requests it emits headers
// (including a Content-Length advertising the resource size) but ZERO body
// bytes, per RFC 7230 §3.3.3. For other methods it emits a normal CL-framed
// body. Used to verify the proxy's keep-alive loop preserves HEAD framing
// semantics across iterations on a reused conn.
struct HeadCompliantBackend {
    addr: SocketAddr,
    accept_count: Arc<std::sync::atomic::AtomicU64>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start_head_compliant_backend() -> HeadCompliantBackend {
    use std::sync::atomic::{AtomicU64, Ordering};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_count = Arc::new(AtomicU64::new(0));
    let ac_outer = Arc::clone(&accept_count);
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    if let Ok((mut s, _)) = accept {
                        ac_outer.fetch_add(1, Ordering::Relaxed);
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 8192];
                            let mut total = 0usize;
                            loop {
                                let head_end = loop {
                                    if let Some(p) = buf[..total]
                                        .windows(4)
                                        .position(|w| w == b"\r\n\r\n")
                                    {
                                        break p + 4;
                                    }
                                    if total >= buf.len() {
                                        return;
                                    }
                                    match s.read(&mut buf[total..]).await {
                                        Ok(0) | Err(_) => return,
                                        Ok(n) => total += n,
                                    }
                                };
                                let head_str = std::str::from_utf8(&buf[..head_end]).unwrap_or("");
                                let method = head_str
                                    .split([' ', '\r', '\n'])
                                    .next()
                                    .unwrap_or("");
                                let response: &[u8] = if method.eq_ignore_ascii_case("HEAD") {
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nContent-Type: text/plain\r\n\r\n"
                                } else {
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"
                                };
                                if s.write_all(response).await.is_err() {
                                    return;
                                }
                                buf.copy_within(head_end..total, 0);
                                total -= head_end;
                            }
                        });
                    }
                }
                _ = &mut stop_rx => return,
            }
        }
    });
    HeadCompliantBackend {
        addr,
        accept_count,
        _shutdown: stop_tx,
    }
}

/// First request on a kept-alive conn is HEAD; the backend returns a response
/// with Content-Length advertising a body it does not send. The proxy must
/// recognize HEAD and skip body framing on both sides - if it tries to read
/// the phantom CL bytes from the backend, the next request on the same
/// client conn would either hang or parse the next response wrong.
#[tokio::test]
async fn client_keepalive_head_then_get_no_framing_drift() {
    let backend = start_head_compliant_backend().await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;
    let mut client = KeepAliveClient::connect(proxy.addr).await;

    let r1 = client
        .request(b"HEAD /res HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r1.status, 200);
    assert_eq!(r1.body.len(), 0, "HEAD response must have no body");
    assert_eq!(
        r1.header("content-length"),
        Some("1024"),
        "Content-Length header must pass through to the client unchanged"
    );
    assert!(r1.connection_has("keep-alive"));

    let r2 = tokio::time::timeout(
        Duration::from_secs(3),
        client.request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n"),
    )
    .await
    .expect("second request must not hang on phantom HEAD body bytes")
    .unwrap();
    assert_eq!(r2.status, 200);
    assert_eq!(r2.body_str(), "hello");

    use std::sync::atomic::Ordering;
    assert_eq!(
        backend.accept_count.load(Ordering::Relaxed),
        1,
        "single backend conn must serve both requests via the keep-alive cache"
    );
}

// A keep-alive backend that honors the Expect: 100-continue contract. When
// the request advertises Expect: 100-continue it emits a 100 interim
// response, drains the announced body, then emits the final 200. Without
// the Expect header it just drains the body (if any) and replies 200.
struct ContinueBackend {
    addr: SocketAddr,
    accept_count: Arc<std::sync::atomic::AtomicU64>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start_continue_backend() -> ContinueBackend {
    use std::sync::atomic::{AtomicU64, Ordering};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_count = Arc::new(AtomicU64::new(0));
    let ac_outer = Arc::clone(&accept_count);
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    if let Ok((mut s, _)) = accept {
                        ac_outer.fetch_add(1, Ordering::Relaxed);
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 8192];
                            let mut total = 0usize;
                            loop {
                                let head_end = loop {
                                    if let Some(p) = buf[..total]
                                        .windows(4)
                                        .position(|w| w == b"\r\n\r\n")
                                    {
                                        break p + 4;
                                    }
                                    if total >= buf.len() {
                                        return;
                                    }
                                    match s.read(&mut buf[total..]).await {
                                        Ok(0) | Err(_) => return,
                                        Ok(n) => total += n,
                                    }
                                };
                                let head_str = std::str::from_utf8(&buf[..head_end]).unwrap_or("");
                                let mut cl = 0usize;
                                let mut has_expect = false;
                                for line in head_str.lines() {
                                    let lower = line.to_ascii_lowercase();
                                    if let Some(v) = lower.strip_prefix("content-length:")
                                        && let Ok(n) = v.trim().parse()
                                    {
                                        cl = n;
                                    } else if let Some(v) = lower.strip_prefix("expect:")
                                        && v.trim() == "100-continue"
                                    {
                                        has_expect = true;
                                    }
                                }
                                if has_expect
                                    && s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.is_err()
                                {
                                    return;
                                }
                                let mut body_read = total - head_end;
                                while body_read < cl {
                                    let mut tmp = [0u8; 4096];
                                    let want = (cl - body_read).min(tmp.len());
                                    match s.read(&mut tmp[..want]).await {
                                        Ok(0) | Err(_) => return,
                                        Ok(n) => body_read += n,
                                    }
                                }
                                if s.write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                                )
                                .await
                                .is_err()
                                {
                                    return;
                                }
                                let consumed = head_end + cl;
                                if consumed < total {
                                    buf.copy_within(consumed..total, 0);
                                    total -= consumed;
                                } else {
                                    total = 0;
                                }
                            }
                        });
                    }
                }
                _ = &mut stop_rx => return,
            }
        }
    });
    ContinueBackend {
        addr,
        accept_count,
        _shutdown: stop_tx,
    }
}

/// First request advertises Expect: 100-continue; the backend emits a 100
/// interim before consuming the body and finally replies 200. The proxy
/// must forward the 100 to the client and keep the backend conn pooled
/// after the final response - the second request on the same client conn
/// must reach the SAME backend conn (accept_count stays at 1).
#[tokio::test]
async fn client_keepalive_100_continue_then_returns_to_pool() {
    let backend = start_continue_backend().await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;
    let mut client = KeepAliveClient::connect(proxy.addr).await;

    let r1 = client
        .request(
            b"POST /upload HTTP/1.1\r\nHost: e.com\r\nExpect: 100-continue\r\n\
              Content-Length: 5\r\n\r\nhello",
        )
        .await
        .unwrap();
    assert_eq!(r1.status, 200);
    assert_eq!(r1.body_str(), "ok");
    assert!(r1.connection_has("keep-alive"));

    let r2 = client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r2.status, 200);

    use std::sync::atomic::Ordering;
    assert_eq!(
        backend.accept_count.load(Ordering::Relaxed),
        1,
        "backend conn must be returned to the cache and reused for the next request"
    );
}

// A keep-alive backend that parses chunked bodies with trailers correctly.
// It captures the trailer headers received per request so tests can assert
// they were forwarded byte-for-byte by the proxy.
type TrailerLog = Arc<Mutex<Vec<Vec<(String, String)>>>>;

struct TrailersBackend {
    addr: SocketAddr,
    accept_count: Arc<std::sync::atomic::AtomicU64>,
    received_trailers: TrailerLog,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start_trailers_backend() -> TrailersBackend {
    use std::sync::atomic::{AtomicU64, Ordering};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_count = Arc::new(AtomicU64::new(0));
    let ac_outer = Arc::clone(&accept_count);
    let received: TrailerLog = Arc::new(Mutex::new(Vec::new()));
    let recv_outer = Arc::clone(&received);
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    if let Ok((mut s, _)) = accept {
                        ac_outer.fetch_add(1, Ordering::Relaxed);
                        let recv = Arc::clone(&recv_outer);
                        tokio::spawn(async move {
                            let mut buf: Vec<u8> = Vec::with_capacity(16384);
                            loop {
                                let head_end = loop {
                                    if let Some(p) =
                                        buf.windows(4).position(|w| w == b"\r\n\r\n")
                                    {
                                        break p + 4;
                                    }
                                    let mut tmp = [0u8; 4096];
                                    match s.read(&mut tmp).await {
                                        Ok(0) | Err(_) => return,
                                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                    }
                                };
                                let head_str =
                                    std::str::from_utf8(&buf[..head_end]).unwrap_or("");
                                let is_chunked = head_str.lines().any(|l| {
                                    let lower = l.to_ascii_lowercase();
                                    lower.starts_with("transfer-encoding:")
                                        && lower.contains("chunked")
                                });
                                let cl: usize = head_str
                                    .lines()
                                    .find_map(|l| {
                                        let lower = l.to_ascii_lowercase();
                                        lower
                                            .strip_prefix("content-length:")
                                            .and_then(|v| v.trim().parse().ok())
                                    })
                                    .unwrap_or(0);

                                let after_body = if is_chunked {
                                    match drain_chunked_body(&mut s, &mut buf, head_end).await {
                                        Some((end, trailers)) => {
                                            recv.lock().unwrap().push(trailers);
                                            end
                                        }
                                        None => return,
                                    }
                                } else {
                                    while buf.len() < head_end + cl {
                                        let mut tmp = [0u8; 4096];
                                        match s.read(&mut tmp).await {
                                            Ok(0) | Err(_) => return,
                                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                        }
                                    }
                                    head_end + cl
                                };

                                if s.write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                                )
                                .await
                                .is_err()
                                {
                                    return;
                                }
                                buf.drain(..after_body);
                            }
                        });
                    }
                }
                _ = &mut stop_rx => return,
            }
        }
    });
    TrailersBackend {
        addr,
        accept_count,
        received_trailers: received,
        _shutdown: stop_tx,
    }
}

// Parses a chunked body (and its trailer block, if any) starting at `start`
// in `buf`, reading more bytes from `s` as needed. Returns the index in
// `buf` one past the last byte consumed by the body, along with the
// trailer name-value pairs.
async fn drain_chunked_body(
    s: &mut tokio::net::TcpStream,
    buf: &mut Vec<u8>,
    start: usize,
) -> Option<(usize, Vec<(String, String)>)> {
    let mut cursor = start;
    loop {
        let line_end = loop {
            if let Some(p) = buf[cursor..].windows(2).position(|w| w == b"\r\n") {
                break cursor + p;
            }
            let mut tmp = [0u8; 4096];
            match s.read(&mut tmp).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        };
        let size_line = std::str::from_utf8(&buf[cursor..line_end]).unwrap_or("0");
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).unwrap_or(0);
        cursor = line_end + 2;
        if size == 0 {
            let mut trailers: Vec<(String, String)> = Vec::new();
            loop {
                let tl_end = loop {
                    if let Some(p) = buf[cursor..].windows(2).position(|w| w == b"\r\n") {
                        break cursor + p;
                    }
                    let mut tmp = [0u8; 4096];
                    match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return None,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                };
                if tl_end == cursor {
                    return Some((cursor + 2, trailers));
                }
                let line = std::str::from_utf8(&buf[cursor..tl_end]).unwrap_or("");
                if let Some(colon) = line.find(':') {
                    trailers.push((
                        line[..colon].trim().to_owned(),
                        line[colon + 1..].trim().to_owned(),
                    ));
                }
                cursor = tl_end + 2;
            }
        }
        while buf.len() < cursor + size + 2 {
            let mut tmp = [0u8; 4096];
            match s.read(&mut tmp).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        cursor += size + 2;
    }
}

/// Chunked request body with trailers forwarded byte-for-byte to the
/// backend; the trailer line lands AFTER the final 0-chunk. The backend
/// conn must return to the cache, and the next request on the same client
/// conn must hit the same backend conn - verifies the keep-alive loop
/// observes the chunked-with-trailers terminator correctly and leaves no
/// stray bytes that would corrupt the next iteration's framing.
#[tokio::test]
async fn client_keepalive_chunked_trailers_then_next_request() {
    let backend = start_trailers_backend().await;
    let proxy = start_proxy(backend.addr, ProxyOpts::default()).await;
    let mut client = KeepAliveClient::connect(proxy.addr).await;

    let mut req = Vec::new();
    req.extend_from_slice(
        b"POST /up HTTP/1.1\r\n\
          Host: e.com\r\n\
          Transfer-Encoding: chunked\r\n\
          Trailer: X-Checksum\r\n\r\n",
    );
    req.extend_from_slice(b"5\r\nhello\r\n");
    req.extend_from_slice(b"0\r\nX-Checksum: abcd\r\n\r\n");
    let r1 = client.request(&req).await.unwrap();
    assert_eq!(r1.status, 200);
    assert!(r1.connection_has("keep-alive"));

    let r2 = client
        .request(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(r2.status, 200);

    use std::sync::atomic::Ordering;
    assert_eq!(
        backend.accept_count.load(Ordering::Relaxed),
        1,
        "single backend conn must serve both requests through the cache"
    );
    let trailers = backend.received_trailers.lock().unwrap().clone();
    assert_eq!(trailers.len(), 1);
    assert!(
        trailers[0]
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("X-Checksum") && v == "abcd"),
        "backend must receive the trailer; got {:?}",
        trailers[0]
    );
}

struct TlsProxy {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    _shutdown: watch::Sender<()>,
    _tempdir: tempfile::TempDir,
}

/// Build an L7+TLS proxy fronting `backend_addr`. The cert is self-signed
/// for `localhost`; the returned `cert_der` lets the test build a trusting
/// client config.
async fn start_proxy_tls(backend_addr: SocketAddr) -> TlsProxy {
    let tc = generate_cert(&["localhost"]);
    let (tempdir, cert_path, key_path) = write_cert_to_tempdir(&tc);
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

    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Arc::new(BackendPool::new(
        "test".into(),
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
        pool: Some("test".to_owned()),
        routes: vec![],
        max_connections: None,
        idle_timeout_secs: None,
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
            output: AccessLogOutput::Named("off".to_owned()),
            format: None,
            file_channel_capacity: 64,
        })
        .unwrap(),
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let serve_cfg = ServeConfig {
        rate_limit: None,
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
        tls_acceptor: Some(acceptor),
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };
    tokio::spawn(listener::serve(listener, router, serve_cfg, shutdown_rx));

    TlsProxy {
        addr,
        cert_der: tc.cert_der,
        _shutdown: shutdown_tx,
        _tempdir: tempdir,
    }
}

/// TLS-terminated L7 listener with the keep-alive loop running over a
/// `tokio::io::split`-backed Mutex pair of stream halves: five sequential
/// GETs on a single client TLS conn must all succeed. A regression where
/// the loop re-splits per iteration (or fails to reuse the halves) would
/// surface as the second request hanging or parsing wrong.
#[tokio::test]
async fn tls_l7_keepalive_sequential() {
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("tls-ka")).await;
    let proxy = start_proxy_tls(backend.addr).await;

    let client_cfg = client_config_trusting(&proxy.cert_der);
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let tcp = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_owned()).unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    for i in 0..5 {
        tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let resp = tls_read_one_response(&mut tls).await;
        assert_eq!(resp.status, 200, "request {i} status");
        assert_eq!(resp.body, b"tls-ka", "request {i} body");
        assert!(
            resp.connection_has("keep-alive"),
            "request {i} keep-alive header"
        );
    }

    assert_eq!(
        backend.accept_count(),
        1,
        "single backend conn must serve all five TLS-fronted requests"
    );
    // explicit close - proxy would otherwise hold the conn until idle.
    let _ = tls.shutdown().await;
}

struct TlsResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl TlsResponse {
    fn connection_has(&self, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
            .flat_map(|(_, v)| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }
}

async fn tls_read_one_response<S>(stream: &mut S) -> TlsResponse
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let head_end = loop {
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await.unwrap();
        if n == 0 {
            panic!("tls stream closed before response head");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head_str = std::str::from_utf8(&buf[..head_end]).unwrap_or("");
    let status_line = head_str.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut headers = Vec::new();
    for line in head_str.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            headers.push((
                line[..colon].trim().to_owned(),
                line[colon + 1..].trim().to_owned(),
            ));
        }
    }
    let cl: usize = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + cl {
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[head_end..head_end + cl].to_vec();
    TlsResponse {
        status,
        headers,
        body,
    }
}
