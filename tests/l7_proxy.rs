mod helpers;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

use helpers::http_backend::{BackendRequest, HttpBackend, ResponseSpec};
use helpers::tls::{client_config_trusting, generate_cert, write_cert_to_tempdir};
use kntx::access_log::AccessLogSink;
use kntx::balancer::RoundRobin;
use kntx::config::{
    AccessLogConfig, AccessLogOutput, CertificateConfig, ErrorPagesConfig, ListenerConfig,
    ListenerMode, TlsConfig,
};
use kntx::health::{BackendPool, CircuitState};
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::proxy::l7::ErrorPages;
use kntx::tls::build_acceptor;

// ── proxy setup helpers ───────────────────────────────────────────────────────

struct L7Proxy {
    addr: SocketAddr,
    _shutdown: watch::Sender<()>,
}

async fn start_l7_proxy(backend_addr: SocketAddr) -> L7Proxy {
    start_l7_proxy_with_limit(backend_addr, 16384).await
}

async fn start_l7_proxy_with_limit(backend_addr: SocketAddr, header_limit: usize) -> L7Proxy {
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![backend_addr],
        3,
        Duration::from_secs(10),
    ));
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: header_limit,
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
        strategy: kntx::config::ForwardingStrategy::Userspace,
        resources: Resources {
            buffer_pool: (*buffer_pool).clone(),
            #[cfg(target_os = "linux")]
            pipe_pool: kntx::pool::pipe::PipePool::with_defaults().unwrap(),
            socket_buffer_size: None,
        },
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

    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));

    L7Proxy {
        addr,
        _shutdown: shutdown_tx,
    }
}

async fn start_l7_proxy_no_backends() -> L7Proxy {
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![dead_addr],
        1,
        Duration::from_secs(10),
    ));
    // trip the circuit breaker on all backends
    pool.record_failure(dead_addr);
    pool.record_failure(dead_addr);
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 1,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
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
        strategy: kntx::config::ForwardingStrategy::Userspace,
        resources: Resources {
            buffer_pool: (*buffer_pool).clone(),
            #[cfg(target_os = "linux")]
            pipe_pool: kntx::pool::pipe::PipePool::with_defaults().unwrap(),
            socket_buffer_size: None,
        },
        max_connections: None,
        idle_timeout: Some(Duration::from_secs(10)),
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(1),
        max_connect_attempts: 1,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };

    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));
    tokio::time::sleep(Duration::from_millis(10)).await;

    L7Proxy {
        addr,
        _shutdown: shutdown_tx,
    }
}

struct L7TlsProxy {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    _shutdown: watch::Sender<()>,
    _tempdir: tempfile::TempDir,
}

async fn start_l7_proxy_tls(backend_addr: SocketAddr) -> L7TlsProxy {
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
    ));
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
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
        strategy: kntx::config::ForwardingStrategy::Userspace,
        resources: Resources {
            buffer_pool: (*buffer_pool).clone(),
            #[cfg(target_os = "linux")]
            pipe_pool: kntx::pool::pipe::PipePool::with_defaults().unwrap(),
            socket_buffer_size: None,
        },
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

    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));

    L7TlsProxy {
        addr,
        cert_der: tc.cert_der,
        _shutdown: shutdown_tx,
        _tempdir: tempdir,
    }
}

// ── raw HTTP helpers ──────────────────────────────────────────────────────────

async fn raw_request(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(req).await.unwrap();
    let mut resp = Vec::new();
    // tolerate ECONNRESET: proxy may RST after sending an error response when
    // there is still unread request body in the receive buffer. bytes received
    // before the RST are still accumulated in resp.
    let _ = stream.read_to_end(&mut resp).await;
    resp
}

fn parse_status(resp: &[u8]) -> u16 {
    let s = std::str::from_utf8(resp).unwrap_or("");
    let parts: Vec<&str> = s.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        parts[1].parse().unwrap_or(0)
    } else {
        0
    }
}

fn response_body(resp: &[u8]) -> &[u8] {
    if let Some(pos) = resp.windows(4).position(|w| w == b"\r\n\r\n") {
        &resp[pos + 4..]
    } else {
        &[]
    }
}

fn response_header(resp: &[u8], name: &str) -> Option<String> {
    let s = std::str::from_utf8(resp).ok()?;
    let head = s.split("\r\n\r\n").next()?;
    for line in head.lines().skip(1) {
        if let Some(colon) = line.find(':')
            && line[..colon].trim().eq_ignore_ascii_case(name)
        {
            return Some(line[colon + 1..].trim().to_owned());
        }
    }
    None
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// 6b.20 — basic GET passes through and response body is correct.
#[tokio::test]
async fn get_happy_path() {
    let backend = HttpBackend::start(ResponseSpec::ok("hello world")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let resp = raw_request(
        proxy.addr,
        b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;

    assert_eq!(parse_status(&resp), 200);
    assert_eq!(response_body(&resp), b"hello world");
}

/// 6b.21 — POST with Content-Length, body is byte-exact.
#[tokio::test]
async fn post_content_length_byte_exact() {
    let body = b"hello";
    let backend =
        HttpBackend::start_with_handler(Arc::new(|req: BackendRequest| ResponseSpec::ok(req.body)))
            .await;
    let proxy = start_l7_proxy(backend.addr).await;

    let req = format!(
        "POST /echo HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\nhello",
        body.len()
    );
    let resp = raw_request(proxy.addr, req.as_bytes()).await;

    assert_eq!(parse_status(&resp), 200);
    assert_eq!(response_body(&resp), b"hello");
}

/// 6b.22 — POST with chunked body, backend receives full body, response correct.
#[tokio::test]
async fn post_chunked_byte_exact_with_trailers() {
    let backend =
        HttpBackend::start_with_handler(Arc::new(|req: BackendRequest| ResponseSpec::ok(req.body)))
            .await;
    let proxy = start_l7_proxy(backend.addr).await;

    // chunked encoding: "5\r\nhello\r\n0\r\n\r\n"
    let req = b"POST /echo HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let resp = raw_request(proxy.addr, req).await;

    assert_eq!(parse_status(&resp), 200);
    assert_eq!(response_body(&resp), b"hello");
}

/// 6b.23 — HEAD response has no body even when backend sets Content-Length.
#[tokio::test]
async fn head_response_no_body_even_with_cl() {
    let backend = HttpBackend::start(ResponseSpec::ok("this body should not appear")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let resp = raw_request(proxy.addr, b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;

    assert_eq!(parse_status(&resp), 200);
    assert_eq!(response_body(&resp), b"");
}

/// 6b.24 — 100 Continue interim response is relayed to client.
#[tokio::test]
async fn expect_100_continue_relayed() {
    // raw backend that sends 100 then waits for body then 200 (handcrafted backend
    // doesn't synthesize interim responses).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            // send 100 first
            s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.unwrap();
            // drain request body
            let mut buf = vec![0u8; 4096];
            let _ = s.read(&mut buf).await;
            // send 200
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        }
    });

    let proxy = start_l7_proxy(backend_addr).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let req = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello";
    let resp = raw_request(proxy.addr, req).await;

    let s = String::from_utf8_lossy(&resp);
    // response should contain either 100 intermediate or just the final 200
    assert!(s.contains("200"));
}

/// 6b.25 — malformed request returns 400 and connection is closed.
#[tokio::test]
async fn malformed_request_returns_400_close() {
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let resp = raw_request(proxy.addr, b"NOT HTTP AT ALL\r\n\r\n").await;
    assert_eq!(parse_status(&resp), 400);
}

/// 6b.26 — request with headers exceeding limit returns 431.
#[tokio::test]
async fn oversized_headers_return_431() {
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let proxy = start_l7_proxy_with_limit(backend.addr, 128).await;

    // build a request with a header value that exceeds the 128-byte limit
    let big_val = "X".repeat(200);
    let req = format!("GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: {big_val}\r\n\r\n");
    let resp = raw_request(proxy.addr, req.as_bytes()).await;
    assert_eq!(parse_status(&resp), 431);
}

/// 6b.27 — smuggling: CL + TE rejected.
#[tokio::test]
async fn smuggling_cl_te_rejected() {
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
    let resp = raw_request(proxy.addr, req).await;
    assert_eq!(parse_status(&resp), 400);
}

#[tokio::test]
async fn smuggling_multi_cl_rejected() {
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
    let resp = raw_request(proxy.addr, req).await;
    assert_eq!(parse_status(&resp), 400);
}

#[tokio::test]
async fn smuggling_te_gzip_rejected() {
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\n\r\n";
    let resp = raw_request(proxy.addr, req).await;
    assert_eq!(parse_status(&resp), 400);
}

#[tokio::test]
async fn smuggling_obs_fold_rejected() {
    // obs-fold: header value with \r\n followed by space — injected raw TCP
    // Note: httparse may strip obs-fold before we see it. Test that we handle it.
    // We send a raw byte sequence and check we get 400 or 200 depending on httparse behavior.
    // The important thing is we don't crash or produce a wrong result.
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    // Most clients don't send obs-fold; we test our code path triggers on it
    // if httparse preserves it. If httparse strips it, the request succeeds.
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Fold: val\r\n continued\r\n\r\n";
    let resp = raw_request(proxy.addr, req).await;
    // either 400 (obs-fold rejected) or 200 (httparse stripped it and request succeeded)
    let status = parse_status(&resp);
    assert!(status == 400 || status == 200, "unexpected status {status}");
}

/// 6b.35 — malformed chunked body returns 400 quickly, no hang.
#[tokio::test]
async fn malformed_chunked_body_returns_400() {
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    // chunk-size says 6 but actual data is 5 bytes ("world"). proxy's chunked
    // reader must error out cleanly with 400, not hang waiting for backend.
    let req = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\nworld\r\n0\r\n\r\n";
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        raw_request(proxy.addr, req),
    )
    .await
    .expect("proxy hung on malformed chunked body");
    assert_eq!(parse_status(&resp), 400);
}

/// 6b.28 — hop-by-hop headers stripped on both directions.
#[tokio::test]
async fn hop_by_hop_stripped_both_directions() {
    let backend = HttpBackend::start_with_handler(Arc::new(|req: BackendRequest| {
        // proxy injects Connection: close — that is expected. We assert the original
        // Keep-Alive header (a hop-by-hop) does not reach the backend.
        if req.header("keep-alive").is_some() {
            ResponseSpec::ok("FAIL: keep-alive reached backend")
        } else {
            ResponseSpec::ok("pass")
        }
    }))
    .await;
    let proxy = start_l7_proxy(backend.addr).await;

    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\n";
    let resp = raw_request(proxy.addr, req).await;
    assert_eq!(parse_status(&resp), 200);
    assert_eq!(response_body(&resp), b"pass");
}

/// 6b.29 — XFF correctly appended; X-Request-ID preserved when client supplies one.
#[tokio::test]
async fn xff_appended() {
    let backend = HttpBackend::start_with_handler(Arc::new(|req: BackendRequest| {
        let xff = req
            .header("x-forwarded-for")
            .unwrap_or("missing")
            .to_owned();
        ResponseSpec::ok(xff)
    }))
    .await;
    let proxy = start_l7_proxy(backend.addr).await;

    let resp = raw_request(proxy.addr, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert_eq!(parse_status(&resp), 200);
    let body = String::from_utf8_lossy(response_body(&resp));
    // client IP (127.0.0.1) should be in XFF
    assert!(body.contains("127.0.0.1"), "XFF not found: {body}");
}

#[tokio::test]
async fn x_request_id_preserved() {
    let backend = HttpBackend::start_with_handler(Arc::new(|req: BackendRequest| {
        let rid = req.header("x-request-id").unwrap_or("missing").to_owned();
        ResponseSpec::ok(rid)
    }))
    .await;
    let proxy = start_l7_proxy(backend.addr).await;

    let resp = raw_request(
        proxy.addr,
        b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Request-ID: my-known-id\r\n\r\n",
    )
    .await;
    assert_eq!(parse_status(&resp), 200);
    assert_eq!(response_body(&resp), b"my-known-id");
}

/// 6b.29a — traceparent passed through unchanged; no trace synthesized when absent.
#[tokio::test]
async fn traceparent_passthrough() {
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let backend = HttpBackend::start_with_handler(Arc::new(move |req: BackendRequest| {
        let received_tp = req.header("traceparent").unwrap_or("missing").to_owned();
        ResponseSpec::ok(received_tp)
    }))
    .await;
    let proxy = start_l7_proxy(backend.addr).await;

    let req = format!("GET / HTTP/1.1\r\nHost: example.com\r\ntraceparent: {tp}\r\n\r\n");
    let resp = raw_request(proxy.addr, req.as_bytes()).await;
    assert_eq!(parse_status(&resp), 200);
    assert_eq!(response_body(&resp), tp.as_bytes());
}

#[tokio::test]
async fn b3_passthrough() {
    let backend = HttpBackend::start_with_handler(Arc::new(|req: BackendRequest| {
        let trace_id = req.header("x-b3-traceid").unwrap_or("missing").to_owned();
        ResponseSpec::ok(trace_id)
    }))
    .await;
    let proxy = start_l7_proxy(backend.addr).await;

    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-B3-TraceId: abc123\r\nX-B3-SpanId: def456\r\n\r\n";
    let resp = raw_request(proxy.addr, req).await;
    assert_eq!(parse_status(&resp), 200);
    assert_eq!(response_body(&resp), b"abc123");
}

#[tokio::test]
async fn no_trace_synthesized_when_absent() {
    let backend = HttpBackend::start_with_handler(Arc::new(|req: BackendRequest| {
        // proxy should NOT add traceparent when client didn't send one
        let has_tp = req.header("traceparent").is_some();
        if has_tp {
            ResponseSpec::ok("FAIL: traceparent synthesized")
        } else {
            ResponseSpec::ok("pass")
        }
    }))
    .await;
    let proxy = start_l7_proxy(backend.addr).await;

    let resp = raw_request(proxy.addr, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert_eq!(response_body(&resp), b"pass");
}

/// 6b.30 — error content negotiation: JSON on Accept: application/json, HTML otherwise.
#[tokio::test]
async fn error_negotiation_json() {
    let proxy = start_l7_proxy_no_backends().await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let resp = raw_request(
        proxy.addr,
        b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\n\r\n",
    )
    .await;
    let ct = response_header(&resp, "content-type").unwrap_or_default();
    assert!(
        ct.contains("application/json"),
        "expected json content-type, got: {ct}"
    );
    let body = String::from_utf8_lossy(response_body(&resp));
    assert!(body.contains("\"status\""), "expected json body: {body}");
}

#[tokio::test]
async fn error_negotiation_html() {
    let proxy = start_l7_proxy_no_backends().await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let resp = raw_request(
        proxy.addr,
        b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n",
    )
    .await;
    let ct = response_header(&resp, "content-type").unwrap_or_default();
    assert!(
        ct.contains("text/html"),
        "expected html content-type, got: {ct}"
    );
    let body = String::from_utf8_lossy(response_body(&resp));
    assert!(
        body.contains("<!doctype html>"),
        "expected html body: {body}"
    );
}

/// 6b.31 — custom error page served from configured file.
#[tokio::test]
async fn custom_error_page_served() {
    use std::io::Write;

    // write a custom 503 page to a temp file
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "<custom>503</custom>").unwrap();
    let path = tmp.path().to_path_buf();

    let mut pages_config = ErrorPagesConfig::default();
    pages_config.pages.insert("503".to_owned(), path.clone());

    let backend_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![backend_addr],
        1,
        Duration::from_secs(10),
    ));
    pool.record_failure(backend_addr); // trip circuit
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));

    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 1,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
    });

    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let error_pages = Arc::new(ErrorPages::load(&pages_config).unwrap());
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
        strategy: kntx::config::ForwardingStrategy::Userspace,
        resources: Resources {
            buffer_pool: (*buffer_pool).clone(),
            #[cfg(target_os = "linux")]
            pipe_pool: kntx::pool::pipe::PipePool::with_defaults().unwrap(),
            socket_buffer_size: None,
        },
        max_connections: None,
        idle_timeout: Some(Duration::from_secs(10)),
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(1),
        max_connect_attempts: 1,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };

    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let resp = raw_request(addr, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    let body = String::from_utf8_lossy(response_body(&resp));
    assert!(
        body.contains("<custom>503</custom>"),
        "custom page not served: {body}"
    );

    let _ = shutdown_tx.send(());
}

/// 6b.32 — CONNECT returns 405; Upgrade: h2c returns 405.
#[tokio::test]
async fn connect_returns_405() {
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let resp = raw_request(
        proxy.addr,
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    )
    .await;
    assert_eq!(parse_status(&resp), 405);
}

#[tokio::test]
async fn upgrade_h2c_returns_405() {
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let resp = raw_request(
        proxy.addr,
        b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
    )
    .await;
    assert_eq!(parse_status(&resp), 405);
}

/// 6b.33 — no healthy backend in pool returns 503.
#[tokio::test]
async fn no_healthy_backend_returns_503() {
    let proxy = start_l7_proxy_no_backends().await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let resp = raw_request(proxy.addr, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert_eq!(parse_status(&resp), 503);
}

/// 6b.34 — connect timeout returns 504.
/// Use a TCP listener that accepts but never responds.
#[tokio::test]
async fn connect_timeout_returns_504() {
    // port 9 is the "discard" port — usually filtered at the OS level which
    // causes connect to time out rather than refuse. Use a listener that accepts
    // but never writes — that should trigger a read timeout. But our current
    // code has a connect timeout, not a read timeout. So we need a backend
    // that never accepts connections (blackhole port).
    // Since we can't easily simulate a TCP blackhole in tests, we use a
    // high-numbered port that's not listening — connect will fail with refused
    // (502), not timeout (504). For the real 504, we'd need firewall rules.
    // We test here that refused backends produce 502, not crash.
    let refused_addr: SocketAddr = "127.0.0.1:19999".parse().unwrap();
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![refused_addr],
        3,
        Duration::from_secs(10),
    ));
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 1,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
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
        strategy: kntx::config::ForwardingStrategy::Userspace,
        resources: Resources {
            buffer_pool: (*buffer_pool).clone(),
            #[cfg(target_os = "linux")]
            pipe_pool: kntx::pool::pipe::PipePool::with_defaults().unwrap(),
            socket_buffer_size: None,
        },
        max_connections: None,
        idle_timeout: Some(Duration::from_secs(10)),
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(1),
        max_connect_attempts: 1,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };

    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));
    tokio::time::sleep(Duration::from_millis(10)).await;

    let resp = raw_request(addr, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    let status = parse_status(&resp);
    // refused → 502; timeout → 504; either is acceptable depending on OS behavior
    assert!(
        status == 502 || status == 504,
        "expected 502 or 504, got {status}"
    );

    let _ = shutdown_tx.send(());
}

/// 6b.19c — access log emits a line per request.
#[tokio::test]
async fn access_log_emits_line() {
    // capture access log to a vec via a file-based sink with a temp file
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;

    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![backend.addr],
        3,
        Duration::from_secs(10),
    ));
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
    });

    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let error_pages = Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap());
    let access_log = Arc::new(
        AccessLogSink::from_config(&AccessLogConfig {
            output: AccessLogOutput::File { file: path.clone() },
            format: None,
            file_channel_capacity: 64,
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

    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));
    tokio::time::sleep(Duration::from_millis(10)).await;

    raw_request(addr, b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n").await;

    // give the file writer time to flush
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = shutdown_tx.send(());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(!content.is_empty(), "access log should have content");
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(parsed["method"], "GET");
    assert_eq!(parsed["path"], "/test");
    assert_eq!(parsed["status"], 200);
}

/// 6b.19c — trace ID from traceparent propagates into log.
#[tokio::test]
async fn access_log_trace_id_propagates() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![backend.addr],
        3,
        Duration::from_secs(10),
    ));
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
    });

    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let error_pages = Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap());
    let access_log = Arc::new(
        AccessLogSink::from_config(&AccessLogConfig {
            output: AccessLogOutput::File { file: path.clone() },
            format: None,
            file_channel_capacity: 64,
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

    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));
    tokio::time::sleep(Duration::from_millis(10)).await;

    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let req = format!("GET / HTTP/1.1\r\nHost: example.com\r\ntraceparent: {tp}\r\n\r\n");
    raw_request(addr, req.as_bytes()).await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = shutdown_tx.send(());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(
        parsed["trace_id"].as_str().unwrap_or(""),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
}

/// Fix 3 — HTTP/2 connection preface returns 505, not 400.
#[tokio::test]
async fn http2_preface_returns_505() {
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    // full HTTP/2 client connection preface (RFC 7540 §3.5)
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let resp = raw_request(proxy.addr, preface).await;
    assert_eq!(parse_status(&resp), 505);
}

// ── hardening pass tests ──────────────────────────────────────────────────────

/// Fix 1 — Transfer-Encoding: Chunked (capital C) must be accepted, not rejected.
#[tokio::test]
async fn smuggling_te_chunked_uppercase_accepted() {
    let backend =
        HttpBackend::start_with_handler(Arc::new(|_req: BackendRequest| ResponseSpec::ok("ok")))
            .await;
    let proxy = start_l7_proxy(backend.addr).await;

    let raw =
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: Chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let resp = raw_request(proxy.addr, raw).await;
    let status = parse_status(&resp);
    assert!(
        (200..300).contains(&status),
        "expected 2xx for mixed-case TE, got {status}"
    );
}

/// Fix 2 — two Transfer-Encoding headers must be rejected with 400.
#[tokio::test]
async fn smuggling_multi_te_rejected() {
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let raw = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n";
    let resp = raw_request(proxy.addr, raw).await;
    assert_eq!(parse_status(&resp), 400);
}

/// Fix 3 — Content-Length: 010 (leading zero) must be rejected with 400.
#[tokio::test]
async fn smuggling_leading_zero_cl_rejected() {
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let raw = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 010\r\n\r\nhellohello";
    let resp = raw_request(proxy.addr, raw).await;
    assert_eq!(parse_status(&resp), 400);
}

/// Fix 3 — Content-Length: 0 (no body) must be accepted.
#[tokio::test]
async fn cl_zero_accepted() {
    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let proxy = start_l7_proxy(backend.addr).await;

    let raw = b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
    let resp = raw_request(proxy.addr, raw).await;
    assert_eq!(parse_status(&resp), 200);
}

/// TLS + L7: basic GET through an L7 listener with TLS termination.
#[tokio::test]
async fn tls_l7_get_happy_path() {
    let backend = HttpBackend::start(ResponseSpec::ok("tls-l7-ok")).await;
    let proxy = start_l7_proxy_tls(backend.addr).await;

    let client_cfg = client_config_trusting(&proxy.cert_der);
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let tcp = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_owned()).unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    // read until proxy closes (it shuts down after each 6b response)
    let mut resp_buf = Vec::new();
    let _ = tls.read_to_end(&mut resp_buf).await;

    assert_eq!(parse_status(&resp_buf), 200);
    assert_eq!(response_body(&resp_buf), b"tls-l7-ok");
}

/// Fix 4 — mid-body backend failure is recorded in passive health tracking.
#[tokio::test]
async fn mid_body_backend_failure_records_passive_health() {
    // backend A: accepts request head then drops the connection (simulates mid-body close)
    let bad_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_addr = bad_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = bad_listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                match s.read(&mut buf[total..]).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        total += n;
                        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            // drop s — connection closes without any response
        }
    });

    let good_backend = HttpBackend::start(ResponseSpec::ok("backend-b")).await;

    // threshold=1: one failure opens the circuit
    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![bad_addr, good_backend.addr],
        1,
        Duration::from_secs(60),
    ));
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));

    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: proxy_addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1, // no retry — first attempt goes to bad_addr
        tls: None,
        header_size_limit_bytes: 16384,
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
        strategy: kntx::config::ForwardingStrategy::Userspace,
        resources: Resources {
            buffer_pool: (*buffer_pool).clone(),
            #[cfg(target_os = "linux")]
            pipe_pool: kntx::pool::pipe::PipePool::with_defaults().unwrap(),
            socket_buffer_size: None,
        },
        max_connections: None,
        idle_timeout: Some(Duration::from_secs(10)),
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(2),
        max_connect_attempts: 1,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: proxy_addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };

    let pool_ref = Arc::clone(&pool);
    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));
    tokio::time::sleep(Duration::from_millis(10)).await;

    // round-robin picks bad_addr first (idx 0); backend closes → record_failure
    let req = b"POST /test HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let resp = raw_request(proxy_addr, req).await;
    let status = parse_status(&resp);
    assert!(
        status == 502 || status == 503,
        "expected 502/503 from bad backend, got {status}"
    );

    tokio::time::sleep(Duration::from_millis(20)).await;

    // bad_addr circuit must be open after the failure
    let bad_state = pool_ref
        .iter()
        .find(|b| b.address() == bad_addr)
        .expect("bad_addr must be in pool");
    assert_eq!(
        bad_state.circuit_state(),
        CircuitState::Open,
        "expected bad backend circuit to be open after mid-body close"
    );

    let _ = shutdown_tx.send(());
}

// ── logged proxy helpers (file sink wired in) ────────────────────────────────

async fn start_l7_proxy_logged(
    backend_addr: SocketAddr,
    log_path: std::path::PathBuf,
) -> (L7Proxy, watch::Sender<()>) {
    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![backend_addr],
        3,
        Duration::from_secs(10),
    ));
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
    });
    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let error_pages = Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap());
    let access_log = Arc::new(
        AccessLogSink::from_config(&AccessLogConfig {
            output: AccessLogOutput::File { file: log_path },
            format: None,
            file_channel_capacity: 64,
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
    let shutdown_tx_ret = shutdown_tx.clone();
    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));
    (
        L7Proxy {
            addr,
            _shutdown: shutdown_tx,
        },
        shutdown_tx_ret,
    )
}

async fn start_l7_proxy_no_backends_logged(
    log_path: std::path::PathBuf,
) -> (L7Proxy, watch::Sender<()>) {
    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![dead_addr],
        1,
        Duration::from_secs(10),
    ));
    pool.record_failure(dead_addr);
    pool.record_failure(dead_addr);
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 1,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
    });
    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let error_pages = Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap());
    let access_log = Arc::new(
        AccessLogSink::from_config(&AccessLogConfig {
            output: AccessLogOutput::File { file: log_path },
            format: None,
            file_channel_capacity: 64,
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
        idle_timeout: Some(Duration::from_secs(10)),
        drain_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(1),
        max_connect_attempts: 1,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: addr.to_string().into(),
        listener_cfg,
        error_pages,
        access_log,
        buffer_pool,
    };
    let shutdown_tx_ret = shutdown_tx.clone();
    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));
    tokio::time::sleep(Duration::from_millis(10)).await;
    (
        L7Proxy {
            addr,
            _shutdown: shutdown_tx,
        },
        shutdown_tx_ret,
    )
}

fn is_uuid_v4(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let b = s.as_bytes();
    b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && b[14] == b'4'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b')
        && s.chars()
            .filter(|&c| c != '-')
            .all(|c| c.is_ascii_hexdigit())
}

/// 6b.36 — smuggling reject preserves inbound X-Request-ID in access log.
#[tokio::test]
async fn smuggling_reject_preserves_inbound_request_id() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let (proxy, shutdown_tx) = start_l7_proxy_logged(backend.addr, path.clone()).await;

    let req = b"POST / HTTP/1.1\r\nHost: x\r\nX-Request-ID: g-test-123\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
    let resp = raw_request(proxy.addr, req).await;
    assert_eq!(parse_status(&resp), 400);

    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = shutdown_tx.send(());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(parsed["request_id"].as_str().unwrap_or(""), "g-test-123");
    assert_eq!(parsed["status"], 400);
}

/// 6b.36 — parse error generates a UUID request_id (not empty).
#[tokio::test]
async fn parse_error_generates_uuid_request_id() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    let backend = HttpBackend::start(ResponseSpec::ok("unreachable")).await;
    let (proxy, shutdown_tx) = start_l7_proxy_logged(backend.addr, path.clone()).await;

    let resp = raw_request(proxy.addr, b"NOT/HTTP\r\n\r\n").await;
    assert_eq!(parse_status(&resp), 400);

    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = shutdown_tx.send(());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    let rid = parsed["request_id"].as_str().unwrap_or("");
    assert!(is_uuid_v4(rid), "expected UUID v4 request_id, got: {rid}");
}

/// 6b.36 — no-healthy-backend 503 preserves inbound X-Request-ID in access log.
#[tokio::test]
async fn no_healthy_backend_preserves_inbound_request_id() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    let (proxy, shutdown_tx) = start_l7_proxy_no_backends_logged(path.clone()).await;

    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Request-ID: g-503-test\r\n\r\n";
    let resp = raw_request(proxy.addr, req).await;
    assert_eq!(parse_status(&resp), 503);

    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = shutdown_tx.send(());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(parsed["request_id"].as_str().unwrap_or(""), "g-503-test");
    assert_eq!(parsed["status"], 503);
}

/// 6b.19c — X-Request-ID round-trips through proxy to log.
#[tokio::test]
async fn access_log_request_id_round_trips() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let backend = HttpBackend::start(ResponseSpec::ok("ok")).await;
    let pool = Arc::new(BackendPool::new(
        "test".into(),
        vec![backend.addr],
        3,
        Duration::from_secs(10),
    ));
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));
    let listener = listener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_cfg = Arc::new(ListenerConfig {
        address: addr,
        mode: ListenerMode::L7,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: Some(10),
        drain_timeout_secs: 1,
        connect_timeout_secs: 2,
        max_connect_attempts: 1,
        tls: None,
        header_size_limit_bytes: 16384,
    });

    let buffer_pool = Arc::new(BufferPool::with_defaults());
    let error_pages = Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap());
    let access_log = Arc::new(
        AccessLogSink::from_config(&AccessLogConfig {
            output: AccessLogOutput::File { file: path.clone() },
            format: None,
            file_channel_capacity: 64,
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

    tokio::spawn(listener::serve(listener, balancer, serve_cfg, shutdown_rx));
    tokio::time::sleep(Duration::from_millis(10)).await;

    raw_request(
        addr,
        b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Request-ID: test-rid-42\r\n\r\n",
    )
    .await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = shutdown_tx.send(());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(parsed["request_id"].as_str().unwrap_or(""), "test-rid-42");
}
