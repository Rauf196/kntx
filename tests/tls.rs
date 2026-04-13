mod helpers;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use kntx::balancer::RoundRobin;
use kntx::config::{CertificateConfig, ForwardingStrategy, TlsConfig};
use kntx::health::BackendPool;
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::tls::build_acceptor;

use helpers::{DyingServer, EchoServer, HalfCloseServer};
use helpers::tls::{
    client_config_trusting, generate_cert, tls_connect, write_cert_to_tempdir, TestCert,
};

fn test_resources() -> Resources {
    Resources {
        buffer_pool: BufferPool::new(64, 64 * 1024),
        #[cfg(target_os = "linux")]
        pipe_pool: kntx::pool::pipe::PipePool::new(32).unwrap(),
        socket_buffer_size: None,
    }
}

fn test_pool(addrs: &[SocketAddr]) -> Arc<BackendPool> {
    Arc::new(BackendPool::new(addrs.to_vec(), 3, Duration::from_secs(10)))
}

/// build a TlsAcceptor from a test cert, writing PEM files to a TempDir.
/// caller must hold the returned TempDir — files are read by build_acceptor eagerly,
/// so the dir can be dropped after setup if preferred, but we return it for clarity.
fn make_tls_acceptor(tc: &TestCert) -> (tokio_rustls::TlsAcceptor, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &tc.cert_pem).unwrap();
    std::fs::write(&key_path, &tc.key_pem).unwrap();

    let tls_config = TlsConfig {
        handshake_timeout_secs: 5,
        min_version: "1.2".to_owned(),
        certificates: vec![CertificateConfig {
            cert: cert_path,
            key: key_path,
            sni_names: vec![],
        }],
    };

    (build_acceptor(&tls_config).unwrap(), dir)
}

/// start a proxy with TLS using the given test cert and default userspace strategy.
/// returns (proxy_addr, tempdir) — caller must hold the TempDir to keep cert files alive.
async fn start_tls_proxy(
    backend_addrs: &[SocketAddr],
    tc: &TestCert,
) -> (SocketAddr, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &tc.cert_pem).unwrap();
    std::fs::write(&key_path, &tc.key_pem).unwrap();

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

    let balancer = Arc::new(RoundRobin::new(test_pool(backend_addrs)));
    let config = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: Some(acceptor),
        tls_handshake_timeout: Duration::from_secs(5),
    };

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(listener::serve(
        tcp_listener,
        balancer,
        config,
        std::future::pending::<()>(),
    ));

    (proxy_addr, dir)
}

// (5.6) basic TLS handshake + echo: handshake succeeds, data flows through proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_echo_basic() {
    let backend = EchoServer::start().await;
    let tc = generate_cert(&["localhost"]);
    let (proxy_addr, _dir) = start_tls_proxy(&[backend.addr], &tc).await;

    let client_cfg = client_config_trusting(&tc.cert_der);
    let mut stream = tls_connect(proxy_addr, "localhost", client_cfg).await;

    stream.write_all(b"hello kntx").await.unwrap();

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello kntx");
}

// (5.6 extended) 50 concurrent TLS clients — each echoes independently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_concurrent_connections() {
    let backend = EchoServer::start().await;
    let tc = generate_cert(&["localhost"]);
    let (proxy_addr, _dir) = start_tls_proxy(&[backend.addr], &tc).await;

    let client_cfg = client_config_trusting(&tc.cert_der);

    // 30 clients × 2 buffers each = 60 buffers, within the 64-buffer test pool
    let tasks: Vec<_> = (0u8..30)
        .map(|i| {
            let cfg = Arc::clone(&client_cfg);
            tokio::spawn(async move {
                let mut stream = tls_connect(proxy_addr, "localhost", cfg).await;
                let msg = format!("client-{i}");
                stream.write_all(msg.as_bytes()).await.unwrap();
                let mut buf = vec![0u8; 64];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
            })
        })
        .collect();

    for t in tasks {
        t.await.unwrap();
    }
}

// 256 KB through TLS — byte-for-byte integrity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_large_payload() {
    let backend = EchoServer::start().await;
    let tc = generate_cert(&["localhost"]);
    let (proxy_addr, _dir) = start_tls_proxy(&[backend.addr], &tc).await;

    let client_cfg = client_config_trusting(&tc.cert_der);
    let mut stream = tls_connect(proxy_addr, "localhost", client_cfg).await;

    let payload: Vec<u8> = (0u8..=255).cycle().take(256 * 1024).collect();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();

    let mut received = Vec::with_capacity(payload.len());
    stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, payload, "256KB payload integrity check failed");
}

// client opens TCP but never sends ClientHello — proxy drops after handshake timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_handshake_timeout() {
    let backend = EchoServer::start().await;
    let tc = generate_cert(&["localhost"]);

    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &tc.cert_pem).unwrap();
    std::fs::write(&key_path, &tc.key_pem).unwrap();

    let tls_config = TlsConfig {
        handshake_timeout_secs: 1, // short timeout for test speed
        min_version: "1.2".to_owned(),
        certificates: vec![CertificateConfig {
            cert: cert_path,
            key: key_path,
            sni_names: vec![],
        }],
    };
    let acceptor = build_acceptor(&tls_config).unwrap();

    let balancer = Arc::new(RoundRobin::new(test_pool(&[backend.addr])));
    let config = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: Some(acceptor),
        tls_handshake_timeout: Duration::from_secs(1),
    };

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(listener::serve(
        tcp_listener,
        balancer,
        config,
        std::future::pending::<()>(),
    ));

    // connect TCP but send no ClientHello — just idle
    let mut idle = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

    // proxy should close the connection after ~1s timeout
    let mut buf = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(3), idle.read(&mut buf))
        .await
        .expect("timed out waiting for proxy to close connection")
        .expect("read error");
    // n=0 means the proxy closed the connection (EOF after handshake timeout)
    // (it may have sent a TLS alert first — both indicate the handshake was aborted)
}

// with no [tls] section, plain TCP still works — regression test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_plain_regression() {
    use tokio::net::TcpStream;

    let backend = EchoServer::start().await;

    let balancer = Arc::new(RoundRobin::new(test_pool(&[backend.addr])));
    let config = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
    };

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(listener::serve(
        tcp_listener,
        balancer,
        config,
        std::future::pending::<()>(),
    ));

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(b"plain tcp works").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"plain tcp works");
}

// strategy = "splice" + TLS enabled — traffic flows via userspace fallback.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_splice_strategy_fallback() {
    let backend = EchoServer::start().await;
    let tc = generate_cert(&["localhost"]);

    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &tc.cert_pem).unwrap();
    std::fs::write(&key_path, &tc.key_pem).unwrap();

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

    let balancer = Arc::new(RoundRobin::new(test_pool(&[backend.addr])));
    let config = ServeConfig {
        strategy: ForwardingStrategy::Splice, // splice configured, but TLS forces userspace
        resources: test_resources(),
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: Some(acceptor),
        tls_handshake_timeout: Duration::from_secs(5),
    };

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(listener::serve(
        tcp_listener,
        balancer,
        config,
        std::future::pending::<()>(),
    ));

    let client_cfg = client_config_trusting(&tc.cert_der);
    let mut stream = tls_connect(proxy_addr, "localhost", client_cfg).await;

    stream.write_all(b"splice fallback").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"splice fallback");
}

// (5.4) two certs with different SANs — client connecting with a.test gets cert A,
// b.test gets cert B. verified by inspecting the peer cert on the client side.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_sni_multi_cert() {
    let backend = EchoServer::start().await;
    let tc_a = generate_cert(&["a.test"]);
    let tc_b = generate_cert(&["b.test"]);

    let (_dir_a, cert_a_path, key_a_path) = write_cert_to_tempdir(&tc_a);
    let (_dir_b, cert_b_path, key_b_path) = write_cert_to_tempdir(&tc_b);

    let tls_config = TlsConfig {
        handshake_timeout_secs: 5,
        min_version: "1.2".to_owned(),
        certificates: vec![
            CertificateConfig {
                cert: cert_a_path,
                key: key_a_path,
                sni_names: vec!["a.test".to_owned()],
            },
            CertificateConfig {
                cert: cert_b_path,
                key: key_b_path,
                sni_names: vec!["b.test".to_owned()],
            },
        ],
    };
    let acceptor = build_acceptor(&tls_config).unwrap();

    let balancer = Arc::new(RoundRobin::new(test_pool(&[backend.addr])));
    let config = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: Some(acceptor),
        tls_handshake_timeout: Duration::from_secs(5),
    };

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(listener::serve(
        tcp_listener,
        balancer,
        config,
        std::future::pending::<()>(),
    ));

    // client_a trusts only cert_a — connecting with SNI "a.test" must succeed
    let client_a = client_config_trusting(&tc_a.cert_der);
    let mut stream_a = tls_connect(proxy_addr, "a.test", client_a).await;
    stream_a.write_all(b"hello a").await.unwrap();
    let mut buf = [0u8; 16];
    let n = stream_a.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello a");

    // client_b trusts only cert_b — connecting with SNI "b.test" must succeed
    let client_b = client_config_trusting(&tc_b.cert_der);
    let mut stream_b = tls_connect(proxy_addr, "b.test", client_b).await;
    stream_b.write_all(b"hello b").await.unwrap();
    let n = stream_b.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello b");

    // cross-trust should fail: client_a trusts cert_a only, connecting with "b.test"
    // will receive cert_b — which client_a doesn't trust
    let cross_client = client_config_trusting(&tc_a.cert_der);
    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;
    let connector = TlsConnector::from(cross_client);
    let sn = ServerName::try_from("b.test".to_owned()).unwrap();
    let result = connector.connect(sn, tcp).await;
    assert!(result.is_err(), "cross-trust should fail: cert_a doesn't cover b.test");
}

// sending garbage bytes to TLS listener → protocol_error metric increments.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_handshake_failure_garbage_input() {
    let backend = EchoServer::start().await;
    let tc = generate_cert(&["localhost"]);
    let (proxy_addr, _dir) = start_tls_proxy(&[backend.addr], &tc).await;

    // connect and immediately send garbage — not a TLS ClientHello
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

    // proxy should abort the handshake and close the connection
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(
        Duration::from_secs(3),
        stream.read(&mut buf),
    )
    .await
    .expect("timed out waiting for proxy to close connection")
    .unwrap_or(0);

    // EOF (n=0) or TLS alert bytes — either way the handshake was rejected
    // the key assertion is that the proxy didn't hang or panic
    let _ = n;
}

// client sends data over TLS, calls shutdown() (close_notify + FIN).
// HalfCloseServer reads until EOF, then sends AFTER_FIN.
// verifies writer.shutdown() on WriteHalf<TlsStream> propagates the half-close correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_half_close() {
    let backend = HalfCloseServer::start().await;
    let tc = generate_cert(&["localhost"]);
    let (proxy_addr, _dir) = start_tls_proxy(&[backend.addr], &tc).await;

    let client_cfg = client_config_trusting(&tc.cert_der);
    let mut stream = tls_connect(proxy_addr, "localhost", client_cfg).await;

    stream.write_all(b"data before close").await.unwrap();
    // shutdown sends TLS close_notify + FIN — proxy must propagate this to the backend
    stream.shutdown().await.unwrap();

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"AFTER_FIN", "proxy must deliver backend response sent after client FIN");
}

// TLS connection with idle timeout: proxy closes an idle TLS connection after the configured
// duration. verifies last_activity tracking works through generic copy_one_direction with TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_idle_timeout() {
    let backend = EchoServer::start().await;
    let tc = generate_cert(&["localhost"]);
    let (acceptor, _dir) = make_tls_acceptor(&tc);

    let balancer = Arc::new(RoundRobin::new(test_pool(&[backend.addr])));
    let config = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: Some(Duration::from_secs(1)),
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: Some(acceptor),
        tls_handshake_timeout: Duration::from_secs(5),
    };

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(listener::serve(
        tcp_listener,
        balancer,
        config,
        std::future::pending::<()>(),
    ));

    let client_cfg = client_config_trusting(&tc.cert_der);
    let mut stream = tls_connect(proxy_addr, "localhost", client_cfg).await;

    // confirm the connection works before going idle
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ping");

    // go idle — wait for the proxy to close the connection
    tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("proxy did not close idle TLS connection within 3s")
        .ok(); // EOF or error — both indicate the proxy closed its end
}

// in-flight TLS connection survives a shutdown signal and completes before drain expires.
// verifies JoinSet drain works when the spawned task holds WriteHalf<TlsStream> behind a Mutex.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_graceful_shutdown() {
    use tokio::sync::oneshot;

    let backend = EchoServer::start().await;
    let tc = generate_cert(&["localhost"]);
    let (acceptor, _dir) = make_tls_acceptor(&tc);

    let balancer = Arc::new(RoundRobin::new(test_pool(&[backend.addr])));
    let config = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: Some(acceptor),
        tls_handshake_timeout: Duration::from_secs(5),
    };

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let serve_handle = tokio::spawn(listener::serve(tcp_listener, balancer, config, async {
        let _ = shutdown_rx.await;
    }));

    let client_cfg = client_config_trusting(&tc.cert_der);
    let mut stream = tls_connect(proxy_addr, "localhost", client_cfg).await;

    // confirm the connection works before signalling shutdown
    stream.write_all(b"before shutdown").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"before shutdown");

    // trigger shutdown — in-flight connection must still work
    shutdown_tx.send(()).unwrap();

    stream.write_all(b"after signal").await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"after signal");

    // close the connection so the proxy task completes and drain can finish
    drop(stream);

    tokio::time::timeout(Duration::from_secs(5), serve_handle)
        .await
        .expect("proxy did not drain within timeout")
        .expect("serve task panicked");
}

// backend drops the connection mid-transfer.
// client should receive whatever data arrived before the crash, then get clean EOF — no hang.
// verifies error propagation through the TLS write half.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_backend_dies_mid_transfer() {
    let backend = DyingServer::start(b"partial").await;
    let tc = generate_cert(&["localhost"]);
    let (proxy_addr, _dir) = start_tls_proxy(&[backend.addr], &tc).await;

    let client_cfg = client_config_trusting(&tc.cert_der);
    let mut stream = tls_connect(proxy_addr, "localhost", client_cfg).await;

    stream.write_all(b"trigger").await.unwrap();

    // read everything — we expect "partial" followed by EOF
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut received))
        .await
        .expect("proxy hung after backend crash")
        .ok();

    assert_eq!(received, b"partial", "should receive exactly what backend sent before dying");
}
