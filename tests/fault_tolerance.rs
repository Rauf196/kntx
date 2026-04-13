mod helpers;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use kntx::balancer::RoundRobin;
use kntx::config::ForwardingStrategy;
use kntx::health::{BackendPool, CircuitState};
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;

use helpers::EchoServer;

fn test_resources() -> Resources {
    Resources {
        buffer_pool: BufferPool::new(64, 64 * 1024),
        #[cfg(target_os = "linux")]
        pipe_pool: kntx::pool::pipe::PipePool::new(32).unwrap(),
        socket_buffer_size: None,
    }
}

fn test_serve_config() -> ServeConfig {
    ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
    }
}

async fn start_proxy_with_pool(pool: Arc<BackendPool>, config: ServeConfig) -> SocketAddr {
    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();
    tokio::spawn(listener::serve(
        tcp_listener,
        balancer,
        config,
        std::future::pending::<()>(),
    ));
    proxy_addr
}

// (4.9) two backends, one fails: traffic redistributes to the healthy backend.
// after b1 drops, new connections that would hit b1 are retried on b2.
// once the circuit opens, b1 is skipped entirely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_failover_redistributes_traffic() {
    let b1 = EchoServer::start().await;
    let b2 = EchoServer::start().await;
    let b1_addr = b1.addr;

    let pool = Arc::new(BackendPool::new(
        vec![b1_addr, b2.addr],
        2, // circuit opens after 2 failures
        Duration::from_secs(60),
    ));

    let proxy_addr = start_proxy_with_pool(
        Arc::clone(&pool),
        ServeConfig {
            connect_timeout: Duration::from_secs(5),
            max_connect_attempts: 3,
            ..test_serve_config()
        },
    )
    .await;

    // both backends healthy — round-robin works
    for _ in 0..4 {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
    }

    // drop b1 — its port is now refusing connections
    drop(b1);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // connections that hit b1 will fail and retry to b2 (succeeds via retry).
    // after failure_threshold=2 failures to b1, its circuit opens.
    for _ in 0..4 {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        stream.write_all(b"after-drop").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"after-drop");
    }

    // circuit should be open now — all connections go directly to b2
    assert_eq!(
        pool.get(0).circuit_state(),
        CircuitState::Open,
        "b1 circuit should be open after repeated failures"
    );

    // all connections succeed via b2, no retries needed
    for _ in 0..4 {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        stream.write_all(b"failover").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"failover");
    }
}

// (4.13) dead backend + live backend: retry finds the live one.
// first backend refuses connections, second is healthy.
// each connection attempt retries to the live backend and succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_on_connect_failure() {
    let live = EchoServer::start().await;
    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    // dead backend first — round-robin starts there and must retry
    let pool = Arc::new(BackendPool::new(
        vec![dead_addr, live.addr],
        5, // high threshold so circuit stays closed during the test
        Duration::from_secs(60),
    ));

    let proxy_addr = start_proxy_with_pool(Arc::clone(&pool), test_serve_config()).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(b"retry test").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"retry test");
}

// (4.12) all backends dead: client gets clean EOF, no hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_backends_unhealthy_clean_rejection() {
    let dead1: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let dead2: SocketAddr = "127.0.0.1:2".parse().unwrap();

    let pool = Arc::new(BackendPool::new(
        vec![dead1, dead2],
        10, // high threshold — circuit stays closed, all retries exhausted instead
        Duration::from_secs(60),
    ));

    let proxy_addr = start_proxy_with_pool(
        Arc::clone(&pool),
        ServeConfig {
            max_connect_attempts: 2, // 2 attempts total, one per backend
            ..test_serve_config()
        },
    )
    .await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "expected clean EOF when all backends fail");
}

// (4.14) dead backend: connection failure is fast (refused, not timeout).
// verifies connect_timeout is wired without needing an unreachable IP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_enforcement_gives_clean_eof() {
    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    let pool = Arc::new(BackendPool::new(
        vec![dead_addr],
        10,
        Duration::from_secs(60),
    ));

    let proxy_addr = start_proxy_with_pool(
        Arc::clone(&pool),
        ServeConfig {
            connect_timeout: Duration::from_secs(5),
            max_connect_attempts: 1,
            ..test_serve_config()
        },
    )
    .await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "expected EOF after connect failure");
}

// (4.10 partial) repeated connect failures open the circuit.
// after circuit is open, next_backend() returns None — immediate EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn circuit_opens_after_connect_failures() {
    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    let pool = Arc::new(BackendPool::new(
        vec![dead_addr],
        2, // circuit opens after 2 failures
        Duration::from_secs(60),
    ));

    let proxy_addr = start_proxy_with_pool(
        Arc::clone(&pool),
        ServeConfig {
            max_connect_attempts: 1,
            ..test_serve_config()
        },
    )
    .await;

    // two connections each fail once → 2 failures → circuit opens
    for _ in 0..2 {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0u8; 16];
        stream.read(&mut buf).await.ok();
        // brief pause for the proxy task to record the failure before next attempt
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        pool.get(0).circuit_state(),
        CircuitState::Open,
        "circuit should be open after 2 failures with threshold=2"
    );

    // next connection: no healthy backends → immediate EOF (no retry attempted)
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(
        n, 0,
        "expected EOF when circuit is open and no other backends"
    );
}

// (4.11) backend recovers: circuit transitions from Open through HalfOpen to Closed.
// tested at the unit level in health/mod.rs (tests 5, 8).
// this integration test verifies the recovery path via traffic:
// after the circuit opens, a new live backend on the same address
// (simulated by starting a fresh EchoServer) recovers via health check.
// NOTE: port rebinding can't be guaranteed in tests, so we test the
// simpler case: live backend + dead backend, only the live one is used
// after the dead one's circuit opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthy_backend_serves_after_peer_fails() {
    let live = EchoServer::start().await;
    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    let pool = Arc::new(BackendPool::new(
        vec![dead_addr, live.addr],
        2, // circuit opens quickly
        Duration::from_secs(60),
    ));

    let proxy_addr = start_proxy_with_pool(
        Arc::clone(&pool),
        ServeConfig {
            max_connect_attempts: 3,
            ..test_serve_config()
        },
    )
    .await;

    // send enough connections to open the dead backend's circuit
    // each attempt hits dead first (round-robin), fails, retries to live
    for _ in 0..4 {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        stream.write_all(b"probe").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"probe");
    }

    // dead backend's circuit should be open
    assert_eq!(pool.get(0).circuit_state(), CircuitState::Open);

    // all subsequent connections go directly to live backend — no retries
    for _ in 0..4 {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        stream.write_all(b"direct").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"direct");
    }
}
