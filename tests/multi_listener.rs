mod helpers;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use kntx::access_log::AccessLogSink;
use kntx::balancer::RoundRobin;
use kntx::config::{ErrorPagesConfig, ForwardingStrategy, ListenerConfig, ListenerMode};
use kntx::health::BackendPool;
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::proxy::l7::ErrorPages;

use helpers::EchoServer;

fn test_resources() -> Resources {
    Resources {
        buffer_pool: BufferPool::new(64, 64 * 1024),
        #[cfg(target_os = "linux")]
        pipe_pool: kntx::pool::pipe::PipePool::new(32).unwrap(),
        socket_buffer_size: None,
    }
}

fn make_pool_named(name: &str, addrs: &[SocketAddr]) -> Arc<BackendPool> {
    Arc::new(BackendPool::new(
        name.into(),
        addrs.to_vec(),
        3,
        Duration::from_secs(10),
    ))
}

fn test_listener_cfg() -> Arc<ListenerConfig> {
    Arc::new(ListenerConfig {
        address: "127.0.0.1:0".parse().unwrap(),
        mode: ListenerMode::L4,
        pool: "test".to_owned(),
        max_connections: None,
        idle_timeout_secs: None,
        drain_timeout_secs: 5,
        connect_timeout_secs: 5,
        max_connect_attempts: 3,
        tls: None,
        header_size_limit_bytes: 16384,
    })
}

fn serve_config(label: &str) -> ServeConfig {
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
        listener_label: label.into(),
        listener_cfg: test_listener_cfg(),
        error_pages: Arc::new(ErrorPages::load(&ErrorPagesConfig::default()).unwrap()),
        access_log: Arc::new(AccessLogSink::Off),
        buffer_pool: Arc::new(BufferPool::new(64, 64 * 1024)),
    }
}

/// start a listener and return its bound address.
/// the returned Sender keeps the listener alive — drop it to shut down.
async fn start_listener(
    balancer: Arc<RoundRobin>,
    label: &str,
) -> (SocketAddr, tokio::sync::watch::Sender<()>) {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    tokio::spawn(listener::serve(
        tcp_listener,
        balancer,
        serve_config(label),
        shutdown_rx,
    ));
    (addr, shutdown_tx)
}

/// send a message through a proxy and assert the echo response.
async fn echo_assert(proxy_addr: SocketAddr, msg: &[u8]) {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, msg);
}

// T9.a: two listeners with different pools — traffic is isolated.
// L1 only routes to b1, L2 only routes to b2.
// connections through L1 must never hit b2 and vice versa.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_listeners_different_pools_are_isolated() {
    let b1 = EchoServer::start().await;
    let b2 = EchoServer::start().await;

    let pool1 = make_pool_named("p1", &[b1.addr]);
    let pool2 = make_pool_named("p2", &[b2.addr]);

    let balancer1 = Arc::new(RoundRobin::new(Arc::clone(&pool1)));
    let balancer2 = Arc::new(RoundRobin::new(Arc::clone(&pool2)));

    let (l1_addr, _tx1) = start_listener(balancer1, "l1").await;
    let (l2_addr, _tx2) = start_listener(balancer2, "l2").await;

    // connections through L1 hit b1
    for _ in 0..4 {
        echo_assert(l1_addr, b"from l1").await;
    }

    // connections through L2 hit b2
    for _ in 0..4 {
        echo_assert(l2_addr, b"from l2").await;
    }

    // now shut down b1 — L1 should fail but L2 should be unaffected
    drop(b1);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // L2 still works fine (b2 is alive)
    echo_assert(l2_addr, b"still works").await;
}

// T9.b: two listeners sharing the same pool share the round-robin counter.
// verifies the architectural invariant that a single Arc<RoundRobin> backs
// both listeners — with independent RRs this test would fail two ways:
// the strong_count check catches it at setup, and the current_index readback
// catches it after traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_listeners_shared_pool_share_rr_counter() {
    let b1 = EchoServer::start().await;
    let b2 = EchoServer::start().await;

    let shared_pool = Arc::new(BackendPool::new(
        "shared".into(),
        vec![b1.addr, b2.addr],
        3,
        Duration::from_secs(10),
    ));
    let shared_rr = Arc::new(RoundRobin::new(Arc::clone(&shared_pool)));

    let (l1_addr, _tx1) = start_listener(Arc::clone(&shared_rr), "l1").await;
    let (l2_addr, _tx2) = start_listener(Arc::clone(&shared_rr), "l2").await;

    // before traffic: test holds 1, each listener task holds 1 → exactly 3.
    // if a listener had cloned into its own RoundRobin this would be 1.
    assert_eq!(
        Arc::strong_count(&shared_rr),
        3,
        "both listeners must share the same Arc<RoundRobin>",
    );

    let hits = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for i in 0..20u8 {
        let addr = if i % 2 == 0 { l1_addr } else { l2_addr };
        let hits = Arc::clone(&hits);
        tasks.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let msg = [i];
            stream.write_all(&msg).await.unwrap();
            let mut buf = [0u8; 1];
            if stream.read_exact(&mut buf).await.is_ok() && buf[0] == i {
                hits.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for t in tasks {
        t.await.unwrap();
    }

    assert_eq!(hits.load(Ordering::Relaxed), 20);

    // shared counter incremented once per accepted connection, from both listeners.
    // independent RRs would leave this at 0 (test never sees the listener-owned counter).
    assert_eq!(
        shared_rr.current_index(),
        20,
        "shared RR counter must advance by total connections across both listeners",
    );
}

// T9.c: shutdown drains both listeners independently.
// L1 has an in-flight connection (streaming data); L2 is idle.
// after firing shutdown, L1 waits for its connection, L2 exits quickly.
// total shutdown is bounded by L1's drain_timeout, not their sum.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_drains_all_listeners_independently() {
    let b1 = EchoServer::start().await;
    let b2 = EchoServer::start().await;

    let pool1 = make_pool_named("p1", &[b1.addr]);
    let pool2 = make_pool_named("p2", &[b2.addr]);

    let balancer1 = Arc::new(RoundRobin::new(pool1));
    let balancer2 = Arc::new(RoundRobin::new(pool2));

    let tcp_l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l1_addr = tcp_l1.local_addr().unwrap();
    let _l2_addr = tcp_l2.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    let h1 = tokio::spawn(listener::serve(
        tcp_l1,
        balancer1,
        ServeConfig {
            drain_timeout: Duration::from_secs(5),
            ..serve_config("l1")
        },
        shutdown_rx.clone(),
    ));
    let h2 = tokio::spawn(listener::serve(
        tcp_l2,
        balancer2,
        ServeConfig {
            drain_timeout: Duration::from_secs(5),
            ..serve_config("l2")
        },
        shutdown_rx,
    ));

    // establish a connection on L1 and keep it open
    let mut s1 = TcpStream::connect(l1_addr).await.unwrap();
    s1.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 16];
    let n = s1.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");

    // L2 has no in-flight connections

    // fire shutdown — both listeners should begin draining
    let _ = shutdown_tx.send(());

    // L2 should exit quickly (nothing to drain)
    tokio::time::timeout(Duration::from_secs(2), h2)
        .await
        .expect("L2 did not exit within 2s")
        .expect("L2 serve task panicked");

    // L1 is still held open by s1 — close it to let drain complete
    drop(s1);

    tokio::time::timeout(Duration::from_secs(3), h1)
        .await
        .expect("L1 did not complete drain within 3s")
        .expect("L1 serve task panicked");
}
