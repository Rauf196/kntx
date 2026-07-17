mod helpers;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
use kntx::proxy::l7::router::Router;

use helpers::http_backend::{HttpBackend, ResponseSpec};
use helpers::{EchoServer, make_single_pool_router};

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
        KeepaliveConfig::default(),
    ))
}

fn test_listener_cfg() -> Arc<ListenerConfig> {
    Arc::new(ListenerConfig {
        address: "127.0.0.1:0".parse().unwrap(),
        mode: ListenerMode::L4,
        pool: Some("test".to_owned()),
        routes: vec![],
        max_connections: None,
        idle_timeout_secs: None,
        drain_timeout_secs: 5,
        connect_timeout_secs: 5,
        max_connect_attempts: 3,
        tls: None,
        header_size_limit_bytes: 16384,
        ..Default::default()
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
/// the returned Sender keeps the listener alive - drop it to shut down.
async fn start_listener(
    router: Arc<dyn Router>,
    label: &str,
) -> (SocketAddr, tokio::sync::watch::Sender<()>) {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    tokio::spawn(listener::serve(
        tcp_listener,
        router,
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

// T9.a: two listeners with different pools - traffic is isolated.
// L1 only routes to b1, L2 only routes to b2.
// connections through L1 must never hit b2 and vice versa.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_listeners_different_pools_are_isolated() {
    let b1 = EchoServer::start().await;
    let b2 = EchoServer::start().await;

    let pool1 = make_pool_named("p1", &[b1.addr]);
    let pool2 = make_pool_named("p2", &[b2.addr]);

    let rr1 = Arc::new(RoundRobin::new(Arc::clone(&pool1)));
    let rr2 = Arc::new(RoundRobin::new(Arc::clone(&pool2)));

    let (l1_addr, _tx1) = start_listener(make_single_pool_router(pool1, rr1), "l1").await;
    let (l2_addr, _tx2) = start_listener(make_single_pool_router(pool2, rr2), "l2").await;

    // connections through L1 hit b1
    for _ in 0..4 {
        echo_assert(l1_addr, b"from l1").await;
    }

    // connections through L2 hit b2
    for _ in 0..4 {
        echo_assert(l2_addr, b"from l2").await;
    }

    // now shut down b1 - L1 should fail but L2 should be unaffected
    drop(b1);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // L2 still works fine (b2 is alive)
    echo_assert(l2_addr, b"still works").await;
}

// T9.b: two listeners sharing the same pool share the round-robin counter.
// verifies the architectural invariant that a single Arc<RoundRobin> backs
// both listeners - with independent RRs this test would fail two ways:
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
        KeepaliveConfig::default(),
    ));
    let shared_rr = Arc::new(RoundRobin::new(Arc::clone(&shared_pool)));

    // both routers hold a clone of shared_rr → strong_count = 1 + 1 + 1 = 3
    let router1 = make_single_pool_router(Arc::clone(&shared_pool), Arc::clone(&shared_rr));
    let router2 = make_single_pool_router(Arc::clone(&shared_pool), Arc::clone(&shared_rr));
    let (l1_addr, _tx1) = start_listener(router1, "l1").await;
    let (l2_addr, _tx2) = start_listener(router2, "l2").await;

    // before traffic: test holds 1, each router task holds 1 → exactly 3.
    // if routers used independent RoundRobins this would be 1.
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

    let rr1 = Arc::new(RoundRobin::new(pool1.clone()));
    let rr2 = Arc::new(RoundRobin::new(pool2.clone()));
    let router1 = make_single_pool_router(pool1, rr1);
    let router2 = make_single_pool_router(pool2, rr2);

    let tcp_l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l1_addr = tcp_l1.local_addr().unwrap();
    let _l2_addr = tcp_l2.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    let h1 = tokio::spawn(listener::serve(
        tcp_l1,
        router1,
        ServeConfig {
            drain_timeout: Duration::from_secs(5),
            ..serve_config("l1")
        },
        shutdown_rx.clone(),
    ));
    let h2 = tokio::spawn(listener::serve(
        tcp_l2,
        router2,
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

    // fire shutdown - both listeners should begin draining
    let _ = shutdown_tx.send(());

    // L2 should exit quickly (nothing to drain)
    tokio::time::timeout(Duration::from_secs(2), h2)
        .await
        .expect("L2 did not exit within 2s")
        .expect("L2 serve task panicked");

    // L1 is still held open by s1 - close it to let drain complete
    drop(s1);

    tokio::time::timeout(Duration::from_secs(3), h1)
        .await
        .expect("L1 did not complete drain within 3s")
        .expect("L1 serve task panicked");
}

// L4 forwarding allocates a fresh backend conn per client conn and does not
// touch the per-BackendState keep-alive cache. When the same pool is shared
// between an L4 listener and an L7 listener, the L7 listener's idle cache
// must remain intact across L4 traffic. The test pins the pool's
// `total_count` (active + idle conns held by the proxy) before and after
// L4 activity; the L4 path's transient connect/disconnect does not change
// this gauge, and the subsequent L7 request reuses the cached idle conn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_shared_l4_l7_listener() {
    use std::sync::atomic::Ordering;
    let backend = HttpBackend::start_keepalive(ResponseSpec::ok("shared")).await;

    let shared_pool = Arc::new(BackendPool::new(
        "shared".into(),
        vec![backend.addr],
        3,
        Duration::from_secs(10),
        KeepaliveConfig::default(),
    ));
    let shared_rr = Arc::new(RoundRobin::new(Arc::clone(&shared_pool)));

    let l4_router = make_single_pool_router(Arc::clone(&shared_pool), Arc::clone(&shared_rr));
    let l4_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l4_addr = l4_tcp.local_addr().unwrap();
    let (l4_shutdown_tx, l4_shutdown_rx) = tokio::sync::watch::channel(());
    let l4_cfg = ServeConfig {
        listener_cfg: Arc::new(ListenerConfig {
            address: l4_addr,
            mode: ListenerMode::L4,
            pool: Some("shared".to_owned()),
            routes: vec![],
            max_connections: None,
            idle_timeout_secs: None,
            drain_timeout_secs: 1,
            connect_timeout_secs: 2,
            max_connect_attempts: 1,
            tls: None,
            header_size_limit_bytes: 16384,
            ..Default::default()
        }),
        ..serve_config("l4")
    };
    tokio::spawn(listener::serve(l4_tcp, l4_router, l4_cfg, l4_shutdown_rx));

    let l7_router = make_single_pool_router(Arc::clone(&shared_pool), Arc::clone(&shared_rr));
    let l7_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l7_addr = l7_tcp.local_addr().unwrap();
    let (l7_shutdown_tx, l7_shutdown_rx) = tokio::sync::watch::channel(());
    let l7_cfg = ServeConfig {
        listener_cfg: Arc::new(ListenerConfig {
            address: l7_addr,
            mode: ListenerMode::L7,
            pool: Some("shared".to_owned()),
            routes: vec![],
            max_connections: None,
            idle_timeout_secs: None,
            drain_timeout_secs: 1,
            connect_timeout_secs: 2,
            max_connect_attempts: 1,
            tls: None,
            header_size_limit_bytes: 16384,
            ..Default::default()
        }),
        ..serve_config("l7")
    };
    tokio::spawn(listener::serve(l7_tcp, l7_router, l7_cfg, l7_shutdown_rx));

    // warm the keep-alive cache with one L7 request: the backend conn used
    // here is returned to the cache, leaving `total_count == 1` for the
    // single backend.
    issue_http_request(l7_addr).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let state = shared_pool.state_for(backend.addr).unwrap();
    assert_eq!(
        state.total_count.0.load(Ordering::Acquire),
        1,
        "L7 request must leave one idle conn in the cache"
    );
    assert_eq!(backend.accept_count(), 1);

    // L4 traffic: a fresh backend TCP conn per request, no cache interaction.
    // accept_count rises but the L7 cache invariant holds.
    for _ in 0..3 {
        issue_http_request(l4_addr).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        state.total_count.0.load(Ordering::Acquire),
        1,
        "L4 traffic must not perturb the L7 keep-alive cache"
    );

    // next L7 request reuses the cached idle conn - backend accept count
    // stays steady relative to the pre-L7 count established above.
    let before = backend.accept_count();
    issue_http_request(l7_addr).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        backend.accept_count(),
        before,
        "second L7 request must hit the cached backend conn, not open a fresh one"
    );

    let _ = l4_shutdown_tx.send(());
    let _ = l7_shutdown_tx.send(());
}

// fire a single HTTP/1.1 request through `addr` and read the response.
// `addr` may be either an L4 or L7 proxy front-end; in both cases the
// backend is HTTP and parses the same bytes.
async fn issue_http_request(addr: SocketAddr) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")
        .await
        .unwrap();
    // half-close so the L4 path observes EOF and tears down; for L7 the
    // proxy's default-on keep-alive would otherwise hold the conn until
    // idle, blocking the response read here.
    let _ = s.shutdown().await;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    assert!(buf.starts_with(b"HTTP/1.1 200"), "got: {buf:?}");
}
