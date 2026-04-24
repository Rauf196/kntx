mod helpers;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use kntx::balancer::RoundRobin;
use kntx::config::ForwardingStrategy;
use kntx::health::BackendPool;
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;

use helpers::{DyingServer, EchoServer, HalfCloseServer};

fn test_resources() -> Resources {
    Resources {
        buffer_pool: BufferPool::new(64, 64 * 1024),
        #[cfg(target_os = "linux")]
        pipe_pool: kntx::pool::pipe::PipePool::new(32).unwrap(),
        socket_buffer_size: None,
    }
}

fn test_pool(addrs: &[SocketAddr]) -> Arc<BackendPool> {
    Arc::new(BackendPool::new(
        "test".into(),
        addrs.to_vec(),
        3,
        Duration::from_secs(10),
    ))
}

fn test_serve_config(strategy: ForwardingStrategy) -> ServeConfig {
    ServeConfig {
        strategy,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: "test-listener".into(),
    }
}

async fn start_proxy(backend_addrs: &[SocketAddr]) -> SocketAddr {
    start_proxy_with_config(
        backend_addrs,
        test_serve_config(ForwardingStrategy::Userspace),
    )
    .await
}

async fn start_proxy_with_config(backend_addrs: &[SocketAddr], config: ServeConfig) -> SocketAddr {
    let balancer = Arc::new(RoundRobin::new(test_pool(backend_addrs)));
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    tokio::spawn(async move {
        let _tx = shutdown_tx;
        std::future::pending::<()>().await
    });
    tokio::spawn(listener::serve(tcp_listener, balancer, config, shutdown_rx));

    proxy_addr
}

async fn verify_half_close(strategy: ForwardingStrategy) {
    let backend = HalfCloseServer::start().await;
    let proxy_addr = start_proxy_with_config(&[backend.addr], test_serve_config(strategy)).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    stream.write_all(b"request data").await.unwrap();
    stream.shutdown().await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"AFTER_FIN");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_close_userspace() {
    verify_half_close(ForwardingStrategy::Userspace).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_close_vectored() {
    verify_half_close(ForwardingStrategy::Vectored).await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_close_splice() {
    verify_half_close(ForwardingStrategy::Splice).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_timeout_closes_connection() {
    let backend = EchoServer::start().await;

    let config = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: None,
        idle_timeout: Some(Duration::from_secs(1)),
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: "test-listener".into(),
    };

    let proxy_addr = start_proxy_with_config(&[backend.addr], config).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "expected EOF after idle timeout");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_connections_rejects_excess() {
    let backend = EchoServer::start().await;

    let config = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: test_resources(),
        max_connections: Some(2),
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
        tls_acceptor: None,
        tls_handshake_timeout: Duration::from_secs(5),
        listener_label: "test-listener".into(),
    };

    let proxy_addr = start_proxy_with_config(&[backend.addr], config).await;

    let mut s1 = TcpStream::connect(proxy_addr).await.unwrap();
    let mut s2 = TcpStream::connect(proxy_addr).await.unwrap();

    s1.write_all(b"one").await.unwrap();
    s2.write_all(b"two").await.unwrap();
    let mut buf = [0u8; 64];
    let n = s1.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"one");
    let n = s2.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"two");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut s3 = TcpStream::connect(proxy_addr).await.unwrap();
    let n = s3.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "expected rejection (EOF) for connection beyond limit");

    drop(s1);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut s4 = TcpStream::connect(proxy_addr).await.unwrap();
    s4.write_all(b"four").await.unwrap();
    let n = s4.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"four");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_shutdown_drains_connections() {
    let backend = EchoServer::start().await;

    let pool = test_pool(&[backend.addr]);
    let balancer = Arc::new(RoundRobin::new(pool));
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
        listener_label: "test-listener".into(),
    };

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let serve_handle = tokio::spawn(listener::serve(tcp_listener, balancer, config, shutdown_rx));

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(b"before shutdown").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"before shutdown");

    let _ = shutdown_tx.send(());

    stream.write_all(b"after signal").await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"after signal");

    drop(stream);

    tokio::time::timeout(Duration::from_secs(5), serve_handle)
        .await
        .expect("serve did not complete within timeout")
        .expect("serve task panicked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_unreachable_clean_close() {
    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let proxy_addr = start_proxy(&[dead_addr]).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "expected clean EOF when backend is unreachable");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_dies_mid_connection() {
    let backend = DyingServer::start(b"partial").await;
    let proxy_addr = start_proxy(&[backend.addr]).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(b"request").await.unwrap();

    let mut received = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }

    assert_eq!(&received, b"partial");
}
