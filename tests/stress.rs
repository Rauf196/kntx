mod helpers;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use kntx::balancer::RoundRobin;
use kntx::config::ForwardingStrategy;
use kntx::health::BackendPool;
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;

use helpers::EchoServer;

fn test_resources() -> Resources {
    // 128 buffers: stress tests use up to 50 concurrent userspace connections (2 buffers each)
    Resources {
        buffer_pool: BufferPool::new(128, 64 * 1024),
        #[cfg(target_os = "linux")]
        pipe_pool: kntx::pool::pipe::PipePool::new(64).unwrap(),
        socket_buffer_size: None,
    }
}

fn test_pool(addrs: &[SocketAddr]) -> Arc<BackendPool> {
    Arc::new(BackendPool::new(addrs.to_vec(), 3, Duration::from_secs(10)))
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

    tokio::spawn(listener::serve(
        tcp_listener,
        balancer,
        config,
        std::future::pending::<()>(),
    ));

    proxy_addr
}

// pool exhaustion: 4 buffers, userspace needs 2 per connection -> max 2 concurrent.
// open 5 connections. at least 1 should succeed, at least 1 should get clean EOF.
// after dropping all connections, verify the proxy recovers (buffers returned).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_exhaustion_degrades_gracefully() {
    let backend = EchoServer::start().await;

    let config = ServeConfig {
        strategy: ForwardingStrategy::Userspace,
        resources: Resources {
            buffer_pool: BufferPool::new(4, 64 * 1024),
            #[cfg(target_os = "linux")]
            pipe_pool: kntx::pool::pipe::PipePool::new(4).unwrap(),
            socket_buffer_size: None,
        },
        max_connections: None,
        idle_timeout: None,
        drain_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_connect_attempts: 3,
    };

    let proxy_addr = start_proxy_with_config(&[backend.addr], config).await;

    // open 5 connections rapidly
    let mut streams = Vec::new();
    for _ in 0..5 {
        streams.push(TcpStream::connect(proxy_addr).await.unwrap());
    }

    // try to use each — some will succeed, some will get EOF (pool exhausted)
    let mut success = 0;
    let mut rejected = 0;
    for stream in &mut streams {
        stream.write_all(b"test").await.unwrap_or(());
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => success += 1,
            _ => rejected += 1,
        }
    }

    assert!(success >= 1, "at least one connection should succeed");
    assert!(
        rejected >= 1,
        "some connections should be rejected (pool exhausted)"
    );

    // drop all connections, let buffers return to pool
    drop(streams);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // verify proxy recovered — new connection should work
    let mut recovery = TcpStream::connect(proxy_addr).await.unwrap();
    recovery.write_all(b"recovered").await.unwrap();
    let mut buf = [0u8; 64];
    let n = recovery.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"recovered");
}

// 100 sequential connections, each sends one message and closes.
// verifies that resources (buffers, pipes, fds) are properly released on each close
// and the proxy remains healthy throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rapid_connection_churn() {
    let backend = EchoServer::start().await;
    let proxy_addr = start_proxy(&[backend.addr]).await;

    for i in 0..100u32 {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let msg = format!("churn-{i}");
        stream.write_all(msg.as_bytes()).await.unwrap();

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
    }
}

// 50 concurrent connections, each sends 10 messages.
// all must complete correctly within a timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_connections_under_load() {
    let backend = EchoServer::start().await;
    let proxy_addr = start_proxy(&[backend.addr]).await;

    let mut tasks = JoinSet::new();

    for i in 0..50u32 {
        let addr = proxy_addr;
        tasks.spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let mut buf = [0u8; 128];

            for j in 0..10u32 {
                let msg = format!("conn-{i}-msg-{j}");
                stream.write_all(msg.as_bytes()).await.unwrap();

                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
            }
        });
    }

    // all should complete within 10 seconds
    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);

    let mut completed = 0u32;
    loop {
        tokio::select! {
            result = tasks.join_next() => {
                match result {
                    Some(Ok(())) => completed += 1,
                    Some(Err(e)) => panic!("connection task panicked: {e}"),
                    None => break,
                }
            }
            _ = &mut deadline => {
                panic!("timeout: only {completed}/50 connections completed");
            }
        }
    }

    assert_eq!(completed, 50);
}

// 3 backends, 30 concurrent connections.
// verifies round-robin and forwarding work correctly under concurrent load.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_backend_concurrent_load() {
    let b1 = EchoServer::start().await;
    let b2 = EchoServer::start().await;
    let b3 = EchoServer::start().await;
    let proxy_addr = start_proxy(&[b1.addr, b2.addr, b3.addr]).await;

    let mut tasks = JoinSet::new();

    for i in 0..30u32 {
        let addr = proxy_addr;
        tasks.spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let msg = format!("multi-{i}");
            stream.write_all(msg.as_bytes()).await.unwrap();

            let mut buf = [0u8; 128];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("connection task panicked");
    }
}

// 20 concurrent connections each send a 256KB payload.
// exercises multi-buffer-cycle under concurrency — verifies no data corruption
// when pool buffers are shared across many simultaneous connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_concurrent_payload() {
    let backend = EchoServer::start().await;
    let proxy_addr = start_proxy(&[backend.addr]).await;

    let mut tasks = JoinSet::new();

    for i in 0..20u32 {
        let addr = proxy_addr;
        tasks.spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();

            // 256KB payload with connection-unique pattern
            let payload: Vec<u8> = (0..256 * 1024)
                .map(|j| ((j + i as usize) % 251) as u8)
                .collect();

            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();

            let mut received = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }

            assert_eq!(received.len(), payload.len(), "conn-{i}: length mismatch");
            assert_eq!(received, payload, "conn-{i}: data corruption");
        });
    }

    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);

    let mut completed = 0u32;
    loop {
        tokio::select! {
            result = tasks.join_next() => {
                match result {
                    Some(Ok(())) => completed += 1,
                    Some(Err(e)) => panic!("connection task panicked: {e}"),
                    None => break,
                }
            }
            _ = &mut deadline => {
                panic!("timeout: only {completed}/20 connections completed");
            }
        }
    }

    assert_eq!(completed, 20);
}
