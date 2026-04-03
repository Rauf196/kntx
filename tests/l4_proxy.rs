mod helpers;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use kntx::balancer::RoundRobin;
use kntx::config::ForwardingStrategy;
use kntx::listener;
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

async fn start_proxy(backend_addrs: &[SocketAddr]) -> SocketAddr {
    start_proxy_with_strategy(backend_addrs, ForwardingStrategy::Userspace).await
}

async fn start_proxy_with_strategy(
    backend_addrs: &[SocketAddr],
    strategy: ForwardingStrategy,
) -> std::net::SocketAddr {
    let backend_addrs: Vec<_> = backend_addrs.to_vec();
    let balancer = Arc::new(RoundRobin::new(backend_addrs));
    let resources = test_resources();

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(async move {
        listener::serve(tcp_listener, balancer, strategy, resources).await;
    });

    proxy_addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_backend_echo() {
    let backend = EchoServer::start().await;
    let proxy_addr = start_proxy(&[backend.addr]).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    stream.write_all(b"hello kntx").await.unwrap();

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello kntx");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_messages() {
    let backend = EchoServer::start().await;
    let proxy_addr = start_proxy(&[backend.addr]).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut buf = [0u8; 64];

    for i in 0..10 {
        let msg = format!("message {i}");
        stream.write_all(msg.as_bytes()).await.unwrap();

        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn round_robin_distribution() {
    let b1 = EchoServer::start().await;
    let b2 = EchoServer::start().await;
    let b1_addr = b1.addr;
    let b2_addr = b2.addr;

    let backend_addrs = vec![b1_addr, b2_addr];
    let balancer = Arc::new(RoundRobin::new(backend_addrs));
    let balancer_ref = Arc::clone(&balancer);
    let resources = test_resources();

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(async move {
        listener::serve(
            tcp_listener,
            balancer_ref,
            ForwardingStrategy::Userspace,
            resources,
        )
        .await;
    });

    for _ in 0..4 {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        stream.write_all(b"ping").await.unwrap();

        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
    }

    // connections consumed indices 0,1,2,3 - next is 4 % 2 == 0 -> first backend
    let next = balancer.next_backend().unwrap();
    assert_eq!(next, b1_addr);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_unreachable() {
    let dead_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let balancer = Arc::new(RoundRobin::new(vec![dead_addr]));
    let resources = test_resources();

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(async move {
        listener::serve(
            tcp_listener,
            balancer,
            ForwardingStrategy::Userspace,
            resources,
        )
        .await;
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);
}

// --- large payload integrity test (all strategies) ---
// verifies no data corruption through each forwarding path with payloads
// larger than a single buffer (64KB), exercising multi-read/write cycles.

async fn verify_large_payload(strategy: ForwardingStrategy) {
    let backend = EchoServer::start().await;
    let proxy_addr = start_proxy_with_strategy(&[backend.addr], strategy).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    // 256KB payload  - larger than one buffer (64KB), forces multiple read/write cycles
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
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

    assert_eq!(received.len(), payload.len(), "length mismatch");
    assert_eq!(received, payload, "data corruption detected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_payload_userspace() {
    verify_large_payload(ForwardingStrategy::Userspace).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_payload_vectored() {
    verify_large_payload(ForwardingStrategy::Vectored).await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_payload_splice() {
    verify_large_payload(ForwardingStrategy::Splice).await;
}

// --- vectored I/O forwarding tests ---

mod vectored_tests {
    use super::*;

    async fn start_vectored_proxy(backend_addrs: &[SocketAddr]) -> SocketAddr {
        start_proxy_with_strategy(backend_addrs, ForwardingStrategy::Vectored).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn single_backend_echo() {
        let backend = EchoServer::start().await;
        let proxy_addr = start_vectored_proxy(&[backend.addr]).await;

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        stream.write_all(b"hello vectored").await.unwrap();

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello vectored");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_messages() {
        let backend = EchoServer::start().await;
        let proxy_addr = start_vectored_proxy(&[backend.addr]).await;

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0u8; 64];

        for i in 0..10 {
            let msg = format!("vectored msg {i}");
            stream.write_all(msg.as_bytes()).await.unwrap();

            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        }
    }
}

// --- splice forwarding tests (linux only) ---
// mirror the userspace tests to verify data integrity through the splice path

#[cfg(target_os = "linux")]
mod splice_tests {
    use super::*;

    async fn start_splice_proxy(backend_addrs: &[SocketAddr]) -> SocketAddr {
        start_proxy_with_strategy(backend_addrs, ForwardingStrategy::Splice).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn single_backend_echo() {
        let backend = EchoServer::start().await;
        let proxy_addr = start_splice_proxy(&[backend.addr]).await;

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        stream.write_all(b"hello splice").await.unwrap();

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello splice");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_messages() {
        let backend = EchoServer::start().await;
        let proxy_addr = start_splice_proxy(&[backend.addr]).await;

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0u8; 64];

        for i in 0..10 {
            let msg = format!("splice msg {i}");
            stream.write_all(msg.as_bytes()).await.unwrap();

            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn round_robin_distribution() {
        let b1 = EchoServer::start().await;
        let b2 = EchoServer::start().await;
        let b1_addr = b1.addr;
        let b2_addr = b2.addr;

        let backend_addrs = vec![b1_addr, b2_addr];
        let balancer = Arc::new(RoundRobin::new(backend_addrs));
        let balancer_ref = Arc::clone(&balancer);
        let resources = test_resources();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = tcp_listener.local_addr().unwrap();

        tokio::spawn(async move {
            listener::serve(
                tcp_listener,
                balancer_ref,
                ForwardingStrategy::Splice,
                resources,
            )
            .await;
        });

        for _ in 0..4 {
            let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
            stream.write_all(b"ping").await.unwrap();

            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
        }

        let next = balancer.next_backend().unwrap();
        assert_eq!(next, b1_addr);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backend_unreachable() {
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let balancer = Arc::new(RoundRobin::new(vec![dead_addr]));
        let resources = test_resources();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = tcp_listener.local_addr().unwrap();

        tokio::spawn(async move {
            listener::serve(
                tcp_listener,
                balancer,
                ForwardingStrategy::Splice,
                resources,
            )
            .await;
        });

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }
}
