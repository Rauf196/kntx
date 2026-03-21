mod helpers;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use kntx::balancer::RoundRobin;
use kntx::listener;

use helpers::EchoServer;

async fn start_proxy(backend_addrs: &[SocketAddr]) -> std::net::SocketAddr {
    let backend_addrs: Vec<_> = backend_addrs.to_vec();
    let balancer = Arc::new(RoundRobin::new(backend_addrs));

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(async move {
        listener::serve(tcp_listener, balancer).await;
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

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(async move {
        listener::serve(tcp_listener, balancer_ref).await;
    });

    for _ in 0..4 {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        stream.write_all(b"ping").await.unwrap();

        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
    }

    // connections consumed indices 0,1,2,3 — next is 4 % 2 == 0 → first backend
    let next = balancer.next_backend().unwrap();
    assert_eq!(next, b1_addr);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_unreachable() {
    let dead_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let balancer = Arc::new(RoundRobin::new(vec![dead_addr]));

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = tcp_listener.local_addr().unwrap();

    tokio::spawn(async move {
        listener::serve(tcp_listener, balancer).await;
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);
}
