#![allow(dead_code)]

pub mod http_backend;
pub mod keepalive_client;
pub mod tls;
pub mod ws_backend;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use kntx::balancer::RoundRobin;
use kntx::config::KeepaliveConfig;
use kntx::health::BackendPool;
use kntx::proxy::l7::matcher::CompositeMatcher;
use kntx::proxy::l7::router::{ConfigRouter, PoolHandle, RouteEntry, Router};

/// wrap a single pool into a catch-all `ConfigRouter` suitable for tests.
pub fn make_single_pool_router(pool: Arc<BackendPool>, rr: Arc<RoundRobin>) -> Arc<dyn Router> {
    let handle = PoolHandle {
        name: pool.name().into(),
        backends: pool,
        rr,
    };
    let entry = RouteEntry {
        rate_limit: None,
        matcher: CompositeMatcher::new(vec![]),
        pool: handle,
        route_id: Arc::from("default"),
    };
    Arc::new(ConfigRouter::new(vec![entry]))
}

/// build a test pool with one or more backend addresses.
pub fn make_test_pool(name: &str, addrs: &[std::net::SocketAddr]) -> Arc<BackendPool> {
    Arc::new(BackendPool::new(
        name.into(),
        addrs.to_vec(),
        3,
        Duration::from_secs(10),
        KeepaliveConfig::default(),
    ))
}

pub struct EchoServer {
    pub addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
}

impl EchoServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        if let Ok((mut stream, _)) = accept {
                            tokio::spawn(async move {
                                let mut buf = [0u8; 1024];
                                loop {
                                    match stream.read(&mut buf).await {
                                        Ok(0) | Err(_) => return,
                                        Ok(n) => {
                                            if stream.write_all(&buf[..n]).await.is_err() {
                                                return;
                                            }
                                        }
                                    }
                                }
                            });
                        }
                    }
                    _ = &mut shutdown_rx => return,
                }
            }
        });

        Self {
            addr,
            _shutdown: shutdown_tx,
        }
    }
}

/// server that reads all data until client EOF, then sends a response.
/// tests that the proxy propagates half-close (FIN) correctly.
pub struct HalfCloseServer {
    pub addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
}

impl HalfCloseServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        if let Ok((mut stream, _)) = accept {
                            tokio::spawn(async move {
                                // drain all client data until EOF
                                let mut buf = [0u8; 1024];
                                loop {
                                    match stream.read(&mut buf).await {
                                        Ok(0) => break,  // client sent FIN
                                        Ok(_) => continue,
                                        Err(_) => return,
                                    }
                                }
                                // send response AFTER seeing client's FIN
                                let _ = stream.write_all(b"AFTER_FIN").await;
                                let _ = stream.shutdown().await;
                            });
                        }
                    }
                    _ = &mut shutdown_rx => return,
                }
            }
        });

        Self {
            addr,
            _shutdown: shutdown_tx,
        }
    }
}

/// server that sends partial data then drops the connection.
/// tests that the proxy handles backend crashes gracefully.
pub struct DyingServer {
    pub addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
}

impl DyingServer {
    pub async fn start(response: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        if let Ok((mut stream, _)) = accept {
                            tokio::spawn(async move {
                                // read one message to establish connection
                                let mut buf = [0u8; 1024];
                                let _ = stream.read(&mut buf).await;
                                // send partial response then drop (simulates crash)
                                let _ = stream.write_all(response).await;
                                drop(stream);
                            });
                        }
                    }
                    _ = &mut shutdown_rx => return,
                }
            }
        });

        Self {
            addr,
            _shutdown: shutdown_tx,
        }
    }
}

/// accepts connections then makes no progress - never reads, never writes,
/// holds the socket open at the TCP layer until dropped. The proxy sees a
/// live backend that stalls forever: a small request-head write succeeds
/// (kernel buffer absorbs it) but a large body write eventually blocks
/// (proxy_send timeout) and a response read never completes (proxy_read
/// timeout). Accepted streams are retained so the kernel does not RST/FIN
/// them (which would surface as a write error instead of a stall).
pub struct BlackholeBackend {
    pub addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
}

impl BlackholeBackend {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            let mut held: Vec<tokio::net::TcpStream> = Vec::new();
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        if let Ok((stream, _)) = accept {
                            held.push(stream); // keep alive, never touch
                        }
                    }
                    _ = &mut shutdown_rx => return,
                }
            }
        });

        Self {
            addr,
            _shutdown: shutdown_tx,
        }
    }
}

/// reads the request (head, best-effort), waits `delay`, then sends a minimal
/// 200. Used to trip the total `request_timeout`: the per-phase proxy_read
/// budget is left large so only the overall cycle deadline clamps the wait.
pub struct SlowResponseBackend {
    pub addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
}

impl SlowResponseBackend {
    pub async fn start(delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        if let Ok((mut stream, _)) = accept {
                            tokio::spawn(async move {
                                // drain whatever the proxy sent (head; the GET
                                // this backend serves carries no body)
                                let mut buf = [0u8; 1024];
                                match stream.read(&mut buf).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(_) => {}
                                }
                                tokio::time::sleep(delay).await;
                                let _ = stream
                                    .write_all(
                                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                                    )
                                    .await;
                                let _ = stream.shutdown().await;
                            });
                        }
                    }
                    _ = &mut shutdown_rx => return,
                }
            }
        });

        Self {
            addr,
            _shutdown: shutdown_tx,
        }
    }
}
