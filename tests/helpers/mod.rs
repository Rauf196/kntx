#![allow(dead_code)]

pub mod http_backend;
pub mod tls;

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

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
