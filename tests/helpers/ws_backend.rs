#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Minimal WebSocket-flavored backend used by the tunneling integration
/// tests. The proxy does not parse frames at L1, so this backend doesn't
/// either: after the handshake it simply echoes bytes both ways.
#[derive(Clone, Copy)]
pub enum WsBackendMode {
    /// Respond 101 with a static Sec-WebSocket-Accept value, then echo
    /// every byte received until the client closes.
    EchoTunnel,
    /// Respond 200 with a small body — the proxy treats this as a
    /// non-upgrade response and falls back to normal forwarding then close.
    Reject200,
    /// Respond 101 reflecting the requested `Sec-WebSocket-Protocol` if any
    /// was offered, then echo.
    EchoWithSubprotocol,
}

pub struct WebSocketBackend {
    pub addr: SocketAddr,
    accept_count: Arc<AtomicU64>,
    _shutdown: oneshot::Sender<()>,
}

impl WebSocketBackend {
    pub async fn start(mode: WsBackendMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let accept_count = Arc::new(AtomicU64::new(0));
        let accept_count_outer = Arc::clone(&accept_count);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        if let Ok((stream, _)) = accept {
                            accept_count_outer.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(serve_conn(stream, mode));
                        }
                    }
                    _ = &mut shutdown_rx => return,
                }
            }
        });

        Self {
            addr,
            accept_count,
            _shutdown: shutdown_tx,
        }
    }

    pub fn accept_count(&self) -> u64 {
        self.accept_count.load(Ordering::Relaxed)
    }
}

async fn serve_conn(mut stream: TcpStream, mode: WsBackendMode) {
    let mut buf = vec![0u8; 8192];
    let mut total = 0usize;
    let head_end = loop {
        if let Some(p) = find_crlfcrlf(&buf[..total]) {
            break p;
        }
        if total >= buf.len() {
            return;
        }
        match stream.read(&mut buf[total..]).await {
            Ok(0) | Err(_) => return,
            Ok(n) => total += n,
        }
    };

    let head = &buf[..head_end];
    let head_str = match std::str::from_utf8(head) {
        Ok(s) => s,
        Err(_) => return,
    };
    let subprotocol = header_value(head_str, "sec-websocket-protocol").unwrap_or_default();

    match mode {
        WsBackendMode::Reject200 => {
            let body = b"not upgrading";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.write_all(body).await;
            let _ = stream.shutdown().await;
        }
        WsBackendMode::EchoTunnel | WsBackendMode::EchoWithSubprotocol => {
            if !has_upgrade_websocket(head_str) || !has_connection_upgrade(head_str) {
                let body = b"missing upgrade tokens";
                let resp = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
                return;
            }
            let proto = match mode {
                WsBackendMode::EchoWithSubprotocol => subprotocol.as_str(),
                _ => "",
            };
            let resp = make_101_response(proto);
            if stream.write_all(resp.as_bytes()).await.is_err() {
                return;
            }
            let leftover = &buf[head_end..total];
            if !leftover.is_empty() && stream.write_all(leftover).await.is_err() {
                return;
            }
            run_echo_loop(stream).await;
        }
    }
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let mut parts = line.splitn(2, ':');
        let h_name = parts.next()?.trim();
        let h_value = parts.next()?.trim();
        h_name
            .eq_ignore_ascii_case(name)
            .then(|| h_value.to_owned())
    })
}

fn has_upgrade_websocket(head: &str) -> bool {
    header_value(head, "upgrade")
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
        })
        .unwrap_or(false)
}

fn has_connection_upgrade(head: &str) -> bool {
    header_value(head, "connection")
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false)
}

async fn run_echo_loop(mut stream: TcpStream) {
    let mut buf = vec![0u8; 4096];
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
}

fn make_101_response(subprotocol: &str) -> String {
    let mut s = String::from(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
    );
    if !subprotocol.is_empty() {
        s.push_str(&format!("Sec-WebSocket-Protocol: {subprotocol}\r\n"));
    }
    s.push_str("\r\n");
    s
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}
