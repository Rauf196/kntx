//! The `[metrics]` and `[admin]` control-plane sockets.
//!
//! Split by exposure class: `[metrics]` is scraped and probed from the network
//! and carries no secrets, `[admin]` dumps config and mutates the instance, so
//! it binds loopback unless a token is set.
//!
//! One hand-rolled GET responder serves both. The exporter's
//! `with_http_listener` cannot: it owns its socket and answers every path with
//! the scrape payload.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::health::CircuitState;
use crate::runtime::Snapshot;

const MAX_HEAD: usize = 4096;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);
const TOKEN_HEADER: &str = "x-kntx-token";

/// which route set a socket serves. fixed at spawn; the two never share a port.
pub enum Surface {
    Metrics {
        handle: PrometheusHandle,
        state: Arc<ArcSwap<Snapshot>>,
    },
    Admin {
        handle: AdminHandle,
        state: Arc<ArcSwap<Snapshot>>,
        started: Instant,
    },
}

/// the running admin socket, as a reload sees it. the address is fixed by the
/// bound listener, but the token swaps live: a leaked one has to be revocable
/// without dropping traffic.
#[derive(Clone)]
pub struct AdminHandle {
    pub address: SocketAddr,
    // arc-swap needs a sized payload, so Arc<String> rather than Arc<str>
    token: Arc<ArcSwapOption<String>>,
}

impl AdminHandle {
    pub fn new(address: SocketAddr, token: Option<&str>) -> Self {
        Self {
            address,
            token: Arc::new(ArcSwapOption::new(token.map(|t| Arc::new(t.to_owned())))),
        }
    }

    /// applies a reloaded token. clearing it is refused while the socket is
    /// bound off-loopback - config validation enforces that pairing against the
    /// configured address, and this enforces it against the one actually serving.
    pub fn set_token(&self, token: Option<&str>) {
        if token.is_none() && !self.address.ip().is_loopback() {
            tracing::warn!(
                address = %self.address,
                "refusing to clear the [admin] token on a non-loopback socket, keeping the running one",
            );
            return;
        }
        // every reload calls this, so log only a real change: an operator
        // grepping for a rotation needs it to mean one happened.
        let changed = self.token.load().as_deref().map(String::as_str) != token;
        self.token.store(token.map(|t| Arc::new(t.to_owned())));
        if changed {
            match token {
                Some(_) => tracing::info!(address = %self.address, "[admin] token rotated"),
                None => tracing::warn!(address = %self.address, "[admin] token removed"),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn token_is(&self, expected: Option<&str>) -> bool {
        self.token.load().as_deref().map(String::as_str) == expected
    }
}

pub async fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(address).await
}

/// takes the listener already bound at startup, so a port conflict fails the
/// process before pools and listeners are built rather than after.
pub fn spawn(listener: TcpListener, surface: Surface) {
    // `install_recorder` leaves upkeep to the caller; `with_http_listener` did it
    if let Surface::Metrics { handle, .. } = &surface {
        let handle = handle.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(UPKEEP_INTERVAL);
            loop {
                ticker.tick().await;
                handle.run_upkeep();
            }
        });
    }

    let surface = Arc::new(surface);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let surface = Arc::clone(&surface);
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(stream, &surface).await {
                            tracing::debug!(error = %e, "control request failed");
                        }
                    });
                }
                Err(e) => tracing::warn!(error = %e, "control accept failed"),
            }
        }
    });
}

async fn handle_conn(mut stream: TcpStream, surface: &Surface) -> std::io::Result<()> {
    let mut buf = [0u8; MAX_HEAD];
    let head = match tokio::time::timeout(READ_TIMEOUT, read_head(&mut stream, &mut buf)).await {
        Ok(Ok(Some(head))) => head,
        Ok(Ok(None)) => return respond(&mut stream, "400 Bad Request", "bad request\n").await,
        Ok(Err(e)) => return Err(e),
        Err(_) => return respond(&mut stream, "408 Request Timeout", "timeout\n").await,
    };

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(head).is_err() {
        return respond(&mut stream, "400 Bad Request", "bad request\n").await;
    }
    if req.method != Some("GET") {
        return respond(
            &mut stream,
            "405 Method Not Allowed",
            "method not allowed\n",
        )
        .await;
    }

    // query strings are not used by any route; strip so `/ready?x=1` still routes
    let path = req.path.unwrap_or("/");
    let path = path.split('?').next().unwrap_or(path);

    match surface {
        Surface::Metrics { handle, state } => match path {
            "/metrics" => respond(&mut stream, "200 OK", &handle.render()).await,
            "/healthz" => respond(&mut stream, "200 OK", "ok\n").await,
            "/ready" => match readiness(&state.load()) {
                Ok(()) => respond(&mut stream, "200 OK", "ready\n").await,
                Err(reason) => {
                    respond(
                        &mut stream,
                        "503 Service Unavailable",
                        &format!("{reason}\n"),
                    )
                    .await
                }
            },
            _ => respond(&mut stream, "404 Not Found", "not found\n").await,
        },
        Surface::Admin {
            handle,
            state,
            started,
        } => {
            // gated per socket, not per route: reading /config_dump leaks as much
            // as draining mutates, so both sit behind the same token.
            let token = handle.token.load();
            if let Some(expected) = token.as_ref() {
                let presented = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case(TOKEN_HEADER))
                    .map(|h| h.value)
                    .unwrap_or(b"");
                if !token_matches(expected.as_bytes(), presented) {
                    return respond(&mut stream, "401 Unauthorized", "unauthorized\n").await;
                }
            }

            match path {
                "/server_info" => {
                    let body = server_info(&state.load(), *started);
                    write_response(&mut stream, "200 OK", "application/json", &body).await
                }
                _ => respond(&mut stream, "404 Not Found", "not found\n").await,
            }
        }
    }
}

/// reads until the end of the request head. `None` means the peer closed or sent
/// more than `MAX_HEAD` bytes without finishing one.
async fn read_head<'a>(
    stream: &mut TcpStream,
    buf: &'a mut [u8; MAX_HEAD],
) -> std::io::Result<Option<&'a [u8]>> {
    let mut len = 0;
    loop {
        if len == buf.len() {
            return Ok(None);
        }
        let n = stream.read(&mut buf[len..]).await?;
        if n == 0 {
            return Ok(None);
        }
        len += n;
        if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(Some(&buf[..len]));
        }
    }
}

/// constant-time; an early return would leak the matched prefix. length is not
/// secret, it comes from config rather than from the guess.
fn token_matches(expected: &[u8], presented: &[u8]) -> bool {
    if expected.len() != presented.len() {
        return false;
    }
    expected
        .iter()
        .zip(presented)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// ready when every pool can still reach a backend. reads `circuit_state`, not
/// `is_available`: the latter CASes an expired Open circuit into HalfOpen, and a
/// readiness probe must not consume the recovery probe a real request needs.
fn readiness(snapshot: &Snapshot) -> Result<(), String> {
    for (name, (pool, _)) in &snapshot.pools {
        let healthy = pool
            .snapshot()
            .iter()
            .any(|b| b.circuit_state() != CircuitState::Open);
        if !healthy {
            return Err(format!("not ready: pool \"{name}\" has no healthy backend"));
        }
    }
    Ok(())
}

fn server_info(snapshot: &Snapshot, started: Instant) -> String {
    format!(
        "{{\"version\":\"{}\",\"uptime_secs\":{},\"config_version\":{},\"pools\":{}}}\n",
        env!("CARGO_PKG_VERSION"),
        started.elapsed().as_secs(),
        snapshot.version,
        snapshot.pools.len(),
    )
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    write_response(stream, status, "text/plain; charset=utf-8", body).await
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         content-type: {content_type}\r\n\
         content-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_compare_rejects_near_misses() {
        assert!(token_matches(b"s3cret", b"s3cret"));
        assert!(!token_matches(b"s3cret", b"s3creT"));
        assert!(!token_matches(b"s3cret", b"s3cre"));
        assert!(!token_matches(b"s3cret", b"s3cretx"));
        assert!(!token_matches(b"s3cret", b""));
        assert!(token_matches(b"", b""));
    }
}
