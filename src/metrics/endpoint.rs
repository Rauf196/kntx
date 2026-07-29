//! `/metrics`, `/healthz` and `/ready` on one socket.
//!
//! These three share an exposure class: read-only, no secrets, and reachable
//! from the network because Prometheus scrapes one and orchestrators probe the
//! others. The mutating admin surface (config dump, drain, forced-unhealthy)
//! does not, and gets its own loopback-default listener when it lands.
//!
//! Hand-rolled rather than built on the exporter's `with_http_listener`, which
//! owns its socket and answers every path with the scrape payload.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::health::CircuitState;
use crate::runtime::Snapshot;

const MAX_HEAD: usize = 4096;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

pub async fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(address).await
}

/// takes the listener already bound at startup, so a port conflict fails the
/// process before pools and listeners are built rather than after.
pub fn spawn(listener: TcpListener, handle: PrometheusHandle, state: Arc<ArcSwap<Snapshot>>) {
    // install_recorder leaves upkeep to the caller; with_http_listener did it for us
    let upkeep = handle.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(UPKEEP_INTERVAL);
        loop {
            ticker.tick().await;
            upkeep.run_upkeep();
        }
    });

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let handle = handle.clone();
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(stream, &handle, &state).await {
                            tracing::debug!(error = %e, "admin request failed");
                        }
                    });
                }
                Err(e) => tracing::warn!(error = %e, "admin accept failed"),
            }
        }
    });
}

async fn handle_conn(
    mut stream: TcpStream,
    handle: &PrometheusHandle,
    state: &ArcSwap<Snapshot>,
) -> std::io::Result<()> {
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

    match path {
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

async fn respond(stream: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         content-type: text/plain; charset=utf-8\r\n\
         content-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await
}
