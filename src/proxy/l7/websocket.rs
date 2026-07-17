use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

use crate::pool::buffer::BufferGuard;
use crate::util::monotonic_millis;

use super::parse::{HttpVersion, ParsedHeader, Request};

#[derive(Debug, PartialEq, Eq)]
pub enum WsDetect {
    No,
    Yes,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelOutcome {
    PeerClosed,
    IdleTimeout,
    Shutdown,
    PeerError,
}

impl TunnelOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeerClosed => "peer_closed",
            Self::IdleTimeout => "idle_timeout",
            Self::Shutdown => "shutdown",
            Self::PeerError => "peer_error",
        }
    }
}

/// RFC 6455 §4.1 / §11.3 - the proxy treats a request as a WebSocket upgrade
/// only when every required handshake input is present and well-formed.
///
/// Returns:
/// - `Yes` when the request is a valid WebSocket upgrade and should be
///   tunneled.
/// - `Malformed` when the request advertises a WebSocket-shaped upgrade
///   (either the `Upgrade: websocket` token is present or the
///   `Connection: upgrade` token is present) but is missing a required
///   handshake field. The caller emits 400 and closes; the explicit signal
///   distinguishes a broken upgrade attempt from a plain HTTP request, which
///   gives operators a useful error in the access log.
/// - `No` when no WebSocket-shaped upgrade is being attempted.
pub fn is_websocket_upgrade(req: &Request) -> WsDetect {
    let upgrade = header_value(&req.headers, "upgrade");
    let connection = header_value(&req.headers, "connection");

    // Anchor: `Upgrade: websocket` token. Without it, this request is not a
    // WebSocket attempt at all - any other upgrade (h2c, etc.) routes to the
    // generic 405 path in `forward.rs`, not this module.
    let has_ws_upgrade = upgrade
        .as_deref()
        .is_some_and(|v| token_present(v, "websocket"));
    if !has_ws_upgrade {
        return WsDetect::No;
    }

    // Past the anchor: this is a WebSocket attempt. Any missing required
    // field is a broken handshake → caller emits 400 with a malformed signal
    // in the access log.
    let has_conn_upgrade = connection
        .as_deref()
        .is_some_and(|v| token_present(v, "upgrade"));
    if !has_conn_upgrade {
        return WsDetect::Malformed;
    }
    if !req.method.eq_ignore_ascii_case("GET") {
        return WsDetect::Malformed;
    }
    if !matches!(req.version, HttpVersion::Http11) {
        return WsDetect::Malformed;
    }
    let Some(key) = header_value(&req.headers, "sec-websocket-key") else {
        return WsDetect::Malformed;
    };
    if !is_valid_sec_ws_key(&key) {
        return WsDetect::Malformed;
    }
    if header_value(&req.headers, "sec-websocket-version").is_none() {
        return WsDetect::Malformed;
    }

    WsDetect::Yes
}

fn header_value(headers: &[ParsedHeader], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| h.value_str())
        .map(|s| s.to_owned())
}

fn token_present(header_value: &str, token: &str) -> bool {
    header_value
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

// RFC 6455 §11.3.1: the key is 16 random bytes encoded as base64, which
// always produces a 24-character string ending in "==" with the 22 leading
// characters drawn from the standard base64 alphabet. Verifying that shape
// is enough to reject obvious garbage without pulling in a base64 dependency
// just for one syntactic check.
fn is_valid_sec_ws_key(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 24
        && &bytes[22..] == b"=="
        && bytes[..22]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Run a bidirectional byte copy between two split stream pairs until any of
/// the termination conditions fire. Returns the cumulative byte counts in
/// both directions (populated even on partial transfer) and the
/// `TunnelOutcome` that ended the loop. First-to-finish wins: when one half
/// completes the other is dropped at its next await, which is acceptable at
/// L1 - WebSocket close handshakes are symmetric in practice and an
/// in-flight write at the moment of cancellation is bounded by one frame.
#[allow(clippy::too_many_arguments)]
pub async fn bidirectional_copy_with_timeout<RC, WC, RB, WB>(
    client_rd: &mut RC,
    client_wr: &mut WC,
    backend_rd: &mut RB,
    backend_wr: &mut WB,
    bufs: (BufferGuard, BufferGuard),
    idle_timeout: Duration,
    drain_timeout: Duration,
    shutdown_rx: &mut watch::Receiver<()>,
) -> (u64, u64, TunnelOutcome)
where
    RC: AsyncRead + Unpin,
    WC: AsyncWrite + Unpin,
    RB: AsyncRead + Unpin,
    WB: AsyncWrite + Unpin,
{
    let last_activity = Arc::new(AtomicU64::new(monotonic_millis()));
    let c2b_count = Arc::new(AtomicU64::new(0));
    let b2c_count = Arc::new(AtomicU64::new(0));

    let (buf_c2b, buf_b2c) = bufs;

    let c2b_fut = copy_half(
        client_rd,
        backend_wr,
        buf_c2b,
        Arc::clone(&last_activity),
        Arc::clone(&c2b_count),
    );
    let b2c_fut = copy_half(
        backend_rd,
        client_wr,
        buf_b2c,
        Arc::clone(&last_activity),
        Arc::clone(&b2c_count),
    );
    let idle_fut = idle_watchdog(Arc::clone(&last_activity), idle_timeout);

    // on a shutdown signal the tunnel waits `drain_timeout` before tearing down,
    // letting in-flight traffic flush. peer-close, idle timeout, or peer error
    // can still resolve the select sooner - the drain branch is a ceiling, not
    // a floor. matches the listener's drain_timeout for plain HTTP connections.
    let shutdown_then_drain = async {
        let _ = shutdown_rx.changed().await;
        tokio::time::sleep(drain_timeout).await;
    };

    let outcome = tokio::select! {
        r = c2b_fut => match r {
            Ok(()) => TunnelOutcome::PeerClosed,
            Err(_) => TunnelOutcome::PeerError,
        },
        r = b2c_fut => match r {
            Ok(()) => TunnelOutcome::PeerClosed,
            Err(_) => TunnelOutcome::PeerError,
        },
        o = idle_fut => o,
        _ = shutdown_then_drain => TunnelOutcome::Shutdown,
    };

    (
        c2b_count.load(Ordering::Relaxed),
        b2c_count.load(Ordering::Relaxed),
        outcome,
    )
}

async fn copy_half<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut buffer: BufferGuard,
    last_activity: Arc<AtomicU64>,
    counter: Arc<AtomicU64>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let n = reader.read(&mut buffer[..]).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buffer[..n]).await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
        last_activity.store(monotonic_millis(), Ordering::Relaxed);
    }
}

async fn idle_watchdog(last_activity: Arc<AtomicU64>, idle_timeout: Duration) -> TunnelOutcome {
    loop {
        let last = last_activity.load(Ordering::Relaxed);
        let now = monotonic_millis();
        let elapsed = Duration::from_millis(now.saturating_sub(last));
        if elapsed >= idle_timeout {
            return TunnelOutcome::IdleTimeout;
        }
        tokio::time::sleep(idle_timeout - elapsed).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::l7::parse::{ParseOutcome, parse_request};

    fn parse(raw: &[u8]) -> Request {
        match parse_request(raw, 64).unwrap() {
            ParseOutcome::Complete(r) => r,
            ParseOutcome::Partial => panic!("expected complete parse"),
        }
    }

    // RFC 6455 §1.2 example handshake - the canonical valid input.
    const VALID_HANDSHAKE: &[u8] = b"\
GET /chat HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";

    #[test]
    fn detects_valid_handshake() {
        assert_eq!(is_websocket_upgrade(&parse(VALID_HANDSHAKE)), WsDetect::Yes);
    }

    #[test]
    fn detects_yes_when_connection_has_multiple_tokens() {
        let raw = b"\
GET /chat HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Connection: keep-alive, Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::Yes);
    }

    #[test]
    fn no_upgrade_no_connection_is_no() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::No);
    }

    #[test]
    fn non_ws_upgrade_token_is_no() {
        let raw = b"\
GET / HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: h2c\r\n\
Connection: Upgrade\r\n\
\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::No);
    }

    #[test]
    fn connection_upgrade_alone_is_no() {
        // No `Upgrade: websocket` token → not a WebSocket attempt even with
        // `Connection: Upgrade` set; falls through to the non-WS upgrade path.
        let raw = b"\
GET / HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: Upgrade\r\n\
\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::No);
    }

    #[test]
    fn missing_connection_upgrade_is_malformed() {
        let raw = b"\
GET / HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::Malformed);
    }

    #[test]
    fn missing_sec_websocket_key_is_malformed() {
        let raw = b"\
GET / HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::Malformed);
    }

    #[test]
    fn missing_sec_websocket_version_is_malformed() {
        let raw = b"\
GET / HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::Malformed);
    }

    #[test]
    fn bad_sec_websocket_key_format_is_malformed() {
        let raw = b"\
GET / HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: notreallybase64==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::Malformed);
    }

    #[test]
    fn non_get_method_is_malformed() {
        let raw = b"\
POST /chat HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::Malformed);
    }

    #[test]
    fn http10_upgrade_is_malformed() {
        let raw = b"\
GET / HTTP/1.0\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::Malformed);
    }

    #[test]
    fn case_insensitive_header_matching() {
        let raw = b"\
GET / HTTP/1.1\r\n\
Host: example.com\r\n\
UPGRADE: WebSocket\r\n\
CONNECTION: upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";
        assert_eq!(is_websocket_upgrade(&parse(raw)), WsDetect::Yes);
    }

    #[test]
    fn sec_ws_key_validator_accepts_canonical_example() {
        assert!(is_valid_sec_ws_key("dGhlIHNhbXBsZSBub25jZQ=="));
    }

    #[test]
    fn sec_ws_key_validator_rejects_wrong_length() {
        assert!(!is_valid_sec_ws_key("short"));
        assert!(!is_valid_sec_ws_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAA=="));
    }

    #[test]
    fn sec_ws_key_validator_rejects_missing_padding() {
        assert!(!is_valid_sec_ws_key("dGhlIHNhbXBsZSBub25jZQ+/"));
    }

    #[test]
    fn sec_ws_key_validator_rejects_non_alphabet_chars() {
        assert!(!is_valid_sec_ws_key("dGhlIHNhbXBsZSBub25j!Q=="));
    }

    #[test]
    fn tunnel_outcome_str_repr() {
        assert_eq!(TunnelOutcome::PeerClosed.as_str(), "peer_closed");
        assert_eq!(TunnelOutcome::IdleTimeout.as_str(), "idle_timeout");
        assert_eq!(TunnelOutcome::Shutdown.as_str(), "shutdown");
        assert_eq!(TunnelOutcome::PeerError.as_str(), "peer_error");
    }
}
