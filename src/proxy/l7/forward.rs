use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use thiserror::Error;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::Instrument;

use crate::access_log::{AccessLogLine, AccessLogSink, extract_trace_id};
use crate::config::ListenerConfig;
use crate::pool::buffer::BufferPool;
use crate::proxy::l7::keepalive::{CheckoutError, KeepaliveCache};
use crate::proxy::l7::matcher::RouteContext;
use crate::proxy::l7::router::Router;
use crate::proxy::l7::websocket::{
    WsDetect, bidirectional_copy_with_timeout, is_websocket_upgrade,
};
use crate::util::monotonic_millis;

use super::error::{ErrorPages, synthesize_error};
use super::framing::{BodyFraming, ChunkedReader, classify_request_body, classify_response_body};
use super::headers::{
    build_request_additions, build_response_additions, resolve_request_id, serialize_request_head,
    serialize_response_head,
};
use super::parse::{
    HttpVersion, ParseError, ParseOutcome, ParsedHeader, parse_request, parse_response,
};

/// default between-request idle window on a kept-alive client conn.
const DEFAULT_KEEPALIVE_IDLE_SECS: u64 = 60;
/// default max requests served on one client conn before forced close.
const DEFAULT_KEEPALIVE_MAX_REQUESTS: u32 = 1000;
/// default for every phase-specific timeout when neither the specific knob nor
/// the listener's legacy `idle_timeout_secs` fallback is set.
const DEFAULT_PHASE_TIMEOUT_SECS: u64 = 60;

/// Resolved phase-specific timeouts. Each is per-call (the gap between two
/// successive successful I/O ops) except `request`, which is the single
/// total-time cap on the whole cycle. Resolution order for each phase:
/// explicit per-phase knob, else the listener's legacy `idle_timeout_secs`,
/// else 60s.
#[derive(Clone, Copy)]
struct PhaseTimeouts {
    header: Duration,
    body: Duration,
    proxy_send: Duration,
    proxy_read: Duration,
    request: Duration,
}

impl PhaseTimeouts {
    fn resolve(cfg: &ListenerConfig) -> Self {
        let idle = cfg.idle_timeout_secs;
        let pick = |specific: Option<u64>| {
            Duration::from_secs(specific.or(idle).unwrap_or(DEFAULT_PHASE_TIMEOUT_SECS))
        };
        Self {
            header: pick(cfg.client_header_timeout_secs),
            body: pick(cfg.client_body_timeout_secs),
            proxy_send: pick(cfg.proxy_send_timeout_secs),
            proxy_read: pick(cfg.proxy_read_timeout_secs),
            request: pick(cfg.request_timeout_secs),
        }
    }
}

/// Effective budget for one I/O call: the phase's per-call timeout, clamped
/// so it can never push the cycle past the total `request` deadline. When
/// the deadline has already passed this is `ZERO`, so the wrapped call trips
/// immediately and the caller treats it as a total-timeout case.
fn call_budget(phase: Duration, deadline: Instant) -> Duration {
    phase.min(deadline.saturating_duration_since(Instant::now()))
}

/// Which post-route phase tripped - drives the emitted status code. The
/// header phase is handled inline before routing (no route context yet) and
/// is not represented here.
#[derive(Clone, Copy, PartialEq)]
enum TimeoutPhase {
    Body,
    ProxySend,
    ProxyRead,
}

/// Status code to emit on a post-route timeout. `None` means close abruptly
/// with no response: either the response head is already on the wire (so a
/// new status line would corrupt the framing the client has already parsed),
/// or it is a body-phase timeout where the backend holds a partial request
/// stream and a synthetic response on the client side would desync framing.
/// In both cases the caller still emits exactly one access-log line.
fn timeout_status(
    phase: TimeoutPhase,
    response_head_sent: bool,
    deadline_hit: bool,
) -> Option<u16> {
    if deadline_hit {
        // total request deadline overrides whichever phase happened to trip first
        return if response_head_sent { None } else { Some(504) };
    }
    match phase {
        TimeoutPhase::Body => None,
        TimeoutPhase::ProxySend | TimeoutPhase::ProxyRead => {
            if response_head_sent {
                None
            } else {
                Some(504)
            }
        }
    }
}

/// shared tail for every post-route timeout: synthesize a status response when
/// one is still possible, then emit exactly one access-log line + request
/// metrics. backend conn discard is implicit on this error path - the caller
/// returns and `KeepaliveConn`'s Drop decrements total_count.
#[allow(clippy::too_many_arguments)]
async fn emit_timeout<W>(
    phase: TimeoutPhase,
    deadline: Instant,
    response_head_sent: bool,
    client_wr: &mut W,
    error_pages: &ErrorPages,
    accept_ref: Option<&str>,
    access_log: &AccessLogSink,
    listener_label: &str,
    client_ip: &str,
    method: &str,
    headers: &[ParsedHeader],
    path: &str,
    pool_name: &str,
    backend_addr: SocketAddr,
    bytes_in: u64,
    bytes_out: u64,
    fallback_status: u16,
    start: Instant,
    request_id: &str,
    route_id: &str,
    keepalive_index: u32,
) where
    W: AsyncWrite + Unpin,
{
    let deadline_hit = Instant::now() >= deadline;
    let logged = match timeout_status(phase, response_head_sent, deadline_hit) {
        Some(s) => {
            let resp = synthesize_error(s, accept_ref, error_pages);
            let _ = client_wr.write_all(&resp).await;
            s
        }
        None => fallback_status,
    };
    emit_and_count(
        access_log,
        listener_label,
        client_ip,
        method,
        headers,
        path,
        pool_name,
        Some(&backend_addr.to_string()),
        logged,
        bytes_in,
        bytes_out,
        start,
        None,
        Some(request_id.to_owned()),
        Some(route_id),
        keepalive_index,
    );
}

/// Outcome of one request/response cycle, consumed by the keep-alive loop.
enum CycleOutcome {
    /// Client closed (or errored) before sending any request bytes - clean
    /// end, no access-log line, does not count toward the keep-alive
    /// request-per-connection histogram.
    NoRequest,
    /// A request was handled (success OR error). `close` is the keep-alive
    /// decision: whether the client conn must close after this response.
    Done { close: bool },
}

#[derive(Debug, Error)]
pub enum L7Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub enum ClientStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl ClientStream {
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn forward_l7(
    client: ClientStream,
    client_addr: SocketAddr,
    sni: Option<Arc<str>>,
    listener_cfg: Arc<ListenerConfig>,
    router: Arc<dyn Router>,
    error_pages: Arc<ErrorPages>,
    access_log: Arc<AccessLogSink>,
    last_activity: Arc<AtomicU64>,
    buffer_pool: Arc<BufferPool>,
    metrics_listener_label: Arc<str>,
    shutdown: watch::Receiver<()>,
) -> Result<(), L7Error> {
    let is_tls = client.is_tls();
    match client {
        // Plain TCP: into_split yields lock-free owned halves - no BiLock
        // on the L7 read/write hot path.
        ClientStream::Plain(tcp) => {
            let (rd, wr) = tcp.into_split();
            serve_l7_conn(
                tokio::io::BufReader::with_capacity(8192, rd),
                wr,
                client_addr,
                is_tls,
                sni,
                listener_cfg,
                router,
                error_pages,
                access_log,
                last_activity,
                buffer_pool,
                metrics_listener_label,
                shutdown,
            )
            .await
        }
        // TLS: read and write share post-handshake cipher state, so the
        // BiLock from tokio::io::split is required (cannot use into_split).
        ClientStream::Tls(tls) => {
            let (rd, wr) = tokio::io::split(*tls);
            serve_l7_conn(
                tokio::io::BufReader::with_capacity(8192, rd),
                wr,
                client_addr,
                is_tls,
                sni,
                listener_cfg,
                router,
                error_pages,
                access_log,
                last_activity,
                buffer_pool,
                metrics_listener_label,
                shutdown,
            )
            .await
        }
    }
}

/// Keep-alive request loop over one client connection.
///
/// The client stream is split exactly once in `forward_l7` and the halves
/// are threaded in - never re-split per request. Plain TCP uses
/// `TcpStream::into_split` (lock-free owned halves); TLS uses
/// `tokio::io::split` (BiLock, required because read/write share handshake
/// state). The body buffer is acquired once per connection and reused
/// across requests; cycling buffers per request would needlessly thrash the
/// global pool.
#[allow(clippy::too_many_arguments)]
async fn serve_l7_conn<R, W>(
    mut client_rd: tokio::io::BufReader<R>,
    mut client_wr: W,
    client_addr: SocketAddr,
    is_tls: bool,
    sni: Option<Arc<str>>,
    listener_cfg: Arc<ListenerConfig>,
    router: Arc<dyn Router>,
    error_pages: Arc<ErrorPages>,
    access_log: Arc<AccessLogSink>,
    last_activity: Arc<AtomicU64>,
    buffer_pool: Arc<BufferPool>,
    listener_label: Arc<str>,
    mut shutdown: watch::Receiver<()>,
) -> Result<(), L7Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // body-forwarding buffer: one per connection, reused every request.
    let mut buf_guard = match buffer_pool.get() {
        Some(g) => g,
        None => {
            metrics::counter!(
                "kntx_l7_buffer_pool_exhausted_total",
                "listener" => listener_label.to_string(),
            )
            .increment(1);
            let resp = synthesize_error(503, None, &error_pages);
            let _ = client_wr.write_all(&resp).await;
            return Ok(());
        }
    };

    let keepalive_idle = Duration::from_secs(
        listener_cfg
            .keepalive_idle_timeout_secs
            .unwrap_or(DEFAULT_KEEPALIVE_IDLE_SECS),
    );
    let keepalive_max = listener_cfg
        .keepalive_max_requests
        .unwrap_or(DEFAULT_KEEPALIVE_MAX_REQUESTS);

    // phase timeouts are per-connection config, constant across the loop.
    let tmo = PhaseTimeouts::resolve(&listener_cfg);

    let mut keepalive_index: u32 = 0;

    loop {
        // between-request idle wait - skipped on the first request.
        if keepalive_index > 0 {
            tokio::select! {
                peek = client_rd.fill_buf() => {
                    match peek {
                        Ok([]) => break, // client closed cleanly between requests
                        Ok(_) => {}      // next request bytes ready
                        Err(_) => break, // client gone
                    }
                }
                _ = tokio::time::sleep(keepalive_idle) => break, // idle close
                _ = shutdown.changed() => break,                  // graceful shutdown between requests
            }
        }

        // The close decision is computed up front from inputs known at the
        // start of the cycle. `shutdown_signalled` is read here, before the
        // cycle begins, so the response `Connection` header is accurate even
        // if a shutdown fires mid-response - the client always sees a
        // consistent close-or-keep-alive signal.
        let shutdown_signalled = shutdown.has_changed().unwrap_or(true);

        // Each iteration owns a fresh tracing span; request_id and trace_id
        // are recorded inside `forward_one_request` once resolved, so values
        // from a prior iteration never bleed across the same connection's
        // log lines.
        let span = tracing::info_span!(
            "l7_request",
            keepalive_index,
            request_id = tracing::field::Empty,
            trace_id = tracing::field::Empty,
        );

        let fut = forward_one_request(
            &mut client_rd,
            &mut client_wr,
            client_addr,
            is_tls,
            sni.as_deref(),
            &listener_cfg,
            &router,
            &error_pages,
            &access_log,
            &last_activity,
            &mut buf_guard,
            &listener_label,
            keepalive_index,
            keepalive_max,
            shutdown_signalled,
            tmo,
            &buffer_pool,
            &mut shutdown,
        )
        .instrument(span);

        // Structural backstop on total cycle time. `forward_one_request`
        // enforces the real request deadline from the inside (so it can emit
        // a proper 504 plus access-log line); this outer wrap with a small
        // grace only fires if an await ever escaped per-call wrapping -
        // unreachable in practice, kept so that a stuck cycle cannot pin
        // the connection indefinitely.
        let outcome =
            match tokio::time::timeout(tmo.request.saturating_add(Duration::from_secs(2)), fut)
                .await
            {
                Ok(o) => o,
                Err(_) => {
                    tracing::warn!(
                        keepalive_index,
                        "request exceeded total-timeout backstop; closing connection"
                    );
                    CycleOutcome::Done { close: true }
                }
            };

        match outcome {
            CycleOutcome::NoRequest => break,
            CycleOutcome::Done { close } => {
                // increment AFTER the cycle - the access-log line and request
                // metrics were emitted with the current index from inside
                // `forward_one_request`. Inverting the order would yield a
                // silent off-by-one in the logged index.
                keepalive_index += 1;
                if close {
                    break;
                }
            }
        }
    }

    let _ = client_wr.shutdown().await;

    // requests-served-per-conn distribution, emitted once at conn close.
    if keepalive_index > 0 {
        metrics::histogram!(
            "kntx_http_keepalive_requests",
            "listener" => listener_label.to_string(),
        )
        .record(keepalive_index as f64);
    }

    Ok(())
}

/// One request/response cycle. The client read/write halves are borrowed
/// from the per-connection loop; the backend conn is checked out at the
/// start of the cycle and either returned to the keepalive cache (success +
/// backend keeps the conn alive) or discarded (every other path, including
/// any error path where request body bytes were already flushed to the
/// backend). `request_id`, the X-Forwarded-For chain, and the trace context
/// are all recomputed here per call - values from one iteration never carry
/// over into the next on the same client connection.
#[allow(clippy::too_many_arguments)]
async fn forward_one_request<R, W>(
    client_rd: &mut R,
    client_wr: &mut W,
    client_addr: SocketAddr,
    is_tls: bool,
    sni: Option<&str>,
    listener_cfg: &ListenerConfig,
    router: &Arc<dyn Router>,
    error_pages: &ErrorPages,
    access_log: &AccessLogSink,
    last_activity: &Arc<AtomicU64>,
    scratch: &mut [u8],
    listener_label: &str,
    keepalive_index: u32,
    keepalive_max: u32,
    shutdown_signalled: bool,
    tmo: PhaseTimeouts,
    buffer_pool: &Arc<BufferPool>,
    shutdown_rx: &mut watch::Receiver<()>,
) -> CycleOutcome
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let start = Instant::now();
    // total-time cap on the whole cycle. Per-call budgets are clamped
    // against this so the cycle can emit its own 504 plus access log before
    // the outer backstop in `serve_l7_conn` ever fires.
    let deadline = start + tmo.request;
    // Single source of truth for "can an error path still emit a status
    // response, or must it close abruptly?" Flipped true once the first byte
    // of the response head is written to the client.
    let mut response_head_sent = false;
    let client_ip = client_addr.ip().to_string();
    // pool_name/route_id are unknown until routing; "-" marks pre-route rejects
    // in both access logs and metric labels (common log format convention).
    let pool_name = String::from("-");
    let header_limit = listener_cfg.header_size_limit_bytes;
    let connect_timeout = Duration::from_secs(listener_cfg.connect_timeout_secs);
    let max_retries = listener_cfg.max_connect_attempts;

    let bump = |la: &Arc<AtomicU64>| la.store(monotonic_millis(), Ordering::Relaxed);

    let mut head_buf: Vec<u8> = Vec::with_capacity(header_limit.min(8192));
    // `client_header_timeout`: per-call gap budget on the request-head
    // read, clamped to the total deadline.
    let read_result = match tokio::time::timeout(
        call_budget(tmo.header, deadline),
        read_head(client_rd, &mut head_buf, header_limit, last_activity),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => {
            // header timeout → 408 (or 504 if the total deadline is what
            // expired). Backend untouched; request_id unresolvable from a
            // partial head, so generate one for the access log.
            let deadline_hit = Instant::now() >= deadline;
            let status = if deadline_hit { 504 } else { 408 };
            let request_id = uuid::Uuid::new_v4().to_string();
            let resp = synthesize_error(status, None, error_pages);
            let _ = client_wr.write_all(&resp).await;
            // no dedicated timeout metric; the emitted status is visible in
            // the access log alongside the other pre-route error paths.
            emit_error_log(
                access_log,
                listener_label,
                &client_ip,
                "",
                "",
                &pool_name,
                status,
                resp.len() as u64,
                start,
                &request_id,
                keepalive_index,
            );
            return CycleOutcome::Done { close: true };
        }
    };

    match read_result {
        HeadReadResult::Eof => {
            // silent: connection closed before this request arrived (clean keep-alive end)
            return CycleOutcome::NoRequest;
        }
        HeadReadResult::TooLarge => {
            let request_id = uuid::Uuid::new_v4().to_string();
            let resp = synthesize_error(431, None, error_pages);
            let _ = client_wr.write_all(&resp).await;
            metrics::counter!(
                "kntx_http_parse_errors_total",
                "listener" => listener_label.to_string()
            )
            .increment(1);
            emit_error_log(
                access_log,
                listener_label,
                &client_ip,
                "",
                "",
                &pool_name,
                431,
                0,
                start,
                &request_id,
                keepalive_index,
            );
            return CycleOutcome::Done { close: true };
        }
        // client-side read error mid-stream: client is gone. End the conn
        // cleanly - a vanished client on a kept-alive conn is normal traffic,
        // not a server error worth a log line.
        HeadReadResult::IoError => return CycleOutcome::NoRequest,
        HeadReadResult::Complete => {}
    }
    bump(last_activity);

    // http/2 connection preface: httparse returns Malformed for it, so we detect
    // it explicitly and return 505 instead of 400.
    if looks_like_http2_preface(&head_buf) {
        let request_id = uuid::Uuid::new_v4().to_string();
        let resp = synthesize_error(505, None, error_pages);
        let _ = client_wr.write_all(&resp).await;
        metrics::counter!(
            "kntx_http_parse_errors_total",
            "listener" => listener_label.to_string()
        )
        .increment(1);
        emit_error_log(
            access_log,
            listener_label,
            &client_ip,
            "",
            "",
            &pool_name,
            505,
            0,
            start,
            &request_id,
            keepalive_index,
        );
        return CycleOutcome::Done { close: true };
    }

    // parse the head
    let req = match parse_request(&head_buf, 128) {
        Err(ParseError::HeaderTooLarge) => {
            let request_id = uuid::Uuid::new_v4().to_string();
            let resp = synthesize_error(431, None, error_pages);
            let _ = client_wr.write_all(&resp).await;
            metrics::counter!("kntx_http_parse_errors_total", "listener" => listener_label.to_string()).increment(1);
            emit_error_log(
                access_log,
                listener_label,
                &client_ip,
                "",
                "",
                &pool_name,
                431,
                0,
                start,
                &request_id,
                keepalive_index,
            );
            return CycleOutcome::Done { close: true };
        }
        Err(ParseError::UnsupportedVersion(kind)) => {
            let request_id = uuid::Uuid::new_v4().to_string();
            let status = match kind {
                super::parse::VersionKind::Http2 => 505,
                _ => 400,
            };
            let resp = synthesize_error(status, None, error_pages);
            let _ = client_wr.write_all(&resp).await;
            metrics::counter!("kntx_http_parse_errors_total", "listener" => listener_label.to_string()).increment(1);
            emit_error_log(
                access_log,
                listener_label,
                &client_ip,
                "",
                "",
                &pool_name,
                status,
                0,
                start,
                &request_id,
                keepalive_index,
            );
            return CycleOutcome::Done { close: true };
        }
        Err(ParseError::Malformed) | Ok(ParseOutcome::Partial) => {
            let request_id = uuid::Uuid::new_v4().to_string();
            let resp = synthesize_error(400, None, error_pages);
            let _ = client_wr.write_all(&resp).await;
            metrics::counter!("kntx_http_parse_errors_total", "listener" => listener_label.to_string()).increment(1);
            emit_error_log(
                access_log,
                listener_label,
                &client_ip,
                "",
                "",
                &pool_name,
                400,
                0,
                start,
                &request_id,
                keepalive_index,
            );
            return CycleOutcome::Done { close: true };
        }
        Ok(ParseOutcome::Complete(r)) => r,
    };

    let request_id = resolve_request_id(&req.headers);

    // bind identifiers onto the current request span (Empty fields were
    // declared in `serve_l7_conn`) so diagnostic log lines within this
    // request carry the right request_id and trace_id, with no bleed into
    // the next keep-alive iteration.
    {
        let span = tracing::Span::current();
        span.record("request_id", request_id.as_str());
        if let Some(tid) = find_header(&req.headers, "traceparent")
            .as_deref()
            .and_then(extract_trace_id)
        {
            span.record("trace_id", tid.as_str());
        }
    }

    let method = req.method.clone();
    let path = req.path.clone();
    let version = req.version;

    // The client-side close decision is fixed up front (post-parse,
    // pre-forward) so the response `Connection` header is accurate even if
    // shutdown fires mid-response. Computed here - not in `serve_l7_conn`
    // - because it needs the parsed request; the loop above passes the raw
    // inputs (shutdown flag, index, cap) and reads `close` back via
    // `CycleOutcome::Done`.
    let req_wants_close = conn_header_has_token(&req.headers, "close");
    let req_wants_keep_alive = conn_header_has_token(&req.headers, "keep-alive");
    let http10_without_keepalive = matches!(version, HttpVersion::Http10) && !req_wants_keep_alive;
    let close_after_response = shutdown_signalled
        || keepalive_index + 1 >= keepalive_max
        || req_wants_close
        || http10_without_keepalive;

    let accept_val = find_header(&req.headers, "accept");
    let accept_ref = accept_val.as_deref();

    // smuggling validation
    let framing = match classify_request_body(&req) {
        Ok(f) => f,
        Err(e) => {
            let resp = synthesize_error(400, accept_ref, error_pages);
            let _ = client_wr.write_all(&resp).await;
            metrics::counter!(
                "kntx_http_smuggling_rejects_total",
                "listener" => listener_label.to_string(),
                "reason" => e.reason_label(),
            )
            .increment(1);
            emit_and_count(
                access_log,
                listener_label,
                &client_ip,
                &method,
                &req.headers,
                &path,
                &pool_name,
                None,
                400,
                0,
                0,
                start,
                None,
                Some(request_id.clone()),
                None,
                keepalive_index,
            );
            return CycleOutcome::Done { close: true };
        }
    };

    // request-body size limit: 0 = unlimited; unset uses 1 MiB default.
    // Content-Length: reject up front (backend untouched, no half-state).
    // Chunked: counted during streaming (later in this fn).
    let max_body_size: u64 = listener_cfg.max_body_size_bytes.unwrap_or(1_048_576);
    if let BodyFraming::ContentLength(n) = &framing
        && max_body_size > 0
        && *n > max_body_size
    {
        let resp = synthesize_error(413, accept_ref, error_pages);
        let _ = client_wr.write_all(&resp).await;
        metrics::counter!(
            "kntx_http_body_too_large_total",
            "listener" => listener_label.to_string(),
        )
        .increment(1);
        emit_and_count(
            access_log,
            listener_label,
            &client_ip,
            &method,
            &req.headers,
            &path,
            &pool_name,
            None,
            413,
            0,
            0,
            start,
            None,
            Some(request_id.clone()),
            None,
            keepalive_index,
        );
        return CycleOutcome::Done { close: true };
    }

    // CONNECT → 405
    if method.eq_ignore_ascii_case("CONNECT") {
        let resp = synthesize_error(405, accept_ref, error_pages);
        let _ = client_wr.write_all(&resp).await;
        emit_and_count(
            access_log,
            listener_label,
            &client_ip,
            &method,
            &req.headers,
            &path,
            &pool_name,
            None,
            405,
            0,
            0,
            start,
            None,
            Some(request_id.clone()),
            None,
            keepalive_index,
        );
        return CycleOutcome::Done { close: true };
    }

    // Classify upgrade intent. `WsDetect::No` covers both "no upgrade
    // header" and "upgrade to something other than websocket" - the latter
    // still gets the 405 path below. WS-shaped attempts that fail validation
    // get 400, valid WS upgrades fall through and route to a pool like any
    // other request; the tunnel handoff fires after the backend response
    // head is parsed.
    let ws_detect = is_websocket_upgrade(&req);
    let is_ws_upgrade = matches!(ws_detect, WsDetect::Yes);

    if matches!(ws_detect, WsDetect::Malformed) {
        let resp = synthesize_error(400, accept_ref, error_pages);
        let _ = client_wr.write_all(&resp).await;
        emit_and_count(
            access_log,
            listener_label,
            &client_ip,
            &method,
            &req.headers,
            &path,
            &pool_name,
            None,
            400,
            0,
            0,
            start,
            None,
            Some(request_id.clone()),
            None,
            keepalive_index,
        );
        return CycleOutcome::Done { close: true };
    }

    if is_ws_upgrade {
        // RFC 6455 §4.1 forbids a body on the upgrade request.
        if !matches!(framing, BodyFraming::None) {
            let resp = synthesize_error(400, accept_ref, error_pages);
            let _ = client_wr.write_all(&resp).await;
            emit_and_count(
                access_log,
                listener_label,
                &client_ip,
                &method,
                &req.headers,
                &path,
                &pool_name,
                None,
                400,
                0,
                0,
                start,
                None,
                Some(request_id.clone()),
                None,
                keepalive_index,
            );
            return CycleOutcome::Done { close: true };
        }
    } else if find_header(&req.headers, "upgrade").is_some() {
        // Non-websocket upgrade (h2c, etc.): kntx does not support it.
        let resp = synthesize_error(405, accept_ref, error_pages);
        let _ = client_wr.write_all(&resp).await;
        emit_and_count(
            access_log,
            listener_label,
            &client_ip,
            &method,
            &req.headers,
            &path,
            &pool_name,
            None,
            405,
            0,
            0,
            start,
            None,
            Some(request_id.clone()),
            None,
            keepalive_index,
        );
        return CycleOutcome::Done { close: true };
    }

    // route the request to a pool
    let host_header = find_header(&req.headers, "host");
    let ctx = RouteContext {
        method: Some(req.method.as_str()),
        host: host_header.as_deref(),
        path: Some(req.path.as_str()),
        headers: &req.headers,
        sni,
        client_ip: client_addr.ip(),
    };
    let entry = match router.route(&ctx) {
        Some(e) => e,
        None => {
            metrics::counter!(
                "kntx_route_no_match_total",
                "listener" => listener_label.to_string(),
            )
            .increment(1);
            let resp = synthesize_error(503, accept_ref, error_pages);
            let _ = client_wr.write_all(&resp).await;
            emit_and_count(
                access_log,
                listener_label,
                &client_ip,
                &method,
                &req.headers,
                &path,
                "-",
                None,
                503,
                0,
                0,
                start,
                None,
                Some(request_id.clone()),
                None,
                keepalive_index,
            );
            return CycleOutcome::Done { close: true };
        }
    };
    let pool = entry.pool.backends.clone();
    let rr = entry.pool.rr.clone();
    let route_id = entry.route_id.clone();
    let pool_name = entry.pool.name.to_string();
    metrics::counter!(
        "kntx_route_matches_total",
        "listener" => listener_label.to_string(),
        "route_id" => route_id.to_string(),
    )
    .increment(1);

    // build the rewritten request head once - the result is independent of which
    // backend we land on, so we serialize before backend selection and reuse the
    // same bytes if the broken-keepalive retry below fires.
    let (skip, additions) = build_request_additions(
        &req.headers,
        &client_ip,
        is_tls,
        version,
        &request_id,
        is_ws_upgrade,
    );
    let mut req_head_buf = BytesMut::with_capacity(header_limit.min(8192));
    serialize_request_head(
        &mut req_head_buf,
        &method,
        &path,
        version,
        &req.headers,
        &skip,
        &additions,
    );

    // Backend selection + head write with two-axis retry:
    //  - Inner: `max_retries` for backend selection (Saturated → next
    //    backend; ConnectFailed / ConnectTimeout → record_failure on the
    //    dead addr + try next, capped by the listener's `max_retries`).
    //  - Outer: at most one retry for the broken-keepalive race - a popped
    //    cached conn whose first write EPIPEs because the backend had
    //    already closed it. Eligibility: `reused` AND the method is
    //    idempotent AND zero body bytes have been flushed to the backend
    //    yet. The zero-body gate is structurally guaranteed at the
    //    head-write boundary; spelling it out keeps the invariant auditable
    //    in code review.
    //
    // Broken-keepalive write failures do NOT call `pool.record_failure`:
    // the backend produced no observable output, so this is a TCP-level
    // race rather than a backend-app health signal. Circuit state stays
    // untouched. The same logic applies to the proxy_send timeout fallback
    // - a stalled write to a freshly-checked-out conn is still "no output
    // observed".
    //
    // Pass-through forwarding cannot replay request body bytes - once any
    // body byte leaves the proxy the cycle is committed, which is why the
    // zero-body gate is required as part of the eligibility check rather
    // than treated as paranoid belt-and-suspenders.
    let backend_wait_start = Instant::now();
    let mut retry_remaining: u32 = 1;
    let (mut conn, backend_addr) = 'outer: loop {
        let mut attempts = 0u32;
        let conn_result: Result<crate::proxy::l7::keepalive::KeepaliveConn, u16> = 'checkout: loop {
            let addr = match rr.next_backend() {
                Some(a) => a,
                None => break 'checkout Err(503u16),
            };
            let state = match pool.state_for(addr) {
                Some(s) => s,
                None => break 'checkout Err(503u16),
            };
            match KeepaliveCache::checkout(&state, addr, connect_timeout).await {
                Ok(c) => break 'checkout Ok(c),
                Err(CheckoutError::Saturated) => {
                    // saturation is not a backend failure; the backend is
                    // operating at capacity. Failover only - never record
                    // a failure that would count toward the circuit breaker.
                    attempts += 1;
                    metrics::counter!(
                        "kntx_pool_full_failovers_total",
                        "pool" => pool_name.clone(),
                        "backend" => addr.to_string(),
                    )
                    .increment(1);
                    if attempts >= max_retries {
                        break 'checkout Err(503u16);
                    }
                }
                Err(CheckoutError::ConnectTimeout) => {
                    pool.record_failure(addr);
                    attempts += 1;
                    metrics::counter!(
                        "kntx_connect_retries_total",
                        "pool" => pool_name.clone(),
                        "listener" => listener_label.to_string(),
                    )
                    .increment(1);
                    if attempts >= max_retries {
                        break 'checkout Err(504u16);
                    }
                }
                Err(CheckoutError::ConnectFailed(_)) => {
                    pool.record_failure(addr);
                    attempts += 1;
                    metrics::counter!(
                        "kntx_connect_retries_total",
                        "pool" => pool_name.clone(),
                        "listener" => listener_label.to_string(),
                    )
                    .increment(1);
                    if attempts >= max_retries {
                        break 'checkout Err(502u16);
                    }
                }
            }
        };

        let mut conn = match conn_result {
            Ok(c) => c,
            Err(status) => {
                let resp = synthesize_error(status, accept_ref, error_pages);
                let _ = client_wr.write_all(&resp).await;
                emit_and_count(
                    access_log,
                    listener_label,
                    &client_ip,
                    &method,
                    &req.headers,
                    &path,
                    &pool_name,
                    None,
                    status,
                    0,
                    0,
                    start,
                    None,
                    Some(request_id.clone()),
                    Some(route_id.as_ref()),
                    keepalive_index,
                );
                return CycleOutcome::Done { close: true };
            }
        };
        let backend_addr = conn.backend_address();
        bump(last_activity);

        // `proxy_send_timeout` on the head write to the backend.
        let write_res = tokio::time::timeout(
            call_budget(tmo.proxy_send, deadline),
            conn.stream_mut().write_all(&req_head_buf),
        )
        .await;

        match write_res {
            Ok(Ok(())) => {
                bump(last_activity);
                break 'outer (conn, backend_addr);
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "failed to write request head to backend");
                // Broken-keepalive retry eligibility (all required):
                //   1. conn came from the cache (`reused == true`). Fresh
                //      connects that immediately fail are not eligible -
                //      those signal that something is wrong with the
                //      backend, not a transient TCP race.
                //   2. method is idempotent per RFC 7231 §4.2.2.
                //   3. zero body bytes have been flushed to the backend
                //      yet. Structurally true here - the body has not
                //      started - but checked explicitly so the invariant
                //      is auditable.
                let eligible = conn.reused
                    && is_idempotent_method(&method)
                    && conn.body_bytes_sent() == 0
                    && retry_remaining > 0;

                if eligible {
                    // explicit discard (decrements total_count; never
                    // returns to cache). No `pool.record_failure` - this
                    // is a TCP race, not a backend health signal.
                    KeepaliveCache::discard(conn);
                    retry_remaining -= 1;
                    metrics::counter!(
                        "kntx_http_retry_attempts_total",
                        "listener" => listener_label.to_string(),
                        "pool" => pool_name.clone(),
                    )
                    .increment(1);
                    continue 'outer;
                }

                // not eligible: 502, no retry. conn drops via Drop fallback
                // (decrements counter, never returns to cache).
                let resp = synthesize_error(502, accept_ref, error_pages);
                let _ = client_wr.write_all(&resp).await;
                emit_and_count(
                    access_log,
                    listener_label,
                    &client_ip,
                    &method,
                    &req.headers,
                    &path,
                    &pool_name,
                    Some(&backend_addr.to_string()),
                    502,
                    0,
                    0,
                    start,
                    None,
                    Some(request_id.clone()),
                    Some(route_id.as_ref()),
                    keepalive_index,
                );
                return CycleOutcome::Done { close: true };
            }
            Err(_) => {
                // proxy_send timeout: stalled write, not a TCP race. Not
                // retry-eligible - the broken-keepalive retry targets
                // immediate EPIPE on a popped cache conn, not slow
                // backends. Still no `record_failure` either, because no
                // backend output was observed on this attempt.
                emit_timeout(
                    TimeoutPhase::ProxySend,
                    deadline,
                    response_head_sent,
                    client_wr,
                    error_pages,
                    accept_ref,
                    access_log,
                    listener_label,
                    &client_ip,
                    &method,
                    &req.headers,
                    &path,
                    &pool_name,
                    backend_addr,
                    0,
                    0,
                    0,
                    start,
                    &request_id,
                    route_id.as_ref(),
                    keepalive_index,
                )
                .await;
                return CycleOutcome::Done { close: true };
            }
        }
    };

    // hoisted so every timeout site below can report consistent counters via
    // emit_timeout.
    let mut bytes_in: u64 = 0;
    let mut bytes_out: u64 = 0;
    #[allow(unused_assignments)]
    let mut final_status = 0u16;

    // Borrowed split: the halves are tied to `&mut conn`'s lifetime. conn
    // stays in scope through function exit; the success path explicitly
    // returns to cache or discards, and error paths drop via the Drop
    // fallback (decrement-only, never re-pool). `body_counter` is an
    // `&AtomicU64` to conn's body_bytes_sent field - a disjoint borrow
    // from the stream, so we can update the counter at each chunk
    // boundary while `server_wr` is alive.
    let (stream_ref, body_counter) = conn.stream_and_body_counter_mut();
    let (server_rd_raw, mut server_wr) = stream_ref.split();
    let mut server_rd = tokio::io::BufReader::with_capacity(8192, server_rd_raw);

    // stream request body (bytes_in hoisted above)
    enum BodyAbort {
        BackendIo, // backend write failed → 502
        Malformed, // chunked framing parse error → 400
        TooLarge,  // chunked body exceeded max_body_size mid-stream → 413
    }
    let mut body_abort: Option<BodyAbort> = None;
    match &framing {
        BodyFraming::None => {}
        BodyFraming::ContentLength(n) => {
            let mut remaining = *n;
            while remaining > 0 {
                let to_read = remaining.min(scratch.len() as u64) as usize;
                // `client_body_timeout`: per-call gap on the client body read.
                let rd = match tokio::time::timeout(
                    call_budget(tmo.body, deadline),
                    client_rd.read(&mut scratch[..to_read]),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        emit_timeout(
                            TimeoutPhase::Body,
                            deadline,
                            response_head_sent,
                            client_wr,
                            error_pages,
                            accept_ref,
                            access_log,
                            listener_label,
                            &client_ip,
                            &method,
                            &req.headers,
                            &path,
                            &pool_name,
                            backend_addr,
                            bytes_in,
                            bytes_out,
                            final_status,
                            start,
                            &request_id,
                            route_id.as_ref(),
                            keepalive_index,
                        )
                        .await;
                        pool.record_failure(backend_addr);
                        return CycleOutcome::Done { close: true };
                    }
                };
                match rd {
                    Ok(0) => break,
                    Ok(n) => {
                        bump(last_activity);
                        // `proxy_send_timeout`: per-call gap on the backend write.
                        match tokio::time::timeout(
                            call_budget(tmo.proxy_send, deadline),
                            server_wr.write_all(&scratch[..n]),
                        )
                        .await
                        {
                            Ok(Ok(())) => {
                                // Increment after the full chunk has been
                                // flushed to the backend's kernel send
                                // buffer - never per-syscall. The counter
                                // is the discriminator for backend-conn
                                // poisoning (any non-zero value means an
                                // error path must discard the conn) and
                                // for retry eligibility (zero required).
                                body_counter.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            Ok(Err(_)) => {
                                pool.record_failure(backend_addr);
                                body_abort = Some(BodyAbort::BackendIo);
                                break;
                            }
                            Err(_) => {
                                emit_timeout(
                                    TimeoutPhase::ProxySend,
                                    deadline,
                                    response_head_sent,
                                    client_wr,
                                    error_pages,
                                    accept_ref,
                                    access_log,
                                    listener_label,
                                    &client_ip,
                                    &method,
                                    &req.headers,
                                    &path,
                                    &pool_name,
                                    backend_addr,
                                    bytes_in,
                                    bytes_out,
                                    final_status,
                                    start,
                                    &request_id,
                                    route_id.as_ref(),
                                    keepalive_index,
                                )
                                .await;
                                pool.record_failure(backend_addr);
                                return CycleOutcome::Done { close: true };
                            }
                        }
                        bump(last_activity);
                        bytes_in += n as u64;
                        remaining -= n as u64;
                    }
                    Err(_) => break, // client-side error, don't record
                }
            }
        }
        BodyFraming::Chunked => {
            let mut cr = ChunkedReader::new();
            while !cr.is_done() {
                // pump_once interleaves the client read and backend write, so a
                // single budget = min(body, proxy_send) bounds the per-call gap;
                // a trip is classified Body (close, no synthetic response - the
                // backend already holds a partial chunked request).
                let pumped = match tokio::time::timeout(
                    call_budget(tmo.body.min(tmo.proxy_send), deadline),
                    cr.pump_once(&mut *client_rd, &mut server_wr, scratch),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        emit_timeout(
                            TimeoutPhase::Body,
                            deadline,
                            response_head_sent,
                            client_wr,
                            error_pages,
                            accept_ref,
                            access_log,
                            listener_label,
                            &client_ip,
                            &method,
                            &req.headers,
                            &path,
                            &pool_name,
                            backend_addr,
                            bytes_in,
                            bytes_out,
                            final_status,
                            start,
                            &request_id,
                            route_id.as_ref(),
                            keepalive_index,
                        )
                        .await;
                        pool.record_failure(backend_addr);
                        return CycleOutcome::Done { close: true };
                    }
                };
                match pumped {
                    Ok(n) => {
                        bump(last_activity);
                        bytes_in += n as u64;
                        // For chunked the pump_once boundary is the outer
                        // iteration; `n` includes framing bytes, which is
                        // fine - the counter answers "did any request
                        // bytes hit the backend?", and framing bytes count
                        // toward that.
                        body_counter.fetch_add(n as u64, Ordering::Relaxed);
                        // Chunked body-size enforcement. bytes_in counts
                        // framing too, so the trip fires slightly earlier
                        // than `max_body_size` would for a pure body -
                        // acceptable: errs on protecting the backend, and
                        // chunked framing overhead is on the order of
                        // 10-50 bytes per chunk. Because the request and
                        // response phases are serialized, the response
                        // head is never on the wire during request body
                        // forwarding, so a 413 is always emissible here.
                        if max_body_size > 0 && bytes_in > max_body_size {
                            body_abort = Some(BodyAbort::TooLarge);
                            break;
                        }
                    }
                    Err(e) => {
                        // pump_once mixes both sides; record conservatively
                        pool.record_failure(backend_addr);
                        body_abort = Some(if e.kind() == std::io::ErrorKind::InvalidData {
                            BodyAbort::Malformed
                        } else {
                            BodyAbort::BackendIo
                        });
                        break;
                    }
                }
            }
        }
        BodyFraming::CloseDelimited => {}
    }

    // Body forwarding aborted before the backend could finish reading the
    // request: synthesize an error to the client and return rather than
    // waiting on a response that will never come. The backend conn drops
    // via the Drop fallback (decrements total_count; never re-pools the
    // poisoned conn).
    if let Some(reason) = body_abort {
        let (status, kind_label) = match reason {
            BodyAbort::Malformed => (400u16, "malformed"),
            BodyAbort::BackendIo => (502u16, "backend_io"),
            BodyAbort::TooLarge => (413u16, "too_large"),
        };
        if matches!(reason, BodyAbort::TooLarge) {
            metrics::counter!(
                "kntx_http_body_too_large_total",
                "listener" => listener_label.to_string(),
            )
            .increment(1);
        } else {
            metrics::counter!(
                "kntx_http_body_parse_errors_total",
                "listener" => listener_label.to_string(),
                "kind" => kind_label,
            )
            .increment(1);
        }
        let resp = synthesize_error(status, accept_ref, error_pages);
        let _ = client_wr.write_all(&resp).await;
        emit_and_count(
            access_log,
            listener_label,
            &client_ip,
            &method,
            &req.headers,
            &path,
            &pool_name,
            Some(&backend_addr.to_string()),
            status,
            bytes_in,
            0,
            start,
            None,
            Some(request_id),
            Some(route_id.as_ref()),
            keepalive_index,
        );
        return CycleOutcome::Done { close: true };
    }

    // read backend response head (loop for 1xx interim responses).
    // bytes_out / final_status hoisted above.
    let mut resp_head_buf: Vec<u8> = Vec::with_capacity(8192);
    #[allow(unused_assignments)]
    let mut backend_wait_ms: Option<f64> = None;
    #[allow(unused_assignments)]
    let mut backend_ok = false;
    // backend conn fate after a clean response cycle. set true only when the
    // response body forwarded without error AND the backend did not signal
    // close on its response. independent of the client-side close decision.
    let mut return_conn = false;

    'response: loop {
        // `proxy_read_timeout`: per-call gap on the backend response-head read.
        let head_result = match tokio::time::timeout(
            call_budget(tmo.proxy_read, deadline),
            read_head(
                &mut server_rd,
                &mut resp_head_buf,
                header_limit,
                last_activity,
            ),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => {
                emit_timeout(
                    TimeoutPhase::ProxyRead,
                    deadline,
                    response_head_sent,
                    client_wr,
                    error_pages,
                    accept_ref,
                    access_log,
                    listener_label,
                    &client_ip,
                    &method,
                    &req.headers,
                    &path,
                    &pool_name,
                    backend_addr,
                    bytes_in,
                    bytes_out,
                    final_status,
                    start,
                    &request_id,
                    route_id.as_ref(),
                    keepalive_index,
                )
                .await;
                pool.record_failure(backend_addr);
                return CycleOutcome::Done { close: true };
            }
        };
        match head_result {
            HeadReadResult::Eof | HeadReadResult::TooLarge | HeadReadResult::IoError => {
                tracing::debug!("backend EOF or error reading response head");
                pool.record_failure(backend_addr);
                let resp = synthesize_error(502, accept_ref, error_pages);
                let _ = client_wr.write_all(&resp).await;
                emit_and_count(
                    access_log,
                    listener_label,
                    &client_ip,
                    &method,
                    &req.headers,
                    &path,
                    &pool_name,
                    Some(&backend_addr.to_string()),
                    502,
                    bytes_in,
                    0,
                    start,
                    None,
                    Some(request_id.clone()),
                    Some(route_id.as_ref()),
                    keepalive_index,
                );
                return CycleOutcome::Done { close: true };
            }
            HeadReadResult::Complete => {}
        }

        let resp = match parse_response(&resp_head_buf, 128) {
            Ok(ParseOutcome::Complete(r)) => r,
            _ => {
                pool.record_failure(backend_addr);
                let err_resp = synthesize_error(502, accept_ref, error_pages);
                let _ = client_wr.write_all(&err_resp).await;
                emit_and_count(
                    access_log,
                    listener_label,
                    &client_ip,
                    &method,
                    &req.headers,
                    &path,
                    &pool_name,
                    Some(&backend_addr.to_string()),
                    502,
                    bytes_in,
                    0,
                    start,
                    None,
                    Some(request_id.clone()),
                    Some(route_id.as_ref()),
                    keepalive_index,
                );
                return CycleOutcome::Done { close: true };
            }
        };

        final_status = resp.status;

        // WebSocket upgrade tunnel handoff. The buffer pair MUST be checked
        // out before the 101 hits the wire: once the client sees the 101 the
        // upgrade is committed and a 503 is no longer recoverable. With this
        // ordering, exhaustion stays a clean failure mode.
        if is_ws_upgrade && resp.status == 101 {
            backend_wait_ms = Some(backend_wait_start.elapsed().as_secs_f64() * 1000.0);
            let tunnel_bufs = match buffer_pool.try_checkout_pair() {
                Some(bufs) => bufs,
                None => {
                    metrics::counter!(
                        "kntx_l7_buffer_pool_exhausted_total",
                        "listener" => listener_label.to_string(),
                    )
                    .increment(1);
                    let resp_503 = synthesize_error(503, accept_ref, error_pages);
                    let body_len = resp_503.len() as u64;
                    let _ = client_wr.write_all(&resp_503).await;
                    emit_and_count(
                        access_log,
                        listener_label,
                        &client_ip,
                        &method,
                        &req.headers,
                        &path,
                        &pool_name,
                        Some(&backend_addr.to_string()),
                        503,
                        bytes_in,
                        body_len,
                        start,
                        backend_wait_ms,
                        Some(request_id.clone()),
                        Some(route_id.as_ref()),
                        keepalive_index,
                    );
                    pool.record_success(backend_addr);
                    return CycleOutcome::Done { close: true };
                }
            };

            // Relay 101 verbatim. Upgrade and Connection: Upgrade are
            // hop-by-hop in general but are exactly the headers the client
            // needs to see for the protocol switch - strip them and the
            // upgrade silently fails.
            let ws_head_bytes = resp.head_len as u64;
            if client_wr
                .write_all(&resp_head_buf[..resp.head_len])
                .await
                .is_err()
            {
                pool.record_failure(backend_addr);
                return CycleOutcome::Done { close: true };
            }
            pool.record_success(backend_addr);

            metrics::gauge!(
                "kntx_websocket_tunnels_active",
                "listener" => listener_label.to_string(),
            )
            .increment(1.0);
            metrics::counter!(
                "kntx_websocket_tunnels_total",
                "listener" => listener_label.to_string(),
            )
            .increment(1);

            let tunnel_idle = Duration::from_secs(
                listener_cfg
                    .idle_timeout_secs
                    .unwrap_or(DEFAULT_PHASE_TIMEOUT_SECS),
            );
            // shave 100ms off the listener's drain so the tunnel returns and
            // emits its access log before the listener's drain_deadline fires
            // its `aborting remaining` warning. without the margin both timers
            // race to the same microsecond and the warning logs spuriously.
            let tunnel_drain = Duration::from_secs(listener_cfg.drain_timeout_secs)
                .saturating_sub(Duration::from_millis(100));

            let (c2b, b2c, outcome) = bidirectional_copy_with_timeout(
                client_rd,
                client_wr,
                &mut server_rd,
                &mut server_wr,
                tunnel_bufs,
                tunnel_idle,
                tunnel_drain,
                shutdown_rx,
            )
            .await;

            metrics::gauge!(
                "kntx_websocket_tunnels_active",
                "listener" => listener_label.to_string(),
            )
            .decrement(1.0);

            // Sync emission: the log line must land before any later await
            // that could be cancelled when a JoinSet drop hits at drain
            // deadline. `try_send` on the file sink is non-awaiting; stdio
            // sinks are blocking writes. Either way, no yield.
            let (path_clean, query) = split_path_query(&path);
            let host = find_header(&req.headers, "host");
            let trace_id = find_header(&req.headers, "traceparent")
                .as_deref()
                .and_then(extract_trace_id);
            access_log.emit_sync(AccessLogLine {
                timestamp: now_rfc3339(),
                listener: listener_label.to_owned(),
                client_ip: client_ip.clone(),
                method: method.clone(),
                host,
                path: path_clean,
                query,
                protocol: "HTTP/1.1".to_owned(),
                status: 101,
                bytes_in: bytes_in + c2b,
                bytes_out: ws_head_bytes + b2c,
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                backend_wait_ms,
                backend: Some(backend_addr.to_string()),
                pool: pool_name.clone(),
                route_id: Some(route_id.to_string()),
                request_id: request_id.clone(),
                trace_id,
                keepalive_index,
                tunnel: Some(true),
                outcome: Some(outcome.as_str().to_owned()),
            });

            metrics::counter!(
                "kntx_http_requests_total",
                "method" => method_label(&method),
                "status" => "101",
                "pool" => intern_label(&pool_name),
                "listener" => intern_label(listener_label),
            )
            .increment(1);
            metrics::histogram!(
                "kntx_http_request_duration_seconds",
                "pool" => pool_name.clone(),
                "listener" => listener_label.to_owned(),
            )
            .record(start.elapsed().as_secs_f64());

            let _ = outcome; // outcome value travelled to the log line; silence unused
            return CycleOutcome::Done { close: true };
        }

        if resp.status < 200 {
            // 1xx interim: relay verbatim to client, read next response
            bump(last_activity);
            let _ = client_wr.write_all(&resp_head_buf[..resp.head_len]).await;
            bump(last_activity);
            resp_head_buf.drain(..resp.head_len);
            continue 'response;
        }

        backend_wait_ms = Some(backend_wait_start.elapsed().as_secs_f64() * 1000.0);

        let resp_version = resp.version;
        // The proxy's hop-by-hop `Connection` header to the client reflects
        // the up-front close decision; the backend's own `Connection`
        // header is stripped via `resp_skip`. `version` is the client
        // request's version, which drives the spelling (mixed-case
        // `Keep-Alive` for HTTP/1.0).
        let (resp_skip, resp_additions) =
            build_response_additions(&resp.headers, resp_version, close_after_response, version);
        let mut resp_head_out = BytesMut::with_capacity(4096);
        serialize_response_head(
            &mut resp_head_out,
            resp_version,
            resp.status,
            &resp.reason,
            &resp.headers,
            &resp_skip,
            &resp_additions,
        );
        bump(last_activity);
        if client_wr.write_all(&resp_head_out).await.is_err() {
            pool.record_failure(backend_addr);
            // client gone mid-response; end the conn (no error response possible)
            return CycleOutcome::Done { close: true };
        }
        bump(last_activity);
        // response head is on the wire - past this point a timeout can no
        // longer synthesize a status response; the proxy must close
        // abruptly to avoid corrupting framing the client has parsed.
        response_head_sent = true;

        // stream response body
        let resp_framing = classify_response_body(&resp, &method);
        let mut body_backend_error = false;
        match resp_framing {
            BodyFraming::None => {}
            BodyFraming::ContentLength(n) => {
                let mut remaining = n;
                while remaining > 0 {
                    let to_read = remaining.min(scratch.len() as u64) as usize;
                    // `proxy_read_timeout`: per-call gap on the backend body read.
                    let rd = match tokio::time::timeout(
                        call_budget(tmo.proxy_read, deadline),
                        server_rd.read(&mut scratch[..to_read]),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => {
                            emit_timeout(
                                TimeoutPhase::ProxyRead,
                                deadline,
                                response_head_sent,
                                client_wr,
                                error_pages,
                                accept_ref,
                                access_log,
                                listener_label,
                                &client_ip,
                                &method,
                                &req.headers,
                                &path,
                                &pool_name,
                                backend_addr,
                                bytes_in,
                                bytes_out,
                                final_status,
                                start,
                                &request_id,
                                route_id.as_ref(),
                                keepalive_index,
                            )
                            .await;
                            pool.record_failure(backend_addr);
                            return CycleOutcome::Done { close: true };
                        }
                    };
                    match rd {
                        Ok(0) => break,
                        Ok(n) => {
                            bump(last_activity);
                            if client_wr.write_all(&scratch[..n]).await.is_err() {
                                break; // client-side error, don't record
                            }
                            bump(last_activity);
                            bytes_out += n as u64;
                            remaining -= n as u64;
                        }
                        Err(_) => {
                            pool.record_failure(backend_addr);
                            body_backend_error = true;
                            break;
                        }
                    }
                }
            }
            BodyFraming::Chunked => {
                let mut cr = ChunkedReader::new();
                while !cr.is_done() {
                    let pumped = match tokio::time::timeout(
                        call_budget(tmo.proxy_read, deadline),
                        cr.pump_once(&mut server_rd, &mut *client_wr, scratch),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => {
                            emit_timeout(
                                TimeoutPhase::ProxyRead,
                                deadline,
                                response_head_sent,
                                client_wr,
                                error_pages,
                                accept_ref,
                                access_log,
                                listener_label,
                                &client_ip,
                                &method,
                                &req.headers,
                                &path,
                                &pool_name,
                                backend_addr,
                                bytes_in,
                                bytes_out,
                                final_status,
                                start,
                                &request_id,
                                route_id.as_ref(),
                                keepalive_index,
                            )
                            .await;
                            pool.record_failure(backend_addr);
                            return CycleOutcome::Done { close: true };
                        }
                    };
                    match pumped {
                        Ok(n) => {
                            bump(last_activity);
                            bytes_out += n as u64;
                        }
                        Err(_) => {
                            pool.record_failure(backend_addr);
                            body_backend_error = true;
                            break;
                        }
                    }
                }
            }
            BodyFraming::CloseDelimited => loop {
                let rd = match tokio::time::timeout(
                    call_budget(tmo.proxy_read, deadline),
                    server_rd.read(scratch),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        emit_timeout(
                            TimeoutPhase::ProxyRead,
                            deadline,
                            response_head_sent,
                            client_wr,
                            error_pages,
                            accept_ref,
                            access_log,
                            listener_label,
                            &client_ip,
                            &method,
                            &req.headers,
                            &path,
                            &pool_name,
                            backend_addr,
                            bytes_in,
                            bytes_out,
                            final_status,
                            start,
                            &request_id,
                            route_id.as_ref(),
                            keepalive_index,
                        )
                        .await;
                        pool.record_failure(backend_addr);
                        return CycleOutcome::Done { close: true };
                    }
                };
                match rd {
                    Ok(0) => break,
                    Ok(n) => {
                        bump(last_activity);
                        if client_wr.write_all(&scratch[..n]).await.is_err() {
                            break; // client-side error, don't record
                        }
                        bump(last_activity);
                        bytes_out += n as u64;
                    }
                    Err(_) => {
                        pool.record_failure(backend_addr);
                        body_backend_error = true;
                        break;
                    }
                }
            },
        }

        if !body_backend_error {
            pool.record_success(backend_addr);
            return_conn = !backend_response_says_close(&resp.headers, resp_version);
        }
        backend_ok = true;
        break 'response;
    }

    // client conn shutdown is owned by serve_l7_conn (it decides keep-alive
    // vs close across iterations). forward_one_request must NOT shut down client_wr.

    let _ = backend_ok; // used indirectly via pool.record_{success,failure}

    // backend conn fate is independent of the client-side close decision:
    // a backend can close its keep-alive while the client conn stays alive.
    // error paths still drop conn implicitly - Drop decrements total_count.
    if return_conn {
        KeepaliveCache::return_to_cache(conn);
    } else {
        KeepaliveCache::discard(conn);
    }

    emit_and_count(
        access_log,
        listener_label,
        &client_ip,
        &method,
        &req.headers,
        &path,
        &pool_name,
        Some(&backend_addr.to_string()),
        final_status,
        bytes_in,
        bytes_out,
        start,
        backend_wait_ms,
        Some(request_id),
        Some(route_id.as_ref()),
        keepalive_index,
    );

    CycleOutcome::Done {
        close: close_after_response,
    }
}

enum HeadReadResult {
    Complete,
    Eof,
    TooLarge,
    IoError,
}

async fn read_head<R>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
    last_activity: &Arc<AtomicU64>,
) -> HeadReadResult
where
    R: AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    loop {
        if buf.len() >= limit {
            return HeadReadResult::TooLarge;
        }
        let avail = match reader.fill_buf().await {
            Ok(b) => b,
            Err(_) => return HeadReadResult::IoError,
        };
        if avail.is_empty() {
            if buf.is_empty() {
                return HeadReadResult::Eof;
            }
            // partial head on EOF - caller treats as malformed
            return HeadReadResult::Complete;
        }

        let take = (limit - buf.len()).min(avail.len());
        // scan_start overlaps last 3 bytes of previous batch so \r\n\r\n
        // straddling two reads is not missed.
        let scan_start = buf.len().saturating_sub(3);
        buf.extend_from_slice(&avail[..take]);
        last_activity.store(monotonic_millis(), Ordering::Relaxed);

        if let Some(idx) = find_double_crlf(&buf[scan_start..]) {
            let head_end = scan_start + idx + 4;
            let consumed_from_avail = head_end - (buf.len() - take);
            buf.truncate(head_end);
            reader.consume(consumed_from_avail);
            return HeadReadResult::Complete;
        }
        reader.consume(take);
    }
}

fn find_double_crlf(slice: &[u8]) -> Option<usize> {
    if slice.len() < 4 {
        return None;
    }
    for i in 0..=slice.len() - 4 {
        if &slice[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

fn looks_like_http2_preface(buf: &[u8]) -> bool {
    buf.starts_with(b"PRI * HTTP/2.0\r\n")
}

fn find_header(headers: &[crate::proxy::l7::parse::ParsedHeader], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| h.value_str())
        .map(|s| s.to_owned())
}

fn split_path_query(path: &str) -> (String, Option<String>) {
    match path.find('?') {
        Some(pos) => (path[..pos].to_owned(), Some(path[pos + 1..].to_owned())),
        None => (path.to_owned(), None),
    }
}

/// true if any `Connection` request header contains `token` as a
/// comma-separated, case-insensitive element (RFC 7230 §6.1).
fn conn_header_has_token(headers: &[ParsedHeader], token: &str) -> bool {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("connection"))
        .filter_map(|h| h.value_str())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// HTTP/1.1 closes only on explicit `Connection: close`; HTTP/1.0 closes
/// unless an explicit `Connection: keep-alive` opt-in is present.
fn backend_response_says_close(headers: &[ParsedHeader], version: HttpVersion) -> bool {
    match version {
        HttpVersion::Http10 => !conn_header_has_token(headers, "keep-alive"),
        HttpVersion::Http11 => conn_header_has_token(headers, "close"),
    }
}

/// methods whose spec semantics promise an equivalent end state on repeat
/// (RFC 7231 §4.2.2). Only these may be retried after a broken-keepalive
/// race - POST/PATCH (and anything unknown) MUST NOT, because the proxy
/// has no way to know whether the backend partially processed and committed
/// a side-effect on the lost conn.
fn is_idempotent_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PUT" | "DELETE",
    )
}

// Static label strings for the common HTTP status codes the proxy emits or
// observes from backends. metrics::counter! requires Into<SharedString>
// (= Cow<'static, str>); returning a borrowed static skips the per-emit
// heap allocation that `status.to_string()` would force. Uncommon codes fall
// through to an owned conversion so labels stay accurate.
fn status_label(code: u16) -> std::borrow::Cow<'static, str> {
    use std::borrow::Cow;
    match code {
        100 => Cow::Borrowed("100"),
        101 => Cow::Borrowed("101"),
        200 => Cow::Borrowed("200"),
        201 => Cow::Borrowed("201"),
        204 => Cow::Borrowed("204"),
        301 => Cow::Borrowed("301"),
        302 => Cow::Borrowed("302"),
        304 => Cow::Borrowed("304"),
        400 => Cow::Borrowed("400"),
        401 => Cow::Borrowed("401"),
        403 => Cow::Borrowed("403"),
        404 => Cow::Borrowed("404"),
        405 => Cow::Borrowed("405"),
        408 => Cow::Borrowed("408"),
        413 => Cow::Borrowed("413"),
        431 => Cow::Borrowed("431"),
        500 => Cow::Borrowed("500"),
        502 => Cow::Borrowed("502"),
        503 => Cow::Borrowed("503"),
        504 => Cow::Borrowed("504"),
        505 => Cow::Borrowed("505"),
        _ => Cow::Owned(code.to_string()),
    }
}

// Same idea for HTTP method names - the RFC 7231 + WebDAV set plus the
// well-known unconventional ones. Falls back to owned for anything outside.
fn method_label(method: &str) -> std::borrow::Cow<'static, str> {
    use std::borrow::Cow;
    match method {
        "GET" => Cow::Borrowed("GET"),
        "HEAD" => Cow::Borrowed("HEAD"),
        "POST" => Cow::Borrowed("POST"),
        "PUT" => Cow::Borrowed("PUT"),
        "DELETE" => Cow::Borrowed("DELETE"),
        "OPTIONS" => Cow::Borrowed("OPTIONS"),
        "TRACE" => Cow::Borrowed("TRACE"),
        "PATCH" => Cow::Borrowed("PATCH"),
        "CONNECT" => Cow::Borrowed("CONNECT"),
        _ => Cow::Owned(method.to_string()),
    }
}

// Intern pool / listener labels into &'static str so metric emissions can
// pass them as Cow::Borrowed instead of allocating a fresh String per emit.
// The set is bounded by the number of (pool, listener) names in the config -
// typically under a dozen - so the leak is one-time and tiny.
fn intern_label(s: &str) -> &'static str {
    use std::collections::HashMap;
    use std::sync::{OnceLock, RwLock};

    static CACHE: OnceLock<RwLock<HashMap<Box<str>, &'static str>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));

    {
        let map = cache.read().expect("intern_label cache poisoned");
        if let Some(&v) = map.get(s) {
            return v;
        }
    }
    let mut map = cache.write().expect("intern_label cache poisoned");
    if let Some(&v) = map.get(s) {
        return v;
    }
    let owned: Box<str> = s.into();
    let leaked: &'static str = Box::leak(owned.clone());
    map.insert(owned, leaked);
    leaked
}

#[allow(clippy::too_many_arguments)]
fn emit_error_log(
    sink: &AccessLogSink,
    listener: &str,
    client_ip: &str,
    method: &str,
    path: &str,
    pool: &str,
    status: u16,
    bytes_out: u64,
    start: Instant,
    request_id: &str,
    keepalive_index: u32,
) {
    let (path_clean, query) = split_path_query(path);
    sink.emit(AccessLogLine {
        timestamp: now_rfc3339(),
        listener: listener.to_owned(),
        client_ip: client_ip.to_owned(),
        method: method.to_owned(),
        host: None,
        path: path_clean,
        query,
        protocol: "HTTP/1.1".to_owned(),
        status,
        bytes_in: 0,
        bytes_out,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
        backend_wait_ms: None,
        backend: None,
        pool: pool.to_owned(),
        route_id: None,
        request_id: request_id.to_owned(),
        trace_id: None,
        keepalive_index,
        tunnel: None,
        outcome: None,
    });
}

#[allow(clippy::too_many_arguments)]
fn emit_and_count(
    sink: &AccessLogSink,
    listener: &str,
    client_ip: &str,
    method: &str,
    headers: &[crate::proxy::l7::parse::ParsedHeader],
    path: &str,
    pool: &str,
    backend: Option<&str>,
    status: u16,
    bytes_in: u64,
    bytes_out: u64,
    start: Instant,
    backend_wait_ms: Option<f64>,
    request_id: Option<String>,
    route_id: Option<&str>,
    keepalive_index: u32,
) {
    let host = find_header(headers, "host");
    let trace_id = find_header(headers, "traceparent")
        .as_deref()
        .and_then(extract_trace_id);
    let (path_clean, query) = split_path_query(path);
    let req_id = request_id.unwrap_or_default();

    sink.emit(AccessLogLine {
        timestamp: now_rfc3339(),
        listener: listener.to_owned(),
        client_ip: client_ip.to_owned(),
        method: method.to_owned(),
        host,
        path: path_clean,
        query,
        protocol: "HTTP/1.1".to_owned(),
        status,
        bytes_in,
        bytes_out,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
        backend_wait_ms,
        backend: backend.map(|s| s.to_owned()),
        pool: pool.to_owned(),
        route_id: route_id.map(|s| s.to_owned()),
        request_id: req_id,
        trace_id,
        keepalive_index,
        tunnel: None,
        outcome: None,
    });

    let pool_static = intern_label(pool);
    let listener_static = intern_label(listener);
    metrics::counter!(
        "kntx_http_requests_total",
        "method" => method_label(method),
        "status" => status_label(status),
        "pool" => pool_static,
        "listener" => listener_static,
    )
    .increment(1);
    metrics::histogram!(
        "kntx_http_request_duration_seconds",
        "pool" => pool_static,
        "listener" => listener_static,
    )
    .record(start.elapsed().as_secs_f64());
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    let secs = us / 1_000_000;
    let micros = us % 1_000_000;
    let (y, mo, d, h, mi, sec) = unix_to_ymdhms(secs as u64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{sec:02}.{micros:06}Z")
}

fn unix_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = (rem / 3600) as u32;
    let mi = ((rem % 3600) / 60) as u32;
    let sec = (rem % 60) as u32;

    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };

    (y as u32, mo as u32, d as u32, h, mi, sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotent_methods_accepted() {
        for m in ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"] {
            assert!(is_idempotent_method(m), "{m} must be idempotent");
        }
    }

    #[test]
    fn non_idempotent_methods_rejected() {
        for m in ["POST", "PATCH", "CONNECT", "FOO", ""] {
            assert!(!is_idempotent_method(m), "{m} must not be idempotent");
        }
    }

    #[test]
    fn idempotent_check_is_case_insensitive() {
        for m in ["get", "Get", "gEt", "head", "delete", "OPTions"] {
            assert!(is_idempotent_method(m), "{m} must match case-insensitively");
        }
        for m in ["post", "Post", "patch"] {
            assert!(
                !is_idempotent_method(m),
                "{m} must remain non-idempotent regardless of case"
            );
        }
    }
}
