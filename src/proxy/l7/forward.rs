use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use bytes::BytesMut;
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::access_log::{AccessLogLine, AccessLogSink, extract_trace_id};
use crate::balancer::RoundRobin;
use crate::config::ListenerConfig;
use crate::health::BackendPool;
use crate::pool::buffer::BufferPool;
use crate::proxy::l4;
use crate::util::monotonic_millis;

use super::error::{ErrorPages, synthesize_error};
use super::framing::{BodyFraming, ChunkedReader, classify_request_body, classify_response_body};
use super::headers::{
    build_request_additions, build_response_additions, resolve_request_id, serialize_request_head,
    serialize_response_head,
};
use super::parse::{ParseError, ParseOutcome, parse_request, parse_response};

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
    listener_cfg: Arc<ListenerConfig>,
    pool: Arc<BackendPool>,
    rr: Arc<RoundRobin>,
    error_pages: Arc<ErrorPages>,
    access_log: Arc<AccessLogSink>,
    last_activity: Arc<AtomicU64>,
    buffer_pool: Arc<BufferPool>,
    metrics_listener_label: Arc<str>,
) -> Result<(), L7Error> {
    let is_tls = client.is_tls();
    let client_ip = client_addr.ip().to_string();
    let pool_name = pool.name().to_string();

    match client {
        ClientStream::Plain(tcp) => {
            handle_l7(
                tcp,
                client_ip,
                is_tls,
                listener_cfg,
                pool,
                rr,
                error_pages,
                access_log,
                last_activity,
                buffer_pool,
                pool_name,
                metrics_listener_label,
            )
            .await
        }
        ClientStream::Tls(tls) => {
            handle_l7(
                *tls,
                client_ip,
                is_tls,
                listener_cfg,
                pool,
                rr,
                error_pages,
                access_log,
                last_activity,
                buffer_pool,
                pool_name,
                metrics_listener_label,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_l7<S>(
    client: S,
    client_ip: String,
    is_tls: bool,
    listener_cfg: Arc<ListenerConfig>,
    pool: Arc<BackendPool>,
    rr: Arc<RoundRobin>,
    error_pages: Arc<ErrorPages>,
    access_log: Arc<AccessLogSink>,
    last_activity: Arc<AtomicU64>,
    buffer_pool: Arc<BufferPool>,
    pool_name: String,
    listener_label: Arc<str>,
) -> Result<(), L7Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    let header_limit = listener_cfg.header_size_limit_bytes;
    let connect_timeout = std::time::Duration::from_secs(listener_cfg.connect_timeout_secs);
    let max_retries = listener_cfg.max_connect_attempts;

    let bump = |la: &Arc<AtomicU64>| la.store(monotonic_millis(), Ordering::Relaxed);

    let (client_rd, mut client_wr) = tokio::io::split(client);
    let mut client_rd = tokio::io::BufReader::with_capacity(8192, client_rd);

    // acquire a pooled buffer for body forwarding
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

    let mut head_buf: Vec<u8> = Vec::with_capacity(header_limit.min(8192));
    let read_result = read_head(&mut client_rd, &mut head_buf, header_limit, &last_activity).await;

    match read_result {
        HeadReadResult::Eof => {
            // silent: connection closed before any request arrived
            return Ok(());
        }
        HeadReadResult::TooLarge => {
            let request_id = uuid::Uuid::new_v4().to_string();
            let resp = synthesize_error(431, None, &error_pages);
            let _ = client_wr.write_all(&resp).await;
            metrics::counter!(
                "kntx_http_parse_errors_total",
                "listener" => listener_label.to_string()
            )
            .increment(1);
            emit_error_log(
                &access_log,
                &listener_label,
                &client_ip,
                "",
                "",
                &pool_name,
                431,
                0,
                start,
                &request_id,
            );
            return Ok(());
        }
        HeadReadResult::IoError(e) => return Err(L7Error::Io(e)),
        HeadReadResult::Complete => {}
    }
    bump(&last_activity);

    // http/2 connection preface: httparse returns Malformed for it, so we detect
    // it explicitly and return 505 instead of 400.
    if looks_like_http2_preface(&head_buf) {
        let request_id = uuid::Uuid::new_v4().to_string();
        let resp = synthesize_error(505, None, &error_pages);
        let _ = client_wr.write_all(&resp).await;
        metrics::counter!(
            "kntx_http_parse_errors_total",
            "listener" => listener_label.to_string()
        )
        .increment(1);
        emit_error_log(
            &access_log,
            &listener_label,
            &client_ip,
            "",
            "",
            &pool_name,
            505,
            0,
            start,
            &request_id,
        );
        return Ok(());
    }

    // parse the head
    let req = match parse_request(&head_buf, 128) {
        Err(ParseError::HeaderTooLarge) => {
            let request_id = uuid::Uuid::new_v4().to_string();
            let resp = synthesize_error(431, None, &error_pages);
            let _ = client_wr.write_all(&resp).await;
            metrics::counter!("kntx_http_parse_errors_total", "listener" => listener_label.to_string()).increment(1);
            emit_error_log(
                &access_log,
                &listener_label,
                &client_ip,
                "",
                "",
                &pool_name,
                431,
                0,
                start,
                &request_id,
            );
            return Ok(());
        }
        Err(ParseError::UnsupportedVersion(kind)) => {
            let request_id = uuid::Uuid::new_v4().to_string();
            let status = match kind {
                super::parse::VersionKind::Http2 => 505,
                _ => 400,
            };
            let resp = synthesize_error(status, None, &error_pages);
            let _ = client_wr.write_all(&resp).await;
            metrics::counter!("kntx_http_parse_errors_total", "listener" => listener_label.to_string()).increment(1);
            emit_error_log(
                &access_log,
                &listener_label,
                &client_ip,
                "",
                "",
                &pool_name,
                status,
                0,
                start,
                &request_id,
            );
            return Ok(());
        }
        Err(ParseError::Malformed) | Ok(ParseOutcome::Partial) => {
            let request_id = uuid::Uuid::new_v4().to_string();
            let resp = synthesize_error(400, None, &error_pages);
            let _ = client_wr.write_all(&resp).await;
            metrics::counter!("kntx_http_parse_errors_total", "listener" => listener_label.to_string()).increment(1);
            emit_error_log(
                &access_log,
                &listener_label,
                &client_ip,
                "",
                "",
                &pool_name,
                400,
                0,
                start,
                &request_id,
            );
            return Ok(());
        }
        Ok(ParseOutcome::Complete(r)) => r,
    };

    let request_id = resolve_request_id(&req.headers);

    let method = req.method.clone();
    let path = req.path.clone();
    let version = req.version;

    let accept_val = find_header(&req.headers, "accept");
    let accept_ref = accept_val.as_deref();

    // smuggling validation
    let framing = match classify_request_body(&req) {
        Ok(f) => f,
        Err(e) => {
            let resp = synthesize_error(400, accept_ref, &error_pages);
            let _ = client_wr.write_all(&resp).await;
            metrics::counter!(
                "kntx_http_smuggling_rejects_total",
                "listener" => listener_label.to_string(),
                "reason" => e.reason_label(),
            )
            .increment(1);
            emit_and_count(
                &access_log,
                &listener_label,
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
            );
            return Ok(());
        }
    };

    // CONNECT → 405
    if method.eq_ignore_ascii_case("CONNECT") {
        let resp = synthesize_error(405, accept_ref, &error_pages);
        let _ = client_wr.write_all(&resp).await;
        emit_and_count(
            &access_log,
            &listener_label,
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
        );
        return Ok(());
    }

    // Upgrade → 405 in 6b (websocket tunneling is 6d)
    if let Some(upgrade_val) = find_header(&req.headers, "upgrade") {
        let _ = upgrade_val; // websocket or anything else — both 405 in this phase
        let resp = synthesize_error(405, accept_ref, &error_pages);
        let _ = client_wr.write_all(&resp).await;
        emit_and_count(
            &access_log,
            &listener_label,
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
        );
        return Ok(());
    }

    // backend selection with retry
    let backend_wait_start = Instant::now();
    let mut attempts = 0u32;
    let mut last_status = 503u16;

    let server_result = loop {
        let addr = match rr.next_backend() {
            Some(a) => a,
            None => {
                last_status = 503;
                break Err(503u16);
            }
        };
        match l4::connect_backend(addr, connect_timeout, None).await {
            Ok(server) => break Ok((addr, server)),
            Err(crate::proxy::l4::ProxyError::BackendConnectTimeout { .. }) => {
                pool.record_failure(addr);
                attempts += 1;
                metrics::counter!(
                    "kntx_connect_retries_total",
                    "pool" => pool_name.clone(),
                    "listener" => listener_label.to_string(),
                )
                .increment(1);
                last_status = 504;
                if attempts >= max_retries {
                    break Err(504u16);
                }
            }
            Err(_) => {
                pool.record_failure(addr);
                attempts += 1;
                metrics::counter!(
                    "kntx_connect_retries_total",
                    "pool" => pool_name.clone(),
                    "listener" => listener_label.to_string(),
                )
                .increment(1);
                last_status = 502;
                if attempts >= max_retries {
                    break Err(502u16);
                }
            }
        }
    };

    let (backend_addr, server) = match server_result {
        Ok(pair) => pair,
        Err(status) => {
            let resp = synthesize_error(status, accept_ref, &error_pages);
            let _ = client_wr.write_all(&resp).await;
            emit_and_count(
                &access_log,
                &listener_label,
                &client_ip,
                &method,
                &req.headers,
                &path,
                &pool_name,
                None,
                last_status,
                0,
                0,
                start,
                None,
                Some(request_id.clone()),
            );
            return Ok(());
        }
    };

    let (server_rd_raw, mut server_wr) = tokio::io::split(server);
    let mut server_rd = tokio::io::BufReader::with_capacity(8192, server_rd_raw);

    // build rewritten request head
    let (skip, additions) =
        build_request_additions(&req.headers, &client_ip, is_tls, version, &request_id);

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
    bump(&last_activity);

    if let Err(e) = server_wr.write_all(&req_head_buf).await {
        tracing::debug!(error = %e, "failed to write request head to backend");
        let resp = synthesize_error(502, accept_ref, &error_pages);
        let _ = client_wr.write_all(&resp).await;
        pool.record_failure(backend_addr);
        emit_and_count(
            &access_log,
            &listener_label,
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
            Some(request_id),
        );
        return Ok(());
    }
    bump(&last_activity);

    // stream request body
    let scratch = &mut *buf_guard;
    let mut bytes_in: u64 = 0;
    enum BodyAbort {
        BackendIo, // backend write failed → 502
        Malformed, // chunked framing parse error → 400
    }
    let mut body_abort: Option<BodyAbort> = None;
    match &framing {
        BodyFraming::None => {}
        BodyFraming::ContentLength(n) => {
            let mut remaining = *n;
            while remaining > 0 {
                let to_read = remaining.min(scratch.len() as u64) as usize;
                match client_rd.read(&mut scratch[..to_read]).await {
                    Ok(0) => break,
                    Ok(n) => {
                        bump(&last_activity);
                        if server_wr.write_all(&scratch[..n]).await.is_err() {
                            pool.record_failure(backend_addr);
                            body_abort = Some(BodyAbort::BackendIo);
                            break;
                        }
                        bump(&last_activity);
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
                match cr.pump_once(&mut client_rd, &mut server_wr, scratch).await {
                    Ok(n) => {
                        bump(&last_activity);
                        bytes_in += n as u64;
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

    // body forwarding aborted before backend could finish reading the request:
    // synthesize an error to the client and return rather than waiting on a
    // response that will never come.
    if let Some(reason) = body_abort {
        let (status, kind_label) = match reason {
            BodyAbort::Malformed => (400u16, "malformed"),
            BodyAbort::BackendIo => (502u16, "backend_io"),
        };
        metrics::counter!(
            "kntx_http_body_parse_errors_total",
            "listener" => listener_label.to_string(),
            "kind" => kind_label,
        )
        .increment(1);
        let resp = synthesize_error(status, accept_ref, &error_pages);
        let _ = client_wr.write_all(&resp).await;
        emit_and_count(
            &access_log,
            &listener_label,
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
        );
        return Ok(());
    }

    // read backend response head (loop for 1xx interim responses)
    let mut resp_head_buf: Vec<u8> = Vec::with_capacity(8192);
    #[allow(unused_assignments)]
    let mut backend_wait_ms: Option<f64> = None;
    #[allow(unused_assignments)]
    let mut final_status = 0u16;
    let mut bytes_out: u64 = 0;
    #[allow(unused_assignments)]
    let mut backend_ok = false;

    'response: loop {
        let head_result = read_head(
            &mut server_rd,
            &mut resp_head_buf,
            header_limit,
            &last_activity,
        )
        .await;
        match head_result {
            HeadReadResult::Eof | HeadReadResult::TooLarge | HeadReadResult::IoError(_) => {
                tracing::debug!("backend EOF or error reading response head");
                pool.record_failure(backend_addr);
                let resp = synthesize_error(502, accept_ref, &error_pages);
                let _ = client_wr.write_all(&resp).await;
                emit_and_count(
                    &access_log,
                    &listener_label,
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
                );
                return Ok(());
            }
            HeadReadResult::Complete => {}
        }

        let resp = match parse_response(&resp_head_buf, 128) {
            Ok(ParseOutcome::Complete(r)) => r,
            _ => {
                pool.record_failure(backend_addr);
                let err_resp = synthesize_error(502, accept_ref, &error_pages);
                let _ = client_wr.write_all(&err_resp).await;
                emit_and_count(
                    &access_log,
                    &listener_label,
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
                );
                return Ok(());
            }
        };

        final_status = resp.status;

        if resp.status < 200 {
            // 1xx interim: relay verbatim to client, read next response
            bump(&last_activity);
            let _ = client_wr.write_all(&resp_head_buf[..resp.head_len]).await;
            bump(&last_activity);
            resp_head_buf.drain(..resp.head_len);
            continue 'response;
        }

        backend_wait_ms = Some(backend_wait_start.elapsed().as_secs_f64() * 1000.0);

        let resp_version = resp.version;
        let (resp_skip, resp_additions) = build_response_additions(&resp.headers, resp_version);
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
        bump(&last_activity);
        if client_wr.write_all(&resp_head_out).await.is_err() {
            pool.record_failure(backend_addr);
            return Ok(());
        }
        bump(&last_activity);

        // stream response body
        let resp_framing = classify_response_body(&resp, &method);
        let mut body_backend_error = false;
        match resp_framing {
            BodyFraming::None => {}
            BodyFraming::ContentLength(n) => {
                let mut remaining = n;
                while remaining > 0 {
                    let to_read = remaining.min(scratch.len() as u64) as usize;
                    match server_rd.read(&mut scratch[..to_read]).await {
                        Ok(0) => break,
                        Ok(n) => {
                            bump(&last_activity);
                            if client_wr.write_all(&scratch[..n]).await.is_err() {
                                break; // client-side error, don't record
                            }
                            bump(&last_activity);
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
                    match cr.pump_once(&mut server_rd, &mut client_wr, scratch).await {
                        Ok(n) => {
                            bump(&last_activity);
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
                match server_rd.read(scratch).await {
                    Ok(0) => break,
                    Ok(n) => {
                        bump(&last_activity);
                        if client_wr.write_all(&scratch[..n]).await.is_err() {
                            break; // client-side error, don't record
                        }
                        bump(&last_activity);
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
        }
        backend_ok = true;
        break 'response;
    }

    let _ = client_wr.shutdown().await;

    let _ = backend_ok; // used indirectly via pool.record_{success,failure}

    emit_and_count(
        &access_log,
        &listener_label,
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
    );

    Ok(())
}

// ── head reading ──────────────────────────────────────────────────────────────

enum HeadReadResult {
    Complete,
    Eof,
    TooLarge,
    IoError(std::io::Error),
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
            Err(e) => return HeadReadResult::IoError(e),
        };
        if avail.is_empty() {
            if buf.is_empty() {
                return HeadReadResult::Eof;
            }
            // partial head on EOF — caller treats as malformed
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

// ── access log helpers ────────────────────────────────────────────────────────

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
        keepalive_index: 0,
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
        route_id: None,
        request_id: req_id,
        trace_id,
        keepalive_index: 0,
    });

    metrics::counter!(
        "kntx_http_requests_total",
        "method" => method.to_owned(),
        "status" => status.to_string(),
        "pool" => pool.to_owned(),
        "listener" => listener.to_owned(),
    )
    .increment(1);
    metrics::histogram!(
        "kntx_http_request_duration_seconds",
        "pool" => pool.to_owned(),
        "listener" => listener.to_owned(),
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
