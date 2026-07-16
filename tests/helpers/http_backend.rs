#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[derive(Debug, Clone)]
pub struct BackendRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl BackendRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone)]
pub struct ResponseSpec {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub chunked: bool,
    pub extra_headers: Vec<(&'static str, String)>,
}

impl ResponseSpec {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type: "text/plain",
            body: body.into(),
            chunked: false,
            extra_headers: vec![],
        }
    }

    pub fn json(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type: "application/json",
            body: body.into(),
            chunked: false,
            extra_headers: vec![],
        }
    }

    pub fn with_status(mut self, status: u16, reason: &'static str) -> Self {
        self.status = status;
        self.reason = reason;
        self
    }

    pub fn chunked_encoding(mut self) -> Self {
        self.chunked = true;
        self
    }

    pub fn with_header(mut self, name: &'static str, value: String) -> Self {
        self.extra_headers.push((name, value));
        self
    }
}

/// per-connection lifecycle. `Close` shuts down after one response (default
/// for legacy tests). `KeepAlive` loops reading requests on the same conn until
/// either side closes or a response is emitted with `Connection: close`.
/// `KeepAliveThenClose(n)` is the dead-conn-recovery shape: serve n responses
/// then shutdown the stream without advertising `Connection: close`, so the
/// proxy returns the conn to its cache and only discovers it's dead on the
/// next checkout probe.
#[derive(Clone, Copy)]
pub enum ConnMode {
    Close,
    KeepAlive,
    KeepAliveThenClose(usize),
}

pub struct HttpBackend {
    pub addr: SocketAddr,
    last_request: Arc<Mutex<Option<BackendRequest>>>,
    accept_count: Arc<AtomicU64>,
    _shutdown: oneshot::Sender<()>,
}

impl HttpBackend {
    pub async fn start(response: ResponseSpec) -> Self {
        let response = Arc::new(response);
        let handler = Arc::new(move |_req: BackendRequest| (*response).clone());
        Self::start_inner(handler, ConnMode::Close).await
    }

    pub async fn start_with_handler<F>(handler: Arc<F>) -> Self
    where
        F: Fn(BackendRequest) -> ResponseSpec + Send + Sync + 'static,
    {
        Self::start_inner(handler, ConnMode::Close).await
    }

    /// Backend that holds each accepted conn open across multiple sequential
    /// requests. The proxy's keep-alive cache is exercised against this mode.
    pub async fn start_keepalive(response: ResponseSpec) -> Self {
        let response = Arc::new(response);
        let handler = Arc::new(move |_req: BackendRequest| (*response).clone());
        Self::start_inner(handler, ConnMode::KeepAlive).await
    }

    pub async fn start_keepalive_with_handler<F>(handler: Arc<F>) -> Self
    where
        F: Fn(BackendRequest) -> ResponseSpec + Send + Sync + 'static,
    {
        Self::start_inner(handler, ConnMode::KeepAlive).await
    }

    /// Serves the response, then shuts the conn down without an explicit
    /// `Connection: close` header. The proxy caches the conn and only sees
    /// it's dead on the next checkout.
    pub async fn start_keepalive_then_die(response: ResponseSpec, n: usize) -> Self {
        let response = Arc::new(response);
        let handler = Arc::new(move |_req: BackendRequest| (*response).clone());
        Self::start_inner(handler, ConnMode::KeepAliveThenClose(n)).await
    }

    async fn start_inner<F>(handler: Arc<F>, mode: ConnMode) -> Self
    where
        F: Fn(BackendRequest) -> ResponseSpec + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let last_request: Arc<Mutex<Option<BackendRequest>>> = Arc::new(Mutex::new(None));
        let accept_count = Arc::new(AtomicU64::new(0));
        let last_req_outer = Arc::clone(&last_request);
        let accept_count_outer = Arc::clone(&accept_count);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        if let Ok((stream, _)) = accept {
                            accept_count_outer.fetch_add(1, Ordering::Relaxed);
                            let handler = Arc::clone(&handler);
                            let last_req = Arc::clone(&last_req_outer);
                            tokio::spawn(serve_conn(stream, handler, last_req, mode));
                        }
                    }
                    _ = &mut shutdown_rx => return,
                }
            }
        });

        Self {
            addr,
            last_request,
            accept_count,
            _shutdown: shutdown_tx,
        }
    }

    pub fn last_request(&self) -> Option<BackendRequest> {
        self.last_request.lock().unwrap().clone()
    }

    pub fn accept_count(&self) -> u64 {
        self.accept_count.load(Ordering::Relaxed)
    }
}

async fn serve_conn<F>(
    mut stream: tokio::net::TcpStream,
    handler: Arc<F>,
    last_req: Arc<Mutex<Option<BackendRequest>>>,
    mode: ConnMode,
) where
    F: Fn(BackendRequest) -> ResponseSpec + Send + Sync + 'static,
{
    // bytes already pulled off the socket belonging to the NEXT request after
    // a keep-alive iteration completes.
    let mut spill: Vec<u8> = Vec::new();
    let mut served: usize = 0;

    loop {
        let mut buf = vec![0u8; 65536];
        let initial = spill.len().min(buf.len());
        buf[..initial].copy_from_slice(&spill[..initial]);
        spill.drain(..initial);
        let mut total = initial;

        let head_end = loop {
            if let Some(pos) = find_crlfcrlf(&buf[..total]) {
                break pos;
            }
            if total >= buf.len() {
                return;
            }
            match stream.read(&mut buf[total..]).await {
                Ok(0) | Err(_) => return,
                Ok(n) => total += n,
            }
        };

        let parsed = match parse_head(&buf[..head_end]) {
            Some(p) => p,
            None => return,
        };

        let is_chunked = parsed.headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
        });
        let inbound_close = parsed.headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("connection")
                && v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"))
        });

        let (body, body_end) = if is_chunked {
            let mut raw = buf[head_end..total].to_vec();
            let mut body_consumed = head_end;
            loop {
                if let Some(p) = find_chunked_end(&raw) {
                    let consumed_in_buf = head_end + p;
                    if consumed_in_buf <= total {
                        body_consumed = consumed_in_buf;
                    }
                    break;
                }
                let mut tmp = [0u8; 4096];
                match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&tmp[..n]),
                }
            }
            (decode_chunked_body(&raw), body_consumed)
        } else {
            let cl = parsed
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse::<usize>().ok())
                .unwrap_or(0);
            let mut body: Vec<u8> = buf[head_end..total].to_vec();
            while body.len() < cl {
                let need = cl - body.len();
                let mut tmp = vec![0u8; need.min(4096)];
                match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                }
            }
            // if we over-read into the next request, retain it for the next loop iteration
            if body.len() > cl {
                spill.extend_from_slice(&body[cl..]);
                body.truncate(cl);
            }
            (body, head_end + cl)
        };

        // re-collect any post-body over-read bytes for the next iteration
        if total > body_end {
            spill.splice(0..0, buf[body_end..total].iter().copied());
        }

        let req = BackendRequest {
            method: parsed.method,
            path: parsed.path,
            headers: parsed.headers,
            body,
        };
        if let Ok(mut guard) = last_req.lock() {
            *guard = Some(req.clone());
        }

        let spec = handler(req);
        let resp_close = spec.extra_headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("connection")
                && v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"))
        });

        let resp_bytes = serialize_response(&spec);
        if stream.write_all(&resp_bytes).await.is_err() {
            return;
        }

        served += 1;

        match mode {
            ConnMode::Close => {
                let _ = stream.shutdown().await;
                return;
            }
            ConnMode::KeepAlive => {
                if resp_close || inbound_close {
                    let _ = stream.shutdown().await;
                    return;
                }
            }
            ConnMode::KeepAliveThenClose(n) => {
                if served >= n || resp_close || inbound_close {
                    let _ = stream.shutdown().await;
                    return;
                }
            }
        }
    }
}

fn find_chunked_end(raw: &[u8]) -> Option<usize> {
    // crude: locate the final "0\r\n" chunk and a trailing CRLF (or trailer block + CRLF).
    let zero_chunk = raw.windows(3).position(|w| w == b"0\r\n")?;
    let after_zero = zero_chunk + 3;
    if let Some(rel) = raw[after_zero..].windows(2).position(|w| w == b"\r\n") {
        return Some(after_zero + rel + 2);
    }
    None
}

struct ParsedHead {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_head(head: &[u8]) -> Option<ParsedHead> {
    let s = std::str::from_utf8(head).ok()?;
    let mut lines = s.split("\r\n");
    let req_line = lines.next()?;
    let mut parts = req_line.splitn(3, ' ');
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            headers.push((
                line[..colon].trim().to_owned(),
                line[colon + 1..].trim().to_owned(),
            ));
        }
    }

    Some(ParsedHead {
        method,
        path,
        headers,
    })
}

fn decode_chunked_body(data: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        // find CRLF ending the chunk-size line
        let Some(crlf) = data[pos..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = &data[pos..pos + crlf];
        // strip chunk extensions
        let size_str = size_line.split(|&b| b == b';').next().unwrap_or(b"");
        let size = usize::from_str_radix(std::str::from_utf8(size_str).unwrap_or("0").trim(), 16)
            .unwrap_or(0);
        pos += crlf + 2;
        if size == 0 {
            break;
        }
        let end = pos + size;
        if end <= data.len() {
            decoded.extend_from_slice(&data[pos..end]);
            pos = end + 2; // skip trailing CRLF
        } else {
            decoded.extend_from_slice(&data[pos..]);
            break;
        }
    }
    decoded
}

fn serialize_response(spec: &ResponseSpec) -> Vec<u8> {
    let mut out = Vec::new();

    if spec.chunked {
        let chunk_header = format!("{:x}\r\n", spec.body.len());
        out.extend_from_slice(
            format!(
                "HTTP/1.1 {} {}\r\nTransfer-Encoding: chunked\r\nContent-Type: {}\r\n",
                spec.status, spec.reason, spec.content_type
            )
            .as_bytes(),
        );
        for (name, value) in &spec.extra_headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(chunk_header.as_bytes());
        out.extend_from_slice(&spec.body);
        out.extend_from_slice(b"\r\n0\r\n\r\n");
    } else {
        out.extend_from_slice(
            format!(
                "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n",
                spec.status,
                spec.reason,
                spec.body.len(),
                spec.content_type
            )
            .as_bytes(),
        );
        for (name, value) in &spec.extra_headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&spec.body);
    }

    out
}
