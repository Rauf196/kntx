//! Minimal HTTP/1.x client that holds one TCP connection open across multiple
//! sequential requests - the instrument for exercising the proxy's client
//! keep-alive loop. Deliberately hand-rolled: a forgiving client (reqwest or
//! hyper) would paper over the framing bugs these tests are meant to catch.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct ParsedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ParsedResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// case-insensitive token membership in any `Connection` header.
    pub fn connection_has(&self, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
            .flat_map(|(_, v)| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }

    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or("")
    }
}

/// A persistent client connection. `request` reuses the same socket; the proxy
/// decides keep-alive vs close. `close` (or drop) ends the connection.
pub struct KeepAliveClient {
    stream: TcpStream,
    /// bytes already pulled off the socket that belong to the NEXT response
    /// (over-read past one response's framed end).
    spill: Vec<u8>,
}

impl KeepAliveClient {
    pub async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect proxy");
        Self {
            stream,
            spill: Vec::new(),
        }
    }

    /// Send a raw request and read the next final response off the same conn.
    /// Interim 1xx responses (e.g. 100 Continue) are silently consumed and the
    /// final ≥200 response is returned. Whether the response carries a body is
    /// inferred from the method on the wire (HEAD → bodyless regardless of
    /// headers, per RFC 7230 §3.3.3) plus the standard status-code rules.
    pub async fn request(&mut self, raw: &[u8]) -> std::io::Result<ParsedResponse> {
        self.stream.write_all(raw).await?;
        let method_is_head = raw
            .iter()
            .position(|&b| b == b' ')
            .map(|p| raw[..p].eq_ignore_ascii_case(b"HEAD"))
            .unwrap_or(false);
        loop {
            let resp = self.read_one_response(method_is_head).await?;
            if !(100..200).contains(&resp.status) {
                return Ok(resp);
            }
        }
    }

    /// Send a request without reading the response (for half-close / timing tests).
    pub async fn send_only(&mut self, raw: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(raw).await
    }

    /// Half-close the write side (FIN) - signals "client done sending".
    pub async fn shutdown_write(&mut self) -> std::io::Result<()> {
        self.stream.shutdown().await
    }

    /// Read until EOF; returns total bytes seen. Used to assert the proxy
    /// closed the conn (e.g. after `Connection: close` or idle timeout).
    pub async fn read_to_eof(&mut self) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.spill);
        let mut tmp = [0u8; 4096];
        loop {
            match self.stream.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&tmp[..n]),
            }
        }
        out
    }

    async fn fill(&mut self) -> std::io::Result<()> {
        let mut tmp = [0u8; 4096];
        let n = self.stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed mid-response",
            ));
        }
        self.spill.extend_from_slice(&tmp[..n]);
        Ok(())
    }

    async fn read_one_response(
        &mut self,
        request_was_head: bool,
    ) -> std::io::Result<ParsedResponse> {
        // 1. accumulate until end of head
        let head_end = loop {
            if let Some(p) = find_subslice(&self.spill, b"\r\n\r\n") {
                break p + 4;
            }
            self.fill().await?;
        };
        let head = self.spill[..head_end].to_vec();
        let (status, headers) = parse_head(&head);

        // 2. determine body framing
        let cl = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.trim().parse::<usize>().ok());
        let chunked = headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
        });
        // 204/304 and 1xx carry no body regardless of headers; a response to
        // HEAD is also always bodyless per RFC 7230 §3.3.3.
        let bodyless =
            status == 204 || status == 304 || (100..200).contains(&status) || request_was_head;

        let body_start = head_end;
        let body: Vec<u8> = if bodyless {
            Vec::new()
        } else if let Some(len) = cl {
            while self.spill.len() < body_start + len {
                self.fill().await?;
            }
            self.spill[body_start..body_start + len].to_vec()
        } else if chunked {
            let end = loop {
                if let Some(p) = find_subslice(&self.spill[body_start..], b"0\r\n\r\n") {
                    break body_start + p + 5;
                }
                self.fill().await?;
            };
            decode_chunked(&self.spill[body_start..end])
        } else {
            // no CL, no chunked: connection-delimited - read to EOF.
            let mut tmp = [0u8; 4096];
            loop {
                match self.stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => self.spill.extend_from_slice(&tmp[..n]),
                }
            }
            self.spill[body_start..].to_vec()
        };

        let consumed = if bodyless || cl.is_some() || !chunked {
            body_start + body.len()
        } else {
            // chunked: recompute consumed from the raw terminator scan
            body_start
                + find_subslice(&self.spill[body_start..], b"0\r\n\r\n")
                    .map(|p| p + 5)
                    .unwrap_or(0)
        };
        // retain any over-read bytes for the next response
        self.spill.drain(..consumed.min(self.spill.len()));

        Ok(ParsedResponse {
            status,
            headers,
            body,
        })
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_head(head: &[u8]) -> (u16, Vec<(String, String)>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            headers.push((
                line[..colon].trim().to_string(),
                line[colon + 1..].trim().to_string(),
            ));
        }
    }
    (status, headers)
}

fn decode_chunked(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let line_end = match find_subslice(&raw[i..], b"\r\n") {
            Some(p) => i + p,
            None => break,
        };
        let size_str = std::str::from_utf8(&raw[i..line_end]).unwrap_or("0");
        let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
        i = line_end + 2;
        if size == 0 {
            break;
        }
        if i + size > raw.len() {
            break;
        }
        out.extend_from_slice(&raw[i..i + size]);
        i += size + 2; // skip chunk data + trailing CRLF
    }
    out
}
