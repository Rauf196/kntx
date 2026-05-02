use std::io;

use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::parse::{HttpVersion, ParsedHeader, Request, Response};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyFraming {
    None,
    ContentLength(u64),
    Chunked,
    /// response only: read until backend EOF
    CloseDelimited,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SmugglingError {
    #[error("both Content-Length and Transfer-Encoding present")]
    BothCLAndTE,
    #[error("multiple Content-Length headers")]
    MultipleCL,
    #[error("multiple Transfer-Encoding headers")]
    MultipleTE,
    #[error("unsupported Transfer-Encoding (only 'chunked' is allowed)")]
    UnsupportedTE,
    #[error("obsolete line folding in header value")]
    ObsFold,
    #[error("HTTP/1.1 request missing Host header")]
    MissingHost,
    #[error("duplicate Host header")]
    DuplicateHost,
    #[error("malformed Content-Length value")]
    MalformedCL,
}

impl SmugglingError {
    pub fn reason_label(&self) -> &'static str {
        match self {
            Self::BothCLAndTE => "both_cl_te",
            Self::MultipleCL => "multiple_cl",
            Self::MultipleTE => "multiple_te",
            Self::UnsupportedTE => "unsupported_te",
            Self::ObsFold => "obs_fold",
            Self::MissingHost => "missing_host",
            Self::DuplicateHost => "duplicate_host",
            Self::MalformedCL => "malformed_cl",
        }
    }
}

fn header_str(headers: &[ParsedHeader], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| h.value_str())
        .map(|s| s.to_owned())
}

fn header_count(headers: &[ParsedHeader], name: &str) -> usize {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .count()
}

fn is_valid_cl_format(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s == "0" {
        return true;
    }
    if s.starts_with('0') {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_digit())
}

/// classify request body framing and enforce request-smuggling defenses.
pub fn classify_request_body(req: &Request) -> Result<BodyFraming, SmugglingError> {
    // 1. obs-fold detection: header value containing \r\n followed by SP/HT
    for header in &req.headers {
        for window in header.value.windows(3) {
            if window[0] == b'\r' && window[1] == b'\n' && (window[2] == b' ' || window[2] == b'\t')
            {
                return Err(SmugglingError::ObsFold);
            }
        }
    }

    // 2. Host count
    let host_count = header_count(&req.headers, "host");
    if req.version == HttpVersion::Http11 && host_count == 0 {
        return Err(SmugglingError::MissingHost);
    }
    if host_count > 1 {
        return Err(SmugglingError::DuplicateHost);
    }

    // 3. Content-Length count
    let cl_count = header_count(&req.headers, "content-length");
    if cl_count > 1 {
        return Err(SmugglingError::MultipleCL);
    }

    // 4. Transfer-Encoding count — multiple TE headers have the same smuggling
    // risk as multiple CL headers: different backends parse differently.
    let te_count = header_count(&req.headers, "transfer-encoding");
    if te_count > 1 {
        return Err(SmugglingError::MultipleTE);
    }

    // 5. CL + TE
    let has_te = te_count > 0;
    if cl_count > 0 && has_te {
        return Err(SmugglingError::BothCLAndTE);
    }

    // 6. TE value validation: must be exactly "chunked" (case-insensitive per RFC 7230)
    if has_te {
        let te_val = header_str(&req.headers, "transfer-encoding").unwrap_or_default();
        let tokens: Vec<String> = te_val
            .split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .collect();
        if tokens.len() != 1 || tokens[0] != "chunked" {
            return Err(SmugglingError::UnsupportedTE);
        }
        return Ok(BodyFraming::Chunked);
    }

    // 7. Content-Length framing — reject leading zeros (octal ambiguity in legacy parsers)
    if let Some(cl_val) = header_str(&req.headers, "content-length") {
        let trimmed = cl_val.trim();
        if !is_valid_cl_format(trimmed) {
            return Err(SmugglingError::MalformedCL);
        }
        let n: u64 = trimmed.parse().map_err(|_| SmugglingError::MalformedCL)?;
        return Ok(BodyFraming::ContentLength(n));
    }

    Ok(BodyFraming::None)
}

/// classify response body framing.
pub fn classify_response_body(resp: &Response, request_method: &str) -> BodyFraming {
    if request_method.eq_ignore_ascii_case("HEAD") {
        return BodyFraming::None;
    }
    if (100..200).contains(&resp.status) || resp.status == 204 || resp.status == 304 {
        return BodyFraming::None;
    }
    if resp.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && h.value_str()
                .map(|v| v.trim().eq_ignore_ascii_case("chunked"))
                .unwrap_or(false)
    }) {
        return BodyFraming::Chunked;
    }
    if let Some(cl) =
        header_str(&resp.headers, "content-length").and_then(|v| v.trim().parse::<u64>().ok())
    {
        return BodyFraming::ContentLength(cl);
    }
    BodyFraming::CloseDelimited
}

#[derive(Debug)]
enum ChunkedState {
    ChunkSize,
    ChunkData,
    Trailers,
    Done,
}

/// pass-through chunked body reader: forwards raw bytes (including framing) verbatim.
pub struct ChunkedReader {
    state: ChunkedState,
    remaining_in_chunk: u64,
    line_buf: Vec<u8>,
}

impl Default for ChunkedReader {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedReader {
    pub fn new() -> Self {
        Self {
            state: ChunkedState::ChunkSize,
            remaining_in_chunk: 0,
            line_buf: Vec::new(),
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, ChunkedState::Done)
    }

    pub async fn pump_once<R, W>(
        &mut self,
        src: &mut R,
        dst: &mut W,
        scratch: &mut [u8],
    ) -> io::Result<usize>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        match self.state {
            ChunkedState::Done => Ok(0),

            ChunkedState::ChunkSize => {
                read_line(src, &mut self.line_buf).await?;
                if self.line_buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "empty chunk-size line",
                    ));
                }
                dst.write_all(&self.line_buf).await?;

                let size_str = std::str::from_utf8(&self.line_buf).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "non-utf8 chunk size")
                })?;
                let size_str = size_str
                    .trim_end_matches(['\r', '\n'])
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim();
                let chunk_size = u64::from_str_radix(size_str, 16).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size")
                })?;

                if chunk_size == 0 {
                    self.state = ChunkedState::Trailers;
                } else {
                    self.remaining_in_chunk = chunk_size + 2; // +2 for trailing \r\n
                    self.state = ChunkedState::ChunkData;
                }
                Ok(self.line_buf.len())
            }

            ChunkedState::ChunkData => {
                let to_read = (self.remaining_in_chunk as usize).min(scratch.len());
                let n = src.read(&mut scratch[..to_read]).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "eof in chunk data",
                    ));
                }
                dst.write_all(&scratch[..n]).await?;
                self.remaining_in_chunk -= n as u64;
                if self.remaining_in_chunk == 0 {
                    self.state = ChunkedState::ChunkSize;
                }
                Ok(n)
            }

            ChunkedState::Trailers => {
                read_line(src, &mut self.line_buf).await?;
                dst.write_all(&self.line_buf).await?;
                let is_end = self.line_buf.trim_ascii().is_empty();
                if is_end {
                    self.state = ChunkedState::Done;
                }
                Ok(self.line_buf.len())
            }
        }
    }
}

/// read until \n (inclusive) using the BufReader's buffering.
async fn read_line<R>(src: &mut R, line: &mut Vec<u8>) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
{
    line.clear();
    let n = src.read_until(b'\n', line).await?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof mid-line"));
    }
    if !line.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no newline before eof",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::l7::parse::ParsedHeader;

    fn h(name: &str, value: &[u8]) -> ParsedHeader {
        ParsedHeader {
            name: name.to_owned(),
            value: value.to_vec(),
        }
    }

    fn req(method: &str, version: HttpVersion, headers: Vec<ParsedHeader>) -> Request {
        Request {
            method: method.to_owned(),
            path: "/".to_owned(),
            version,
            headers,
            head_len: 0,
        }
    }

    fn resp(status: u16, version: HttpVersion, headers: Vec<ParsedHeader>) -> Response {
        Response {
            version,
            status,
            reason: "OK".to_owned(),
            headers,
            head_len: 0,
        }
    }

    #[test]
    fn classify_get_no_body() {
        let r = req("GET", HttpVersion::Http11, vec![h("Host", b"example.com")]);
        assert_eq!(classify_request_body(&r).unwrap(), BodyFraming::None);
    }

    #[test]
    fn classify_post_content_length() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![h("Host", b"example.com"), h("Content-Length", b"42")],
        );
        assert_eq!(
            classify_request_body(&r).unwrap(),
            BodyFraming::ContentLength(42)
        );
    }

    #[test]
    fn classify_post_chunked() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![
                h("Host", b"example.com"),
                h("Transfer-Encoding", b"chunked"),
            ],
        );
        assert_eq!(classify_request_body(&r).unwrap(), BodyFraming::Chunked);
    }

    #[test]
    fn reject_cl_plus_te() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![
                h("Host", b"example.com"),
                h("Content-Length", b"10"),
                h("Transfer-Encoding", b"chunked"),
            ],
        );
        assert_eq!(classify_request_body(&r), Err(SmugglingError::BothCLAndTE));
    }

    #[test]
    fn reject_multiple_cl_matching_values() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![
                h("Host", b"example.com"),
                h("Content-Length", b"10"),
                h("Content-Length", b"10"),
            ],
        );
        assert_eq!(classify_request_body(&r), Err(SmugglingError::MultipleCL));
    }

    #[test]
    fn reject_multiple_cl_diverging_values() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![
                h("Host", b"example.com"),
                h("Content-Length", b"10"),
                h("Content-Length", b"11"),
            ],
        );
        assert_eq!(classify_request_body(&r), Err(SmugglingError::MultipleCL));
    }

    #[test]
    fn reject_te_gzip() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![h("Host", b"example.com"), h("Transfer-Encoding", b"gzip")],
        );
        assert_eq!(
            classify_request_body(&r),
            Err(SmugglingError::UnsupportedTE)
        );
    }

    #[test]
    fn reject_te_chunked_gzip() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![
                h("Host", b"example.com"),
                h("Transfer-Encoding", b"chunked, gzip"),
            ],
        );
        assert_eq!(
            classify_request_body(&r),
            Err(SmugglingError::UnsupportedTE)
        );
    }

    #[test]
    fn reject_obs_fold() {
        let r = req(
            "GET",
            HttpVersion::Http11,
            vec![h("Host", b"example.com"), h("X-Foo", b"val\r\n continued")],
        );
        assert_eq!(classify_request_body(&r), Err(SmugglingError::ObsFold));
    }

    #[test]
    fn reject_missing_host_http_1_1() {
        let r = req("GET", HttpVersion::Http11, vec![]);
        assert_eq!(classify_request_body(&r), Err(SmugglingError::MissingHost));
    }

    #[test]
    fn accept_missing_host_http_1_0() {
        let r = req("GET", HttpVersion::Http10, vec![]);
        assert_eq!(classify_request_body(&r).unwrap(), BodyFraming::None);
    }

    #[test]
    fn reject_duplicate_host() {
        let r = req(
            "GET",
            HttpVersion::Http11,
            vec![h("Host", b"example.com"), h("Host", b"other.com")],
        );
        assert_eq!(
            classify_request_body(&r),
            Err(SmugglingError::DuplicateHost)
        );
    }

    #[test]
    fn reject_malformed_cl() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![h("Host", b"example.com"), h("Content-Length", b"abc")],
        );
        assert_eq!(classify_request_body(&r), Err(SmugglingError::MalformedCL));
    }

    #[test]
    fn accept_te_chunked_mixed_case() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![
                h("Host", b"example.com"),
                h("Transfer-Encoding", b"Chunked"),
            ],
        );
        assert_eq!(classify_request_body(&r).unwrap(), BodyFraming::Chunked);
    }

    #[test]
    fn accept_te_chunked_uppercase() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![
                h("Host", b"example.com"),
                h("Transfer-Encoding", b"CHUNKED"),
            ],
        );
        assert_eq!(classify_request_body(&r).unwrap(), BodyFraming::Chunked);
    }

    #[test]
    fn reject_multi_te() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![
                h("Host", b"example.com"),
                h("Transfer-Encoding", b"chunked"),
                h("Transfer-Encoding", b"identity"),
            ],
        );
        assert_eq!(classify_request_body(&r), Err(SmugglingError::MultipleTE));
    }

    #[test]
    fn reject_multi_te_both_chunked() {
        // even if both values are "chunked", multi-TE is ambiguous framing
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![
                h("Host", b"example.com"),
                h("Transfer-Encoding", b"chunked"),
                h("Transfer-Encoding", b"chunked"),
            ],
        );
        assert_eq!(classify_request_body(&r), Err(SmugglingError::MultipleTE));
    }

    #[test]
    fn reject_leading_zero_cl() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![h("Host", b"example.com"), h("Content-Length", b"010")],
        );
        assert_eq!(classify_request_body(&r), Err(SmugglingError::MalformedCL));
    }

    #[test]
    fn reject_leading_zero_cl_long() {
        let r = req(
            "POST",
            HttpVersion::Http11,
            vec![h("Host", b"example.com"), h("Content-Length", b"00100")],
        );
        assert_eq!(classify_request_body(&r), Err(SmugglingError::MalformedCL));
    }

    #[test]
    fn accept_cl_zero() {
        let r = req(
            "GET",
            HttpVersion::Http11,
            vec![h("Host", b"example.com"), h("Content-Length", b"0")],
        );
        assert_eq!(
            classify_request_body(&r).unwrap(),
            BodyFraming::ContentLength(0),
        );
    }

    #[tokio::test]
    async fn chunked_reader_forwards_bytes_unchanged() {
        let input = b"5\r\nhello\r\n0\r\n\r\n";
        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(input as &[u8]));
        let mut output = Vec::new();
        let mut cr = ChunkedReader::new();
        let mut scratch = vec![0u8; 256];
        while !cr.is_done() {
            cr.pump_once(&mut reader, &mut output, &mut scratch)
                .await
                .unwrap();
        }
        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn chunked_reader_handles_extensions() {
        let input = b"5;name=val\r\nhello\r\n0\r\n\r\n";
        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(input as &[u8]));
        let mut output = Vec::new();
        let mut cr = ChunkedReader::new();
        let mut scratch = vec![0u8; 256];
        while !cr.is_done() {
            cr.pump_once(&mut reader, &mut output, &mut scratch)
                .await
                .unwrap();
        }
        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn chunked_reader_forwards_trailers() {
        let input = b"5\r\nhello\r\n0\r\nX-Trailer: val\r\n\r\n";
        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(input as &[u8]));
        let mut output = Vec::new();
        let mut cr = ChunkedReader::new();
        let mut scratch = vec![0u8; 256];
        while !cr.is_done() {
            cr.pump_once(&mut reader, &mut output, &mut scratch)
                .await
                .unwrap();
        }
        assert_eq!(output, input);
    }

    #[test]
    fn response_classify_head_no_body() {
        let r = resp(200, HttpVersion::Http11, vec![h("Content-Length", b"100")]);
        assert_eq!(classify_response_body(&r, "HEAD"), BodyFraming::None);
    }

    #[test]
    fn response_classify_204_no_body() {
        let r = resp(204, HttpVersion::Http11, vec![]);
        assert_eq!(classify_response_body(&r, "GET"), BodyFraming::None);
    }

    #[test]
    fn response_classify_close_delimited_when_no_cl_te() {
        let r = resp(200, HttpVersion::Http10, vec![h("Server", b"test")]);
        assert_eq!(
            classify_response_body(&r, "GET"),
            BodyFraming::CloseDelimited
        );
    }
}
