use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

/// a single parsed header with owned name and value.
#[derive(Debug, Clone)]
pub struct ParsedHeader {
    pub name: String,
    pub value: Vec<u8>,
}

impl ParsedHeader {
    pub fn value_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }
}

/// parsed HTTP request (owned data — avoids lifetime coupling to the read buffer).
#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub version: HttpVersion,
    pub headers: Vec<ParsedHeader>,
    pub head_len: usize,
}

/// parsed HTTP response (owned data).
pub struct Response {
    pub version: HttpVersion,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<ParsedHeader>,
    pub head_len: usize,
}

#[derive(Debug)]
pub enum ParseOutcome<T> {
    Complete(T),
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionKind {
    Http2,
    Http09,
    Other(u8),
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("malformed HTTP request")]
    Malformed,
    #[error("header too large")]
    HeaderTooLarge,
    #[error("unsupported HTTP version")]
    UnsupportedVersion(VersionKind),
}

pub fn parse_request(buf: &[u8], max_headers: usize) -> Result<ParseOutcome<Request>, ParseError> {
    let mut headers = vec![httparse::EMPTY_HEADER; max_headers];
    let mut req = httparse::Request::new(&mut headers);

    match req.parse(buf) {
        Ok(httparse::Status::Partial) => Ok(ParseOutcome::Partial),
        Ok(httparse::Status::Complete(head_len)) => {
            // httparse minor version: 0 = HTTP/1.0, 1 = HTTP/1.1
            let version = match req.version {
                Some(0) => HttpVersion::Http10,
                Some(1) => HttpVersion::Http11,
                Some(v) => return Err(ParseError::UnsupportedVersion(VersionKind::Other(v))),
                None => return Err(ParseError::Malformed),
            };
            let method = req.method.ok_or(ParseError::Malformed)?.to_owned();
            let path = req.path.ok_or(ParseError::Malformed)?.to_owned();
            let headers_out: Vec<ParsedHeader> = req
                .headers
                .iter()
                .take_while(|h| !h.name.is_empty())
                .map(|h| ParsedHeader {
                    name: h.name.to_owned(),
                    value: h.value.to_vec(),
                })
                .collect();

            Ok(ParseOutcome::Complete(Request {
                method,
                path,
                version,
                headers: headers_out,
                head_len,
            }))
        }
        Err(httparse::Error::TooManyHeaders) => Err(ParseError::HeaderTooLarge),
        Err(_) => Err(ParseError::Malformed),
    }
}

pub fn parse_response(
    buf: &[u8],
    max_headers: usize,
) -> Result<ParseOutcome<Response>, ParseError> {
    let mut headers = vec![httparse::EMPTY_HEADER; max_headers];
    let mut resp = httparse::Response::new(&mut headers);

    match resp.parse(buf) {
        Ok(httparse::Status::Partial) => Ok(ParseOutcome::Partial),
        Ok(httparse::Status::Complete(head_len)) => {
            let version = match resp.version {
                Some(0) => HttpVersion::Http10,
                Some(1) => HttpVersion::Http11,
                Some(v) => return Err(ParseError::UnsupportedVersion(VersionKind::Other(v))),
                None => return Err(ParseError::Malformed),
            };
            let status = resp.code.ok_or(ParseError::Malformed)?;
            let reason = resp.reason.unwrap_or("").to_owned();
            let headers_out: Vec<ParsedHeader> = resp
                .headers
                .iter()
                .take_while(|h| !h.name.is_empty())
                .map(|h| ParsedHeader {
                    name: h.name.to_owned(),
                    value: h.value.to_vec(),
                })
                .collect();

            Ok(ParseOutcome::Complete(Response {
                version,
                status,
                reason,
                headers: headers_out,
                head_len,
            }))
        }
        Err(httparse::Error::TooManyHeaders) => Err(ParseError::HeaderTooLarge),
        Err(_) => Err(ParseError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_get() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match parse_request(req, 64).unwrap() {
            ParseOutcome::Complete(r) => {
                assert_eq!(r.method, "GET");
                assert_eq!(r.path, "/");
                assert_eq!(r.version, HttpVersion::Http11);
                assert_eq!(r.head_len, req.len());
            }
            ParseOutcome::Partial => panic!("expected complete"),
        }
    }

    #[test]
    fn parses_post_with_content_length() {
        let req = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        match parse_request(req, 64).unwrap() {
            ParseOutcome::Complete(r) => {
                assert_eq!(r.method, "POST");
                assert_eq!(r.path, "/submit");
                assert_eq!(r.headers.len(), 2);
                assert!(r.head_len < req.len());
            }
            ParseOutcome::Partial => panic!("expected complete"),
        }
    }

    #[test]
    fn partial_request_returns_partial() {
        let req = b"GET / HTTP/1.1\r\nHost: examp";
        assert!(matches!(
            parse_request(req, 64).unwrap(),
            ParseOutcome::Partial
        ));
    }

    #[test]
    fn header_buffer_oversized_errors() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Foo: bar\r\n\r\n";
        let err = parse_request(req, 1).unwrap_err();
        assert!(matches!(err, ParseError::HeaderTooLarge));
    }

    #[test]
    fn http_10_parsed() {
        let req = b"GET / HTTP/1.0\r\n\r\n";
        match parse_request(req, 64).unwrap() {
            ParseOutcome::Complete(r) => assert_eq!(r.version, HttpVersion::Http10),
            ParseOutcome::Partial => panic!("expected complete"),
        }
    }

    #[test]
    fn http_09_marked_unsupported() {
        // HTTP/1.0 maps to Http10 (version=0 in httparse)
        let req = b"GET / HTTP/1.0\r\n\r\n";
        let result = parse_request(req, 64).unwrap();
        assert!(matches!(result, ParseOutcome::Complete(_)));
    }

    #[test]
    fn http_2_0_marked_unsupported() {
        // HTTP/2 connection preface is not valid HTTP/1.x
        let req = b"PRI * HTTP/2.0\r\nSM\r\n\r\n";
        let result = parse_request(req, 64);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_request_line() {
        let req = b"NOTHTTP\r\n\r\n";
        let result = parse_request(req, 64);
        assert!(result.is_err());
    }
}
