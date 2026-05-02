use std::collections::HashMap;

use bytes::Bytes;

use crate::config::ErrorPagesConfig;

struct ErrorPageBody {
    bytes: Bytes,
    content_type: &'static str,
}

pub struct ErrorPages {
    pages: HashMap<u16, ErrorPageBody>,
}

impl ErrorPages {
    pub fn load(config: &ErrorPagesConfig) -> Result<Self, std::io::Error> {
        let mut pages = HashMap::new();
        for (status_str, path) in &config.pages {
            let status: u16 = status_str.parse().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid status code key")
            })?;
            let bytes = std::fs::read(path)?;
            let content_type = content_type_from_path(path);
            pages.insert(
                status,
                ErrorPageBody {
                    bytes: Bytes::from(bytes),
                    content_type,
                },
            );
        }
        Ok(Self { pages })
    }

    fn get(&self, status: u16) -> Option<(&Bytes, &'static str)> {
        self.pages.get(&status).map(|p| (&p.bytes, p.content_type))
    }
}

fn content_type_from_path(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "text/plain; charset=utf-8",
    }
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// build a complete HTTP/1.1 error response as raw bytes.
/// if a custom page exists for this status, use it.
/// otherwise content-negotiate on `accept`.
pub fn synthesize_error(status: u16, accept: Option<&str>, pages: &ErrorPages) -> Bytes {
    let reason = reason_phrase(status);

    if let Some((body, content_type)) = pages.get(status) {
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nServer: kntx\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut out = head.into_bytes();
        out.extend_from_slice(body);
        return Bytes::from(out);
    }

    let wants_json = accept
        .map(|a| a.contains("application/json"))
        .unwrap_or(false);

    let (body, content_type) = if wants_json {
        (
            format!(r#"{{"error":"{reason}","status":{status}}}"#),
            "application/json",
        )
    } else {
        (
            format!(
                "<!doctype html><meta charset=\"utf-8\"><title>{status} {reason}</title><h1>{status} {reason}</h1>"
            ),
            "text/html; charset=utf-8",
        )
    };

    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nServer: kntx\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    Bytes::from(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ErrorPagesConfig;

    fn empty_pages() -> ErrorPages {
        ErrorPages {
            pages: HashMap::new(),
        }
    }

    #[test]
    fn synthesize_json_when_accept_json() {
        let pages = empty_pages();
        let resp = synthesize_error(503, Some("application/json"), &pages);
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.contains("application/json"));
        assert!(s.contains(r#""status":503"#));
    }

    #[test]
    fn synthesize_html_when_accept_html() {
        let pages = empty_pages();
        let resp = synthesize_error(503, Some("text/html"), &pages);
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.contains("text/html"));
        assert!(s.contains("<!doctype html>"));
    }

    #[test]
    fn synthesize_html_when_no_accept() {
        let pages = empty_pages();
        let resp = synthesize_error(502, None, &pages);
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.contains("text/html"));
    }

    #[test]
    fn custom_page_overrides_default() {
        let mut pages = HashMap::new();
        pages.insert(
            503u16,
            ErrorPageBody {
                bytes: Bytes::from_static(b"<custom>"),
                content_type: "text/html; charset=utf-8",
            },
        );
        let ep = ErrorPages { pages };
        let resp = synthesize_error(503, Some("application/json"), &ep);
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.contains("<custom>"));
        // even though accept=json, custom page wins
    }

    #[test]
    fn content_type_inferred_from_extension() {
        use std::path::Path;
        assert_eq!(
            content_type_from_path(Path::new("e.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type_from_path(Path::new("e.json")),
            "application/json"
        );
        assert_eq!(
            content_type_from_path(Path::new("e.txt")),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            content_type_from_path(Path::new("e.unknown")),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn error_pages_load_fails_on_missing_file() {
        let mut cfg = ErrorPagesConfig::default();
        cfg.pages
            .insert("503".to_owned(), "/nonexistent/page.html".into());
        let result = ErrorPages::load(&cfg);
        assert!(result.is_err());
    }
}
