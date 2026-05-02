use bytes::BytesMut;

use super::parse::{HttpVersion, ParsedHeader};

// transfer-encoding is intentionally excluded: the proxy forwards chunked
// bodies verbatim, so the backend must see the TE header to parse the body.
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

/// set of header indices (into the parsed headers slice) that should be skipped
/// when serializing the outgoing head.
pub struct SkipSet {
    indices: Vec<usize>,
}

impl SkipSet {
    pub fn build(
        headers: &[ParsedHeader],
        connection_value: Option<&str>,
        extra_skip_names: &[&str],
    ) -> Self {
        let mut conn_listed: Vec<&str> = Vec::new();
        if let Some(val) = connection_value {
            for token in val.split(',') {
                let t = token.trim();
                if !t.is_empty() {
                    conn_listed.push(t);
                }
            }
        }

        let mut indices = Vec::new();
        for (i, h) in headers.iter().enumerate() {
            if HOP_BY_HOP
                .iter()
                .any(|&hop| h.name.eq_ignore_ascii_case(hop))
            {
                indices.push(i);
                continue;
            }
            if conn_listed.iter().any(|&n| h.name.eq_ignore_ascii_case(n)) {
                indices.push(i);
                continue;
            }
            if extra_skip_names
                .iter()
                .any(|&n| h.name.eq_ignore_ascii_case(n))
            {
                indices.push(i);
                continue;
            }
        }

        Self { indices }
    }

    pub fn contains(&self, idx: usize) -> bool {
        self.indices.contains(&idx)
    }
}

/// header lines to append after the filtered original headers.
pub struct Additions {
    pub lines: Vec<(String, String)>,
}

impl Default for Additions {
    fn default() -> Self {
        Self::new()
    }
}

impl Additions {
    pub fn new() -> Self {
        Self { lines: Vec::new() }
    }

    pub fn push(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.lines.push((name.into(), value.into()));
    }
}

pub fn serialize_request_head(
    out: &mut BytesMut,
    method: &str,
    path: &str,
    version: HttpVersion,
    headers: &[ParsedHeader],
    skip: &SkipSet,
    additions: &Additions,
) {
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(version.as_str().as_bytes());
    out.extend_from_slice(b"\r\n");

    for (i, h) in headers.iter().enumerate() {
        if skip.contains(i) {
            continue;
        }
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&h.value);
        out.extend_from_slice(b"\r\n");
    }

    for (name, value) in &additions.lines {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(b"\r\n");
}

pub fn serialize_response_head(
    out: &mut BytesMut,
    version: HttpVersion,
    status: u16,
    reason: &str,
    headers: &[ParsedHeader],
    skip: &SkipSet,
    additions: &Additions,
) {
    out.extend_from_slice(version.as_str().as_bytes());
    out.extend_from_slice(b" ");
    let status_str = status.to_string();
    out.extend_from_slice(status_str.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(reason.as_bytes());
    out.extend_from_slice(b"\r\n");

    for (i, h) in headers.iter().enumerate() {
        if skip.contains(i) {
            continue;
        }
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&h.value);
        out.extend_from_slice(b"\r\n");
    }

    for (name, value) in &additions.lines {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(b"\r\n");
}

fn find_header(headers: &[ParsedHeader], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| h.value_str())
        .map(|s| s.to_owned())
}

/// build request-side SkipSet + Additions for forwarding to backend.
pub fn build_request_additions(
    headers: &[ParsedHeader],
    client_ip: &str,
    is_tls: bool,
    version: HttpVersion,
    request_id: &str,
) -> (SkipSet, Additions) {
    let proto = if is_tls { "https" } else { "http" };
    let via_proto = match version {
        HttpVersion::Http10 => "1.0",
        HttpVersion::Http11 => "1.1",
    };

    let existing_xff = find_header(headers, "x-forwarded-for");
    let existing_via = find_header(headers, "via");
    let connection_val = find_header(headers, "connection");

    let xff = match existing_xff.as_deref() {
        Some(existing) => format!("{existing}, {client_ip}"),
        None => client_ip.to_owned(),
    };

    let via = match existing_via.as_deref() {
        Some(existing) => format!("{existing}, {via_proto} kntx"),
        None => format!("{via_proto} kntx"),
    };

    let extra_skip: &[&str] = &[
        "x-forwarded-for",
        "x-real-ip",
        "x-forwarded-proto",
        "x-request-id",
        "via",
    ];
    let skip = SkipSet::build(headers, connection_val.as_deref(), extra_skip);

    let mut additions = Additions::new();
    additions.push("X-Forwarded-For", xff);
    additions.push("X-Real-IP", client_ip);
    additions.push("X-Forwarded-Proto", proto);
    additions.push("X-Request-ID", request_id.to_owned());
    additions.push("Via", via);
    additions.push("Connection", "close");

    (skip, additions)
}

/// build response-side SkipSet + Additions.
pub fn build_response_additions(
    headers: &[ParsedHeader],
    version: HttpVersion,
) -> (SkipSet, Additions) {
    let via_proto = match version {
        HttpVersion::Http10 => "1.0",
        HttpVersion::Http11 => "1.1",
    };

    let connection_val = find_header(headers, "connection");
    let existing_via = find_header(headers, "via");

    let via = match existing_via.as_deref() {
        Some(existing) => format!("{existing}, {via_proto} kntx"),
        None => format!("{via_proto} kntx"),
    };

    let skip = SkipSet::build(headers, connection_val.as_deref(), &["via"]);

    let mut additions = Additions::new();
    additions.push("Connection", "close");
    additions.push("Via", via);

    (skip, additions)
}

fn is_valid_request_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// resolve request id: preserve inbound X-Request-ID if it passes charset
/// validation, otherwise generate a fresh UUID.
pub fn resolve_request_id(headers: &[ParsedHeader]) -> String {
    if let Some(s) = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("x-request-id"))
        .and_then(|h| h.value_str())
        && is_valid_request_id(s)
    {
        return s.to_owned();
    }
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, value: &[u8]) -> ParsedHeader {
        ParsedHeader {
            name: name.to_owned(),
            value: value.to_vec(),
        }
    }

    #[test]
    fn hop_by_hop_stripped_standard_list() {
        let headers = vec![
            h("Host", b"example.com"),
            h("Connection", b"keep-alive"),
            h("Keep-Alive", b"timeout=5"),
            h("Transfer-Encoding", b"chunked"),
        ];
        let skip = SkipSet::build(&headers, None, &[]);
        assert!(!skip.contains(0)); // Host kept
        assert!(skip.contains(1)); // Connection skipped
        assert!(skip.contains(2)); // Keep-Alive skipped
        assert!(!skip.contains(3)); // Transfer-Encoding kept (proxy forwards chunked verbatim)
    }

    #[test]
    fn hop_by_hop_stripped_connection_listed_names() {
        let headers = vec![
            h("Host", b"example.com"),
            h("Connection", b"X-Custom"),
            h("X-Custom", b"value"),
            h("X-Other", b"kept"),
        ];
        let skip = SkipSet::build(&headers, Some("X-Custom"), &[]);
        assert!(!skip.contains(0));
        assert!(skip.contains(1)); // Connection (standard hop-by-hop)
        assert!(skip.contains(2)); // X-Custom (listed in Connection)
        assert!(!skip.contains(3)); // X-Other kept
    }

    #[test]
    fn xff_appended_to_existing_chain() {
        let headers = vec![h("Host", b"example.com"), h("X-Forwarded-For", b"1.2.3.4")];
        let rid = resolve_request_id(&headers);
        let (_, additions) =
            build_request_additions(&headers, "5.6.7.8", false, HttpVersion::Http11, &rid);
        let xff = additions
            .lines
            .iter()
            .find(|(n, _)| n == "X-Forwarded-For")
            .unwrap();
        assert_eq!(xff.1, "1.2.3.4, 5.6.7.8");
    }

    #[test]
    fn xff_created_when_absent() {
        let headers = vec![h("Host", b"example.com")];
        let rid = resolve_request_id(&headers);
        let (_, additions) =
            build_request_additions(&headers, "1.2.3.4", false, HttpVersion::Http11, &rid);
        let xff = additions
            .lines
            .iter()
            .find(|(n, _)| n == "X-Forwarded-For")
            .unwrap();
        assert_eq!(xff.1, "1.2.3.4");
    }

    #[test]
    fn x_request_id_preserved_when_valid() {
        let headers = vec![
            h("Host", b"example.com"),
            h("X-Request-ID", b"my-req-id-123"),
        ];
        let rid = resolve_request_id(&headers);
        let (_, additions) =
            build_request_additions(&headers, "1.1.1.1", false, HttpVersion::Http11, &rid);
        let entry = additions
            .lines
            .iter()
            .find(|(n, _)| n == "X-Request-ID")
            .unwrap();
        assert_eq!(entry.1, "my-req-id-123");
    }

    #[test]
    fn x_request_id_generated_when_absent() {
        let headers = vec![h("Host", b"example.com")];
        let rid = resolve_request_id(&headers);
        let (_, additions) =
            build_request_additions(&headers, "1.1.1.1", false, HttpVersion::Http11, &rid);
        let entry = additions
            .lines
            .iter()
            .find(|(n, _)| n == "X-Request-ID")
            .unwrap();
        assert!(!entry.1.is_empty());
        assert_eq!(entry.1.len(), 36);
    }

    #[test]
    fn x_request_id_regenerated_when_invalid_charset() {
        let headers = vec![
            h("Host", b"example.com"),
            h("X-Request-ID", b"invalid chars here!!!"),
        ];
        let rid = resolve_request_id(&headers);
        let (_, additions) =
            build_request_additions(&headers, "1.1.1.1", false, HttpVersion::Http11, &rid);
        let entry = additions
            .lines
            .iter()
            .find(|(n, _)| n == "X-Request-ID")
            .unwrap();
        assert_eq!(entry.1.len(), 36);
    }

    #[test]
    fn via_appended_to_existing() {
        let headers = vec![h("Host", b"example.com"), h("Via", b"1.0 upstream")];
        let rid = resolve_request_id(&headers);
        let (_, additions) =
            build_request_additions(&headers, "1.1.1.1", false, HttpVersion::Http11, &rid);
        let via = additions.lines.iter().find(|(n, _)| n == "Via").unwrap();
        assert_eq!(via.1, "1.0 upstream, 1.1 kntx");
    }

    #[test]
    fn via_created_when_absent() {
        let headers = vec![h("Host", b"example.com")];
        let rid = resolve_request_id(&headers);
        let (_, additions) =
            build_request_additions(&headers, "1.1.1.1", false, HttpVersion::Http11, &rid);
        let via = additions.lines.iter().find(|(n, _)| n == "Via").unwrap();
        assert_eq!(via.1, "1.1 kntx");
    }

    #[test]
    fn serialize_request_head_round_trip() {
        let headers = vec![h("Host", b"example.com"), h("Content-Length", b"5")];
        let skip = SkipSet { indices: vec![] };
        let additions = Additions::new();
        let mut out = BytesMut::new();
        serialize_request_head(
            &mut out,
            "POST",
            "/test",
            HttpVersion::Http11,
            &headers,
            &skip,
            &additions,
        );
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("POST /test HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }
}
