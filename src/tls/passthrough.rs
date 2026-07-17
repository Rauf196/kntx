//! ClientHello peek for TLS passthrough.
//!
//! Validates TLS framing only - just enough to extract the SNI hostname.
//! Protocol legality is left to the backend: a stricter parser (rustls's,
//! for instance) would reject hellos the backend may accept, the wrong
//! failure mode for a proxy that never terminates these connections.
//! nginx ssl_preread and HAProxy req.ssl_sni take the same approach.
//!
//! Scope: ClientHello within a single TLS record (max 16384-byte payload).
//! Multi-record hellos are rejected; they do not occur in practice and
//! nginx has the same limit.

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;
/// RFC 8446 §5.1: record payload must not exceed 2^14 bytes.
const MAX_RECORD_LEN: usize = 16384;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const EXTENSION_SERVER_NAME: u16 = 0;
const SNI_TYPE_HOST_NAME: u8 = 0;
/// DNS caps hostnames at 253 bytes; anything longer cannot match a route.
const MAX_HOSTNAME_LEN: usize = 253;

/// verdict on a (possibly partial) buffer of client bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum HelloParse {
    /// full ClientHello parsed; sni is the lowercased host_name if the
    /// server_name extension was present.
    Complete { sni: Option<String> },
    /// valid so far, but the full hello has not arrived yet.
    Incomplete,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HelloError {
    #[error("first bytes are not a TLS handshake record")]
    NotTls,
    #[error("TLS record length exceeds the {MAX_RECORD_LEN}-byte maximum")]
    TooLarge,
    #[error("ClientHello spans multiple TLS records (unsupported)")]
    MultiRecord,
    #[error("malformed ClientHello: {0}")]
    Malformed(&'static str),
}

/// successful peek: SNI (if present) and how many bytes were consumed.
/// consumed bytes must be the first bytes written to the backend.
#[derive(Debug)]
pub struct PeekedHello {
    pub sni: Option<String>,
    pub len: usize,
}

#[derive(Debug, Error)]
pub enum PeekError {
    #[error(transparent)]
    Parse(#[from] HelloError),
    #[error("client closed before completing ClientHello")]
    Eof,
    #[error("ClientHello larger than the peek buffer")]
    BufferFull,
    #[error("i/o error reading ClientHello")]
    Io(#[from] std::io::Error),
}

impl PeekError {
    /// closed set for the rejects metric reason label.
    pub fn metric_reason(&self) -> &'static str {
        match self {
            Self::Parse(HelloError::NotTls) => "not_tls",
            Self::Parse(HelloError::TooLarge) => "too_large",
            Self::Parse(HelloError::MultiRecord) => "multi_record",
            Self::Parse(HelloError::Malformed(_)) => "malformed",
            Self::Eof => "eof",
            Self::BufferFull => "buffer_full",
            Self::Io(_) => "io",
        }
    }
}

/// bounds-checked reader over a complete record body. overruns here mean
/// structural corruption, not missing bytes.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], HelloError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .ok_or(HelloError::Malformed(what))?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, HelloError> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, HelloError> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
}

/// parse a ClientHello from the start of `buf`.
///
/// `Incomplete` means more bytes may still produce a verdict; callers read
/// and re-parse. bytes after the hello (coalesced records, early data) are
/// left in place and reach the backend with everything else.
pub fn parse_client_hello(buf: &[u8]) -> Result<HelloParse, HelloError> {
    if buf.len() < RECORD_HEADER_LEN {
        return Ok(HelloParse::Incomplete);
    }
    if buf[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(HelloError::NotTls);
    }
    // legacy record version: major must be 3; minor lenient (SSL3.0-TLS1.3 wire values)
    if buf[1] != 3 || buf[2] > 4 {
        return Err(HelloError::NotTls);
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if record_len > MAX_RECORD_LEN {
        return Err(HelloError::TooLarge);
    }
    if record_len < HANDSHAKE_HEADER_LEN {
        return Err(HelloError::Malformed(
            "record too short for handshake header",
        ));
    }

    // verdicts available from the handshake header alone are taken before
    // waiting for the rest of the record
    if buf.len() >= RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN {
        if buf[5] != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(HelloError::Malformed("handshake type is not client_hello"));
        }
        let hs_len = u32::from_be_bytes([0, buf[6], buf[7], buf[8]]) as usize;
        if HANDSHAKE_HEADER_LEN + hs_len > record_len {
            return Err(HelloError::MultiRecord);
        }
    }

    if buf.len() < RECORD_HEADER_LEN + record_len {
        return Ok(HelloParse::Incomplete);
    }

    let hs_len = u32::from_be_bytes([0, buf[6], buf[7], buf[8]]) as usize;
    let body_start = RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN;
    let mut cur = Cursor::new(&buf[body_start..body_start + hs_len]);

    cur.take(2, "legacy version")?;
    cur.take(32, "random")?;
    let sid_len = cur.u8("session id length")? as usize;
    if sid_len > 32 {
        return Err(HelloError::Malformed("session id longer than 32 bytes"));
    }
    cur.take(sid_len, "session id")?;
    let cs_len = cur.u16("cipher suites length")? as usize;
    if cs_len < 2 || !cs_len.is_multiple_of(2) {
        return Err(HelloError::Malformed("cipher suites length"));
    }
    cur.take(cs_len, "cipher suites")?;
    let comp_len = cur.u8("compression methods length")? as usize;
    if comp_len < 1 {
        return Err(HelloError::Malformed("compression methods length"));
    }
    cur.take(comp_len, "compression methods")?;

    // the extensions block is optional
    if cur.is_empty() {
        return Ok(HelloParse::Complete { sni: None });
    }
    let ext_total = cur.u16("extensions length")? as usize;
    let mut ext = Cursor::new(cur.take(ext_total, "extensions block")?);
    while !ext.is_empty() {
        let ext_type = ext.u16("extension type")?;
        let ext_len = ext.u16("extension length")? as usize;
        let data = ext.take(ext_len, "extension data")?;
        if ext_type == EXTENSION_SERVER_NAME {
            return Ok(HelloParse::Complete {
                sni: parse_sni_extension(data)?,
            });
        }
    }
    Ok(HelloParse::Complete { sni: None })
}

/// read from `stream` into `buf` until a full ClientHello is parsed.
/// the caller enforces the overall timeout.
pub async fn peek_client_hello<S>(stream: &mut S, buf: &mut [u8]) -> Result<PeekedHello, PeekError>
where
    S: AsyncRead + Unpin,
{
    let mut filled = 0usize;
    loop {
        match parse_client_hello(&buf[..filled])? {
            HelloParse::Complete { sni } => return Ok(PeekedHello { sni, len: filled }),
            HelloParse::Incomplete => {}
        }
        if filled == buf.len() {
            return Err(PeekError::BufferFull);
        }
        let n = stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Err(PeekError::Eof);
        }
        filled += n;
    }
}

/// extract and normalize the first host_name entry of a server_name
/// extension. unusable names (empty, non-ASCII, oversized) yield `None`:
/// they cannot match any route pattern, but a catch-all route may still
/// take the connection.
fn parse_sni_extension(data: &[u8]) -> Result<Option<String>, HelloError> {
    let mut cur = Cursor::new(data);
    let list_len = cur.u16("server name list length")? as usize;
    let mut entries = Cursor::new(cur.take(list_len, "server name list")?);
    while !entries.is_empty() {
        let name_type = entries.u8("server name type")?;
        let name_len = entries.u16("server name length")? as usize;
        let name = entries.take(name_len, "server name")?;
        if name_type == SNI_TYPE_HOST_NAME {
            return Ok(normalize_hostname(name));
        }
    }
    Ok(None)
}

fn normalize_hostname(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_HOSTNAME_LEN {
        return None;
    }
    if !raw.iter().all(|b| b.is_ascii() && !b.is_ascii_control()) {
        return None;
    }
    // ascii verified above, so utf-8 conversion cannot fail
    let mut name = String::from_utf8(raw.to_vec()).ok()?;
    name.make_ascii_lowercase();
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn install_ring() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// ClientHello bytes produced by rustls, so the parser is tested
    /// against real wire format rather than hand-made fixtures.
    fn genuine_hello(
        server_name: rustls::pki_types::ServerName<'static>,
        tls12_only: bool,
    ) -> Vec<u8> {
        install_ring();
        let roots = rustls::RootCertStore::empty();
        let builder = if tls12_only {
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        } else {
            rustls::ClientConfig::builder()
        };
        let config = builder.with_root_certificates(roots).with_no_client_auth();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut out = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut out).unwrap();
        }
        out
    }

    fn dns_name(name: &str) -> rustls::pki_types::ServerName<'static> {
        rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap()
    }

    fn ip_name() -> rustls::pki_types::ServerName<'static> {
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        rustls::pki_types::ServerName::IpAddress(ip.into())
    }

    /// minimal structurally-valid hello with controllable extensions, for
    /// edge cases rustls will never emit.
    fn synthetic_hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // empty session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        if !extensions.is_empty() {
            let mut block = Vec::new();
            for (typ, data) in extensions {
                block.extend_from_slice(&typ.to_be_bytes());
                block.extend_from_slice(&(data.len() as u16).to_be_bytes());
                block.extend_from_slice(data);
            }
            body.extend_from_slice(&(block.len() as u16).to_be_bytes());
            body.extend_from_slice(&block);
        }
        let mut hs = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // u24
        hs.extend_from_slice(&body);
        let mut rec = vec![CONTENT_TYPE_HANDSHAKE, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn sni_extension(name_type: u8, host: &[u8]) -> (u16, Vec<u8>) {
        let mut entry = vec![name_type];
        entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        entry.extend_from_slice(host);
        let mut data = (entry.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&entry);
        (EXTENSION_SERVER_NAME, data)
    }

    fn parse_sni(buf: &[u8]) -> Option<String> {
        match parse_client_hello(buf).unwrap() {
            HelloParse::Complete { sni } => sni,
            HelloParse::Incomplete => panic!("expected complete hello"),
        }
    }

    #[test]
    fn parses_sni_from_genuine_tls13_hello() {
        let hello = genuine_hello(dns_name("api.example.com"), false);
        assert_eq!(parse_sni(&hello).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn parses_sni_from_genuine_tls12_hello() {
        let hello = genuine_hello(dns_name("legacy.example.com"), true);
        assert_eq!(parse_sni(&hello).as_deref(), Some("legacy.example.com"));
    }

    #[test]
    fn genuine_hello_without_sni_yields_none() {
        // rustls omits the server_name extension for IP-address names
        let hello = genuine_hello(ip_name(), false);
        assert_eq!(parse_sni(&hello), None);
    }

    #[test]
    fn every_truncation_is_incomplete() {
        let hello = genuine_hello(dns_name("api.example.com"), false);
        for len in 0..hello.len() {
            match parse_client_hello(&hello[..len]) {
                Ok(HelloParse::Incomplete) => {}
                other => panic!("prefix of {len} bytes gave {other:?}, expected Incomplete"),
            }
        }
    }

    #[test]
    fn trailing_bytes_after_hello_ok() {
        let mut hello = genuine_hello(dns_name("api.example.com"), false);
        hello.extend_from_slice(b"\x17\x03\x03junk-that-looks-like-another-record");
        assert_eq!(parse_sni(&hello).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn http_bytes_rejected_not_tls() {
        let err = parse_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap_err();
        assert_eq!(err, HelloError::NotTls);
    }

    #[test]
    fn alert_record_rejected_not_tls() {
        let err = parse_client_hello(&[21, 3, 3, 0, 2, 2, 40]).unwrap_err();
        assert_eq!(err, HelloError::NotTls);
    }

    #[test]
    fn bad_version_major_rejected() {
        let err = parse_client_hello(&[22, 2, 0, 0, 100, 0, 0, 0]).unwrap_err();
        assert_eq!(err, HelloError::NotTls);
    }

    #[test]
    fn record_len_over_16384_too_large() {
        // length field 16385
        let err = parse_client_hello(&[22, 3, 1, 0x40, 0x01]).unwrap_err();
        assert_eq!(err, HelloError::TooLarge);
    }

    #[test]
    fn server_hello_rejected_malformed() {
        let mut hello = synthetic_hello(&[]);
        hello[5] = 2; // handshake type: server_hello
        assert!(matches!(
            parse_client_hello(&hello).unwrap_err(),
            HelloError::Malformed(_)
        ));
    }

    #[test]
    fn hello_spanning_records_multi_record() {
        // record claims 4 payload bytes, handshake claims 256 body bytes
        let err = parse_client_hello(&[22, 3, 3, 0, 4, 1, 0, 1, 0]).unwrap_err();
        assert_eq!(err, HelloError::MultiRecord);
    }

    #[test]
    fn overrun_session_id_malformed() {
        let mut hello = synthetic_hello(&[sni_extension(0, b"a.test")]);
        hello[43] = 200; // session id length far beyond the body
        assert!(matches!(
            parse_client_hello(&hello).unwrap_err(),
            HelloError::Malformed(_)
        ));
    }

    #[test]
    fn overrun_cipher_suites_malformed() {
        let mut hello = synthetic_hello(&[sni_extension(0, b"a.test")]);
        hello[44] = 0xff; // cipher suites length overruns the body
        hello[45] = 0xfe;
        assert!(matches!(
            parse_client_hello(&hello).unwrap_err(),
            HelloError::Malformed(_)
        ));
    }

    #[test]
    fn odd_cipher_suites_len_malformed() {
        let mut hello = synthetic_hello(&[]);
        hello[45] = 3; // odd cipher suites length
        // downstream length checks also break; any Malformed variant is acceptable
        assert!(matches!(
            parse_client_hello(&hello).unwrap_err(),
            HelloError::Malformed(_)
        ));
    }

    #[test]
    fn overrun_extensions_block_malformed() {
        let mut hello = synthetic_hello(&[sni_extension(0, b"a.test")]);
        // extensions total length sits right after compression methods
        hello[51] = hello[51].wrapping_add(10);
        assert!(matches!(
            parse_client_hello(&hello).unwrap_err(),
            HelloError::Malformed(_)
        ));
    }

    #[test]
    fn uppercase_sni_lowercased() {
        let hello = synthetic_hello(&[sni_extension(0, b"API.Example.COM")]);
        assert_eq!(parse_sni(&hello).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn unknown_extensions_skipped_before_sni() {
        let hello = synthetic_hello(&[
            (0x0a0a, vec![0xde, 0xad]), // GREASE-style unknown extension
            (0x002b, vec![0x02, 0x03, 0x04]),
            sni_extension(0, b"behind.others.test"),
        ]);
        assert_eq!(parse_sni(&hello).as_deref(), Some("behind.others.test"));
    }

    #[test]
    fn empty_hostname_yields_none() {
        let hello = synthetic_hello(&[sni_extension(0, b"")]);
        assert_eq!(parse_sni(&hello), None);
    }

    #[test]
    fn non_hostname_name_type_skipped() {
        let hello = synthetic_hello(&[sni_extension(1, b"api.test")]);
        assert_eq!(parse_sni(&hello), None);
    }

    #[test]
    fn non_ascii_hostname_yields_none() {
        let hello = synthetic_hello(&[sni_extension(0, &[0x80, 0x81, b'.', b't'])]);
        assert_eq!(parse_sni(&hello), None);
    }

    /// AsyncRead yielding one preset chunk per read call, to exercise the
    /// peek loop's partial-read path deterministically.
    struct ChunkedReader {
        chunks: std::collections::VecDeque<Vec<u8>>,
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if let Some(chunk) = self.chunks.pop_front() {
                buf.put_slice(&chunk);
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn peek_assembles_fragmented_hello() {
        let hello = genuine_hello(dns_name("frag.example.com"), false);
        let (a, rest) = hello.split_at(3);
        let (b, c) = rest.split_at(20);
        let mut reader = ChunkedReader {
            chunks: [a.to_vec(), b.to_vec(), c.to_vec()].into(),
        };
        let mut buf = vec![0u8; 32 * 1024];
        let peeked = peek_client_hello(&mut reader, &mut buf).await.unwrap();
        assert_eq!(peeked.sni.as_deref(), Some("frag.example.com"));
        assert_eq!(peeked.len, hello.len());
        assert_eq!(&buf[..peeked.len], &hello[..]);
    }

    #[tokio::test]
    async fn peek_eof_mid_hello_is_eof_error() {
        let hello = genuine_hello(dns_name("cut.example.com"), false);
        let mut reader = ChunkedReader {
            chunks: [hello[..10].to_vec()].into(),
        };
        let mut buf = vec![0u8; 32 * 1024];
        let err = peek_client_hello(&mut reader, &mut buf).await.unwrap_err();
        assert!(matches!(err, PeekError::Eof));
        assert_eq!(err.metric_reason(), "eof");
    }
}
