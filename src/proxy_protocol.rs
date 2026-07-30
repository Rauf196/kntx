//! PROXY protocol v1/v2 ingress.
//!
//! Behind an L4 balancer the TCP peer is the balancer, so the client address has
//! to come from a header the balancer prepends. HAProxy defined the protocol for
//! exactly this; NLB, ELB, nginx and Envoy all speak it.
//!
//! Enabling it on a listener makes the header mandatory. Accepting either a
//! header or a bare connection on one port would let any client choose its own
//! source address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const V1_SIGNATURE: &[u8] = b"PROXY ";
const V2_SIGNATURE: &[u8] = b"\r\n\r\n\x00\r\nQUIT\n";
const V2_HEADER_LEN: usize = 16;
/// spec cap for v1, CRLF included.
const MAX_V1_LEN: usize = 107;
/// v2 declares a u16 body length, so the wire allows 64 KiB. This covers the
/// largest fixed address block (AF_UNIX, 216 bytes) plus TLV room; anything
/// beyond it is refused rather than buffered.
const MAX_HEADER_LEN: usize = 512;

const V2_CMD_LOCAL: u8 = 0;
const V2_CMD_PROXY: u8 = 1;
const V2_AF_INET: u8 = 1;
const V2_AF_INET6: u8 = 2;
const V2_INET_BLOCK: usize = 12;
const V2_INET6_BLOCK: usize = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

/// verdict on a (possibly partial) buffer of peer bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum HeaderParse {
    /// header fully present in `len` bytes. `source` is None when it carried no
    /// usable client address - v1 UNKNOWN, v2 LOCAL, or an address family that
    /// is not TCP - in which case the socket peer stands as the client.
    Complete {
        source: Option<SocketAddr>,
        len: usize,
        version: Version,
    },
    Incomplete,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeaderError {
    #[error("connection did not begin with a PROXY protocol header")]
    NotProxyProtocol,
    #[error("PROXY protocol header exceeds the {MAX_HEADER_LEN}-byte maximum")]
    TooLarge,
    #[error("malformed PROXY protocol header: {0}")]
    Malformed(&'static str),
}

#[derive(Debug, Error)]
pub enum ReadError {
    #[error(transparent)]
    Header(#[from] HeaderError),
    #[error("peer closed before completing the PROXY protocol header")]
    Eof,
    #[error("i/o error reading the PROXY protocol header")]
    Io(#[from] std::io::Error),
}

/// what a completed header recovered.
#[derive(Debug)]
pub struct RecoveredPeer {
    pub source: Option<SocketAddr>,
    pub version: Version,
}

/// a peer allowed to speak the protocol, as `<address>` or `<address>/<prefix>`.
/// deserialized through `FromStr` like `ListenerConfig.address`, so a bad value
/// fails at config parse with the offending line attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct TrustedCidr {
    network: IpAddr,
    bits: u8,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CidrError {
    #[error("'{0}' is not an address or address/prefix")]
    Shape(String),
    #[error("'{0}' has an invalid address")]
    Address(String),
    #[error("'{cidr}' prefix length exceeds {max} for its address family")]
    PrefixLen { cidr: String, max: u8 },
}

impl Version {
    /// closed set for the headers metric label.
    pub fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

impl ReadError {
    /// closed set for the rejects metric reason label.
    pub fn metric_reason(&self) -> &'static str {
        match self {
            Self::Header(HeaderError::NotProxyProtocol) => "not_proxy_protocol",
            Self::Header(HeaderError::TooLarge) => "too_large",
            Self::Header(HeaderError::Malformed(_)) => "malformed",
            Self::Eof => "eof",
            Self::Io(_) => "io",
        }
    }
}

impl TrustedCidr {
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(peer)) => {
                prefix_eq(&net.octets(), &peer.octets(), self.bits)
            }
            (IpAddr::V6(net), IpAddr::V6(peer)) => {
                prefix_eq(&net.octets(), &peer.octets(), self.bits)
            }
            _ => false,
        }
    }
}

impl FromStr for TrustedCidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let network: IpAddr = addr
            .parse::<IpAddr>()
            .map_err(|_| CidrError::Address(s.to_owned()))?
            .to_canonical();
        let max = if network.is_ipv4() { 32 } else { 128 };
        let bits = match prefix {
            Some(p) => p.parse().map_err(|_| CidrError::Shape(s.to_owned()))?,
            None => max,
        };
        if bits > max {
            return Err(CidrError::PrefixLen {
                cidr: s.to_owned(),
                max,
            });
        }
        Ok(Self { network, bits })
    }
}

impl TryFrom<String> for TrustedCidr {
    type Error = CidrError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// parse a header from the start of `buf`.
///
/// `Incomplete` means more bytes may still produce a verdict. Both signatures
/// are checked against whatever prefix has arrived, so a peer that is not
/// speaking the protocol is rejected on its first bytes rather than after the
/// size cap.
pub fn parse(buf: &[u8]) -> Result<HeaderParse, HeaderError> {
    match buf.first() {
        None => Ok(HeaderParse::Incomplete),
        Some(b'P') => parse_v1(buf),
        Some(b'\r') => parse_v2(buf),
        Some(_) => Err(HeaderError::NotProxyProtocol),
    }
}

fn parse_v1(buf: &[u8]) -> Result<HeaderParse, HeaderError> {
    let seen = buf.len().min(V1_SIGNATURE.len());
    if buf[..seen] != V1_SIGNATURE[..seen] {
        return Err(HeaderError::NotProxyProtocol);
    }

    let Some(crlf) = buf.windows(2).position(|w| w == b"\r\n") else {
        return if buf.len() >= MAX_V1_LEN {
            Err(HeaderError::TooLarge)
        } else {
            Ok(HeaderParse::Incomplete)
        };
    };
    let len = crlf + 2;
    if len > MAX_V1_LEN {
        return Err(HeaderError::TooLarge);
    }
    let line = &buf[..crlf];
    if line.len() < V1_SIGNATURE.len() {
        return Err(HeaderError::Malformed("v1 line ends inside the signature"));
    }

    let text = std::str::from_utf8(&line[V1_SIGNATURE.len()..])
        .map_err(|_| HeaderError::Malformed("v1 line is not ascii"))?;
    let mut fields = text.split(' ');
    let family = fields.next().unwrap_or_default();
    if family == "UNKNOWN" {
        // the sender could not determine the client, e.g. its own health probe
        return Ok(HeaderParse::Complete {
            source: None,
            len,
            version: Version::V1,
        });
    }
    if family != "TCP4" && family != "TCP6" {
        return Err(HeaderError::Malformed("v1 unsupported address family"));
    }

    let source = fields
        .next()
        .ok_or(HeaderError::Malformed("v1 missing source address"))?;
    // destination address and port are consumed for the field count only; kntx
    // knows the address it is listening on.
    let _destination = fields
        .next()
        .ok_or(HeaderError::Malformed("v1 missing destination address"))?;
    let source_port = fields
        .next()
        .ok_or(HeaderError::Malformed("v1 missing source port"))?;
    let _destination_port = fields
        .next()
        .ok_or(HeaderError::Malformed("v1 missing destination port"))?;
    if fields.next().is_some() {
        return Err(HeaderError::Malformed("v1 trailing field"));
    }

    let ip: IpAddr = source
        .parse()
        .map_err(|_| HeaderError::Malformed("v1 source address"))?;
    if ip.is_ipv4() != (family == "TCP4") {
        return Err(HeaderError::Malformed(
            "v1 source address disagrees with the declared family",
        ));
    }
    let port: u16 = source_port
        .parse()
        .map_err(|_| HeaderError::Malformed("v1 source port"))?;

    Ok(HeaderParse::Complete {
        source: Some(SocketAddr::new(ip, port)),
        len,
        version: Version::V1,
    })
}

fn parse_v2(buf: &[u8]) -> Result<HeaderParse, HeaderError> {
    let seen = buf.len().min(V2_SIGNATURE.len());
    if buf[..seen] != V2_SIGNATURE[..seen] {
        return Err(HeaderError::NotProxyProtocol);
    }
    if buf.len() < V2_HEADER_LEN {
        return Ok(HeaderParse::Incomplete);
    }

    if buf[12] >> 4 != 2 {
        return Err(HeaderError::Malformed("v2 version is not 2"));
    }
    let command = buf[12] & 0x0f;
    let family = buf[13] >> 4;
    let len = V2_HEADER_LEN + u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if len > MAX_HEADER_LEN {
        return Err(HeaderError::TooLarge);
    }
    if buf.len() < len {
        return Ok(HeaderParse::Incomplete);
    }

    let source = match command {
        // the sender is speaking for itself, e.g. a balancer health check. it is
        // not a client and must not be logged or rate limited as one.
        V2_CMD_LOCAL => None,
        V2_CMD_PROXY => parse_v2_address(family, &buf[V2_HEADER_LEN..len])?,
        _ => {
            return Err(HeaderError::Malformed(
                "v2 command is neither LOCAL nor PROXY",
            ));
        }
    };

    Ok(HeaderParse::Complete {
        source,
        len,
        version: Version::V2,
    })
}

/// the low nibble of byte 13 is the transport, which kntx does not act on: a
/// mismatch is the sender's problem, the address is what gets consumed.
fn parse_v2_address(family: u8, block: &[u8]) -> Result<Option<SocketAddr>, HeaderError> {
    match family {
        V2_AF_INET => {
            if block.len() < V2_INET_BLOCK {
                return Err(HeaderError::Malformed("v2 inet block is short"));
            }
            let ip = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let port = u16::from_be_bytes([block[8], block[9]]);
            Ok(Some(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        V2_AF_INET6 => {
            if block.len() < V2_INET6_BLOCK {
                return Err(HeaderError::Malformed("v2 inet6 block is short"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[..16]);
            let port = u16::from_be_bytes([block[32], block[33]]);
            Ok(Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        // AF_UNSPEC and AF_UNIX carry nothing usable as a client identity
        _ => Ok(None),
    }
}

/// read exactly the header off `stream`, leaving every following byte on the
/// socket.
///
/// The bytes after the header belong to the client - a ClientHello, an HTTP
/// head, or raw L4 payload - and may share a segment with it, so this peeks
/// first and consumes only what the parse claimed. Draining before looping is
/// what keeps it from spinning: `peek` returns immediately while the socket
/// buffer still holds bytes it already showed, so the buffer has to be emptied
/// for the next peek to wait on new data. Everything drained is provably header,
/// since the parse asked for more than it had.
///
/// The caller enforces the overall timeout.
pub async fn read_header(stream: &mut TcpStream) -> Result<RecoveredPeer, ReadError> {
    let mut buf = [0u8; MAX_HEADER_LEN];
    let mut consumed = 0usize;
    loop {
        let peeked = stream.peek(&mut buf[consumed..]).await?;
        let filled = consumed + peeked;

        if let HeaderParse::Complete {
            source,
            len,
            version,
        } = parse(&buf[..filled])?
        {
            if len > consumed {
                stream.read_exact(&mut buf[consumed..len]).await?;
            }
            return Ok(RecoveredPeer { source, version });
        }

        if peeked == 0 {
            return Err(ReadError::Eof);
        }
        if filled == buf.len() {
            return Err(HeaderError::TooLarge.into());
        }
        stream.read_exact(&mut buf[consumed..filled]).await?;
        consumed = filled;
    }
}

/// an empty list trusts any peer that can reach the listener, which is the
/// deployment the header assumes and what HAProxy's `accept-proxy` does.
pub fn peer_trusted(trusted: &[TrustedCidr], peer: IpAddr) -> bool {
    trusted.is_empty() || trusted.iter().any(|cidr| cidr.contains(peer))
}

fn prefix_eq(network: &[u8], addr: &[u8], bits: u8) -> bool {
    let whole = (bits / 8) as usize;
    if network[..whole] != addr[..whole] {
        return false;
    }
    let rest = bits % 8;
    rest == 0 || (network[whole] ^ addr[whole]) >> (8 - rest) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_header(command: u8, family: u8, block: &[u8]) -> Vec<u8> {
        let mut out = V2_SIGNATURE.to_vec();
        out.push(0x20 | command);
        out.push(family << 4 | 1);
        out.extend_from_slice(&(block.len() as u16).to_be_bytes());
        out.extend_from_slice(block);
        out
    }

    fn inet_block(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut b = src.to_vec();
        b.extend_from_slice(&dst);
        b.extend_from_slice(&sport.to_be_bytes());
        b.extend_from_slice(&dport.to_be_bytes());
        b
    }

    fn complete(buf: &[u8]) -> (Option<SocketAddr>, usize, Version) {
        match parse(buf).expect("parses") {
            HeaderParse::Complete {
                source,
                len,
                version,
            } => (source, len, version),
            HeaderParse::Incomplete => panic!("expected a complete header"),
        }
    }

    #[test]
    fn v1_tcp4_recovers_source_only() {
        let raw = b"PROXY TCP4 192.0.2.7 198.51.100.1 51234 443\r\n";
        let (source, len, version) = complete(raw);
        assert_eq!(source, Some("192.0.2.7:51234".parse().unwrap()));
        assert_eq!(len, raw.len());
        assert_eq!(version, Version::V1);
    }

    #[test]
    fn v1_tcp6_recovers_source_only() {
        let raw = b"PROXY TCP6 2001:db8::1 2001:db8::2 51234 443\r\n";
        let (source, len, _) = complete(raw);
        assert_eq!(source, Some("[2001:db8::1]:51234".parse().unwrap()));
        assert_eq!(len, raw.len());
    }

    #[test]
    fn v1_unknown_yields_no_address() {
        let raw = b"PROXY UNKNOWN\r\n";
        let (source, len, _) = complete(raw);
        assert_eq!(source, None);
        assert_eq!(len, raw.len());
    }

    #[test]
    fn v1_stops_at_crlf_and_leaves_the_rest() {
        let raw = b"PROXY TCP4 192.0.2.7 198.51.100.1 51234 443\r\nGET / HTTP/1.1\r\n";
        let (_, len, _) = complete(raw);
        assert_eq!(&raw[len..], b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn v1_without_crlf_within_the_cap_is_too_large() {
        let mut raw = b"PROXY TCP4 192.0.2.7 198.51.100.1 51234 443".to_vec();
        raw.resize(MAX_V1_LEN, b' ');
        assert_eq!(parse(&raw), Err(HeaderError::TooLarge));
        // one byte short of the cap it is still just unfinished
        assert_eq!(
            parse(&raw[..MAX_V1_LEN - 1]),
            Ok(HeaderParse::Incomplete),
            "the cap must be exclusive, not off by one"
        );
    }

    #[test]
    fn v1_crlf_landing_past_the_cap_is_too_large() {
        let mut raw = b"PROXY TCP4 192.0.2.7 198.51.100.1 51234 443".to_vec();
        raw.resize(MAX_V1_LEN - 1, b' ');
        raw.extend_from_slice(b"\r\n");
        assert_eq!(parse(&raw), Err(HeaderError::TooLarge));
    }

    #[test]
    fn v1_rejects_structural_damage() {
        let cases: &[&[u8]] = &[
            b"PROXY \r\n",
            b"PROXY TCP4 192.0.2.7 198.51.100.1 51234\r\n",
            b"PROXY TCP4 192.0.2.7 198.51.100.1 51234 443 extra\r\n",
            b"PROXY TCP4 2001:db8::1 2001:db8::2 51234 443\r\n",
            b"PROXY TCP6 192.0.2.7 198.51.100.1 51234 443\r\n",
            b"PROXY TCP4 192.0.2.7 198.51.100.1 99999 443\r\n",
            b"PROXY TCP4 010.0.2.7 198.51.100.1 51234 443\r\n",
            b"PROXY UDP4 192.0.2.7 198.51.100.1 51234 443\r\n",
        ];
        for raw in cases {
            assert!(
                matches!(parse(raw), Err(HeaderError::Malformed(_))),
                "expected malformed for {:?}, got {:?}",
                String::from_utf8_lossy(raw),
                parse(raw)
            );
        }
    }

    #[test]
    fn v2_inet_recovers_source_only() {
        let raw = v2_header(
            V2_CMD_PROXY,
            V2_AF_INET,
            &inet_block([192, 0, 2, 7], [198, 51, 100, 1], 51234, 443),
        );
        let (source, len, version) = complete(&raw);
        assert_eq!(source, Some("192.0.2.7:51234".parse().unwrap()));
        assert_eq!(len, raw.len());
        assert_eq!(version, Version::V2);
    }

    #[test]
    fn v2_inet6_recovers_source_only() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut block = src.octets().to_vec();
        block.extend_from_slice(&dst.octets());
        block.extend_from_slice(&51234u16.to_be_bytes());
        block.extend_from_slice(&443u16.to_be_bytes());
        let raw = v2_header(V2_CMD_PROXY, V2_AF_INET6, &block);
        let (source, _, _) = complete(&raw);
        assert_eq!(source, Some("[2001:db8::1]:51234".parse().unwrap()));
    }

    #[test]
    fn v2_local_yields_no_address() {
        let raw = v2_header(V2_CMD_LOCAL, 0, &[]);
        let (source, len, _) = complete(&raw);
        assert_eq!(source, None);
        assert_eq!(len, V2_HEADER_LEN);
    }

    #[test]
    fn v2_local_ignores_any_address_block_it_carries() {
        let raw = v2_header(
            V2_CMD_LOCAL,
            V2_AF_INET,
            &inet_block([192, 0, 2, 7], [198, 51, 100, 1], 51234, 443),
        );
        let (source, _, _) = complete(&raw);
        assert_eq!(source, None);
    }

    #[test]
    fn v2_unspecified_family_yields_no_address() {
        let raw = v2_header(V2_CMD_PROXY, 0, &[]);
        let (source, _, _) = complete(&raw);
        assert_eq!(source, None);
    }

    #[test]
    fn v2_tlvs_after_the_address_block_are_skipped() {
        let mut block = inet_block([192, 0, 2, 7], [198, 51, 100, 1], 51234, 443);
        block.extend_from_slice(&[0xEA, 0x00, 0x03, b'a', b'b', b'c']);
        let raw = v2_header(V2_CMD_PROXY, V2_AF_INET, &block);
        let (source, len, _) = complete(&raw);
        assert_eq!(source, Some("192.0.2.7:51234".parse().unwrap()));
        assert_eq!(len, raw.len(), "the TLV must be consumed, not left behind");
    }

    #[test]
    fn v2_rejects_structural_damage() {
        let good = inet_block([192, 0, 2, 7], [198, 51, 100, 1], 51234, 443);

        let mut wrong_version = v2_header(V2_CMD_PROXY, V2_AF_INET, &good);
        wrong_version[12] = 0x11;
        assert_eq!(
            parse(&wrong_version),
            Err(HeaderError::Malformed("v2 version is not 2"))
        );

        let mut bad_command = v2_header(V2_CMD_PROXY, V2_AF_INET, &good);
        bad_command[12] = 0x27;
        assert!(matches!(
            parse(&bad_command),
            Err(HeaderError::Malformed(_))
        ));

        let short_inet = v2_header(V2_CMD_PROXY, V2_AF_INET, &good[..8]);
        assert_eq!(
            parse(&short_inet),
            Err(HeaderError::Malformed("v2 inet block is short"))
        );

        let short_inet6 = v2_header(V2_CMD_PROXY, V2_AF_INET6, &good);
        assert_eq!(
            parse(&short_inet6),
            Err(HeaderError::Malformed("v2 inet6 block is short"))
        );

        let mut over_cap = v2_header(V2_CMD_PROXY, V2_AF_INET, &good);
        let body = (MAX_HEADER_LEN - V2_HEADER_LEN + 1) as u16;
        over_cap[14..16].copy_from_slice(&body.to_be_bytes());
        assert_eq!(parse(&over_cap), Err(HeaderError::TooLarge));
    }

    #[test]
    fn a_non_speaker_is_rejected_on_its_first_bytes() {
        assert_eq!(
            parse(b"GET / HTTP/1.1\r\n"),
            Err(HeaderError::NotProxyProtocol)
        );
        assert_eq!(parse(b"G"), Err(HeaderError::NotProxyProtocol));
        // a TLS ClientHello starts 0x16, which is neither signature
        assert_eq!(
            parse(&[0x16, 0x03, 0x01]),
            Err(HeaderError::NotProxyProtocol)
        );
        assert_eq!(parse(b"PROXZ"), Err(HeaderError::NotProxyProtocol));
        // a line ending inside the signature can only be a non-speaker: the
        // signature holds no CR or LF for it to have matched
        assert_eq!(parse(b"PROX\r\n"), Err(HeaderError::NotProxyProtocol));
        assert_eq!(parse(b"\r\n\r\nX"), Err(HeaderError::NotProxyProtocol));
        assert_eq!(parse(b""), Ok(HeaderParse::Incomplete));
    }

    /// every proper prefix of a good header must ask for more, never claim a
    /// short header or reject a peer that is speaking correctly.
    #[test]
    fn every_truncation_of_a_good_header_is_incomplete() {
        let v1 = b"PROXY TCP4 192.0.2.7 198.51.100.1 51234 443\r\n".to_vec();
        let v2 = v2_header(
            V2_CMD_PROXY,
            V2_AF_INET,
            &inet_block([192, 0, 2, 7], [198, 51, 100, 1], 51234, 443),
        );
        for raw in [v1, v2] {
            for cut in 0..raw.len() {
                assert_eq!(
                    parse(&raw[..cut]),
                    Ok(HeaderParse::Incomplete),
                    "prefix of {cut} bytes should be incomplete"
                );
            }
            assert!(matches!(
                parse(&raw),
                Ok(HeaderParse::Complete {
                    source: Some(_),
                    ..
                })
            ));
        }
    }

    #[test]
    fn cidr_matches_on_the_prefix_boundary() {
        let net: TrustedCidr = "10.1.0.0/16".parse().unwrap();
        assert!(net.contains("10.1.0.0".parse().unwrap()));
        assert!(net.contains("10.1.255.255".parse().unwrap()));
        assert!(!net.contains("10.2.0.0".parse().unwrap()));

        // a boundary that does not fall on a byte
        let net: TrustedCidr = "10.0.0.0/12".parse().unwrap();
        assert!(net.contains("10.15.255.255".parse().unwrap()));
        assert!(!net.contains("10.16.0.0".parse().unwrap()));

        let any: TrustedCidr = "0.0.0.0/0".parse().unwrap();
        assert!(any.contains("203.0.113.9".parse().unwrap()));
        assert!(
            !any.contains("2001:db8::1".parse().unwrap()),
            "families must not cross"
        );

        let host: TrustedCidr = "10.0.0.5".parse().unwrap();
        assert!(host.contains("10.0.0.5".parse().unwrap()));
        assert!(!host.contains("10.0.0.6".parse().unwrap()));

        let v6: TrustedCidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
    }

    /// a v4 peer on a dual-stack listener arrives as ::ffff:a.b.c.d, so without
    /// canonicalizing it would miss every v4 CIDR.
    #[test]
    fn cidr_matches_a_v4_mapped_peer() {
        let net: TrustedCidr = "10.1.0.0/16".parse().unwrap();
        assert!(net.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!net.contains("::ffff:10.2.2.3".parse().unwrap()));
    }

    #[test]
    fn cidr_rejects_bad_input() {
        assert!(matches!(
            "10.0.0.0/33".parse::<TrustedCidr>(),
            Err(CidrError::PrefixLen { max: 32, .. })
        ));
        assert!(matches!(
            "2001:db8::/129".parse::<TrustedCidr>(),
            Err(CidrError::PrefixLen { max: 128, .. })
        ));
        assert!(matches!(
            "10.0.0/8".parse::<TrustedCidr>(),
            Err(CidrError::Address(_))
        ));
        assert!(matches!(
            "10.0.0.0/x".parse::<TrustedCidr>(),
            Err(CidrError::Shape(_))
        ));
    }

    #[test]
    fn an_empty_trust_list_trusts_everything() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(peer_trusted(&[], peer));
        let only_private: TrustedCidr = "10.0.0.0/8".parse().unwrap();
        assert!(!peer_trusted(&[only_private], peer));
        assert!(peer_trusted(&[only_private], "10.9.9.9".parse().unwrap()));
    }
}
