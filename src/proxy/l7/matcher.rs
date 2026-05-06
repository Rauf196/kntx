use std::net::IpAddr;

use crate::proxy::l7::parse::ParsedHeader;

pub struct RouteContext<'a> {
    pub method: Option<&'a str>,
    /// raw Host header value (port not stripped). Matchers strip on demand.
    pub host: Option<&'a str>,
    pub path: Option<&'a str>,
    /// always present for L7; empty slice for L4.
    pub headers: &'a [ParsedHeader],
    pub sni: Option<&'a str>,
    pub client_ip: IpAddr,
}

pub trait Matcher: Send + Sync {
    fn matches(&self, ctx: &RouteContext<'_>) -> bool;
}

#[derive(Debug, Clone)]
pub(crate) enum HostPattern {
    Exact(String),
    /// stored as ".example.com" — host must end with this and have a non-empty prefix.
    Wildcard(String),
}

impl HostPattern {
    /// host must already be port-stripped via `host_for_routing`.
    fn matches_host_value(&self, host: &str) -> bool {
        match self {
            HostPattern::Exact(s) => host.eq_ignore_ascii_case(s),
            HostPattern::Wildcard(suffix) => {
                host.len() > suffix.len()
                    && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            }
        }
    }

    /// re-render as the user-facing string (e.g. "*.example.com" for a wildcard).
    #[allow(dead_code)] // used in M2 router for derive_route_id
    pub(crate) fn to_config_string(&self) -> String {
        match self {
            HostPattern::Exact(s) => s.clone(),
            HostPattern::Wildcard(suffix) => format!("*{suffix}"),
        }
    }
}

pub struct HostMatcher {
    pattern: HostPattern,
}

pub struct PathPrefixMatcher {
    prefix: String,
}

pub struct MethodMatcher {
    method: String,
}

pub struct SniMatcher {
    pattern: HostPattern,
}

pub struct CompositeMatcher {
    matchers: Vec<Box<dyn Matcher + Send + Sync>>,
}

#[derive(Debug, thiserror::Error)]
pub enum MatcherBuildError {
    #[error("invalid host pattern '{pattern}': {reason}")]
    InvalidHostPattern { pattern: String, reason: String },
    #[error("invalid path prefix '{prefix}': {reason}")]
    InvalidPathPrefix { prefix: String, reason: String },
    #[error("invalid method '{method}': {reason}")]
    InvalidMethod { method: String, reason: String },
}

pub(crate) fn parse_host_pattern(pattern: &str) -> Result<HostPattern, MatcherBuildError> {
    if pattern.contains('*') {
        if !pattern.starts_with("*.") {
            return Err(MatcherBuildError::InvalidHostPattern {
                pattern: pattern.to_owned(),
                reason: "wildcard must start with '*.' (e.g. '*.example.com')".to_owned(),
            });
        }
        let rest = &pattern[2..];
        if rest.is_empty() {
            return Err(MatcherBuildError::InvalidHostPattern {
                pattern: pattern.to_owned(),
                reason: "wildcard suffix must not be empty".to_owned(),
            });
        }
        Ok(HostPattern::Wildcard(format!(".{rest}")))
    } else {
        Ok(HostPattern::Exact(pattern.to_owned()))
    }
}

impl HostMatcher {
    pub fn new(pattern: &str) -> Result<Self, MatcherBuildError> {
        Ok(Self {
            pattern: parse_host_pattern(pattern)?,
        })
    }
}

impl Matcher for HostMatcher {
    fn matches(&self, ctx: &RouteContext<'_>) -> bool {
        ctx.host
            .is_some_and(|h| self.pattern.matches_host_value(host_for_routing(h)))
    }
}

impl PathPrefixMatcher {
    pub fn new(prefix: &str) -> Result<Self, MatcherBuildError> {
        if !prefix.starts_with('/') {
            return Err(MatcherBuildError::InvalidPathPrefix {
                prefix: prefix.to_owned(),
                reason: "must start with '/'".to_owned(),
            });
        }
        if prefix != "/" && prefix.ends_with('/') {
            return Err(MatcherBuildError::InvalidPathPrefix {
                prefix: prefix.to_owned(),
                reason: "must not end with '/' (write '/api' not '/api/')".to_owned(),
            });
        }
        Ok(Self {
            prefix: prefix.to_owned(),
        })
    }
}

impl Matcher for PathPrefixMatcher {
    fn matches(&self, ctx: &RouteContext<'_>) -> bool {
        let path = match ctx.path {
            Some(p) => p,
            None => return false,
        };
        if self.prefix == "/" {
            return path.starts_with('/');
        }
        if path == self.prefix.as_str() {
            return true;
        }
        if path.starts_with(self.prefix.as_str())
            && path.as_bytes().get(self.prefix.len()) == Some(&b'/')
        {
            return true;
        }
        false
    }
}

fn is_valid_method_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

impl MethodMatcher {
    pub fn new(method: &str) -> Result<Self, MatcherBuildError> {
        if method.is_empty() {
            return Err(MatcherBuildError::InvalidMethod {
                method: method.to_owned(),
                reason: "must not be empty".to_owned(),
            });
        }
        if !method.bytes().all(is_valid_method_token_char) {
            return Err(MatcherBuildError::InvalidMethod {
                method: method.to_owned(),
                reason: "must contain only ASCII token characters".to_owned(),
            });
        }
        Ok(Self {
            method: method.to_owned(),
        })
    }
}

impl Matcher for MethodMatcher {
    fn matches(&self, ctx: &RouteContext<'_>) -> bool {
        ctx.method == Some(self.method.as_str())
    }
}

impl SniMatcher {
    pub fn new(pattern: &str) -> Result<Self, MatcherBuildError> {
        Ok(Self {
            pattern: parse_host_pattern(pattern)?,
        })
    }
}

impl Matcher for SniMatcher {
    fn matches(&self, ctx: &RouteContext<'_>) -> bool {
        // SNI from rustls has no port; compare directly (case-insensitive per spec)
        ctx.sni.is_some_and(|s| self.pattern.matches_host_value(s))
    }
}

impl CompositeMatcher {
    pub fn new(matchers: Vec<Box<dyn Matcher + Send + Sync>>) -> Self {
        Self { matchers }
    }

    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }
}

impl Matcher for CompositeMatcher {
    fn matches(&self, ctx: &RouteContext<'_>) -> bool {
        self.matchers.iter().all(|m| m.matches(ctx))
    }
}

/// strip port from a Host header value; preserve IPv6 brackets.
///
/// "example.com:8080" -> "example.com"
/// "example.com"      -> "example.com"
/// "[::1]:8080"       -> "[::1]"
/// "[::1]"            -> "[::1]"
pub fn host_for_routing(host: &str) -> &str {
    if host.starts_with('[') {
        // IPv6 literal — find closing bracket
        if let Some(close) = host.find(']') {
            return &host[..=close];
        }
        return host; // defensive: malformed IPv6, return whole
    }
    match host.find(':') {
        Some(idx) => &host[..idx],
        None => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const EMPTY_HEADERS: &[ParsedHeader] = &[];

    fn ctx_with_host(host: &str) -> RouteContext<'_> {
        RouteContext {
            method: Some("GET"),
            host: Some(host),
            path: Some("/"),
            headers: EMPTY_HEADERS,
            sni: None,
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        }
    }

    fn ctx_with_path(path: &str) -> RouteContext<'_> {
        RouteContext {
            method: Some("GET"),
            host: None,
            path: Some(path),
            headers: EMPTY_HEADERS,
            sni: None,
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        }
    }

    fn ctx_with_method(method: &str) -> RouteContext<'_> {
        RouteContext {
            method: Some(method),
            host: None,
            path: Some("/"),
            headers: EMPTY_HEADERS,
            sni: None,
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        }
    }

    fn ctx_with_sni(sni: &str) -> RouteContext<'_> {
        RouteContext {
            method: None,
            host: None,
            path: None,
            headers: EMPTY_HEADERS,
            sni: Some(sni),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        }
    }

    fn empty_ctx() -> RouteContext<'static> {
        RouteContext {
            method: None,
            host: None,
            path: None,
            headers: EMPTY_HEADERS,
            sni: None,
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        }
    }

    // --- HostMatcher ---

    #[test]
    fn host_exact_case_insensitive() {
        let m = HostMatcher::new("example.com").unwrap();
        assert!(m.matches(&ctx_with_host("Example.COM")));
        assert!(m.matches(&ctx_with_host("EXAMPLE.COM")));
        assert!(m.matches(&ctx_with_host("example.com")));
    }

    #[test]
    fn host_exact_with_port_stripped() {
        let m = HostMatcher::new("example.com").unwrap();
        assert!(m.matches(&ctx_with_host("Example.com:8080")));
        assert!(!m.matches(&ctx_with_host("other.com:8080")));
    }

    #[test]
    fn host_exact_ipv6_brackets_preserved() {
        let m = HostMatcher::new("[::1]").unwrap();
        assert!(m.matches(&ctx_with_host("[::1]:8080")));
        assert!(m.matches(&ctx_with_host("[::1]")));
        assert!(!m.matches(&ctx_with_host("[::2]:8080")));
    }

    #[test]
    fn host_wildcard_single_label() {
        let m = HostMatcher::new("*.example.com").unwrap();
        assert!(m.matches(&ctx_with_host("api.example.com")));
    }

    #[test]
    fn host_wildcard_multi_label() {
        // critical regression: deep subdomain must match
        let m = HostMatcher::new("*.example.com").unwrap();
        assert!(m.matches(&ctx_with_host("a.b.example.com")));
        assert!(m.matches(&ctx_with_host("x.y.z.example.com")));
    }

    #[test]
    fn host_wildcard_does_not_match_apex() {
        let m = HostMatcher::new("*.example.com").unwrap();
        assert!(!m.matches(&ctx_with_host("example.com")));
    }

    #[test]
    fn host_wildcard_does_not_match_unrelated() {
        let m = HostMatcher::new("*.example.com").unwrap();
        assert!(!m.matches(&ctx_with_host("api.other.com")));
        assert!(!m.matches(&ctx_with_host("api.example.org")));
    }

    // --- PathPrefixMatcher ---

    #[test]
    fn path_prefix_exact_match() {
        let m = PathPrefixMatcher::new("/api").unwrap();
        assert!(m.matches(&ctx_with_path("/api")));
    }

    #[test]
    fn path_prefix_with_trailing_segment() {
        let m = PathPrefixMatcher::new("/api").unwrap();
        assert!(m.matches(&ctx_with_path("/api/v1")));
        assert!(m.matches(&ctx_with_path("/api/")));
    }

    #[test]
    fn path_prefix_word_boundary_blocks_apiv2() {
        // critical regression: word boundary enforcement
        let m = PathPrefixMatcher::new("/api").unwrap();
        assert!(!m.matches(&ctx_with_path("/apiv2")));
        assert!(!m.matches(&ctx_with_path("/apiother")));
    }

    #[test]
    fn path_prefix_root_matches_everything() {
        let m = PathPrefixMatcher::new("/").unwrap();
        assert!(m.matches(&ctx_with_path("/")));
        assert!(m.matches(&ctx_with_path("/foo")));
        assert!(m.matches(&ctx_with_path("/foo/bar")));
        assert!(m.matches(&ctx_with_path("/api/v1/resource")));
    }

    // --- MethodMatcher ---

    #[test]
    fn method_exact_case_sensitive() {
        let m = MethodMatcher::new("GET").unwrap();
        assert!(m.matches(&ctx_with_method("GET")));
        assert!(!m.matches(&ctx_with_method("get")));
        assert!(!m.matches(&ctx_with_method("Get")));
        assert!(!m.matches(&ctx_with_method("POST")));
    }

    // --- SniMatcher ---

    #[test]
    fn sni_wildcard_multi_label() {
        let m = SniMatcher::new("*.example.com").unwrap();
        assert!(m.matches(&ctx_with_sni("a.b.example.com")));
        assert!(m.matches(&ctx_with_sni("api.example.com")));
        assert!(!m.matches(&ctx_with_sni("example.com")));
        assert!(!m.matches(&ctx_with_sni("api.other.com")));
    }

    // --- CompositeMatcher ---

    #[test]
    fn composite_and_all_required() {
        let composite = CompositeMatcher::new(vec![
            Box::new(HostMatcher::new("api.example.com").unwrap()),
            Box::new(PathPrefixMatcher::new("/v1").unwrap()),
        ]);
        // both match
        let ctx = RouteContext {
            method: Some("GET"),
            host: Some("api.example.com"),
            path: Some("/v1/users"),
            headers: EMPTY_HEADERS,
            sni: None,
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        };
        assert!(composite.matches(&ctx));

        // host matches, path does not
        let ctx_no_path = RouteContext {
            path: Some("/other"),
            ..ctx
        };
        assert!(!composite.matches(&ctx_no_path));

        // path matches, host does not
        let ctx_no_host = RouteContext {
            host: Some("other.example.com"),
            path: Some("/v1/users"),
            ..ctx
        };
        assert!(!composite.matches(&ctx_no_host));
    }

    #[test]
    fn composite_empty_is_catch_all() {
        let composite = CompositeMatcher::new(vec![]);
        assert!(composite.is_empty());
        assert!(composite.matches(&empty_ctx()));
        assert!(composite.matches(&ctx_with_host("anything.com")));
        assert!(composite.matches(&ctx_with_path("/any/path")));
    }

    // --- host_for_routing ---

    #[test]
    fn host_for_routing_strips_port() {
        assert_eq!(host_for_routing("example.com:8080"), "example.com");
        assert_eq!(host_for_routing("localhost:3000"), "localhost");
    }

    #[test]
    fn host_for_routing_ipv6() {
        assert_eq!(host_for_routing("[::1]:8080"), "[::1]");
        assert_eq!(host_for_routing("[2001:db8::1]:443"), "[2001:db8::1]");
    }

    #[test]
    fn host_for_routing_no_port_passthrough() {
        assert_eq!(host_for_routing("example.com"), "example.com");
        assert_eq!(host_for_routing("[::1]"), "[::1]");
    }

    // --- parse_host_pattern ---

    #[test]
    fn parses_exact_pattern() {
        let p = parse_host_pattern("example.com").unwrap();
        assert!(matches!(p, HostPattern::Exact(_)));
    }

    #[test]
    fn parses_wildcard_pattern() {
        let p = parse_host_pattern("*.example.com").unwrap();
        assert!(matches!(p, HostPattern::Wildcard(_)));
        assert_eq!(p.to_config_string(), "*.example.com");
    }

    #[test]
    fn rejects_bare_star() {
        assert!(parse_host_pattern("*").is_err());
    }

    #[test]
    fn rejects_no_dot_after_star() {
        assert!(parse_host_pattern("*example.com").is_err());
    }

    #[test]
    fn rejects_mid_string_star() {
        assert!(parse_host_pattern("foo.*.com").is_err());
    }

    #[test]
    fn rejects_bare_star_dot() {
        // "*." has empty rest
        assert!(parse_host_pattern("*.").is_err());
    }

    // --- PathPrefixMatcher validation ---

    #[test]
    fn rejects_path_prefix_without_leading_slash() {
        assert!(PathPrefixMatcher::new("api").is_err());
        assert!(PathPrefixMatcher::new("api/v1").is_err());
    }

    #[test]
    fn rejects_path_prefix_trailing_slash() {
        assert!(PathPrefixMatcher::new("/api/").is_err());
        assert!(PathPrefixMatcher::new("/v1/").is_err());
    }

    #[test]
    fn allows_root_path_prefix() {
        // "/" alone is allowed even though it ends with '/'
        assert!(PathPrefixMatcher::new("/").is_ok());
    }

    // --- MethodMatcher validation ---

    #[test]
    fn rejects_empty_method() {
        assert!(MethodMatcher::new("").is_err());
    }

    #[test]
    fn rejects_method_with_whitespace() {
        assert!(MethodMatcher::new("G ET").is_err());
        assert!(MethodMatcher::new("GET ").is_err());
        assert!(MethodMatcher::new(" GET").is_err());
    }

    #[test]
    fn accepts_valid_method_tokens() {
        // lowercase is valid token chars per spec; case-sensitivity is in matching not validation
        assert!(MethodMatcher::new("GET").is_ok());
        assert!(MethodMatcher::new("POST").is_ok());
        assert!(MethodMatcher::new("PATCH").is_ok());
        assert!(MethodMatcher::new("get").is_ok());
    }
}
