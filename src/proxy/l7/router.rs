use std::collections::HashMap;
use std::sync::Arc;

use crate::balancer::RoundRobin;
use crate::config::ListenerConfig;
use crate::health::BackendPool;
use crate::proxy::l7::matcher::{
    CompositeMatcher, HostMatcher, Matcher, MatcherBuildError, MethodMatcher, PathPrefixMatcher,
    RouteContext, SniMatcher,
};

/// resolved pool target returned by a route match.
#[derive(Clone)]
pub struct PoolHandle {
    pub backends: Arc<BackendPool>,
    pub rr: Arc<RoundRobin>,
    pub name: Arc<str>,
}

pub struct RouteEntry {
    pub matcher: CompositeMatcher,
    pub pool: PoolHandle,
    /// auto-derived at config load; never re-computed per request.
    pub route_id: Arc<str>,
}

pub trait Router: Send + Sync {
    fn route<'a>(&'a self, ctx: &RouteContext<'_>) -> Option<&'a RouteEntry>;
}

pub struct ConfigRouter {
    routes: Vec<RouteEntry>,
}

impl ConfigRouter {
    pub fn new(routes: Vec<RouteEntry>) -> Self {
        Self { routes }
    }
}

impl Router for ConfigRouter {
    fn route<'a>(&'a self, ctx: &RouteContext<'_>) -> Option<&'a RouteEntry> {
        self.routes.iter().find(|r| r.matcher.matches(ctx))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RouterBuildError {
    #[error("route on listener {listener} references unknown pool '{pool}'")]
    UnknownPool { listener: String, pool: String },
    #[error("invalid host pattern '{pattern}': {reason}")]
    InvalidHostPattern { pattern: String, reason: String },
    #[error("invalid path prefix '{prefix}': {reason}")]
    InvalidPathPrefix { prefix: String, reason: String },
    #[error("invalid method '{method}': {reason}")]
    InvalidMethod { method: String, reason: String },
}

impl From<MatcherBuildError> for RouterBuildError {
    fn from(e: MatcherBuildError) -> Self {
        match e {
            MatcherBuildError::InvalidHostPattern { pattern, reason } => {
                RouterBuildError::InvalidHostPattern { pattern, reason }
            }
            MatcherBuildError::InvalidPathPrefix { prefix, reason } => {
                RouterBuildError::InvalidPathPrefix { prefix, reason }
            }
            MatcherBuildError::InvalidMethod { method, reason } => {
                RouterBuildError::InvalidMethod { method, reason }
            }
        }
    }
}

/// derive a stable, human-readable route_id from matcher conditions.
///
/// pairs are sorted alphabetically by key so the result is deterministic
/// regardless of config field declaration order.
pub fn derive_route_id(
    host: Option<&str>,
    path_prefix: Option<&str>,
    method: Option<&str>,
    sni: Option<&str>,
) -> Arc<str> {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    if let Some(h) = host {
        pairs.push(("host", h));
    }
    if let Some(m) = method {
        pairs.push(("method", m));
    }
    if let Some(p) = path_prefix {
        pairs.push(("path", p));
    }
    if let Some(s) = sni {
        pairs.push(("sni", s));
    }
    if pairs.is_empty() {
        return Arc::from("default");
    }
    pairs.sort_by_key(|(k, _)| *k);
    let id = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",");
    Arc::from(id.as_str())
}

/// build a `ConfigRouter` for a listener from the pool map.
///
/// if `listener.pool` is set → single catch-all entry.
/// if `listener.routes` is non-empty → one entry per route, declaration order preserved.
pub fn build_router(
    listener: &ListenerConfig,
    pool_map: &HashMap<String, (Arc<BackendPool>, Arc<RoundRobin>)>,
) -> Result<ConfigRouter, RouterBuildError> {
    if let Some(pool_name) = &listener.pool {
        let (backends, rr) =
            pool_map
                .get(pool_name)
                .ok_or_else(|| RouterBuildError::UnknownPool {
                    listener: listener.address.to_string(),
                    pool: pool_name.clone(),
                })?;
        let handle = PoolHandle {
            backends: backends.clone(),
            rr: rr.clone(),
            name: Arc::from(pool_name.as_str()),
        };
        return Ok(ConfigRouter::new(vec![RouteEntry {
            matcher: CompositeMatcher::new(vec![]),
            pool: handle,
            route_id: Arc::from("default"),
        }]));
    }

    let mut entries = Vec::with_capacity(listener.routes.len());
    for route_cfg in &listener.routes {
        let (backends, rr) =
            pool_map
                .get(&route_cfg.pool)
                .ok_or_else(|| RouterBuildError::UnknownPool {
                    listener: listener.address.to_string(),
                    pool: route_cfg.pool.clone(),
                })?;
        let handle = PoolHandle {
            backends: backends.clone(),
            rr: rr.clone(),
            name: Arc::from(route_cfg.pool.as_str()),
        };
        let mut matchers: Vec<Box<dyn Matcher + Send + Sync>> = Vec::new();
        if let Some(ref host) = route_cfg.host {
            matchers.push(Box::new(HostMatcher::new(host)?));
        }
        if let Some(ref path) = route_cfg.path_prefix {
            matchers.push(Box::new(PathPrefixMatcher::new(path)?));
        }
        if let Some(ref method) = route_cfg.method {
            matchers.push(Box::new(MethodMatcher::new(method)?));
        }
        if let Some(ref sni) = route_cfg.sni {
            matchers.push(Box::new(SniMatcher::new(sni)?));
        }
        let route_id = derive_route_id(
            route_cfg.host.as_deref(),
            route_cfg.path_prefix.as_deref(),
            route_cfg.method.as_deref(),
            route_cfg.sni.as_deref(),
        );
        entries.push(RouteEntry {
            matcher: CompositeMatcher::new(matchers),
            pool: handle,
            route_id,
        });
    }
    Ok(ConfigRouter::new(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeepaliveConfig;
    use crate::proxy::l7::matcher::{
        HostMatcher, Matcher, MethodMatcher, PathPrefixMatcher, RouteContext,
    };
    use std::net::IpAddr;
    use std::time::Duration;

    const EMPTY_HEADERS: &[crate::proxy::l7::parse::ParsedHeader] = &[];

    fn make_ctx<'a>(
        method: Option<&'a str>,
        host: Option<&'a str>,
        path: Option<&'a str>,
    ) -> RouteContext<'a> {
        RouteContext {
            method,
            host,
            path,
            headers: EMPTY_HEADERS,
            sni: None,
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        }
    }

    fn make_pool_handle(name: &str) -> PoolHandle {
        let pool = Arc::new(BackendPool::new(
            Arc::from(name),
            vec!["127.0.0.1:9000".parse().unwrap()],
            3,
            Duration::from_secs(10),
            KeepaliveConfig::default(),
        ));
        let rr = Arc::new(RoundRobin::new(pool.clone()));
        PoolHandle {
            backends: pool,
            rr,
            name: Arc::from(name),
        }
    }

    fn make_entry(matchers: Vec<Box<dyn Matcher + Send + Sync>>, pool_name: &str) -> RouteEntry {
        RouteEntry {
            matcher: CompositeMatcher::new(matchers),
            pool: make_pool_handle(pool_name),
            route_id: Arc::from(pool_name),
        }
    }

    fn host_matcher(h: &str) -> Box<dyn Matcher + Send + Sync> {
        Box::new(HostMatcher::new(h).unwrap())
    }

    fn path_matcher(p: &str) -> Box<dyn Matcher + Send + Sync> {
        Box::new(PathPrefixMatcher::new(p).unwrap())
    }

    fn method_matcher(m: &str) -> Box<dyn Matcher + Send + Sync> {
        Box::new(MethodMatcher::new(m).unwrap())
    }

    #[test]
    fn first_match_wins() {
        let router = ConfigRouter::new(vec![
            make_entry(vec![host_matcher("api.example.com")], "api"),
            make_entry(vec![host_matcher("web.example.com")], "web"),
        ]);
        let ctx = make_ctx(None, Some("api.example.com"), None);
        assert_eq!(router.route(&ctx).unwrap().pool.name.as_ref(), "api");
        let ctx2 = make_ctx(None, Some("web.example.com"), None);
        assert_eq!(router.route(&ctx2).unwrap().pool.name.as_ref(), "web");
    }

    #[test]
    fn declaration_order_overrides_specificity() {
        // catch-all listed first - specific host listed second never wins
        let router = ConfigRouter::new(vec![
            make_entry(vec![], "catch_all"),
            make_entry(vec![host_matcher("api.example.com")], "api"),
        ]);
        let ctx = make_ctx(None, Some("api.example.com"), None);
        assert_eq!(router.route(&ctx).unwrap().pool.name.as_ref(), "catch_all");
    }

    #[test]
    fn catch_all_falls_through() {
        let router = ConfigRouter::new(vec![
            make_entry(vec![host_matcher("api.example.com")], "api"),
            make_entry(vec![], "default"),
        ]);
        let ctx = make_ctx(None, Some("other.example.com"), None);
        assert_eq!(router.route(&ctx).unwrap().pool.name.as_ref(), "default");
    }

    #[test]
    fn no_match_returns_none() {
        let router = ConfigRouter::new(vec![make_entry(
            vec![host_matcher("api.example.com")],
            "api",
        )]);
        let ctx = make_ctx(None, Some("other.com"), None);
        assert!(router.route(&ctx).is_none());
    }

    #[test]
    fn route_id_single_host() {
        let id = derive_route_id(Some("api.example.com"), None, None, None);
        assert_eq!(id.as_ref(), "host=api.example.com");
    }

    #[test]
    fn route_id_single_path() {
        let id = derive_route_id(None, Some("/admin"), None, None);
        assert_eq!(id.as_ref(), "path=/admin");
    }

    #[test]
    fn route_id_composite_sorted() {
        // declared as path+host - must sort to host,path
        let id = derive_route_id(Some("api.example.com"), Some("/v1"), None, None);
        assert_eq!(id.as_ref(), "host=api.example.com,path=/v1");
    }

    #[test]
    fn route_id_wildcard_host_renders_star() {
        let id = derive_route_id(Some("*.example.com"), None, None, None);
        assert_eq!(id.as_ref(), "host=*.example.com");
    }

    #[test]
    fn route_id_catch_all_is_default() {
        let id = derive_route_id(None, None, None, None);
        assert_eq!(id.as_ref(), "default");
    }

    #[test]
    fn route_id_method_included() {
        let id = derive_route_id(None, None, Some("POST"), None);
        assert_eq!(id.as_ref(), "method=POST");
    }

    #[test]
    fn route_id_all_fields_sorted() {
        let id = derive_route_id(
            Some("api.example.com"),
            Some("/v1"),
            Some("POST"),
            Some("api.test"),
        );
        assert_eq!(
            id.as_ref(),
            "host=api.example.com,method=POST,path=/v1,sni=api.test"
        );
    }

    // verify unused helpers compile cleanly (prevents dead-code warnings on test helpers)
    #[test]
    fn composite_routing_with_method_and_path() {
        let router = ConfigRouter::new(vec![
            make_entry(vec![method_matcher("POST"), path_matcher("/api")], "api"),
            make_entry(vec![], "default"),
        ]);
        // POST /api/v1 → api
        let ctx = make_ctx(Some("POST"), None, Some("/api/v1"));
        assert_eq!(router.route(&ctx).unwrap().pool.name.as_ref(), "api");
        // GET /api/v1 → default (method mismatch)
        let ctx2 = make_ctx(Some("GET"), None, Some("/api/v1"));
        assert_eq!(router.route(&ctx2).unwrap().pool.name.as_ref(), "default");
    }
}
