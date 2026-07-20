use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

/// route entry inside a `[[listeners.routes]]` array.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RouteConfig {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    pub pool: String,
    /// rate limit zone enforced per request after this route matches. l7 only.
    #[serde(default)]
    pub rate_limit: Option<String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file '{path}'")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config file '{path}'")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },

    #[error("listeners list is empty")]
    EmptyListeners,

    #[error("pools list is empty")]
    EmptyPools,

    #[error("duplicate pool name: '{name}'")]
    DuplicatePoolName { name: String },

    #[error("duplicate listener address: {address}")]
    DuplicateListenerAddress { address: SocketAddr },

    #[error(
        "listener {wildcard} overlaps with {other} \
         (wildcard address claims the same port on all interfaces)"
    )]
    OverlappingListenerAddress {
        wildcard: SocketAddr,
        other: SocketAddr,
    },

    #[error("listener {listener} references unknown pool '{pool}'")]
    UnknownPoolReference { listener: SocketAddr, pool: String },

    #[error("listener {listener} has both 'pool' and 'routes' - use one or the other")]
    ListenerHasBothPoolAndRoutes { listener: SocketAddr },

    #[error("listener {listener} has neither 'pool' nor 'routes' - one is required")]
    ListenerHasNeitherPoolNorRoutes { listener: SocketAddr },

    #[error(
        "listener {listener} has routes but is plain L4 (no TLS) - routes require L7 or L4+TLS"
    )]
    RoutesOnPlainL4Listener { listener: SocketAddr },

    #[error("route on listener {listener} uses 'sni' but listener has no TLS")]
    SniMatcherOnNonTlsListener { listener: SocketAddr },

    #[error(
        "listener {listener} is tls-passthrough but has a [listeners.tls] section - \
         passthrough never terminates TLS"
    )]
    TlsTerminationOnPassthroughListener { listener: SocketAddr },

    #[error(
        "route on listener {listener} uses '{field}' but the listener is tls-passthrough - \
         only 'sni' is visible without terminating TLS"
    )]
    HttpMatcherOnPassthroughListener {
        listener: SocketAddr,
        field: &'static str,
    },

    #[error("route on listener {listener} references unknown pool '{pool}'")]
    UnknownRoutePoolReference { listener: SocketAddr, pool: String },

    #[error("route on listener {listener} has invalid host pattern '{pattern}'")]
    InvalidHostPattern {
        listener: SocketAddr,
        pattern: String,
    },

    #[error("route on listener {listener} has invalid path prefix '{prefix}'")]
    InvalidPathPrefix {
        listener: SocketAddr,
        prefix: String,
    },

    #[error("route on listener {listener} has invalid method '{method}'")]
    InvalidRouteMethod {
        listener: SocketAddr,
        method: String,
    },

    #[error("pool '{pool}' has no backends")]
    EmptyPoolBackends { pool: String },

    #[error("invalid value for '{field}': {reason}")]
    InvalidValue { field: &'static str, reason: String },

    #[error("TLS cert file not found: '{path}'")]
    TlsCertFileNotFound { path: PathBuf },

    #[error("TLS key file not found: '{path}'")]
    TlsKeyFileNotFound { path: PathBuf },

    #[error("error page file not found for status {status}: '{path}'")]
    ErrorPageFileNotFound { status: String, path: PathBuf },

    #[error("rate limit zone '{zone}': rate must be >= 1")]
    RateLimitZeroRate { zone: String },

    #[error("rate limit zone '{zone}': max_keys only applies to client_ip zones, not global")]
    RateLimitMaxKeysOnGlobalZone { zone: String },

    #[error("rate limit zone '{zone}': max_keys must be >= 4 (one 4-way set)")]
    RateLimitMaxKeysTooSmall { zone: String },

    #[error("listener {listener} references unknown rate limit zone '{zone}'")]
    UnknownRateLimitZone { listener: SocketAddr, zone: String },

    #[error("route on listener {listener} references unknown rate limit zone '{zone}'")]
    UnknownRouteRateLimitZone { listener: SocketAddr, zone: String },

    #[error(
        "route on listener {listener} sets 'rate_limit' but the listener is not l7 - \
         route limits are enforced per HTTP request; use the listener-level rate_limit"
    )]
    RateLimitOnNonL7Route { listener: SocketAddr },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardingStrategy {
    #[default]
    Userspace,
    Vectored,
    #[cfg(target_os = "linux")]
    Splice,
}

impl fmt::Display for ForwardingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Userspace => f.write_str("userspace"),
            Self::Vectored => f.write_str("vectored"),
            #[cfg(target_os = "linux")]
            Self::Splice => f.write_str("splice"),
        }
    }
}

/// which protocol mode this listener runs in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerMode {
    #[default]
    L4,
    L7,
    /// peek the ClientHello for SNI, route, then forward raw encrypted bytes.
    /// the client handshakes with the backend - kntx never terminates.
    #[serde(rename = "tls-passthrough")]
    TlsPassthrough,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    #[serde(default)]
    pub pools: Vec<PoolConfig>,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub forwarding: ForwardingConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub error_pages: ErrorPagesConfig,
    #[serde(default)]
    pub access_log: AccessLogConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    pub address: SocketAddr,
    #[serde(default)]
    pub mode: ListenerMode,
    /// single-pool reference. exactly one of pool or routes must be set.
    pub pool: Option<String>,
    /// config-driven route table. exactly one of pool or routes must be set.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    pub max_connections: Option<usize>,
    pub idle_timeout_secs: Option<u64>,
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_max_connect_attempts")]
    pub max_connect_attempts: u32,
    pub tls: Option<TlsConfig>,
    #[serde(default = "default_header_size_limit")]
    pub header_size_limit_bytes: usize,
    // phase-specific timeouts; each falls back to idle_timeout_secs when None.
    pub client_header_timeout_secs: Option<u64>,
    pub client_body_timeout_secs: Option<u64>,
    pub proxy_send_timeout_secs: Option<u64>,
    pub proxy_read_timeout_secs: Option<u64>,
    // overall request deadline from head-start to response-body-complete.
    pub request_timeout_secs: Option<u64>,
    // max request body bytes; None uses proxy default (1 MiB); 0 = unlimited.
    pub max_body_size_bytes: Option<u64>,
    // max idle gap between requests on a kept-alive client connection.
    pub keepalive_idle_timeout_secs: Option<u64>,
    // max sequential requests on one client keep-alive connection; None = default 1000.
    pub keepalive_max_requests: Option<u32>,
    // tls-passthrough only: max time to receive the full ClientHello.
    // slowloris bound on the peek phase, like nginx preread_timeout.
    #[serde(default = "default_clienthello_timeout")]
    pub clienthello_timeout_secs: u64,
    /// rate limit zone enforced per connection at accept, any mode.
    pub rate_limit: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PoolConfig {
    pub name: String,
    pub backends: Vec<BackendConfig>,
    pub health: Option<PoolHealthOverride>,
    #[serde(default)]
    pub keepalive: KeepaliveConfig,
}

impl PoolConfig {
    pub fn effective_health(&self, defaults: &HealthConfig) -> ResolvedHealth {
        let ovr = self.health.as_ref();
        ResolvedHealth {
            check_interval_secs: ovr
                .and_then(|o| o.check_interval_secs)
                .or(defaults.check_interval_secs),
            failure_threshold: ovr
                .and_then(|o| o.failure_threshold)
                .unwrap_or(defaults.failure_threshold),
            recovery_timeout_secs: ovr
                .and_then(|o| o.recovery_timeout_secs)
                .unwrap_or(defaults.recovery_timeout_secs),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PoolHealthOverride {
    pub check_interval_secs: Option<u64>,
    pub failure_threshold: Option<u32>,
    pub recovery_timeout_secs: Option<u64>,
}

pub struct ResolvedHealth {
    pub check_interval_secs: Option<u64>,
    pub failure_threshold: u32,
    pub recovery_timeout_secs: u64,
}

/// backend keep-alive cache configuration. nested as `[pools.keepalive]`.
///
/// named `idle_conn_ttl_secs` not `idle_timeout_secs` to avoid collision
/// with the listener-level `idle_timeout_secs` (completely different semantics:
/// cache TTL for an idle backend conn vs inter-byte gap on a request stream).
#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct KeepaliveConfig {
    /// max idle conns per backend; 0 disables backend keep-alive entirely.
    pub max_idle: usize,
    /// how long an idle conn stays in the cache before the sweeper drops it.
    pub idle_conn_ttl_secs: u64,
    /// max total conns to one backend (active + idle); 0 = unlimited.
    pub max_total: u64,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            max_idle: 32,
            idle_conn_ttl_secs: 60,
            max_total: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_min_version")]
    pub min_version: String,
    pub certificates: Vec<CertificateConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertificateConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// SNI hostnames this cert serves. required when multiple certs are configured.
    #[serde(default)]
    pub sni_names: Vec<String>,
}

fn default_handshake_timeout() -> u64 {
    5
}

fn default_min_version() -> String {
    "1.2".to_owned()
}

#[derive(Debug, Default, Deserialize)]
pub struct ForwardingConfig {
    #[serde(default)]
    pub strategy: ForwardingStrategy,
    /// SO_RCVBUF/SO_SNDBUF size in bytes. None = OS default.
    pub socket_buffer_size: Option<usize>,
    /// Body-forwarding buffer pool capacity (number of buffers).
    /// Each L7 connection holds one buffer for its lifetime, so this caps
    /// concurrent L7 connections; tune up for high-fanout deployments. None
    /// = built-in default (matches the L4 pipe-pool sizing assumption).
    pub buffer_pool_capacity: Option<usize>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:0".parse().unwrap(),
            mode: ListenerMode::default(),
            pool: None,
            routes: Vec::new(),
            max_connections: None,
            idle_timeout_secs: None,
            drain_timeout_secs: default_drain_timeout(),
            connect_timeout_secs: default_connect_timeout(),
            max_connect_attempts: default_max_connect_attempts(),
            tls: None,
            header_size_limit_bytes: default_header_size_limit(),
            client_header_timeout_secs: None,
            client_body_timeout_secs: None,
            proxy_send_timeout_secs: None,
            proxy_read_timeout_secs: None,
            request_timeout_secs: None,
            max_body_size_bytes: None,
            keepalive_idle_timeout_secs: None,
            keepalive_max_requests: None,
            clienthello_timeout_secs: default_clienthello_timeout(),
            rate_limit: None,
        }
    }
}

fn default_drain_timeout() -> u64 {
    30
}

fn default_clienthello_timeout() -> u64 {
    10
}

fn default_connect_timeout() -> u64 {
    5
}

fn default_max_connect_attempts() -> u32 {
    3
}

#[derive(Debug, Deserialize)]
pub struct HealthConfig {
    /// active probe interval in seconds. None = no active health checks.
    pub check_interval_secs: Option<u64>,
    /// consecutive failures before circuit opens. default 3.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// seconds to wait in Open state before allowing a probe. default 10.
    #[serde(default = "default_recovery_timeout")]
    pub recovery_timeout_secs: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: None,
            failure_threshold: default_failure_threshold(),
            recovery_timeout_secs: default_recovery_timeout(),
        }
    }
}

fn default_failure_threshold() -> u32 {
    3
}

fn default_recovery_timeout() -> u64 {
    10
}

#[derive(Debug, Deserialize)]
pub struct BackendConfig {
    pub address: SocketAddr,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    pub address: SocketAddr,
}

fn default_header_size_limit() -> usize {
    16384
}

/// maps status codes (as strings) to custom error page file paths.
/// keys are strings because TOML requires string keys for quoted numeric keys.
#[derive(Debug, Default, Deserialize)]
pub struct ErrorPagesConfig {
    #[serde(flatten)]
    pub pages: std::collections::HashMap<String, std::path::PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AccessLogOutput {
    Named(String),
    File { file: std::path::PathBuf },
}

impl Default for AccessLogOutput {
    fn default() -> Self {
        Self::Named("stdout".to_owned())
    }
}

#[derive(Debug, Deserialize)]
pub struct AccessLogConfig {
    #[serde(default)]
    pub output: AccessLogOutput,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default = "default_file_channel_capacity")]
    pub file_channel_capacity: usize,
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            output: AccessLogOutput::default(),
            format: None,
            file_channel_capacity: default_file_channel_capacity(),
        }
    }
}

fn default_file_channel_capacity() -> usize {
    4096
}

/// named rate limit zones, `[rate_limit.zones.<name>]`. a zone is one
/// limiter instance; every listener and route referencing the name shares
/// its budget.
#[derive(Debug, Default, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub zones: HashMap<String, ZoneConfig>,
}

pub const DEFAULT_ZONE_MAX_KEYS: u32 = 65536;

#[derive(Debug, Deserialize)]
pub struct ZoneConfig {
    pub key: ZoneKey,
    /// admitted events per `per`, sustained. must be >= 1.
    pub rate: u32,
    #[serde(default)]
    pub per: RatePeriod,
    /// events admitted back to back beyond the paced one; 0 = strict pacing.
    #[serde(default)]
    pub burst: u32,
    /// client_ip zones only: state capacity, rounded up to a power-of-two
    /// set count at startup. None = 65536 (~1 MiB).
    pub max_keys: Option<u32>,
}

/// what a zone counts: one budget per client IP, or one shared budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKey {
    ClientIp,
    Global,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum RatePeriod {
    #[default]
    #[serde(rename = "s")]
    Second,
    #[serde(rename = "m")]
    Minute,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(Path::new(path)).map_err(|source| ConfigError::ReadFile {
                path: path.to_owned(),
                source,
            })?;

        let config: Config = toml::from_str(&content).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.listeners.is_empty() {
            return Err(ConfigError::EmptyListeners);
        }
        if self.pools.is_empty() {
            return Err(ConfigError::EmptyPools);
        }

        // listener address uniqueness - exact dup
        let mut seen_addrs: HashSet<SocketAddr> = HashSet::new();
        for listener in &self.listeners {
            if !seen_addrs.insert(listener.address) {
                return Err(ConfigError::DuplicateListenerAddress {
                    address: listener.address,
                });
            }
        }

        // listener address overlap - wildcard (0.0.0.0 / ::) on a port
        // claims that port on every interface, so it conflicts with any
        // other listener on the same port. kernel would catch this with
        // EADDRINUSE on bind, but a config-time error is clearer.
        let mut by_port: HashMap<u16, Vec<SocketAddr>> = HashMap::new();
        for listener in &self.listeners {
            by_port
                .entry(listener.address.port())
                .or_default()
                .push(listener.address);
        }
        for addrs in by_port.values() {
            if addrs.len() <= 1 {
                continue;
            }
            if let Some(wildcard) = addrs.iter().find(|a| a.ip().is_unspecified()) {
                let other = addrs
                    .iter()
                    .find(|a| *a != wildcard)
                    .copied()
                    .expect("len > 1 and wildcard found, so a different addr must exist");
                return Err(ConfigError::OverlappingListenerAddress {
                    wildcard: *wildcard,
                    other,
                });
            }
        }

        // pool name uniqueness
        let mut seen_pools: HashSet<&str> = HashSet::new();
        for pool in &self.pools {
            if !seen_pools.insert(pool.name.as_str()) {
                return Err(ConfigError::DuplicatePoolName {
                    name: pool.name.clone(),
                });
            }
        }

        // rate limit zone definitions
        for (name, zone) in &self.rate_limit.zones {
            if zone.rate == 0 {
                return Err(ConfigError::RateLimitZeroRate { zone: name.clone() });
            }
            match (zone.key, zone.max_keys) {
                (ZoneKey::Global, Some(_)) => {
                    return Err(ConfigError::RateLimitMaxKeysOnGlobalZone { zone: name.clone() });
                }
                (ZoneKey::ClientIp, Some(max_keys)) if max_keys < 4 => {
                    return Err(ConfigError::RateLimitMaxKeysTooSmall { zone: name.clone() });
                }
                _ => {}
            }
        }

        // listener routing: exactly one of pool or routes, validated per listener
        for listener in &self.listeners {
            if let Some(zone) = &listener.rate_limit
                && !self.rate_limit.zones.contains_key(zone)
            {
                return Err(ConfigError::UnknownRateLimitZone {
                    listener: listener.address,
                    zone: zone.clone(),
                });
            }
            match (&listener.pool, listener.routes.is_empty()) {
                (Some(_), false) => {
                    return Err(ConfigError::ListenerHasBothPoolAndRoutes {
                        listener: listener.address,
                    });
                }
                (None, true) => {
                    return Err(ConfigError::ListenerHasNeitherPoolNorRoutes {
                        listener: listener.address,
                    });
                }
                (Some(pool), true) => {
                    // single-pool listener: validate the pool reference
                    if !seen_pools.contains(pool.as_str()) {
                        return Err(ConfigError::UnknownPoolReference {
                            listener: listener.address,
                            pool: pool.clone(),
                        });
                    }
                }
                (None, false) => {
                    // routes-based listener: plain L4 without TLS cannot have routes
                    if listener.mode == ListenerMode::L4 && listener.tls.is_none() {
                        return Err(ConfigError::RoutesOnPlainL4Listener {
                            listener: listener.address,
                        });
                    }
                    for route in &listener.routes {
                        if !seen_pools.contains(route.pool.as_str()) {
                            return Err(ConfigError::UnknownRoutePoolReference {
                                listener: listener.address,
                                pool: route.pool.clone(),
                            });
                        }
                        if let Some(zone) = &route.rate_limit {
                            if !self.rate_limit.zones.contains_key(zone) {
                                return Err(ConfigError::UnknownRouteRateLimitZone {
                                    listener: listener.address,
                                    zone: zone.clone(),
                                });
                            }
                            // the route hook lives in the L7 request path;
                            // anywhere else the field would be silently dead
                            if listener.mode != ListenerMode::L7 {
                                return Err(ConfigError::RateLimitOnNonL7Route {
                                    listener: listener.address,
                                });
                            }
                        }
                        // sni needs either TLS termination (rustls extracts it) or
                        // passthrough mode (the ClientHello peek extracts it)
                        if route.sni.is_some()
                            && listener.tls.is_none()
                            && listener.mode != ListenerMode::TlsPassthrough
                        {
                            return Err(ConfigError::SniMatcherOnNonTlsListener {
                                listener: listener.address,
                            });
                        }
                        if listener.mode == ListenerMode::TlsPassthrough {
                            let http_fields: [(bool, &'static str); 3] = [
                                (route.host.is_some(), "host"),
                                (route.path_prefix.is_some(), "path_prefix"),
                                (route.method.is_some(), "method"),
                            ];
                            if let Some((_, field)) = http_fields.iter().find(|(set, _)| *set) {
                                return Err(ConfigError::HttpMatcherOnPassthroughListener {
                                    listener: listener.address,
                                    field,
                                });
                            }
                        }
                        if let Some(host) = &route.host
                            && !is_valid_host_pattern(host)
                        {
                            return Err(ConfigError::InvalidHostPattern {
                                listener: listener.address,
                                pattern: host.clone(),
                            });
                        }
                        if let Some(sni) = &route.sni
                            && !is_valid_host_pattern(sni)
                        {
                            return Err(ConfigError::InvalidHostPattern {
                                listener: listener.address,
                                pattern: sni.clone(),
                            });
                        }
                        if let Some(path) = &route.path_prefix
                            && !is_valid_path_prefix(path)
                        {
                            return Err(ConfigError::InvalidPathPrefix {
                                listener: listener.address,
                                prefix: path.clone(),
                            });
                        }
                        if let Some(method) = &route.method
                            && !is_valid_method_token(method)
                        {
                            return Err(ConfigError::InvalidRouteMethod {
                                listener: listener.address,
                                method: method.clone(),
                            });
                        }
                    }
                }
            }
        }

        // pool backends non-empty
        for pool in &self.pools {
            if pool.backends.is_empty() {
                return Err(ConfigError::EmptyPoolBackends {
                    pool: pool.name.clone(),
                });
            }
        }

        // per-listener validation
        for listener in &self.listeners {
            if listener.max_connections == Some(0) {
                return Err(ConfigError::InvalidValue {
                    field: "listener.max_connections",
                    reason: "must be at least 1".to_owned(),
                });
            }
            if listener.idle_timeout_secs == Some(0) {
                return Err(ConfigError::InvalidValue {
                    field: "listener.idle_timeout_secs",
                    reason: "must be at least 1".to_owned(),
                });
            }
            if listener.connect_timeout_secs == 0 {
                return Err(ConfigError::InvalidValue {
                    field: "listener.connect_timeout_secs",
                    reason: "must be at least 1".to_owned(),
                });
            }
            if listener.max_connect_attempts == 0 {
                return Err(ConfigError::InvalidValue {
                    field: "listener.max_connect_attempts",
                    reason: "must be at least 1".to_owned(),
                });
            }
            if listener.drain_timeout_secs == 0 {
                return Err(ConfigError::InvalidValue {
                    field: "listener.drain_timeout_secs",
                    reason: "must be at least 1".to_owned(),
                });
            }
            if listener.clienthello_timeout_secs == 0 {
                return Err(ConfigError::InvalidValue {
                    field: "listener.clienthello_timeout_secs",
                    reason: "must be at least 1".to_owned(),
                });
            }
            if listener.mode == ListenerMode::TlsPassthrough && listener.tls.is_some() {
                return Err(ConfigError::TlsTerminationOnPassthroughListener {
                    listener: listener.address,
                });
            }

            if let Some(ref tls) = listener.tls {
                validate_tls_config(tls)?;
            }
            if listener.header_size_limit_bytes < 64 {
                return Err(ConfigError::InvalidValue {
                    field: "listener.header_size_limit_bytes",
                    reason: "must be at least 64".to_owned(),
                });
            }

            // phase-specific timeouts - must be > 0 if explicitly set
            let phase_timeouts: [(Option<u64>, &'static str); 5] = [
                (
                    listener.client_header_timeout_secs,
                    "listener.client_header_timeout_secs",
                ),
                (
                    listener.client_body_timeout_secs,
                    "listener.client_body_timeout_secs",
                ),
                (
                    listener.proxy_send_timeout_secs,
                    "listener.proxy_send_timeout_secs",
                ),
                (
                    listener.proxy_read_timeout_secs,
                    "listener.proxy_read_timeout_secs",
                ),
                (
                    listener.request_timeout_secs,
                    "listener.request_timeout_secs",
                ),
            ];
            for (val, field) in phase_timeouts {
                if val == Some(0) {
                    return Err(ConfigError::InvalidValue {
                        field,
                        reason: "must be at least 1".to_owned(),
                    });
                }
            }
            if listener.keepalive_idle_timeout_secs == Some(0) {
                return Err(ConfigError::InvalidValue {
                    field: "listener.keepalive_idle_timeout_secs",
                    reason: "must be at least 1".to_owned(),
                });
            }
            if listener.keepalive_max_requests == Some(0) {
                return Err(ConfigError::InvalidValue {
                    field: "listener.keepalive_max_requests",
                    reason: "must be at least 1".to_owned(),
                });
            }

            // L7-specific fields are meaningless on L4 listeners
            if listener.mode == ListenerMode::L4 {
                let l7_only: &[(&'static str, bool)] = &[
                    (
                        "listener.client_header_timeout_secs",
                        listener.client_header_timeout_secs.is_some(),
                    ),
                    (
                        "listener.client_body_timeout_secs",
                        listener.client_body_timeout_secs.is_some(),
                    ),
                    (
                        "listener.proxy_send_timeout_secs",
                        listener.proxy_send_timeout_secs.is_some(),
                    ),
                    (
                        "listener.proxy_read_timeout_secs",
                        listener.proxy_read_timeout_secs.is_some(),
                    ),
                    (
                        "listener.request_timeout_secs",
                        listener.request_timeout_secs.is_some(),
                    ),
                    (
                        "listener.max_body_size_bytes",
                        listener.max_body_size_bytes.is_some(),
                    ),
                    (
                        "listener.keepalive_idle_timeout_secs",
                        listener.keepalive_idle_timeout_secs.is_some(),
                    ),
                    (
                        "listener.keepalive_max_requests",
                        listener.keepalive_max_requests.is_some(),
                    ),
                ];
                for &(field, is_set) in l7_only {
                    if is_set {
                        return Err(ConfigError::InvalidValue {
                            field,
                            reason: "not applicable to L4 listeners".to_owned(),
                        });
                    }
                }
            }
        }

        // global health defaults
        if self.health.failure_threshold == 0 {
            return Err(ConfigError::InvalidValue {
                field: "health.failure_threshold",
                reason: "must be at least 1".to_owned(),
            });
        }
        if self.health.recovery_timeout_secs == 0 {
            return Err(ConfigError::InvalidValue {
                field: "health.recovery_timeout_secs",
                reason: "must be at least 1".to_owned(),
            });
        }
        if self.health.check_interval_secs == Some(0) {
            return Err(ConfigError::InvalidValue {
                field: "health.check_interval_secs",
                reason: "must be at least 1".to_owned(),
            });
        }

        // per-pool health override
        for pool in &self.pools {
            if let Some(ref ovr) = pool.health {
                if ovr.check_interval_secs == Some(0) {
                    return Err(ConfigError::InvalidValue {
                        field: "pool.health.check_interval_secs",
                        reason: "must be at least 1".to_owned(),
                    });
                }
                if ovr.failure_threshold == Some(0) {
                    return Err(ConfigError::InvalidValue {
                        field: "pool.health.failure_threshold",
                        reason: "must be at least 1".to_owned(),
                    });
                }
                if ovr.recovery_timeout_secs == Some(0) {
                    return Err(ConfigError::InvalidValue {
                        field: "pool.health.recovery_timeout_secs",
                        reason: "must be at least 1".to_owned(),
                    });
                }
            }
        }

        // per-pool keepalive config validation
        for pool in &self.pools {
            let kc = &pool.keepalive;
            if kc.max_idle > 0 && kc.idle_conn_ttl_secs == 0 {
                return Err(ConfigError::InvalidValue {
                    field: "pools.keepalive.idle_conn_ttl_secs",
                    reason: "must be at least 1 when max_idle > 0".to_owned(),
                });
            }
            if kc.max_total > 0 && kc.max_idle > 0 && kc.max_total < kc.max_idle as u64 {
                return Err(ConfigError::InvalidValue {
                    field: "pools.keepalive.max_total",
                    reason: format!(
                        "must be >= max_idle ({}) when both are nonzero",
                        kc.max_idle
                    ),
                });
            }
        }

        // error pages: missing file is fatal at startup
        for (status, path) in &self.error_pages.pages {
            if !path.exists() {
                return Err(ConfigError::ErrorPageFileNotFound {
                    status: status.clone(),
                    path: path.clone(),
                });
            }
        }

        // access log validation
        if let Some(ref fmt) = self.access_log.format
            && fmt != "json"
        {
            return Err(ConfigError::InvalidValue {
                field: "access_log.format",
                reason: format!("only 'json' is supported, got '{fmt}'"),
            });
        }
        if self.access_log.file_channel_capacity < 64 {
            return Err(ConfigError::InvalidValue {
                field: "access_log.file_channel_capacity",
                reason: "must be at least 64".to_owned(),
            });
        }
        // validate named output values
        if let AccessLogOutput::Named(ref name) = self.access_log.output
            && name != "stdout"
            && name != "stderr"
            && name != "off"
        {
            return Err(ConfigError::InvalidValue {
                field: "access_log.output",
                reason: format!("must be 'stdout', 'stderr', 'off', or a file table, got '{name}'"),
            });
        }

        Ok(())
    }
}

fn is_valid_host_pattern(pattern: &str) -> bool {
    if pattern.contains('*') {
        // must be "*.something" with non-empty something
        pattern.starts_with("*.") && pattern.len() > 2
    } else {
        !pattern.is_empty()
    }
}

fn is_valid_path_prefix(prefix: &str) -> bool {
    if !prefix.starts_with('/') {
        return false;
    }
    // "/" is valid; any other prefix ending with "/" is not
    if prefix != "/" && prefix.ends_with('/') {
        return false;
    }
    true
}

fn is_valid_method_token(method: &str) -> bool {
    if method.is_empty() {
        return false;
    }
    method
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

fn validate_tls_config(tls: &TlsConfig) -> Result<(), ConfigError> {
    if tls.certificates.is_empty() {
        return Err(ConfigError::InvalidValue {
            field: "listener.tls.certificates",
            reason: "must have at least one certificate".to_owned(),
        });
    }
    if tls.handshake_timeout_secs == 0 {
        return Err(ConfigError::InvalidValue {
            field: "listener.tls.handshake_timeout_secs",
            reason: "must be at least 1".to_owned(),
        });
    }
    if tls.min_version != "1.2" && tls.min_version != "1.3" {
        return Err(ConfigError::InvalidValue {
            field: "listener.tls.min_version",
            reason: format!("must be '1.2' or '1.3', got '{}'", tls.min_version),
        });
    }
    let multi = tls.certificates.len() > 1;
    for cert_config in &tls.certificates {
        if !cert_config.cert.exists() {
            return Err(ConfigError::TlsCertFileNotFound {
                path: cert_config.cert.clone(),
            });
        }
        if !cert_config.key.exists() {
            return Err(ConfigError::TlsKeyFileNotFound {
                path: cert_config.key.clone(),
            });
        }
        if multi && cert_config.sni_names.is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "listener.tls.certificates[].sni_names",
                reason: "required when multiple certificates are configured".to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_config(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    fn write_pem_files() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        use rcgen::generate_simple_self_signed;
        let cert = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        (dir, cert_path, key_path)
    }

    #[test]
    fn parse_minimal_valid_config() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.listeners[0].address, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(config.listeners[0].pool.as_deref(), Some("web"));
        assert_eq!(config.pools.len(), 1);
        assert_eq!(config.pools[0].name, "web");
        assert_eq!(config.pools[0].backends.len(), 1);
    }

    #[test]
    fn parse_rate_limit_zones_with_defaults() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"
            rate_limit = "per_ip"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [rate_limit.zones.per_ip]
            key = "client_ip"
            rate = 100

            [rate_limit.zones.api_global]
            key = "global"
            rate = 50
            per = "m"
            burst = 20
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.listeners[0].rate_limit.as_deref(), Some("per_ip"));

        let per_ip = &config.rate_limit.zones["per_ip"];
        assert_eq!(per_ip.key, ZoneKey::ClientIp);
        assert_eq!(per_ip.rate, 100);
        assert_eq!(per_ip.per, RatePeriod::Second);
        assert_eq!(per_ip.burst, 0);
        assert_eq!(per_ip.max_keys, None);

        let global = &config.rate_limit.zones["api_global"];
        assert_eq!(global.key, ZoneKey::Global);
        assert_eq!(global.per, RatePeriod::Minute);
        assert_eq!(global.burst, 20);
    }

    #[test]
    fn parse_route_rate_limit_on_l7_listener() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            path_prefix = "/login"
            pool = "web"
            rate_limit = "login"

            [[listeners.routes]]
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [rate_limit.zones.login]
            key = "client_ip"
            rate = 5
            max_keys = 4096
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(
            config.listeners[0].routes[0].rate_limit.as_deref(),
            Some("login")
        );
        assert_eq!(config.listeners[0].routes[1].rate_limit, None);
        assert_eq!(config.rate_limit.zones["login"].max_keys, Some(4096));
    }

    #[test]
    fn rate_limit_zone_zero_rate_rejected() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [rate_limit.zones.bad]
            key = "global"
            rate = 0
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::RateLimitZeroRate { zone } if zone == "bad"));
    }

    #[test]
    fn rate_limit_max_keys_on_global_zone_rejected() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [rate_limit.zones.bad]
            key = "global"
            rate = 10
            max_keys = 1024
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::RateLimitMaxKeysOnGlobalZone { zone } if zone == "bad"));
    }

    #[test]
    fn rate_limit_max_keys_boundary() {
        // 3 is below one 4-way set; 4 is the minimum valid value
        for (max_keys, ok) in [(3, false), (4, true)] {
            let file = write_temp_config(&format!(
                r#"
                [[listeners]]
                address = "0.0.0.0:8080"
                pool = "web"

                [[pools]]
                name = "web"

                [[pools.backends]]
                address = "127.0.0.1:3001"

                [rate_limit.zones.z]
                key = "client_ip"
                rate = 10
                max_keys = {max_keys}
                "#
            ));
            let result = Config::from_file(file.path().to_str().unwrap());
            match (ok, result) {
                (true, Ok(_)) => {}
                (false, Err(ConfigError::RateLimitMaxKeysTooSmall { zone })) => {
                    assert_eq!(zone, "z");
                }
                (_, other) => panic!("max_keys = {max_keys}: unexpected result {other:?}"),
            }
        }
    }

    #[test]
    fn listener_unknown_rate_limit_zone_rejected() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"
            rate_limit = "missing"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownRateLimitZone { zone, .. } if zone == "missing"));
    }

    #[test]
    fn route_unknown_rate_limit_zone_rejected() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            pool = "web"
            rate_limit = "missing"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::UnknownRouteRateLimitZone { zone, .. } if zone == "missing")
        );
    }

    #[test]
    fn route_rate_limit_on_non_l7_listener_rejected() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            mode = "tls-passthrough"

            [[listeners.routes]]
            sni = "a.test"
            pool = "web"
            rate_limit = "per_ip"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [rate_limit.zones.per_ip]
            key = "client_ip"
            rate = 10
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::RateLimitOnNonL7Route { .. }));
    }

    #[test]
    fn rate_limit_invalid_per_rejected() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [rate_limit.zones.z]
            key = "client_ip"
            rate = 10
            per = "h"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn rate_limit_duplicate_zone_name_rejected() {
        // toml itself rejects a table defined twice; guard the assumption
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [rate_limit.zones.z]
            key = "client_ip"
            rate = 10

            [rate_limit.zones.z]
            key = "global"
            rate = 20
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn parse_multi_listener_multi_pool() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[listeners]]
            address = "0.0.0.0:8081"
            pool = "api"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [[pools.backends]]
            address = "127.0.0.1:3002"

            [[pools]]
            name = "api"

            [[pools.backends]]
            address = "127.0.0.1:4001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.listeners.len(), 2);
        assert_eq!(config.pools.len(), 2);
        assert_eq!(config.pools[0].backends.len(), 2);
        assert_eq!(config.pools[1].backends.len(), 1);
    }

    #[test]
    fn parse_per_pool_health_override() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "api"

            [[pools]]
            name = "api"

            [pools.health]
            check_interval_secs = 5
            failure_threshold = 2

            [[pools.backends]]
            address = "127.0.0.1:4001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let ovr = config.pools[0].health.as_ref().unwrap();
        assert_eq!(ovr.check_interval_secs, Some(5));
        assert_eq!(ovr.failure_threshold, Some(2));
        assert!(ovr.recovery_timeout_secs.is_none());

        // effective_health merges with global defaults
        let effective = config.pools[0].effective_health(&config.health);
        assert_eq!(effective.check_interval_secs, Some(5));
        assert_eq!(effective.failure_threshold, 2);
        assert_eq!(effective.recovery_timeout_secs, 10); // from global default
    }

    #[test]
    fn defaults_applied() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.logging.level, "info");
        assert!(config.metrics.is_none());
        assert_eq!(config.listeners[0].drain_timeout_secs, 30);
        assert_eq!(config.listeners[0].connect_timeout_secs, 5);
        assert_eq!(config.listeners[0].max_connect_attempts, 3);
        assert!(config.listeners[0].idle_timeout_secs.is_none());
        assert!(config.listeners[0].max_connections.is_none());
        assert_eq!(config.listeners[0].mode, ListenerMode::L4);
    }

    #[test]
    fn metrics_parsed_when_present() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [metrics]
            address = "0.0.0.0:9090"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(
            config.metrics.unwrap().address,
            "0.0.0.0:9090".parse().unwrap()
        );
    }

    #[test]
    fn reject_empty_listeners() {
        let file = write_temp_config(
            r#"
            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyListeners));
    }

    #[test]
    fn reject_empty_pools() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyPools));
    }

    #[test]
    fn reject_duplicate_pool_name() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3002"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicatePoolName { .. }));
    }

    #[test]
    fn reject_duplicate_listener_address() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateListenerAddress { .. }));
    }

    #[test]
    fn reject_wildcard_overlaps_specific_address_same_port() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[listeners]]
            address = "127.0.0.1:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::OverlappingListenerAddress { .. }
        ));
    }

    #[test]
    fn reject_wildcard_overlaps_regardless_of_declaration_order() {
        // specific listed first, wildcard second - overlap detection must still fire
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "127.0.0.1:8080"
            pool = "web"

            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::OverlappingListenerAddress { .. }
        ));
    }

    #[test]
    fn allow_distinct_specific_addresses_on_same_port() {
        // two specific (non-wildcard) IPs on the same port don't overlap;
        // the kernel allows binding distinct interfaces to the same port
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "127.0.0.1:8080"
            pool = "web"

            [[listeners]]
            address = "127.0.0.2:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        Config::from_file(file.path().to_str().unwrap())
            .expect("two distinct specific addresses on same port must be allowed");
    }

    #[test]
    fn allow_wildcard_on_different_ports() {
        // 0.0.0.0:8080 and 0.0.0.0:8081 don't overlap (different ports)
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[listeners]]
            address = "0.0.0.0:8081"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        Config::from_file(file.path().to_str().unwrap())
            .expect("wildcards on different ports must be allowed");
    }

    #[test]
    fn reject_unknown_pool_reference() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "nonexistent"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownPoolReference { .. }));
    }

    #[test]
    fn reject_empty_pool_backends() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"
            backends = []
            "#,
        );
        let result = Config::from_file(file.path().to_str().unwrap());
        // empty backends array is either a parse error (inline array) or EmptyPoolBackends
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_address() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "not_an_address"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn reject_malformed_toml() {
        let file = write_temp_config("this is not [valid toml");
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn file_not_found() {
        let err = Config::from_file("/nonexistent/path.toml").unwrap_err();
        assert!(matches!(err, ConfigError::ReadFile { .. }));
    }

    #[test]
    fn forwarding_strategy_defaults_to_userspace() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.forwarding.strategy, ForwardingStrategy::Userspace);
    }

    #[test]
    fn forwarding_strategy_parsed() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [forwarding]
            strategy = "userspace"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.forwarding.strategy, ForwardingStrategy::Userspace);
    }

    #[test]
    fn reject_zero_max_connections() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"
            max_connections = 0

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_zero_idle_timeout() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"
            idle_timeout_secs = 0

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_zero_connect_timeout() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"
            connect_timeout_secs = 0

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_zero_max_connect_attempts() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"
            max_connect_attempts = 0

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_zero_drain_timeout() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"
            drain_timeout_secs = 0

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn health_defaults_applied() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert!(config.health.check_interval_secs.is_none());
        assert_eq!(config.health.failure_threshold, 3);
        assert_eq!(config.health.recovery_timeout_secs, 10);
    }

    #[test]
    fn health_values_parsed() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [health]
            check_interval_secs = 5
            failure_threshold = 2
            recovery_timeout_secs = 30
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.health.check_interval_secs, Some(5));
        assert_eq!(config.health.failure_threshold, 2);
        assert_eq!(config.health.recovery_timeout_secs, 30);
    }

    #[test]
    fn reject_zero_failure_threshold() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [health]
            failure_threshold = 0
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_zero_recovery_timeout() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [health]
            recovery_timeout_secs = 0
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_zero_check_interval() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [health]
            check_interval_secs = 0
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_zero_pool_override_interval() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [pools.health]
            check_interval_secs = 0

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_zero_pool_override_failure_threshold() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [pools.health]
            failure_threshold = 0

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn tls_section_absent_is_plain_mode() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert!(config.listeners[0].tls.is_none());
    }

    #[test]
    fn parse_tls_single_cert() {
        let (_dir, cert_path, key_path) = write_pem_files();
        let content = format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            pool = "web"

            [[listeners.tls.certificates]]
            cert = "{}"
            key = "{}"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
            cert_path.display(),
            key_path.display(),
        );
        let file = write_temp_config(&content);
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let tls = config.listeners[0].tls.as_ref().unwrap();
        assert_eq!(tls.certificates.len(), 1);
        assert_eq!(tls.handshake_timeout_secs, 5);
        assert_eq!(tls.min_version, "1.2");
    }

    #[test]
    fn parse_tls_multi_cert() {
        let (_dir1, cert1, key1) = write_pem_files();
        let (_dir2, cert2, key2) = write_pem_files();
        let content = format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            pool = "web"

            [[listeners.tls.certificates]]
            cert = "{}"
            key = "{}"
            sni_names = ["a.test"]

            [[listeners.tls.certificates]]
            cert = "{}"
            key = "{}"
            sni_names = ["b.test"]

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
            cert1.display(),
            key1.display(),
            cert2.display(),
            key2.display(),
        );
        let file = write_temp_config(&content);
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let tls = config.listeners[0].tls.as_ref().unwrap();
        assert_eq!(tls.certificates.len(), 2);
        assert_eq!(tls.certificates[0].sni_names, ["a.test"]);
        assert_eq!(tls.certificates[1].sni_names, ["b.test"]);
    }

    #[test]
    fn tls_defaults_applied() {
        let (_dir, cert_path, key_path) = write_pem_files();
        let content = format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            pool = "web"

            [[listeners.tls.certificates]]
            cert = "{}"
            key = "{}"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
            cert_path.display(),
            key_path.display(),
        );
        let file = write_temp_config(&content);
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let tls = config.listeners[0].tls.as_ref().unwrap();
        assert_eq!(tls.handshake_timeout_secs, 5);
        assert_eq!(tls.min_version, "1.2");
    }

    #[test]
    fn reject_empty_certificates() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            pool = "web"

            [listeners.tls]
            certificates = []

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_invalid_min_version() {
        let (_dir, cert_path, key_path) = write_pem_files();
        let content = format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            pool = "web"

            [listeners.tls]
            min_version = "1.1"

            [[listeners.tls.certificates]]
            cert = "{}"
            key = "{}"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
            cert_path.display(),
            key_path.display(),
        );
        let file = write_temp_config(&content);
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_missing_cert_file_path() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            pool = "web"

            [[listeners.tls.certificates]]
            cert = "/nonexistent/cert.pem"
            key = "/nonexistent/key.pem"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::TlsCertFileNotFound { .. }));
    }

    #[test]
    fn reject_missing_key_file_path() {
        let (_dir, cert_path, _key_path) = write_pem_files();
        let content = format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            pool = "web"

            [[listeners.tls.certificates]]
            cert = "{}"
            key = "/nonexistent/key.pem"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
            cert_path.display(),
        );
        let file = write_temp_config(&content);
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::TlsKeyFileNotFound { .. }));
    }

    fn base_pool_toml() -> &'static str {
        r#"
        [[pools]]
        name = "web"

        [[pools.backends]]
        address = "127.0.0.1:3001"

        [[pools]]
        name = "api"

        [[pools.backends]]
        address = "127.0.0.1:3002"
        "#
    }

    #[test]
    fn parse_listener_with_single_pool() {
        // regression: old pool = "X" format still works
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.listeners[0].pool.as_deref(), Some("web"));
        assert!(config.listeners[0].routes.is_empty());
    }

    #[test]
    fn parse_listener_with_routes_array() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            host = "api.example.com"
            pool = "api"

            [[listeners.routes]]
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert!(config.listeners[0].pool.is_none());
        assert_eq!(config.listeners[0].routes.len(), 2);
        assert_eq!(
            config.listeners[0].routes[0].host.as_deref(),
            Some("api.example.com")
        );
        assert_eq!(config.listeners[0].routes[0].pool, "api");
        assert_eq!(config.listeners[0].routes[1].host, None);
        assert_eq!(config.listeners[0].routes[1].pool, "web");
    }

    #[test]
    fn parse_listener_with_route_having_all_matchers() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            host = "api.example.com"
            path_prefix = "/v1"
            method = "POST"
            pool = "api"
            {}
            "#,
            base_pool_toml()
        ));
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let r = &config.listeners[0].routes[0];
        assert_eq!(r.host.as_deref(), Some("api.example.com"));
        assert_eq!(r.path_prefix.as_deref(), Some("/v1"));
        assert_eq!(r.method.as_deref(), Some("POST"));
        assert_eq!(r.pool, "api");
    }

    #[test]
    fn parse_listener_routes_absent_deserializes_to_empty_vec() {
        // routes field absent in TOML → empty vec; old configs work as-is
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert!(config.listeners[0].routes.is_empty());
    }

    #[test]
    fn validate_rejects_listener_with_both_pool_and_routes() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"

            [[listeners.routes]]
            pool = "api"
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::ListenerHasBothPoolAndRoutes { .. }),
            "expected ListenerHasBothPoolAndRoutes, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_listener_with_neither() {
        // no pool and no routes
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::ListenerHasNeitherPoolNorRoutes { .. }),
            "expected ListenerHasNeitherPoolNorRoutes, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_route_with_unknown_pool() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            pool = "nonexistent"
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::UnknownRoutePoolReference { .. }),
            "expected UnknownRoutePoolReference, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_routes_on_plain_l4_listener() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l4"

            [[listeners.routes]]
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::RoutesOnPlainL4Listener { .. }),
            "expected RoutesOnPlainL4Listener, got: {err}"
        );
    }

    #[test]
    fn validate_allows_routes_on_l4_with_tls() {
        let (_dir, cert_path, key_path) = write_pem_files();
        let content = format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            mode = "l4"

            [[listeners.tls.certificates]]
            cert = "{}"
            key = "{}"

            [[listeners.routes]]
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
            cert_path.display(),
            key_path.display(),
        );
        let file = write_temp_config(&content);
        Config::from_file(file.path().to_str().unwrap())
            .expect("L4+TLS listener with routes must be allowed");
    }

    #[test]
    fn validate_allows_routes_on_l7() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            host = "api.example.com"
            pool = "api"

            [[listeners.routes]]
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        Config::from_file(file.path().to_str().unwrap())
            .expect("L7 listener with routes must be allowed");
    }

    #[test]
    fn validate_rejects_sni_on_non_tls_listener() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            sni = "api.test"
            pool = "api"
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::SniMatcherOnNonTlsListener { .. }),
            "expected SniMatcherOnNonTlsListener, got: {err}"
        );
    }

    #[test]
    fn validate_allows_sni_on_tls_listener() {
        let (_dir, cert_path, key_path) = write_pem_files();
        let content = format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            mode = "l7"

            [[listeners.tls.certificates]]
            cert = "{}"
            key = "{}"

            [[listeners.routes]]
            sni = "api.test"
            pool = "api"

            [[listeners.routes]]
            pool = "web"

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"

            [[pools]]
            name = "api"

            [[pools.backends]]
            address = "127.0.0.1:3002"
            "#,
            cert_path.display(),
            key_path.display(),
        );
        let file = write_temp_config(&content);
        Config::from_file(file.path().to_str().unwrap())
            .expect("SNI route on TLS listener must be allowed");
    }

    #[test]
    fn parses_tls_passthrough_mode() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            mode = "tls-passthrough"
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.listeners[0].mode, ListenerMode::TlsPassthrough);
    }

    #[test]
    fn clienthello_timeout_defaults_to_10() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            mode = "tls-passthrough"
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.listeners[0].clienthello_timeout_secs, 10);
    }

    #[test]
    fn validate_rejects_zero_clienthello_timeout() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            mode = "tls-passthrough"
            pool = "web"
            clienthello_timeout_secs = 0
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::InvalidValue {
                    field: "listener.clienthello_timeout_secs",
                    ..
                }
            ),
            "expected InvalidValue for clienthello_timeout_secs, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_tls_section_on_passthrough() {
        let (_dir, cert_path, key_path) = write_pem_files();
        let content = format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            mode = "tls-passthrough"
            pool = "web"

            [[listeners.tls.certificates]]
            cert = "{}"
            key = "{}"
            {}
            "#,
            cert_path.display(),
            key_path.display(),
            base_pool_toml(),
        );
        let file = write_temp_config(&content);
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::TlsTerminationOnPassthroughListener { .. }),
            "expected TlsTerminationOnPassthroughListener, got: {err}"
        );
    }

    #[test]
    fn validate_allows_sni_routes_on_passthrough() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8443"
            mode = "tls-passthrough"

            [[listeners.routes]]
            sni = "api.test"
            pool = "api"

            [[listeners.routes]]
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        Config::from_file(file.path().to_str().unwrap())
            .expect("SNI routes on tls-passthrough listener must be allowed");
    }

    #[test]
    fn validate_rejects_http_matchers_on_passthrough() {
        for (field_toml, field_name) in [
            (r#"host = "api.test""#, "host"),
            (r#"path_prefix = "/api""#, "path_prefix"),
            (r#"method = "GET""#, "method"),
        ] {
            let file = write_temp_config(&format!(
                r#"
                [[listeners]]
                address = "0.0.0.0:8443"
                mode = "tls-passthrough"

                [[listeners.routes]]
                {field_toml}
                pool = "api"
                {}
                "#,
                base_pool_toml()
            ));
            let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::HttpMatcherOnPassthroughListener { field, .. }
                    if field == field_name
                ),
                "expected HttpMatcherOnPassthroughListener for '{field_name}', got: {err}"
            );
        }
    }

    #[test]
    fn validate_rejects_invalid_host_pattern_bare_star() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            host = "*"
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidHostPattern { .. }),
            "expected InvalidHostPattern, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_invalid_host_pattern_mid_string_star() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            host = "foo.*.com"
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidHostPattern { .. }),
            "expected InvalidHostPattern, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_invalid_path_prefix_no_slash() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            path_prefix = "api"
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidPathPrefix { .. }),
            "expected InvalidPathPrefix, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_invalid_path_prefix_trailing_slash() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            path_prefix = "/api/"
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidPathPrefix { .. }),
            "expected InvalidPathPrefix, got: {err}"
        );
    }

    #[test]
    fn validate_allows_root_path_prefix() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            path_prefix = "/"
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        Config::from_file(file.path().to_str().unwrap())
            .expect("root path prefix '/' must be allowed");
    }

    #[test]
    fn validate_rejects_invalid_method_empty() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            method = ""
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        // TOML may serialize "" as empty string; empty is rejected
        let result = Config::from_file(file.path().to_str().unwrap());
        assert!(result.is_err(), "empty method should be rejected");
    }

    #[test]
    fn validate_rejects_invalid_method_whitespace() {
        let file = write_temp_config(&format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"

            [[listeners.routes]]
            method = "G ET"
            pool = "web"
            {}
            "#,
            base_pool_toml()
        ));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidRouteMethod { .. }),
            "expected InvalidRouteMethod, got: {err}"
        );
    }

    /// minimal valid L7 listener config with an extra field injected into the listeners block.
    fn l7_listener_with(extra: &str) -> String {
        format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"
            {extra}

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#
        )
    }

    /// minimal valid L4 listener config with an extra field injected into the listeners block.
    fn l4_listener_with(extra: &str) -> String {
        format!(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            pool = "web"
            {extra}

            [[pools]]
            name = "web"

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#
        )
    }

    #[test]
    fn keepalive_defaults_when_section_absent() {
        let file = write_temp_config(&l7_listener_with(""));
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let kc = &config.pools[0].keepalive;
        assert_eq!(kc.max_idle, 32);
        assert_eq!(kc.idle_conn_ttl_secs, 60);
        assert_eq!(kc.max_total, 0);
    }

    #[test]
    fn keepalive_all_fields_parsed() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"

            [[pools]]
            name = "web"

            [pools.keepalive]
            max_idle = 16
            idle_conn_ttl_secs = 30
            max_total = 64

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let kc = &config.pools[0].keepalive;
        assert_eq!(kc.max_idle, 16);
        assert_eq!(kc.idle_conn_ttl_secs, 30);
        assert_eq!(kc.max_total, 64);
    }

    #[test]
    fn keepalive_max_idle_zero_disables_keepalive() {
        // max_idle = 0 is a valid opt-out (D2 escape hatch)
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"

            [[pools]]
            name = "web"

            [pools.keepalive]
            max_idle = 0

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.pools[0].keepalive.max_idle, 0);
    }

    #[test]
    fn keepalive_max_total_zero_is_unlimited() {
        // max_total = 0 means unlimited and must be accepted by validation.
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"

            [[pools]]
            name = "web"

            [pools.keepalive]
            max_idle = 8
            max_total = 0

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.pools[0].keepalive.max_total, 0);
    }

    #[test]
    fn keepalive_max_idle_zero_with_zero_ttl_allowed() {
        // when max_idle = 0 (disabled), idle_conn_ttl_secs value is irrelevant
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"

            [[pools]]
            name = "web"

            [pools.keepalive]
            max_idle = 0
            idle_conn_ttl_secs = 0

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        // should not reject: keepalive disabled, ttl is don't-care
        Config::from_file(file.path().to_str().unwrap())
            .expect("max_idle=0 with idle_conn_ttl_secs=0 must be allowed");
    }

    #[test]
    fn reject_keepalive_idle_ttl_zero_when_max_idle_nonzero() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"

            [[pools]]
            name = "web"

            [pools.keepalive]
            max_idle = 3
            idle_conn_ttl_secs = 0

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn reject_keepalive_max_total_less_than_max_idle() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"

            [[pools]]
            name = "web"

            [pools.keepalive]
            max_idle = 5
            max_total = 2

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn keepalive_max_total_equals_max_idle_allowed() {
        // max_total == max_idle is valid (tight cap, no growth beyond idle capacity)
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"

            [[pools]]
            name = "web"

            [pools.keepalive]
            max_idle = 4
            max_total = 4

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        Config::from_file(file.path().to_str().unwrap())
            .expect("max_total == max_idle must be allowed");
    }

    #[test]
    fn reject_keepalive_max_requests_zero() {
        let file = write_temp_config(&l7_listener_with("keepalive_max_requests = 0"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn reject_keepalive_idle_timeout_zero() {
        let file = write_temp_config(&l7_listener_with("keepalive_idle_timeout_secs = 0"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn reject_phase_timeout_header_zero() {
        let file = write_temp_config(&l7_listener_with("client_header_timeout_secs = 0"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn reject_phase_timeout_body_zero() {
        let file = write_temp_config(&l7_listener_with("client_body_timeout_secs = 0"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn reject_phase_timeout_proxy_send_zero() {
        let file = write_temp_config(&l7_listener_with("proxy_send_timeout_secs = 0"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn reject_phase_timeout_proxy_read_zero() {
        let file = write_temp_config(&l7_listener_with("proxy_read_timeout_secs = 0"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn reject_request_timeout_zero() {
        let file = write_temp_config(&l7_listener_with("request_timeout_secs = 0"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn max_body_size_zero_is_unlimited() {
        // 0 means unlimited and must not be rejected by validation.
        let file = write_temp_config(&l7_listener_with("max_body_size_bytes = 0"));
        Config::from_file(file.path().to_str().unwrap())
            .expect("max_body_size_bytes=0 (unlimited) must be allowed");
    }

    #[test]
    fn l4_listener_rejects_client_header_timeout() {
        let file = write_temp_config(&l4_listener_with("client_header_timeout_secs = 30"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn l4_listener_rejects_client_body_timeout() {
        let file = write_temp_config(&l4_listener_with("client_body_timeout_secs = 30"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn l4_listener_rejects_proxy_send_timeout() {
        let file = write_temp_config(&l4_listener_with("proxy_send_timeout_secs = 30"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn l4_listener_rejects_proxy_read_timeout() {
        let file = write_temp_config(&l4_listener_with("proxy_read_timeout_secs = 30"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn l4_listener_rejects_request_timeout() {
        let file = write_temp_config(&l4_listener_with("request_timeout_secs = 60"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn l4_listener_rejects_max_body_size() {
        let file = write_temp_config(&l4_listener_with("max_body_size_bytes = 1048576"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn l4_listener_rejects_keepalive_idle_timeout() {
        let file = write_temp_config(&l4_listener_with("keepalive_idle_timeout_secs = 60"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn l4_listener_rejects_keepalive_max_requests() {
        let file = write_temp_config(&l4_listener_with("keepalive_max_requests = 1000"));
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn l7_listener_accepts_all_new_fields() {
        let file = write_temp_config(
            r#"
            [[listeners]]
            address = "0.0.0.0:8080"
            mode = "l7"
            pool = "web"
            client_header_timeout_secs = 10
            client_body_timeout_secs = 20
            proxy_send_timeout_secs = 30
            proxy_read_timeout_secs = 40
            request_timeout_secs = 60
            max_body_size_bytes = 1048576
            keepalive_idle_timeout_secs = 60
            keepalive_max_requests = 500

            [[pools]]
            name = "web"

            [pools.keepalive]
            max_idle = 16
            idle_conn_ttl_secs = 30
            max_total = 32

            [[pools.backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let l = &config.listeners[0];
        assert_eq!(l.client_header_timeout_secs, Some(10));
        assert_eq!(l.client_body_timeout_secs, Some(20));
        assert_eq!(l.proxy_send_timeout_secs, Some(30));
        assert_eq!(l.proxy_read_timeout_secs, Some(40));
        assert_eq!(l.request_timeout_secs, Some(60));
        assert_eq!(l.max_body_size_bytes, Some(1_048_576));
        assert_eq!(l.keepalive_idle_timeout_secs, Some(60));
        assert_eq!(l.keepalive_max_requests, Some(500));
    }

    #[test]
    fn new_listener_l7_defaults_are_none() {
        // all new optional fields default to None when not set
        let file = write_temp_config(&l7_listener_with(""));
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let l = &config.listeners[0];
        assert!(l.client_header_timeout_secs.is_none());
        assert!(l.client_body_timeout_secs.is_none());
        assert!(l.proxy_send_timeout_secs.is_none());
        assert!(l.proxy_read_timeout_secs.is_none());
        assert!(l.request_timeout_secs.is_none());
        assert!(l.max_body_size_bytes.is_none());
        assert!(l.keepalive_idle_timeout_secs.is_none());
        assert!(l.keepalive_max_requests.is_none());
    }
}
