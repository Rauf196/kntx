use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

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
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    pub address: SocketAddr,
    #[serde(default)]
    pub mode: ListenerMode,
    pub pool: String,
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
}

#[derive(Debug, Deserialize)]
pub struct PoolConfig {
    pub name: String,
    pub backends: Vec<BackendConfig>,
    pub health: Option<PoolHealthOverride>,
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
}

fn default_drain_timeout() -> u64 {
    30
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

        // listener address uniqueness — exact dup
        let mut seen_addrs: HashSet<SocketAddr> = HashSet::new();
        for listener in &self.listeners {
            if !seen_addrs.insert(listener.address) {
                return Err(ConfigError::DuplicateListenerAddress {
                    address: listener.address,
                });
            }
        }

        // listener address overlap — wildcard (0.0.0.0 / ::) on a port
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

        // listener pool references
        for listener in &self.listeners {
            if !seen_pools.contains(listener.pool.as_str()) {
                return Err(ConfigError::UnknownPoolReference {
                    listener: listener.address,
                    pool: listener.pool.clone(),
                });
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

            if let Some(ref tls) = listener.tls {
                validate_tls_config(tls)?;
            }
            if listener.header_size_limit_bytes < 64 {
                return Err(ConfigError::InvalidValue {
                    field: "listener.header_size_limit_bytes",
                    reason: "must be at least 64".to_owned(),
                });
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
        assert_eq!(config.listeners[0].pool, "web");
        assert_eq!(config.pools.len(), 1);
        assert_eq!(config.pools[0].name, "web");
        assert_eq!(config.pools[0].backends.len(), 1);
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
        // specific listed first, wildcard second — overlap detection must still fire
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
}
