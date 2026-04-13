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

    #[error("no backends configured")]
    NoBackends,

    #[error("invalid value for '{field}': {reason}")]
    InvalidValue { field: &'static str, reason: String },

    #[error("TLS cert file not found: '{path}'")]
    TlsCertFileNotFound { path: PathBuf },

    #[error("TLS key file not found: '{path}'")]
    TlsKeyFileNotFound { path: PathBuf },
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

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listener: ListenerConfig,
    #[serde(default)]
    pub backends: Vec<BackendConfig>,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub forwarding: ForwardingConfig,
    #[serde(default)]
    pub connection: ConnectionConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_min_version")]
    pub min_version: String,
    pub certificates: Vec<CertificateConfig>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct ListenerConfig {
    pub address: SocketAddr,
    /// max concurrent connections. None = unlimited.
    pub max_connections: Option<usize>,
    /// seconds to wait for in-flight connections during shutdown. default 30.
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
}

fn default_drain_timeout() -> u64 {
    30
}

#[derive(Debug, Deserialize)]
pub struct ConnectionConfig {
    /// close connections with no data transfer for this many seconds. None = no timeout.
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// timeout for connecting to a backend. default 5s.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// max connect attempts before giving up and closing the client connection. default 3.
    #[serde(default = "default_max_connect_attempts")]
    pub max_connect_attempts: u32,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: None,
            connect_timeout_secs: default_connect_timeout(),
            max_connect_attempts: default_max_connect_attempts(),
        }
    }
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
        if self.backends.is_empty() {
            return Err(ConfigError::NoBackends);
        }
        if self.listener.max_connections == Some(0) {
            return Err(ConfigError::InvalidValue {
                field: "listener.max_connections",
                reason: "must be at least 1".to_owned(),
            });
        }
        if self.connection.idle_timeout_secs == Some(0) {
            return Err(ConfigError::InvalidValue {
                field: "connection.idle_timeout_secs",
                reason: "must be at least 1".to_owned(),
            });
        }
        if self.connection.connect_timeout_secs == 0 {
            return Err(ConfigError::InvalidValue {
                field: "connection.connect_timeout_secs",
                reason: "must be at least 1".to_owned(),
            });
        }
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
        if let Some(ref tls) = self.tls {
            if tls.certificates.is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "tls.certificates",
                    reason: "must have at least one certificate".to_owned(),
                });
            }
            if tls.handshake_timeout_secs == 0 {
                return Err(ConfigError::InvalidValue {
                    field: "tls.handshake_timeout_secs",
                    reason: "must be at least 1".to_owned(),
                });
            }
            if tls.min_version != "1.2" && tls.min_version != "1.3" {
                return Err(ConfigError::InvalidValue {
                    field: "tls.min_version",
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
                        field: "tls.certificates[].sni_names",
                        reason: "required when multiple certificates are configured".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
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

    #[test]
    fn parse_valid_config() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [[backends]]
            address = "127.0.0.1:3002"
            "#,
        );

        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.listener.address, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(config.backends.len(), 2);
        assert_eq!(
            config.backends[0].address,
            "127.0.0.1:3001".parse().unwrap()
        );
    }

    #[test]
    fn defaults_when_optional_sections_omitted() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"
            "#,
        );

        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.logging.level, "info");
        assert!(config.metrics.is_none());
    }

    #[test]
    fn explicit_logging_overrides_default() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [logging]
            level = "debug"
            "#,
        );

        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn metrics_parsed_when_present() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [metrics]
            address = "0.0.0.0:9090"
            "#,
        );

        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let metrics = config.metrics.unwrap();
        assert_eq!(metrics.address, "0.0.0.0:9090".parse().unwrap());
    }

    #[test]
    fn reject_no_backends() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"
            "#,
        );

        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::NoBackends));
    }

    #[test]
    fn reject_empty_backends_list() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            backends = []
            "#,
        );

        // `backends = []` (inline array) vs `[[backends]]` (table array) parse
        // differently  - either way, no backends means rejection
        let result = Config::from_file(file.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_address() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "not_an_address"

            [[backends]]
            address = "127.0.0.1:3001"
            "#,
        );

        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn reject_missing_listener() {
        let file = write_temp_config(
            r#"
            [[backends]]
            address = "127.0.0.1:3001"
            "#,
        );

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
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
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
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [forwarding]
            strategy = "userspace"
            "#,
        );

        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.forwarding.strategy, ForwardingStrategy::Userspace);
    }

    #[test]
    fn reject_malformed_toml() {
        let file = write_temp_config("this is not [valid toml");

        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn reject_zero_max_connections() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"
            max_connections = 0

            [[backends]]
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
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [connection]
            idle_timeout_secs = 0
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn connection_defaults_applied() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"
            "#,
        );

        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.connection.connect_timeout_secs, 5);
        assert_eq!(config.connection.max_connect_attempts, 3);
        assert!(config.connection.idle_timeout_secs.is_none());
    }

    #[test]
    fn health_defaults_applied_when_section_omitted() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
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
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
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
    fn reject_zero_connect_timeout() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [connection]
            connect_timeout_secs = 0
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_zero_failure_threshold() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
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
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
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
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [health]
            check_interval_secs = 0
            "#,
        );
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    // --- TLS config tests ---

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
    fn tls_section_absent_is_plain_mode() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"
            "#,
        );
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        assert!(config.tls.is_none());
    }

    #[test]
    fn parse_tls_single_cert() {
        let (_dir, cert_path, key_path) = write_pem_files();
        let content = format!(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [[tls.certificates]]
            cert = "{}"
            key = "{}"
            "#,
            cert_path.display(),
            key_path.display(),
        );
        let file = write_temp_config(&content);
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let tls = config.tls.unwrap();
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
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [[tls.certificates]]
            cert = "{}"
            key = "{}"
            sni_names = ["a.test"]

            [[tls.certificates]]
            cert = "{}"
            key = "{}"
            sni_names = ["b.test"]
            "#,
            cert1.display(),
            key1.display(),
            cert2.display(),
            key2.display(),
        );
        let file = write_temp_config(&content);
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let tls = config.tls.unwrap();
        assert_eq!(tls.certificates.len(), 2);
        assert_eq!(tls.certificates[0].sni_names, ["a.test"]);
        assert_eq!(tls.certificates[1].sni_names, ["b.test"]);
    }

    #[test]
    fn tls_defaults_applied() {
        let (_dir, cert_path, key_path) = write_pem_files();
        let content = format!(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [[tls.certificates]]
            cert = "{}"
            key = "{}"
            "#,
            cert_path.display(),
            key_path.display(),
        );
        let file = write_temp_config(&content);
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let tls = config.tls.unwrap();
        assert_eq!(tls.handshake_timeout_secs, 5);
        assert_eq!(tls.min_version, "1.2");
    }

    #[test]
    fn reject_empty_certificates() {
        let file = write_temp_config(
            r#"
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [tls]
            certificates = []
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
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [tls]
            min_version = "1.1"

            [[tls.certificates]]
            cert = "{}"
            key = "{}"
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
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [[tls.certificates]]
            cert = "/nonexistent/cert.pem"
            key = "/nonexistent/key.pem"
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
            [listener]
            address = "0.0.0.0:8080"

            [[backends]]
            address = "127.0.0.1:3001"

            [[tls.certificates]]
            cert = "{}"
            key = "/nonexistent/key.pem"
            "#,
            cert_path.display(),
        );
        let file = write_temp_config(&content);
        let err = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::TlsKeyFileNotFound { .. }));
    }
}
