use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

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
    InvalidValue {
        field: &'static str,
        reason: String,
    },
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

#[derive(Debug, Default, Deserialize)]
pub struct ConnectionConfig {
    /// close connections with no data transfer for this many seconds. None = no timeout.
    pub idle_timeout_secs: Option<u64>,
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
}
