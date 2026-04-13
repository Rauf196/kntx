use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("failed to read {kind} file '{path}'")]
    ReadFile {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("no certificates found in '{path}'")]
    EmptyCertFile { path: PathBuf },

    #[error("no private key found in '{path}'")]
    EmptyKeyFile { path: PathBuf },

    #[error("invalid private key in '{path}'")]
    InvalidKey { path: PathBuf },

    #[error("invalid TLS min version '{0}' (expected '1.2' or '1.3')")]
    InvalidMinVersion(String),

    #[error("failed to build rustls server config")]
    BuildConfig(#[source] rustls::Error),
}

pub fn build_acceptor(config: &TlsConfig) -> Result<TlsAcceptor, TlsError> {
    // install ring as the crypto provider. idempotent — ok if already installed.
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap_or(());

    let versions = tls_versions(&config.min_version)?;

    let server_config = if config.certificates.len() == 1 {
        let cert_cfg = &config.certificates[0];
        let certs = load_certs(&cert_cfg.cert)?;
        let key = load_key(&cert_cfg.key)?;

        ServerConfig::builder_with_protocol_versions(versions)
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(TlsError::BuildConfig)?
    } else {
        use rustls::server::ResolvesServerCertUsingSni;
        use rustls::sign::CertifiedKey;

        let mut resolver = ResolvesServerCertUsingSni::new();

        for cert_cfg in &config.certificates {
            let certs = load_certs(&cert_cfg.cert)?;
            let key = load_key(&cert_cfg.key)?;

            let signing_key = Arc::new(
                rustls::crypto::ring::default_provider()
                    .key_provider
                    .load_private_key(key)
                    .map_err(|_| TlsError::InvalidKey {
                        path: cert_cfg.key.clone(),
                    })?,
            );

            for name in &cert_cfg.sni_names {
                // CertifiedKey wraps Arc<dyn SigningKey> — cheap to clone per name
                let certified = CertifiedKey::new(certs.clone(), Arc::clone(&signing_key));
                resolver
                    .add(name, certified)
                    .map_err(TlsError::BuildConfig)?;
            }
        }

        ServerConfig::builder_with_protocol_versions(versions)
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver))
    };

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

fn tls_versions(
    min: &str,
) -> Result<&'static [&'static rustls::SupportedProtocolVersion], TlsError> {
    match min {
        "1.2" => Ok(rustls::ALL_VERSIONS),
        "1.3" => Ok(TLS13_ONLY),
        other => Err(TlsError::InvalidMinVersion(other.to_owned())),
    }
}

fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let data = std::fs::read(path).map_err(|source| TlsError::ReadFile {
        kind: "cert",
        path: path.to_path_buf(),
        source,
    })?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::ReadFile {
            kind: "cert",
            path: path.to_path_buf(),
            source,
        })?;

    if certs.is_empty() {
        return Err(TlsError::EmptyCertFile {
            path: path.to_path_buf(),
        });
    }

    Ok(certs)
}

fn load_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let data = std::fs::read(path).map_err(|source| TlsError::ReadFile {
        kind: "key",
        path: path.to_path_buf(),
        source,
    })?;

    rustls_pemfile::private_key(&mut data.as_slice())
        .map_err(|source| TlsError::ReadFile {
            kind: "key",
            path: path.to_path_buf(),
            source,
        })?
        .ok_or_else(|| TlsError::EmptyKeyFile {
            path: path.to_path_buf(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CertificateConfig;

    fn make_test_cert(sans: &[&str]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        use rcgen::generate_simple_self_signed;
        let names: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let cert = generate_simple_self_signed(names).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        (dir, cert_path, key_path)
    }

    fn single_cert_config(cert: &std::path::Path, key: &std::path::Path) -> TlsConfig {
        TlsConfig {
            handshake_timeout_secs: 5,
            min_version: "1.2".to_owned(),
            certificates: vec![CertificateConfig {
                cert: cert.to_path_buf(),
                key: key.to_path_buf(),
                sni_names: vec![],
            }],
        }
    }

    #[test]
    fn build_acceptor_single_cert_succeeds() {
        let (_dir, cert, key) = make_test_cert(&["localhost"]);
        let config = single_cert_config(&cert, &key);
        assert!(build_acceptor(&config).is_ok());
    }

    #[test]
    fn build_acceptor_multi_cert_succeeds() {
        let (_dir1, cert1, key1) = make_test_cert(&["a.test"]);
        let (_dir2, cert2, key2) = make_test_cert(&["b.test"]);
        let config = TlsConfig {
            handshake_timeout_secs: 5,
            min_version: "1.2".to_owned(),
            certificates: vec![
                CertificateConfig {
                    cert: cert1,
                    key: key1,
                    sni_names: vec!["a.test".to_owned()],
                },
                CertificateConfig {
                    cert: cert2,
                    key: key2,
                    sni_names: vec!["b.test".to_owned()],
                },
            ],
        };
        assert!(build_acceptor(&config).is_ok());
    }

    #[test]
    fn build_acceptor_missing_cert_file() {
        let config = TlsConfig {
            handshake_timeout_secs: 5,
            min_version: "1.2".to_owned(),
            certificates: vec![CertificateConfig {
                cert: "/nonexistent/cert.pem".into(),
                key: "/nonexistent/key.pem".into(),
                sni_names: vec![],
            }],
        };
        let err = build_acceptor(&config).map(|_| ()).unwrap_err();
        assert!(matches!(err, TlsError::ReadFile { .. }));
    }

    #[test]
    fn build_acceptor_empty_cert_file() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("empty.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, b"").unwrap();
        std::fs::write(&key_path, b"").unwrap();
        let config = single_cert_config(&cert_path, &key_path);
        let err = build_acceptor(&config).map(|_| ()).unwrap_err();
        assert!(matches!(err, TlsError::EmptyCertFile { .. }));
    }

    #[test]
    fn build_acceptor_empty_key_file() {
        let (_dir, cert, _key) = make_test_cert(&["localhost"]);
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("empty_key.pem");
        std::fs::write(&key_path, b"").unwrap();
        let config = single_cert_config(&cert, &key_path);
        let err = build_acceptor(&config).map(|_| ()).unwrap_err();
        assert!(matches!(err, TlsError::EmptyKeyFile { .. }));
    }

    #[test]
    fn build_acceptor_min_version_1_3() {
        let (_dir, cert, key) = make_test_cert(&["localhost"]);
        let config = TlsConfig {
            handshake_timeout_secs: 5,
            min_version: "1.3".to_owned(),
            certificates: vec![CertificateConfig {
                cert,
                key,
                sni_names: vec![],
            }],
        };
        assert!(build_acceptor(&config).is_ok());
    }

    #[test]
    fn build_acceptor_invalid_min_version() {
        let (_dir, cert, key) = make_test_cert(&["localhost"]);
        let config = TlsConfig {
            handshake_timeout_secs: 5,
            min_version: "1.1".to_owned(),
            certificates: vec![CertificateConfig {
                cert,
                key,
                sni_names: vec![],
            }],
        };
        let err = build_acceptor(&config).map(|_| ()).unwrap_err();
        assert!(matches!(err, TlsError::InvalidMinVersion(_)));
    }
}
