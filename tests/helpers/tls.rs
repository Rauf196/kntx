#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub struct TestCert {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// DER bytes for building a trust anchor in clients
    pub cert_der: Vec<u8>,
}

/// generate a self-signed cert for the given SANs.
pub fn generate_cert(subject_alt_names: &[&str]) -> TestCert {
    let names: Vec<String> = subject_alt_names.iter().map(|s| s.to_string()).collect();
    let cert = generate_simple_self_signed(names).unwrap();
    let cert_der = cert.cert.der().to_vec();
    TestCert {
        cert_pem: cert.cert.pem().into_bytes(),
        key_pem: cert.key_pair.serialize_pem().into_bytes(),
        cert_der,
    }
}

/// write cert and key PEM files to a tempdir, returning (dir, cert_path, key_path).
/// the TempDir must be kept alive — it deletes files on drop.
pub fn write_cert_to_tempdir(
    cert: &TestCert,
) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &cert.cert_pem).unwrap();
    std::fs::write(&key_path, &cert.key_pem).unwrap();
    (dir, cert_path, key_path)
}

/// build a rustls ClientConfig that trusts only the given DER cert.
/// used in tests so the client can verify the proxy's self-signed cert.
pub fn client_config_trusting(cert_der: &[u8]) -> Arc<rustls::ClientConfig> {
    use rustls::RootCertStore;

    // install ring once (idempotent)
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap_or(());

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der.to_vec())).unwrap();

    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// open a TLS connection to `addr` presenting `server_name` for SNI.
pub async fn tls_connect(
    addr: SocketAddr,
    server_name: &str,
    client_config: Arc<rustls::ClientConfig>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let connector = TlsConnector::from(client_config);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(server_name.to_owned()).unwrap();
    connector.connect(server_name, tcp).await.unwrap()
}
