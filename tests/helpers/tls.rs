#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
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
/// the TempDir must be kept alive - it deletes files on drop.
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

/// open a TLS connection using an IP-address ServerName - rustls omits the
/// SNI extension entirely for these. cert must carry a matching IP SAN.
pub async fn tls_connect_no_sni(
    addr: SocketAddr,
    client_config: Arc<rustls::ClientConfig>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let connector = TlsConnector::from(client_config);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    connector
        .connect(ServerName::IpAddress(ip.into()), tcp)
        .await
        .unwrap()
}

/// rustls ServerConfig serving the given test cert.
pub fn server_config_from(cert: &TestCert) -> Arc<rustls::ServerConfig> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap_or(());

    let certs = vec![CertificateDer::from(cert.cert_der.clone())];
    let key = rustls_pemfile::private_key(&mut &cert.key_pem[..])
        .unwrap()
        .unwrap();
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

/// TLS-terminating echo backend: handshakes with its own cert, then echoes
/// until EOF. the cert a client sees proves which backend it reached.
pub struct TlsEchoBackend {
    pub addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
}

impl TlsEchoBackend {
    pub async fn start(cert: &TestCert) -> Self {
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config_from(cert));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        let Ok((tcp, _)) = accept else { continue };
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                            let mut buf = [0u8; 4096];
                            loop {
                                match tls.read(&mut buf).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => {
                                        if tls.write_all(&buf[..n]).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        });
                    }
                    _ = &mut shutdown_rx => return,
                }
            }
        });

        Self {
            addr,
            _shutdown: shutdown_tx,
        }
    }
}

/// plain-TCP backend that writes PONG on accept, then records every received
/// byte until the client closes. lets tests assert the proxy delivered the
/// peeked ClientHello (and everything after it) byte-exact.
pub struct SinkBackend {
    pub addr: SocketAddr,
    pub received: Arc<Mutex<Vec<u8>>>,
    _shutdown: oneshot::Sender<()>,
}

impl SinkBackend {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_writer = Arc::clone(&received);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        let Ok((mut stream, _)) = accept else { continue };
                        let received = Arc::clone(&received_writer);
                        tokio::spawn(async move {
                            if stream.write_all(b"PONG").await.is_err() {
                                return;
                            }
                            let mut buf = [0u8; 4096];
                            loop {
                                match stream.read(&mut buf).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => received.lock().unwrap().extend_from_slice(&buf[..n]),
                                }
                            }
                        });
                    }
                    _ = &mut shutdown_rx => return,
                }
            }
        });

        Self {
            addr,
            received,
            _shutdown: shutdown_tx,
        }
    }
}

/// ClientHello bytes generated by rustls. `None` uses an IP-address
/// ServerName, for which rustls omits the SNI extension.
pub fn client_hello_bytes(server_name: Option<&str>) -> Vec<u8> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap_or(());

    let name: ServerName<'static> = match server_name {
        Some(n) => ServerName::try_from(n.to_owned()).unwrap(),
        None => {
            let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
            ServerName::IpAddress(ip.into())
        }
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).unwrap();
    }
    out
}
