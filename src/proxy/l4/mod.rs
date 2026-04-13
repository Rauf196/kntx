pub mod userspace;
pub mod vectored;

#[cfg(target_os = "linux")]
pub mod splice;

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use thiserror::Error;
use tokio::net::TcpStream;

use crate::config::ForwardingStrategy;
use crate::pool::buffer::BufferPool;

/// shared resources for forwarding paths, created once at startup.
/// cheaply cloneable  - pools share inner state via Arc.
#[derive(Clone)]
pub struct Resources {
    pub buffer_pool: BufferPool,
    #[cfg(target_os = "linux")]
    pub pipe_pool: crate::pool::pipe::PipePool,
    /// SO_RCVBUF/SO_SNDBUF size in bytes. None = OS default.
    pub socket_buffer_size: Option<usize>,
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("failed to connect to backend {backend}")]
    BackendConnect {
        backend: SocketAddr,
        #[source]
        source: io::Error,
    },

    #[error("connect timeout to backend {backend}")]
    BackendConnectTimeout { backend: SocketAddr },

    #[error("forwarding failed: {direction}")]
    Forward {
        direction: Direction,
        #[source]
        source: io::Error,
    },

    #[error("buffer pool exhausted")]
    BufferPoolExhausted,

    #[error("pipe pool exhausted")]
    PipePoolExhausted,
}

#[derive(Debug)]
pub enum Direction {
    ClientToBackend,
    BackendToClient,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientToBackend => f.write_str("client -> backend"),
            Self::BackendToClient => f.write_str("backend -> client"),
        }
    }
}

pub struct ForwardResult {
    pub client_to_backend: u64,
    pub backend_to_client: u64,
}

/// connect to backend and apply socket tuning (TCP_NODELAY, buffer sizes).
/// centralized here so each forwarding strategy doesn't repeat this.
pub async fn connect_backend(
    backend: SocketAddr,
    connect_timeout: Duration,
    socket_buffer_size: Option<usize>,
) -> Result<TcpStream, ProxyError> {
    let server = tokio::time::timeout(connect_timeout, TcpStream::connect(backend))
        .await
        .map_err(|_| ProxyError::BackendConnectTimeout { backend })?
        .map_err(|source| ProxyError::BackendConnect { backend, source })?;

    if let Err(e) = server.set_nodelay(true) {
        tracing::warn!(%backend, error = %e, "failed to set tcp_nodelay on backend");
    }

    #[cfg(target_os = "linux")]
    if let Some(size) = socket_buffer_size {
        use std::os::fd::AsRawFd;
        if let Err(e) = crate::util::set_socket_buffer_size(server.as_raw_fd(), size) {
            tracing::warn!(%backend, error = %e, "failed to set socket buffer size on backend");
        }
    }

    // suppress unused variable warning on non-linux
    #[cfg(not(target_os = "linux"))]
    let _ = socket_buffer_size;

    Ok(server)
}

/// forward a TLS-terminated client stream to a plain TCP backend.
///
/// always uses userspace — splice cannot operate on decrypted bytes in userspace.
/// the function signature itself encodes this: no strategy parameter.
pub async fn forward_tls(
    client: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    server: TcpStream,
    resources: &Resources,
    last_activity: &AtomicU64,
) -> Result<ForwardResult, ProxyError> {
    userspace::forward_tls(client, server, &resources.buffer_pool, last_activity).await
}

/// dispatch to the configured forwarding strategy on already-connected streams.
pub async fn forward_connected(
    client: TcpStream,
    server: TcpStream,
    strategy: ForwardingStrategy,
    resources: &Resources,
    last_activity: &AtomicU64,
) -> Result<ForwardResult, ProxyError> {
    match strategy {
        ForwardingStrategy::Userspace => {
            userspace::forward(client, server, &resources.buffer_pool, last_activity).await
        }
        ForwardingStrategy::Vectored => {
            vectored::forward(client, server, &resources.buffer_pool, last_activity).await
        }
        #[cfg(target_os = "linux")]
        ForwardingStrategy::Splice => {
            splice::forward(client, server, &resources.pipe_pool, last_activity).await
        }
    }
}
