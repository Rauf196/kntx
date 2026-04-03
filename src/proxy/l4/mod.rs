pub mod userspace;
pub mod vectored;

#[cfg(target_os = "linux")]
pub mod splice;

use std::io;
use std::net::SocketAddr;

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
async fn connect_backend(
    backend: SocketAddr,
    socket_buffer_size: Option<usize>,
) -> Result<TcpStream, ProxyError> {
    let server = TcpStream::connect(backend)
        .await
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

/// dispatch to the configured forwarding strategy
pub async fn forward(
    client: TcpStream,
    backend: SocketAddr,
    strategy: ForwardingStrategy,
    resources: &Resources,
) -> Result<ForwardResult, ProxyError> {
    let server = connect_backend(backend, resources.socket_buffer_size).await?;

    match strategy {
        ForwardingStrategy::Userspace => {
            userspace::forward(client, server, &resources.buffer_pool).await
        }
        ForwardingStrategy::Vectored => {
            vectored::forward(client, server, &resources.buffer_pool).await
        }
        #[cfg(target_os = "linux")]
        ForwardingStrategy::Splice => splice::forward(client, server, &resources.pipe_pool).await,
    }
}
