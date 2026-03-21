use std::net::SocketAddr;

use tokio::io;
use tokio::net::TcpStream;
use thiserror::Error;

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
}

#[derive(Debug)]
pub enum Direction {
    ClientToBackend,
    BackendToClient,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientToBackend => f.write_str("client → backend"),
            Self::BackendToClient => f.write_str("backend → client"),
        }
    }
}

pub struct ForwardResult {
    pub client_to_backend: u64,
    pub backend_to_client: u64,
}

pub async fn forward(
    mut client: TcpStream,
    backend: SocketAddr,
) -> Result<ForwardResult, ProxyError> {
    let mut server = TcpStream::connect(backend)
        .await
        .map_err(|source| ProxyError::BackendConnect { backend, source })?;

    let (client_to_backend, backend_to_client) =
        io::copy_bidirectional(&mut client, &mut server)
            .await
            .map_err(|source| {
                ProxyError::Forward {
                    direction: Direction::ClientToBackend,
                    source,
                }
            })?;

    Ok(ForwardResult {
        client_to_backend,
        backend_to_client,
    })
}
