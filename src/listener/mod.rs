use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;
use tokio::net::TcpListener;
use tracing::Instrument;

use crate::balancer::RoundRobin;
use crate::config::ForwardingStrategy;
use crate::proxy::l4::{self, Resources};

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("failed to bind to {address}")]
    Bind {
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to accept connection")]
    Accept(#[source] std::io::Error),
}

pub async fn bind(address: SocketAddr) -> Result<TcpListener, ListenerError> {
    TcpListener::bind(address)
        .await
        .map_err(|source| ListenerError::Bind { address, source })
}

pub async fn serve(
    listener: TcpListener,
    balancer: Arc<RoundRobin>,
    strategy: ForwardingStrategy,
    resources: Resources,
) {
    let address = listener.local_addr().expect("listener has local address");
    tracing::info!(%address, %strategy, "listening");

    loop {
        match listener.accept().await {
            Ok((client, peer)) => {
                // disable nagle  - proxy forwards data immediately, coalescing adds latency
                if let Err(e) = client.set_nodelay(true) {
                    tracing::warn!(%peer, error = %e, "failed to set tcp_nodelay");
                }

                // apply socket buffer tuning if configured
                #[cfg(target_os = "linux")]
                if let Some(size) = resources.socket_buffer_size {
                    use std::os::fd::AsRawFd;
                    if let Err(e) = crate::util::set_socket_buffer_size(client.as_raw_fd(), size) {
                        tracing::warn!(%peer, error = %e, "failed to set socket buffer size");
                    }
                }

                let balancer = Arc::clone(&balancer);
                let resources = resources.clone();
                tokio::spawn(async move {
                    let backend = match balancer.next_backend() {
                        Some(addr) => addr,
                        None => {
                            tracing::warn!(%peer, "no backends available");
                            return;
                        }
                    };

                    let span = tracing::info_span!(
                        "conn",
                        %peer,
                        %backend,
                    );

                    async {
                        match l4::forward(client, backend, strategy, &resources).await {
                            Ok(result) => {
                                tracing::debug!(
                                    sent = result.client_to_backend,
                                    recv = result.backend_to_client,
                                    "connection closed",
                                );
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "connection failed");
                            }
                        }
                    }
                    .instrument(span)
                    .await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
            }
        }
    }
}
