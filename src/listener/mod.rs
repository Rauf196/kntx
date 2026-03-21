use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use thiserror::Error;
use tracing::Instrument;

use crate::balancer::RoundRobin;
use crate::proxy::l4;

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

pub async fn serve(listener: TcpListener, balancer: Arc<RoundRobin>) {
    let address = listener.local_addr().expect("listener has local address");
    tracing::info!(%address, "listening");

    loop {
        match listener.accept().await {
            Ok((client, peer)) => {
                let balancer = Arc::clone(&balancer);
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
                        match l4::forward(client, backend).await {
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
