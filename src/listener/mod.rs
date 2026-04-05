use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::Instrument;

use crate::balancer::RoundRobin;
use crate::config::ForwardingStrategy;
use crate::proxy::l4::{self, Resources};
use crate::util::monotonic_millis;

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("failed to bind to {address}")]
    Bind {
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

pub struct ServeConfig {
    pub strategy: ForwardingStrategy,
    pub resources: Resources,
    pub max_connections: Option<usize>,
    pub idle_timeout: Option<Duration>,
    pub drain_timeout: Duration,
}

pub async fn bind(address: SocketAddr) -> Result<TcpListener, ListenerError> {
    TcpListener::bind(address)
        .await
        .map_err(|source| ListenerError::Bind { address, source })
}

async fn idle_watchdog(last_activity: &AtomicU64, timeout: Duration) {
    let timeout_millis = timeout.as_millis() as u64;
    // check at reasonable intervals — fast enough for detection, slow enough to be negligible
    let check_interval = Duration::from_secs(1).min(timeout / 4);
    loop {
        tokio::time::sleep(check_interval).await;
        let elapsed = monotonic_millis().saturating_sub(last_activity.load(Ordering::Relaxed));
        if elapsed >= timeout_millis {
            return;
        }
    }
}

pub async fn serve(
    listener: TcpListener,
    balancer: Arc<RoundRobin>,
    config: ServeConfig,
    shutdown: impl Future<Output = ()> + Send,
) {
    use tokio::task::JoinSet;

    let address = listener.local_addr().expect("listener has local address");
    tracing::info!(%address, strategy = %config.strategy, "listening");

    let connection_semaphore = config
        .max_connections
        .map(|max| Arc::new(Semaphore::new(max)));
    let idle_timeout = config.idle_timeout;
    let strategy = config.strategy;
    let drain_timeout = config.drain_timeout;

    let mut tasks: JoinSet<()> = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((client, peer)) => 'accept: {
                        // disable nagle  - proxy forwards data immediately, coalescing adds latency
                        if let Err(e) = client.set_nodelay(true) {
                            tracing::warn!(%peer, error = %e, "failed to set tcp_nodelay");
                        }

                        // apply socket buffer tuning if configured
                        #[cfg(target_os = "linux")]
                        if let Some(size) = config.resources.socket_buffer_size {
                            use std::os::fd::AsRawFd;
                            if let Err(e) = crate::util::set_socket_buffer_size(client.as_raw_fd(), size) {
                                tracing::warn!(%peer, error = %e, "failed to set socket buffer size");
                            }
                        }

                        // connection limit: try_acquire_owned is non-blocking — reject immediately
                        let permit = if let Some(ref sem) = connection_semaphore {
                            match sem.clone().try_acquire_owned() {
                                Ok(permit) => Some(permit),
                                Err(_) => {
                                    tracing::warn!(%peer, "max connections reached, rejecting");
                                    metrics::counter!("kntx_connections_rejected_total").increment(1);
                                    break 'accept;
                                }
                            }
                        } else {
                            None
                        };

                        metrics::counter!("kntx_connections_total").increment(1);
                        metrics::gauge!("kntx_connections_active").increment(1.0);

                        let balancer = Arc::clone(&balancer);
                        let resources = config.resources.clone();

                        tasks.spawn(async move {
                            // permit held for connection lifetime — dropped on task end
                            let _permit = permit;

                            let backend = match balancer.next_backend() {
                                Some(addr) => addr,
                                None => {
                                    tracing::warn!(%peer, "no backends available");
                                    metrics::gauge!("kntx_connections_active").decrement(1.0);
                                    return;
                                }
                            };

                            let span = tracing::info_span!("conn", %peer, %backend);

                            async {
                                let last_activity = AtomicU64::new(monotonic_millis());

                                let result = if let Some(timeout) = idle_timeout {
                                    tokio::select! {
                                        result = l4::forward(client, backend, strategy, &resources, &last_activity) => Some(result),
                                        _ = idle_watchdog(&last_activity, timeout) => {
                                            tracing::info!("idle timeout");
                                            None
                                        }
                                    }
                                } else {
                                    Some(l4::forward(client, backend, strategy, &resources, &last_activity).await)
                                };

                                match result {
                                    Some(Ok(fwd)) => {
                                        metrics::counter!("kntx_forwarded_bytes_total", "direction" => "client_to_backend")
                                            .increment(fwd.client_to_backend);
                                        metrics::counter!("kntx_forwarded_bytes_total", "direction" => "backend_to_client")
                                            .increment(fwd.backend_to_client);
                                        tracing::debug!(
                                            sent = fwd.client_to_backend,
                                            recv = fwd.backend_to_client,
                                            "connection closed",
                                        );
                                    }
                                    Some(Err(e)) => {
                                        tracing::warn!(error = %e, "connection failed");
                                    }
                                    None => {
                                        // idle timeout — connection dropped by select cancellation
                                        metrics::counter!("kntx_idle_timeouts_total").increment(1);
                                    }
                                }

                                metrics::gauge!("kntx_connections_active").decrement(1.0);
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
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received");
                break;
            }
            // reap completed tasks to prevent unbounded JoinSet growth
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }

    // drain phase: wait for in-flight connections to finish
    if !tasks.is_empty() {
        tracing::info!(remaining = tasks.len(), "draining in-flight connections");
        let drain_deadline = tokio::time::sleep(drain_timeout);
        tokio::pin!(drain_deadline);
        loop {
            tokio::select! {
                result = tasks.join_next() => {
                    match result {
                        Some(_) if tasks.is_empty() => {
                            tracing::info!("all connections drained");
                            break;
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
                _ = &mut drain_deadline => {
                    tracing::warn!(
                        remaining = tasks.len(),
                        "drain timeout reached, aborting remaining connections"
                    );
                    tasks.abort_all();
                    break;
                }
            }
        }
    }

    tracing::info!("shutdown complete");
}
