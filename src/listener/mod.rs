use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::sync::watch;
use tracing::Instrument;

use crate::access_log::AccessLogSink;
use crate::config::{ForwardingStrategy, ListenerConfig, ListenerMode};
use crate::pool::buffer::BufferPool;
use crate::proxy::l4::{self, Resources};
use crate::proxy::l7::matcher::RouteContext;
use crate::proxy::l7::router::Router;
use crate::proxy::l7::{self, ClientStream, ErrorPages};
use crate::tls::passthrough;
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
    pub connect_timeout: Duration,
    pub max_connect_attempts: u32,
    pub tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    pub tls_handshake_timeout: Duration,
    pub listener_label: Arc<str>,
    pub listener_cfg: Arc<ListenerConfig>,
    pub error_pages: Arc<ErrorPages>,
    pub access_log: Arc<AccessLogSink>,
    pub buffer_pool: Arc<BufferPool>,
}

enum ClientConn {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

pub async fn bind(address: SocketAddr) -> Result<TcpListener, ListenerError> {
    TcpListener::bind(address)
        .await
        .map_err(|source| ListenerError::Bind { address, source })
}

async fn idle_watchdog(last_activity: &AtomicU64, timeout: Duration) {
    let timeout_millis = timeout.as_millis() as u64;
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
    router: Arc<dyn Router>,
    config: ServeConfig,
    mut shutdown: watch::Receiver<()>,
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
    let connect_timeout = config.connect_timeout;
    let max_connect_attempts = config.max_connect_attempts;
    let tls_acceptor = config.tls_acceptor;
    let tls_handshake_timeout = config.tls_handshake_timeout;
    let listener_label = config.listener_label.clone();
    let listener_cfg = config.listener_cfg.clone();
    let error_pages = config.error_pages.clone();
    let access_log = config.access_log.clone();
    let buffer_pool = config.buffer_pool.clone();

    let mut tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((client, peer)) => 'accept: {
                        if let Err(e) = client.set_nodelay(true) {
                            tracing::warn!(%peer, error = %e, "failed to set tcp_nodelay");
                        }

                        #[cfg(target_os = "linux")]
                        if let Some(size) = config.resources.socket_buffer_size {
                            use std::os::fd::AsRawFd;
                            if let Err(e) = crate::util::set_socket_buffer_size(client.as_raw_fd(), size) {
                                tracing::warn!(%peer, error = %e, "failed to set socket buffer size");
                            }
                        }

                        let permit = if let Some(ref sem) = connection_semaphore {
                            match sem.clone().try_acquire_owned() {
                                Ok(permit) => Some(permit),
                                Err(_) => {
                                    tracing::warn!(%peer, "max connections reached, rejecting");
                                    metrics::counter!(
                                        "kntx_connections_rejected_total",
                                        "listener" => listener_label.to_string(),
                                    )
                                    .increment(1);
                                    break 'accept;
                                }
                            }
                        } else {
                            None
                        };

                        metrics::counter!(
                            "kntx_connections_total",
                            "listener" => listener_label.to_string(),
                        )
                        .increment(1);
                        metrics::gauge!(
                            "kntx_connections_active",
                            "listener" => listener_label.to_string(),
                        )
                        .increment(1.0);

                        let router = Arc::clone(&router);
                        let resources = config.resources.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        let listener_label = listener_label.clone();
                        let listener_cfg = listener_cfg.clone();
                        let error_pages = error_pages.clone();
                        let access_log = access_log.clone();
                        let buffer_pool = buffer_pool.clone();
                        // per-conn shutdown receiver: the keep-alive loop selects on
                        // this to stop looping gracefully on shutdown.
                        let conn_shutdown = shutdown.clone();

                        tasks.spawn(async move {
                            let _permit = permit;

                            // peeked is Some only for tls-passthrough: ClientHello bytes the
                            // client already sent, which must reach the backend first.
                            let (client_conn, conn_sni, peeked) = if listener_cfg.mode
                                == ListenerMode::TlsPassthrough
                            {
                                let mut client = client;
                                let Some(mut peek_buf) = buffer_pool.get() else {
                                    tracing::warn!(%peer, "buffer pool exhausted during ClientHello peek");
                                    metrics::counter!(
                                        "kntx_tls_passthrough_rejects_total",
                                        "listener" => listener_label.to_string(),
                                        "reason" => "buffer_exhausted",
                                    )
                                    .increment(1);
                                    metrics::gauge!(
                                        "kntx_connections_active",
                                        "listener" => listener_label.to_string(),
                                    )
                                    .decrement(1.0);
                                    return;
                                };
                                let clienthello_timeout =
                                    Duration::from_secs(listener_cfg.clienthello_timeout_secs);
                                match tokio::time::timeout(
                                    clienthello_timeout,
                                    passthrough::peek_client_hello(&mut client, &mut peek_buf),
                                )
                                .await
                                {
                                    Ok(Ok(hello)) => {
                                        let sni: Option<Arc<str>> =
                                            hello.sni.as_deref().map(Arc::from);
                                        if let Some(ref s) = sni {
                                            tracing::debug!(%peer, sni = %s, len = hello.len, "ClientHello peeked");
                                        } else {
                                            tracing::debug!(%peer, len = hello.len, "ClientHello peeked (no SNI)");
                                            metrics::counter!(
                                                "kntx_tls_passthrough_no_sni_total",
                                                "listener" => listener_label.to_string(),
                                            )
                                            .increment(1);
                                        }
                                        (ClientConn::Plain(client), sni, Some((peek_buf, hello.len)))
                                    }
                                    Ok(Err(e)) => {
                                        tracing::debug!(%peer, error = %e, "ClientHello peek failed");
                                        metrics::counter!(
                                            "kntx_tls_passthrough_rejects_total",
                                            "listener" => listener_label.to_string(),
                                            "reason" => e.metric_reason(),
                                        )
                                        .increment(1);
                                        metrics::gauge!(
                                            "kntx_connections_active",
                                            "listener" => listener_label.to_string(),
                                        )
                                        .decrement(1.0);
                                        return;
                                    }
                                    Err(_) => {
                                        tracing::debug!(%peer, "ClientHello peek timed out");
                                        metrics::counter!(
                                            "kntx_tls_passthrough_rejects_total",
                                            "listener" => listener_label.to_string(),
                                            "reason" => "timeout",
                                        )
                                        .increment(1);
                                        metrics::gauge!(
                                            "kntx_connections_active",
                                            "listener" => listener_label.to_string(),
                                        )
                                        .decrement(1.0);
                                        return;
                                    }
                                }
                            } else if let Some(acceptor) = tls_acceptor {
                                let handshake_start = std::time::Instant::now();
                                match tokio::time::timeout(
                                    tls_handshake_timeout,
                                    acceptor.accept(client),
                                )
                                .await
                                {
                                    Ok(Ok(tls)) => {
                                        let duration = handshake_start.elapsed();
                                        metrics::histogram!(
                                            "kntx_tls_handshake_duration_seconds",
                                            "listener" => listener_label.to_string(),
                                        )
                                        .record(duration.as_secs_f64());
                                        metrics::counter!(
                                            "kntx_tls_handshakes_total",
                                            "listener" => listener_label.to_string(),
                                        )
                                        .increment(1);

                                        let sni: Option<Arc<str>> = tls
                                            .get_ref()
                                            .1
                                            .server_name()
                                            .map(Arc::from);
                                        if let Some(ref s) = sni {
                                            tracing::debug!(%peer, sni = %s, "TLS handshake completed");
                                        } else {
                                            tracing::debug!(%peer, "TLS handshake completed (no SNI)");
                                        }

                                        (ClientConn::Tls(Box::new(tls)), sni, None)
                                    }
                                    Ok(Err(e)) => {
                                        tracing::debug!(%peer, error = %e, "TLS handshake failed");
                                        metrics::counter!(
                                            "kntx_tls_handshake_failures_total",
                                            "listener" => listener_label.to_string(),
                                            "reason" => "protocol_error",
                                        )
                                        .increment(1);
                                        metrics::gauge!(
                                            "kntx_connections_active",
                                            "listener" => listener_label.to_string(),
                                        )
                                        .decrement(1.0);
                                        return;
                                    }
                                    Err(_) => {
                                        tracing::debug!(%peer, "TLS handshake timed out");
                                        metrics::counter!(
                                            "kntx_tls_handshake_failures_total",
                                            "listener" => listener_label.to_string(),
                                            "reason" => "timeout",
                                        )
                                        .increment(1);
                                        metrics::gauge!(
                                            "kntx_connections_active",
                                            "listener" => listener_label.to_string(),
                                        )
                                        .decrement(1.0);
                                        return;
                                    }
                                }
                            } else {
                                (ClientConn::Plain(client), None, None)
                            };

                            let span = tracing::info_span!("conn", %peer);

                            async {
                                let last_activity = Arc::new(AtomicU64::new(monotonic_millis()));

                                match listener_cfg.mode {
                                    ListenerMode::L7 => {
                                        let l7_stream = match client_conn {
                                            ClientConn::Plain(tcp) => ClientStream::Plain(tcp),
                                            ClientConn::Tls(tls) => ClientStream::Tls(tls),
                                        };

                                        let forward_fut = l7::forward_l7(
                                            l7_stream,
                                            peer,
                                            conn_sni.clone(),
                                            listener_cfg.clone(),
                                            Arc::clone(&router),
                                            Arc::clone(&error_pages),
                                            Arc::clone(&access_log),
                                            Arc::clone(&last_activity),
                                            Arc::clone(&buffer_pool),
                                            listener_label.clone(),
                                            conn_shutdown,
                                        );

                                        let result = if let Some(timeout) = idle_timeout {
                                            tokio::select! {
                                                r = forward_fut => r.err().map(|e| tracing::warn!(error = %e, "l7 error")),
                                                _ = idle_watchdog(&last_activity, timeout) => {
                                                    tracing::info!("idle timeout");
                                                    metrics::counter!(
                                                        "kntx_idle_timeouts_total",
                                                        "listener" => listener_label.to_string(),
                                                    ).increment(1);
                                                    None
                                                }
                                            }
                                        } else {
                                            if let Err(e) = forward_fut.await { tracing::warn!(error = %e, "l7 error"); }
                                            None
                                        };
                                        let _ = result;
                                    }
                                    ListenerMode::L4 | ListenerMode::TlsPassthrough => {
                                        let l4_ctx = RouteContext {
                                            method: None,
                                            host: None,
                                            path: None,
                                            headers: &[],
                                            sni: conn_sni.as_deref(),
                                            client_ip: peer.ip(),
                                        };
                                        let l4_entry = match router.route(&l4_ctx) {
                                            Some(e) => e,
                                            None => {
                                                tracing::warn!(%peer, "no route for L4 connection");
                                                metrics::counter!(
                                                    "kntx_route_no_match_total",
                                                    "listener" => listener_label.to_string(),
                                                )
                                                .increment(1);
                                                metrics::gauge!(
                                                    "kntx_connections_active",
                                                    "listener" => listener_label.to_string(),
                                                )
                                                .decrement(1.0);
                                                return;
                                            }
                                        };
                                        if listener_cfg.mode == ListenerMode::TlsPassthrough {
                                            metrics::counter!(
                                                "kntx_tls_passthrough_connections_total",
                                                "listener" => listener_label.to_string(),
                                                "route_id" => l4_entry.route_id.to_string(),
                                            )
                                            .increment(1);
                                        }
                                        let pool = l4_entry.pool.backends.clone();
                                        let rr = l4_entry.pool.rr.clone();
                                        let pool_name = l4_entry.pool.name.to_string();
                                        let mut attempts = 0u32;
                                        let backend_result = loop {
                                            let addr = match rr.next_backend() {
                                                Some(a) => a,
                                                None => {
                                                    tracing::warn!(%peer, "no healthy backends available");
                                                    break None;
                                                }
                                            };
                                            match l4::connect_backend(addr, connect_timeout, resources.socket_buffer_size).await {
                                                Ok(server) => break Some((addr, server)),
                                                Err(e) => {
                                                    pool.record_failure(addr);
                                                    attempts += 1;
                                                    metrics::counter!(
                                                        "kntx_connect_retries_total",
                                                        "pool" => pool_name.clone(),
                                                        "listener" => listener_label.to_string(),
                                                    ).increment(1);
                                                    if attempts >= max_connect_attempts {
                                                        tracing::warn!(%peer, attempts, "all retry attempts exhausted");
                                                        break None;
                                                    }
                                                    tracing::debug!(%peer, %addr, attempt = attempts, error = %e, "retrying");
                                                }
                                            }
                                        };

                                        let (backend_addr, mut server) = match backend_result {
                                            Some(pair) => pair,
                                            None => {
                                                metrics::gauge!(
                                                    "kntx_connections_active",
                                                    "listener" => listener_label.to_string(),
                                                ).decrement(1.0);
                                                return;
                                            }
                                        };

                                        if let Some((peek_buf, peek_len)) = peeked {
                                            use tokio::io::AsyncWriteExt;
                                            if let Err(e) = server.write_all(&peek_buf[..peek_len]).await {
                                                tracing::warn!(%peer, error = %e, "failed to flush ClientHello to backend");
                                                pool.record_failure(backend_addr);
                                                metrics::gauge!(
                                                    "kntx_connections_active",
                                                    "listener" => listener_label.to_string(),
                                                ).decrement(1.0);
                                                return;
                                            }
                                            metrics::counter!(
                                                "kntx_forwarded_bytes_total",
                                                "direction" => "client_to_backend",
                                                "listener" => listener_label.to_string(),
                                            ).increment(peek_len as u64);
                                            // guard drops here - buffer returns to the pool
                                            // before forwarding begins
                                        }

                                        let forward_fut = async {
                                            match client_conn {
                                                ClientConn::Plain(tcp) => {
                                                    l4::forward_connected(tcp, server, strategy, &resources, &last_activity).await
                                                }
                                                ClientConn::Tls(tls) => {
                                                    l4::forward_tls(*tls, server, &resources, &last_activity).await
                                                }
                                            }
                                        };

                                        let result = if let Some(timeout) = idle_timeout {
                                            tokio::select! {
                                                result = forward_fut => Some(result),
                                                _ = idle_watchdog(&last_activity, timeout) => {
                                                    tracing::info!("idle timeout");
                                                    None
                                                }
                                            }
                                        } else {
                                            Some(forward_fut.await)
                                        };

                                        match result {
                                            Some(Ok(fwd)) => {
                                                pool.record_success(backend_addr);
                                                metrics::counter!(
                                                    "kntx_forwarded_bytes_total",
                                                    "direction" => "client_to_backend",
                                                    "listener" => listener_label.to_string(),
                                                ).increment(fwd.client_to_backend);
                                                metrics::counter!(
                                                    "kntx_forwarded_bytes_total",
                                                    "direction" => "backend_to_client",
                                                    "listener" => listener_label.to_string(),
                                                ).increment(fwd.backend_to_client);
                                                tracing::debug!(
                                                    sent = fwd.client_to_backend,
                                                    recv = fwd.backend_to_client,
                                                    "connection closed",
                                                );
                                            }
                                            Some(Err(e)) => {
                                                pool.record_failure(backend_addr);
                                                tracing::warn!(error = %e, "connection failed");
                                            }
                                            None => {
                                                metrics::counter!(
                                                    "kntx_idle_timeouts_total",
                                                    "listener" => listener_label.to_string(),
                                                ).increment(1);
                                            }
                                        }
                                    }
                                }

                                metrics::gauge!(
                                    "kntx_connections_active",
                                    "listener" => listener_label.to_string(),
                                )
                                .decrement(1.0);
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
            _ = shutdown.changed() => {
                tracing::info!(%address, "shutdown signal received");
                break;
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }

    // close the listening socket before draining. the kernel otherwise keeps
    // completing handshakes into the backlog that nobody will ever accept,
    // leaving those clients hanging in dead air instead of refused-and-retrying
    // elsewhere. nginx closes listen sockets at the same point.
    drop(listener);

    if !tasks.is_empty() {
        tracing::info!(%address, remaining = tasks.len(), "draining in-flight connections");
        let drain_deadline = tokio::time::sleep(drain_timeout);
        tokio::pin!(drain_deadline);
        loop {
            tokio::select! {
                result = tasks.join_next() => {
                    match result {
                        Some(_) if tasks.is_empty() => {
                            tracing::info!(%address, "all connections drained");
                            break;
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
                _ = &mut drain_deadline => {
                    tracing::warn!(
                        %address,
                        remaining = tasks.len(),
                        "drain timeout reached, aborting remaining connections"
                    );
                    tasks.abort_all();
                    break;
                }
            }
        }
    }

    tracing::info!(%address, "shutdown complete");
}
