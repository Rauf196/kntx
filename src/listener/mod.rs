use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
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
use crate::proxy_protocol;
use crate::rate_limit::{Decision, ZoneHandle};
use crate::tls::passthrough;
use crate::util::monotonic_millis;

/// bound on the header-read phase. the balancer sends it in its first segment,
/// so this is a slowloris cap rather than a knob anyone needs to tune.
const PROXY_PROTOCOL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("failed to bind to {address}")]
    Bind {
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// the half of a listener's configuration a reload can replace without rebinding
/// the socket. `serve` reads the cell once per accepted connection, so a
/// connection routes by the vintage it started with for its whole life,
/// keep-alive requests included. backend membership underneath stays live.
pub struct ListenerRuntime {
    pub router: Arc<dyn Router>,
    pub listener_cfg: Arc<ListenerConfig>,
    /// rebuilt from disk on every reload, so a rotated cert is served by the next
    /// handshake. sessions already established keep the acceptor they started with.
    pub tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    /// listener-level zone, enforced at accept. swapped per reload so a tightened
    /// limit takes effect for connections accepted after it; an unchanged zone keeps
    /// its live limiter across the reload (budget not reset).
    pub rate_limit: Option<ZoneHandle>,
}

pub type RuntimeCell = Arc<ArcSwap<ListenerRuntime>>;

/// set once at bind. changing any of these needs a restart, including the
/// timeouts - they shadow the same fields on `ListenerRuntime.listener_cfg`,
/// which a reload does replace. move one here into the runtime read path when
/// there is a reason for it to be live.
pub struct ServeConfig {
    pub strategy: ForwardingStrategy,
    pub resources: Resources,
    pub max_connections: Option<usize>,
    pub idle_timeout: Option<Duration>,
    pub drain_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_connect_attempts: u32,
    pub tls_handshake_timeout: Duration,
    pub listener_label: Arc<str>,
    pub error_pages: Arc<ErrorPages>,
    pub access_log: Arc<AccessLogSink>,
    pub buffer_pool: Arc<BufferPool>,
}

impl ListenerRuntime {
    pub fn cell(
        router: Arc<dyn Router>,
        listener_cfg: Arc<ListenerConfig>,
        tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
        rate_limit: Option<ZoneHandle>,
    ) -> RuntimeCell {
        Arc::new(ArcSwap::from_pointee(Self {
            router,
            listener_cfg,
            tls_acceptor,
            rate_limit,
        }))
    }
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

/// close a rate limited connection with an RST instead of a FIN: no proxy-side
/// TIME_WAIT buildup under flood, and the client hears the refusal immediately.
/// non-linux keeps the plain close.
fn reject_rate_limited(client: TcpStream, peer: SocketAddr, zone: &str, listener_label: &str) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        if let Err(e) = crate::util::set_linger_rst(client.as_raw_fd()) {
            tracing::debug!(%peer, error = %e, "failed to set linger on rate limited conn");
        }
    }
    drop(client);
    tracing::debug!(%peer, zone, "connection rate limited");
    metrics::counter!(
        "kntx_rate_limit_rejected_total",
        "listener" => listener_label.to_string(),
        "zone" => zone.to_string(),
        "scope" => "listener",
    )
    .increment(1);
}

/// count a refused PROXY protocol connection and close out its share of the
/// active gauge, which the accept loop already incremented.
fn reject_proxy_protocol(listener_label: &str, reason: &'static str) {
    metrics::counter!(
        "kntx_proxy_protocol_rejects_total",
        "listener" => listener_label.to_string(),
        "reason" => reason,
    )
    .increment(1);
    metrics::gauge!(
        "kntx_connections_active",
        "listener" => listener_label.to_string(),
    )
    .decrement(1.0);
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
    runtime: RuntimeCell,
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
    let tls_handshake_timeout = config.tls_handshake_timeout;
    let listener_label = config.listener_label.clone();
    let error_pages = config.error_pages.clone();
    let access_log = config.access_log.clone();
    let buffer_pool = config.buffer_pool.clone();

    let mut tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((client, peer)) => 'accept: {
                        // pin the routing vintage for this connection's whole life,
                        // keep-alive requests included. a reload swaps the cell for
                        // connections accepted after it; the rate-limit zone rides on
                        // the same pinned runtime.
                        let rt = runtime.load_full();

                        // before the max_connections permit (a rejected conn must
                        // not consume a slot) and before any socket or TLS work.
                        // a proxy_protocol listener cannot check here - the peer is
                        // the balancer and the address to key on has not been read
                        // yet - so it checks inside the task instead.
                        if !rt.listener_cfg.proxy_protocol
                            && let Some(ref rl) = rt.rate_limit
                            && let Decision::Deny { .. } = rl.limiter.check(peer.ip())
                        {
                            reject_rate_limited(client, peer, &rl.name, &listener_label);
                            break 'accept;
                        }

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

                        let resources = config.resources.clone();
                        let listener_label = listener_label.clone();
                        let error_pages = error_pages.clone();
                        let access_log = access_log.clone();
                        let buffer_pool = buffer_pool.clone();
                        // per-conn shutdown receiver: the keep-alive loop selects on
                        // this to stop looping gracefully on shutdown.
                        let conn_shutdown = shutdown.clone();

                        tasks.spawn(async move {
                            let _permit = permit;

                            // behind an L4 balancer the socket peer is the balancer.
                            // client_addr is the single answer to "who is the client"
                            // from here down: routing, rate limiting, XFF, access log.
                            let mut client = client;
                            let mut client_addr = peer;

                            if rt.listener_cfg.proxy_protocol {
                                if !proxy_protocol::peer_trusted(
                                    &rt.listener_cfg.proxy_protocol_from,
                                    peer.ip(),
                                ) {
                                    tracing::warn!(%peer, "peer is not trusted to send a PROXY protocol header");
                                    reject_proxy_protocol(&listener_label, "untrusted");
                                    return;
                                }

                                match tokio::time::timeout(
                                    PROXY_PROTOCOL_TIMEOUT,
                                    proxy_protocol::read_header(&mut client),
                                )
                                .await
                                {
                                    Ok(Ok(recovered)) => {
                                        metrics::counter!(
                                            "kntx_proxy_protocol_headers_total",
                                            "listener" => listener_label.to_string(),
                                            "version" => recovered.version.label(),
                                        )
                                        .increment(1);
                                        match recovered.source {
                                            Some(source) => {
                                                tracing::debug!(%peer, client = %source, "client address recovered");
                                                client_addr = source;
                                            }
                                            // LOCAL or UNKNOWN: the sender is speaking
                                            // for itself, typically a health check, so
                                            // it is the client.
                                            None => tracing::debug!(%peer, "PROXY protocol header carried no client address"),
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        tracing::debug!(%peer, error = %e, "PROXY protocol header rejected");
                                        reject_proxy_protocol(&listener_label, e.metric_reason());
                                        return;
                                    }
                                    Err(_) => {
                                        tracing::debug!(%peer, "PROXY protocol header timed out");
                                        reject_proxy_protocol(&listener_label, "timeout");
                                        return;
                                    }
                                }

                                // deferred from the accept loop. the cost of keying on
                                // the real client is that a denial here has already
                                // taken a max_connections permit, so that limit rather
                                // than the zone is what bounds a flood on this listener.
                                if let Some(ref rl) = rt.rate_limit
                                    && let Decision::Deny { .. } =
                                        rl.limiter.check(client_addr.ip())
                                {
                                    reject_rate_limited(client, client_addr, &rl.name, &listener_label);
                                    metrics::gauge!(
                                        "kntx_connections_active",
                                        "listener" => listener_label.to_string(),
                                    )
                                    .decrement(1.0);
                                    return;
                                }
                            }

                            // peeked is Some only for tls-passthrough: ClientHello bytes the
                            // client already sent, which must reach the backend first.
                            let (client_conn, conn_sni, peeked) = if rt.listener_cfg.mode
                                == ListenerMode::TlsPassthrough
                            {
                                let Some(mut peek_buf) = buffer_pool.get() else {
                                    tracing::warn!(%client_addr, "buffer pool exhausted during ClientHello peek");
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
                                    Duration::from_secs(rt.listener_cfg.clienthello_timeout_secs);
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
                                            tracing::debug!(%client_addr, sni = %s, len = hello.len, "ClientHello peeked");
                                        } else {
                                            tracing::debug!(%client_addr, len = hello.len, "ClientHello peeked (no SNI)");
                                            metrics::counter!(
                                                "kntx_tls_passthrough_no_sni_total",
                                                "listener" => listener_label.to_string(),
                                            )
                                            .increment(1);
                                        }
                                        (ClientConn::Plain(client), sni, Some((peek_buf, hello.len)))
                                    }
                                    Ok(Err(e)) => {
                                        tracing::debug!(%client_addr, error = %e, "ClientHello peek failed");
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
                                        tracing::debug!(%client_addr, "ClientHello peek timed out");
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
                            } else if let Some(ref acceptor) = rt.tls_acceptor {
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
                                            tracing::debug!(%client_addr, sni = %s, "TLS handshake completed");
                                        } else {
                                            tracing::debug!(%client_addr, "TLS handshake completed (no SNI)");
                                        }

                                        (ClientConn::Tls(Box::new(tls)), sni, None)
                                    }
                                    Ok(Err(e)) => {
                                        tracing::debug!(%client_addr, error = %e, "TLS handshake failed");
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
                                        tracing::debug!(%client_addr, "TLS handshake timed out");
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

                            let span = tracing::info_span!("conn", client = %client_addr);

                            async {
                                let last_activity = Arc::new(AtomicU64::new(monotonic_millis()));

                                match rt.listener_cfg.mode {
                                    ListenerMode::L7 => {
                                        let l7_stream = match client_conn {
                                            ClientConn::Plain(tcp) => ClientStream::Plain(tcp),
                                            ClientConn::Tls(tls) => ClientStream::Tls(tls),
                                        };

                                        let forward_fut = l7::forward_l7(
                                            l7_stream,
                                            client_addr,
                                            conn_sni.clone(),
                                            Arc::clone(&rt.listener_cfg),
                                            Arc::clone(&rt.router),
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
                                            client_ip: client_addr.ip(),
                                        };
                                        let l4_entry = match rt.router.route(&l4_ctx) {
                                            Some(e) => e,
                                            None => {
                                                tracing::warn!("no route for L4 connection");
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
                                        if rt.listener_cfg.mode == ListenerMode::TlsPassthrough {
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
                                                    tracing::warn!("no healthy backends available");
                                                    break None;
                                                }
                                            };
                                            match l4::connect_backend(addr, connect_timeout, resources.socket_buffer_size).await {
                                                Ok(server) => {
                                                    // None only if a reload removed this backend
                                                    // between selection and connect - nothing left
                                                    // to count load against.
                                                    let active = pool.state_for(addr).map(|s| s.track_active());
                                                    break Some((addr, server, active));
                                                }
                                                Err(e) => {
                                                    pool.record_failure(addr);
                                                    attempts += 1;
                                                    metrics::counter!(
                                                        "kntx_connect_retries_total",
                                                        "pool" => pool_name.clone(),
                                                        "listener" => listener_label.to_string(),
                                                    ).increment(1);
                                                    if attempts >= max_connect_attempts {
                                                        tracing::warn!(attempts, "all retry attempts exhausted");
                                                        break None;
                                                    }
                                                    tracing::debug!(%addr, attempt = attempts, error = %e, "retrying");
                                                }
                                            }
                                        };

                                        // _active must stay bound: dropping it here would
                                        // zero the least-conn reading for the whole
                                        // connection it is supposed to represent.
                                        let (backend_addr, mut server, _active) = match backend_result {
                                            Some(triple) => triple,
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
                                                tracing::warn!(error = %e, "failed to flush ClientHello to backend");
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
