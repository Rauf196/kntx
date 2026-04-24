use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use tokio::task::JoinSet;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use kntx::balancer::RoundRobin;
use kntx::config;
use kntx::health::{BackendPool, HealthChecker};
use kntx::listener::{self, ServeConfig};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;

#[derive(Parser)]
#[command(name = "kntx", version, about = "High-performance L4/L7 reverse proxy")]
struct Args {
    /// path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// override log level (trace, debug, info, warn, error)
    #[arg(short, long)]
    log_level: Option<String>,

    /// log output format
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,

    /// validate configuration and exit
    #[arg(long)]
    validate: bool,
}

#[derive(Clone, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

fn init_tracing(level: Option<&str>, format: &LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.unwrap_or("info")));

    match format {
        LogFormat::Text => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer())
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .init();
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => { tracing::info!("received SIGINT"); }
            _ = sigterm.recv() => { tracing::info!("received SIGTERM"); }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for ctrl-c");
        tracing::info!("received SIGINT");
    }
}

/// pre-flight fd budget check. runs BEFORE allocating the pipe pool so the
/// failure mode is an actionable message instead of a bare `Too many open files`.
/// budget = pipe pool fds (capacity * 2) + 2 fds per max-connection slot (client + backend) + 256 base.
#[cfg(target_os = "linux")]
fn preflight_fd_check(config: &kntx::config::Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    if ret != 0 {
        return Ok(()); // can't read limit, let pipe pool surface the OS error
    }

    let pipe_fds = (kntx::pool::pipe::DEFAULT_PIPE_POOL_CAPACITY * 2) as u64;
    let conn_fds: u64 = config
        .listeners
        .iter()
        .map(|l| l.max_connections.unwrap_or(0) as u64 * 2)
        .sum();
    let base = 256u64;
    let required = pipe_fds + conn_fds + base;

    if rlim.rlim_cur < required {
        return Err(format!(
            "file descriptor limit too low: current={}, required={} \
             (pipe pool: {}, max connections: {}, base: {}). \
             raise it with: ulimit -n {} \
             (or edit /etc/security/limits.conf for a permanent change)",
            rlim.rlim_cur, required, pipe_fds, conn_fds, base, required
        )
        .into());
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        let mut src = std::error::Error::source(&*e);
        while let Some(s) = src {
            eprintln!("  caused by: {s}");
            src = s.source();
        }
        std::process::exit(1);
    }
}

#[tokio::main]
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let config = config::Config::from_file(&args.config)?;

    let log_level = args.log_level.as_deref().unwrap_or(&config.logging.level);
    init_tracing(Some(log_level), &args.log_format);

    if args.validate {
        tracing::info!(config = %args.config, "configuration is valid");
        return Ok(());
    }

    if let Some(ref metrics_config) = config.metrics {
        kntx::metrics::install(metrics_config.address)?;
        tracing::info!(address = %metrics_config.address, "metrics endpoint started");
    }

    let strategy = config.forwarding.strategy;

    #[cfg(target_os = "linux")]
    preflight_fd_check(&config)?;

    let buffer_pool = BufferPool::with_defaults();

    #[cfg(target_os = "linux")]
    let pipe_pool = kntx::pool::pipe::PipePool::with_defaults()?;

    let resources = Resources {
        buffer_pool,
        #[cfg(target_os = "linux")]
        pipe_pool,
        socket_buffer_size: config.forwarding.socket_buffer_size,
    };

    tracing::info!(
        buffer_pool_capacity = resources.buffer_pool.capacity(),
        buffer_size = resources.buffer_pool.buffer_size(),
        "resource pools initialized",
    );

    // shutdown coordination: all listener tasks and health checkers share this receiver
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let shutdown_tx = Arc::new(shutdown_tx);

    // signal handler fires the watch channel
    let signal_tx = Arc::clone(&shutdown_tx);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = signal_tx.send(());
    });

    // build one BackendPool + RoundRobin per pool
    let mut pool_map: HashMap<String, (Arc<BackendPool>, Arc<RoundRobin>)> = HashMap::new();
    for pool_cfg in &config.pools {
        let health = pool_cfg.effective_health(&config.health);
        let addrs: Vec<_> = pool_cfg.backends.iter().map(|b| b.address).collect();
        let pool = Arc::new(BackendPool::new(
            pool_cfg.name.as_str().into(),
            addrs,
            health.failure_threshold,
            Duration::from_secs(health.recovery_timeout_secs),
        ));
        if config.metrics.is_some() {
            pool.emit_initial_metrics();
        }
        let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));
        pool_map.insert(pool_cfg.name.clone(), (pool, balancer));
    }

    // pre-bind every listener and build TLS acceptors. fail fast on bind / cert errors
    // BEFORE spawning any background task — avoids transient checkers / metrics noise on startup failure.
    let mut prepared: Vec<(usize, tokio::net::TcpListener, Option<tokio_rustls::TlsAcceptor>)> =
        Vec::with_capacity(config.listeners.len());
    for (idx, listener_cfg) in config.listeners.iter().enumerate() {
        let tls_acceptor = if let Some(ref tls_cfg) = listener_cfg.tls {
            Some(kntx::tls::build_acceptor(tls_cfg)?)
        } else {
            None
        };
        let tcp = listener::bind(listener_cfg.address).await?;
        prepared.push((idx, tcp, tls_acceptor));
    }

    // all listeners bound — now spawn health checkers
    let mut health_handles = Vec::new();
    for pool_cfg in &config.pools {
        let health = pool_cfg.effective_health(&config.health);
        if let Some(interval_secs) = health.check_interval_secs {
            let (pool, _) = pool_map.get(&pool_cfg.name).unwrap();
            let checker = HealthChecker::new(
                Arc::clone(pool),
                Duration::from_secs(interval_secs),
                // connect_timeout for health probes: 5s default (D7 — per-pool tuning deferred)
                Duration::from_secs(5),
            );
            let handle = checker.spawn(shutdown_rx.clone());
            health_handles.push(handle);
            tracing::info!(pool = %pool_cfg.name, interval_secs, "health checker started");
        }
    }

    // spawn serve tasks for the pre-bound listeners.
    // side table maps task::Id → listener address so panic logs can name the culprit.
    let mut listener_tasks: JoinSet<()> = JoinSet::new();
    let mut task_addrs: HashMap<tokio::task::Id, SocketAddr> = HashMap::new();
    for (idx, tcp_listener, tls_acceptor) in prepared {
        let listener_cfg = &config.listeners[idx];
        let (_, balancer) = pool_map.get(&listener_cfg.pool).unwrap();

        if let Some(ref tls_cfg) = listener_cfg.tls {
            tracing::info!(
                address = %listener_cfg.address,
                certificates = tls_cfg.certificates.len(),
                min_version = %tls_cfg.min_version,
                "TLS termination enabled",
            );
            #[cfg(target_os = "linux")]
            if matches!(strategy, kntx::config::ForwardingStrategy::Splice) {
                tracing::info!(
                    address = %listener_cfg.address,
                    "TLS connections will use userspace forwarding (splice requires plain TCP)",
                );
            }
        }

        let tls_handshake_timeout = listener_cfg
            .tls
            .as_ref()
            .map(|t| Duration::from_secs(t.handshake_timeout_secs))
            .unwrap_or(Duration::from_secs(5));

        let serve_config = ServeConfig {
            strategy,
            resources: resources.clone(),
            max_connections: listener_cfg.max_connections,
            idle_timeout: listener_cfg.idle_timeout_secs.map(Duration::from_secs),
            drain_timeout: Duration::from_secs(listener_cfg.drain_timeout_secs),
            connect_timeout: Duration::from_secs(listener_cfg.connect_timeout_secs),
            max_connect_attempts: listener_cfg.max_connect_attempts,
            tls_acceptor,
            tls_handshake_timeout,
            listener_label: listener_cfg.address.to_string().into(),
        };

        tracing::info!(
            address = %listener_cfg.address,
            pool = %listener_cfg.pool,
            %strategy,
            "listener starting",
        );

        let balancer = Arc::clone(balancer);
        let rx = shutdown_rx.clone();
        let abort = listener_tasks.spawn(listener::serve(tcp_listener, balancer, serve_config, rx));
        task_addrs.insert(abort.id(), listener_cfg.address);
    }

    // monitor listener tasks: any abnormal exit triggers shutdown of all listeners
    let mut had_error = false;
    while let Some(result) = listener_tasks.join_next_with_id().await {
        match result {
            Ok((id, ())) => {
                task_addrs.remove(&id);
            }
            Err(e) => {
                let id = e.id();
                let address = task_addrs
                    .remove(&id)
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "<unknown>".to_string());

                if e.is_panic() {
                    let payload = e.into_panic();
                    let msg = payload
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "<non-string panic>".to_string());
                    tracing::error!(
                        %address,
                        payload = %msg,
                        "listener task panicked, initiating shutdown",
                    );
                } else {
                    tracing::error!(
                        %address,
                        error = %e,
                        "listener task failed, initiating shutdown",
                    );
                }
                had_error = true;
                let _ = shutdown_tx.send(());
            }
        }
    }

    // wait for health checkers to exit after their shutdown receivers fire
    for handle in health_handles {
        let _ = handle.await;
    }

    tracing::info!("kntx stopped");

    if had_error {
        std::process::exit(1);
    }

    Ok(())
}
