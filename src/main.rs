use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
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

#[cfg(target_os = "linux")]
fn check_fd_limit(pipe_pool: &kntx::pool::pipe::PipePool) {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    if ret == 0 {
        // each pipe pair = 2 fds, plus headroom for sockets, listeners, etc.
        let pipe_fds = (pipe_pool.capacity() * 2) as u64;
        let recommended = pipe_fds + 256; // headroom for sockets, stdout, etc.
        if rlim.rlim_cur < recommended {
            tracing::warn!(
                current = rlim.rlim_cur,
                recommended,
                pipe_fds,
                "ulimit -n is low for the configured pipe pool size. \
                 run: ulimit -n {recommended}",
            );
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    tracing::info!(
        listen = %config.listener.address,
        backends = config.backends.len(),
        %strategy,
        "kntx starting",
    );

    let backend_addrs: Vec<_> = config.backends.iter().map(|b| b.address).collect();

    let pool = Arc::new(BackendPool::new(
        backend_addrs,
        config.health.failure_threshold,
        Duration::from_secs(config.health.recovery_timeout_secs),
    ));

    let balancer = Arc::new(RoundRobin::new(Arc::clone(&pool)));

    if config.metrics.is_some() {
        pool.emit_initial_metrics();
    }

    if let Some(interval_secs) = config.health.check_interval_secs {
        let checker = HealthChecker::new(
            Arc::clone(&pool),
            Duration::from_secs(interval_secs),
            Duration::from_secs(config.connection.connect_timeout_secs),
        );
        checker.spawn();
        tracing::info!(interval_secs, "health checker started");
    }

    let buffer_pool = BufferPool::with_defaults();

    #[cfg(target_os = "linux")]
    let pipe_pool = kntx::pool::pipe::PipePool::with_defaults()?;

    #[cfg(target_os = "linux")]
    check_fd_limit(&pipe_pool);

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

    let tls_acceptor = if let Some(ref tls_config) = config.tls {
        let acceptor = kntx::tls::build_acceptor(tls_config)?;
        tracing::info!(
            certificates = tls_config.certificates.len(),
            min_version = %tls_config.min_version,
            "TLS termination enabled",
        );
        #[cfg(target_os = "linux")]
        if matches!(strategy, kntx::config::ForwardingStrategy::Splice) {
            tracing::info!(
                "TLS connections will use userspace forwarding (splice requires plain TCP)",
            );
        }
        Some(acceptor)
    } else {
        None
    };

    let tls_handshake_timeout = config
        .tls
        .as_ref()
        .map(|t| Duration::from_secs(t.handshake_timeout_secs))
        .unwrap_or(Duration::from_secs(5));

    let serve_config = ServeConfig {
        strategy: config.forwarding.strategy,
        resources,
        max_connections: config.listener.max_connections,
        idle_timeout: config.connection.idle_timeout_secs.map(Duration::from_secs),
        drain_timeout: Duration::from_secs(config.listener.drain_timeout_secs),
        connect_timeout: Duration::from_secs(config.connection.connect_timeout_secs),
        max_connect_attempts: config.connection.max_connect_attempts,
        tls_acceptor,
        tls_handshake_timeout,
    };

    let tcp_listener = listener::bind(config.listener.address).await?;
    listener::serve(tcp_listener, balancer, serve_config, shutdown_signal()).await;

    tracing::info!("kntx stopped");
    Ok(())
}
