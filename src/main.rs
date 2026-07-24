use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use clap::{Parser, ValueEnum};
use tokio::task::JoinSet;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use kntx::access_log::AccessLogSink;
use kntx::config;
use kntx::listener::{self, ListenerRuntime};
use kntx::pool::buffer::BufferPool;
use kntx::proxy::l4::Resources;
use kntx::proxy::l7::ErrorPages;
use kntx::proxy::l7::router::{Router, build_router};
use kntx::runtime::{
    ListenerHandle, ListenerRegistry, ListenerSpawn, PoolTasks, ReloadContext, SharedServe,
};

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

    let buffer_pool = BufferPool::from_capacity(config.forwarding.buffer_pool_capacity);

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

    // serve ingredients that never change after startup. one builder assembles a
    // listener's ServeConfig from these, at boot and on reload alike.
    let shared_serve = Arc::new(SharedServe {
        strategy,
        buffer_pool: Arc::new(resources.buffer_pool.clone()),
        resources: resources.clone(),
        error_pages: Arc::new(ErrorPages::load(&config.error_pages)?),
        access_log: Arc::new(AccessLogSink::from_config(&config.access_log)?),
    });

    // shutdown coordination: health checkers and sweepers hold this receiver directly;
    // listeners are reached through their own drain channels (see the supervision loop).
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(());
    let shutdown_tx = Arc::new(shutdown_tx);

    // signal handler fires the watch channel
    let signal_tx = Arc::clone(&shutdown_tx);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = signal_tx.send(());
    });

    // effective running config: pools (BackendPool + RoundRobin) and rate-limit
    // zones. held in an ArcSwap so the SIGHUP reload task can reconcile it live.
    // one builder is shared by startup and reload so the two never diverge.
    let config_state = Arc::new(arc_swap::ArcSwap::from_pointee(
        kntx::runtime::build_snapshot(&config),
    ));
    // owned snapshot for startup wiring; safe to hold across the bind awaits below.
    let snapshot = config_state.load_full();

    if config.metrics.is_some() {
        for (pool, _) in snapshot.pools.values() {
            pool.emit_initial_metrics();
        }
        // publish the version from boot so the series exists before any reload
        metrics::gauge!("kntx_config_version").set(0.0);
    }

    // pre-bind every listener and build TLS acceptors. fail fast on bind / cert errors
    // BEFORE spawning any background task - avoids transient checkers / metrics noise on startup failure.
    let mut prepared: Vec<(
        usize,
        tokio::net::TcpListener,
        Option<tokio_rustls::TlsAcceptor>,
    )> = Vec::with_capacity(config.listeners.len());
    for (idx, listener_cfg) in config.listeners.iter().enumerate() {
        let tls_acceptor = if let Some(ref tls_cfg) = listener_cfg.tls {
            Some(kntx::tls::build_acceptor(tls_cfg)?)
        } else {
            None
        };
        let tcp = listener::bind(listener_cfg.address).await?;
        prepared.push((idx, tcp, tls_acceptor));
    }

    // all listeners bound - now start each pool's health checker and keepalive sweeper.
    // the registry is what lets a reload start tasks for an added pool and stop them
    // for a removed one.
    let pool_tasks: PoolTasks = Arc::new(Mutex::new(HashMap::new()));
    for pool_cfg in &config.pools {
        let (pool, _) = snapshot.pools.get(&pool_cfg.name).unwrap();
        let health = pool_cfg.effective_health(&config.health);
        pool_tasks.lock().expect("pool task lock").insert(
            pool_cfg.name.clone(),
            kntx::runtime::spawn_pool_tasks(pool, &health, &shutdown_rx),
        );
    }

    // spawn serve tasks for the pre-bound listeners.
    // side table maps task::Id → listener address so panic logs can name the culprit.
    let mut listener_tasks: JoinSet<()> = JoinSet::new();
    let mut task_addrs: HashMap<tokio::task::Id, SocketAddr> = HashMap::new();
    let listeners: ListenerRegistry = Arc::new(Mutex::new(HashMap::new()));
    // a reload binds new listeners on its own task but hands them here to spawn, so
    // the supervision loop stays the single owner of listener task lifecycle.
    let (spawn_tx, mut spawn_rx) = tokio::sync::mpsc::unbounded_channel::<ListenerSpawn>();
    for (idx, tcp_listener, tls_acceptor) in prepared {
        let listener_cfg = &config.listeners[idx];
        let router: Arc<dyn Router> = Arc::new(
            build_router(listener_cfg, &snapshot.pools, &snapshot.zones)
                .expect("pool and zone refs validated"),
        );
        let rate_limit = kntx::runtime::build_zone_handle(listener_cfg, &snapshot.zones)
            .expect("zone refs validated");
        let runtime = ListenerRuntime::cell(
            router,
            Arc::new(listener_cfg.clone()),
            tls_acceptor,
            rate_limit,
        );
        let (drain_tx, drain_rx) = tokio::sync::watch::channel(());
        listeners.lock().expect("registry lock").insert(
            listener_cfg.address,
            ListenerHandle {
                runtime: Arc::clone(&runtime),
                drain: drain_tx,
            },
        );

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

        let serve_config = kntx::runtime::build_serve_config(&shared_serve, listener_cfg);

        tracing::info!(
            address = %listener_cfg.address,
            pool = listener_cfg.pool.as_deref().unwrap_or("(routed)"),
            %strategy,
            "listener starting",
        );

        let abort = listener_tasks.spawn(listener::serve(
            tcp_listener,
            runtime,
            serve_config,
            drain_rx,
        ));
        task_addrs.insert(abort.id(), listener_cfg.address);
    }

    // SIGHUP: re-read + validate config, reconcile the running snapshot and push new
    // routing tables to the bound listeners. a bad config is rejected and the current
    // one keeps serving (nginx -t safety). registered after the listeners exist so a
    // reload can never race startup.
    #[cfg(unix)]
    {
        let ctx = ReloadContext {
            state: Arc::clone(&config_state),
            listeners: Arc::clone(&listeners),
            pool_tasks: Arc::clone(&pool_tasks),
            shared: Arc::clone(&shared_serve),
            spawn_tx,
            shutdown: shutdown_rx.clone(),
        };
        let reload_path = args.config.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sighup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "failed to register SIGHUP handler; reload disabled");
                    return;
                }
            };
            while sighup.recv().await.is_some() {
                kntx::runtime::reload_from_file(&ctx, &reload_path).await;
            }
        });
    }
    #[cfg(not(unix))]
    drop(spawn_tx);

    // supervise listener tasks: adopt the ones a reload binds, fan process shutdown
    // out to every listener's drain channel, and treat any abnormal exit as fatal.
    // a queued spawn keeps the loop alive when the last old listener has already
    // exited - the reload that replaces a listener sends before it drains the old one.
    let mut had_error = false;
    while !listener_tasks.is_empty() || !spawn_rx.is_empty() {
        tokio::select! {
            Some((address, task)) = spawn_rx.recv() => {
                let abort = listener_tasks.spawn(task);
                task_addrs.insert(abort.id(), address);
            }
            Ok(()) = shutdown_rx.changed() => {
                kntx::runtime::drain_all(&listeners);
            }
            Some(result) = listener_tasks.join_next_with_id() => {
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
            else => break,
        }
    }

    // wait for health checkers and keepalive sweepers to exit after their shutdown receivers fire
    let handles: Vec<_> = pool_tasks
        .lock()
        .expect("pool task lock")
        .drain()
        .flat_map(|(_, handles)| handles)
        .collect();
    for handle in handles {
        let _ = handle.await;
    }

    tracing::info!("kntx stopped");

    if had_error {
        std::process::exit(1);
    }

    Ok(())
}
