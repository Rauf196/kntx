use std::sync::Arc;

use clap::{Parser, ValueEnum};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use kntx::balancer::RoundRobin;
use kntx::config;
use kntx::listener;

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

    tracing::info!(
        listen = %config.listener.address,
        backends = config.backends.len(),
        "kntx starting",
    );

    let backend_addrs: Vec<_> = config.backends.iter().map(|b| b.address).collect();
    let balancer = Arc::new(RoundRobin::new(backend_addrs));

    let tcp_listener = listener::bind(config.listener.address).await?;
    listener::serve(tcp_listener, balancer).await;

    Ok(())
}
