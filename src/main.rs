use clap::{Parser, ValueEnum};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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

    init_tracing(args.log_level.as_deref(), &args.log_format);

    tracing::info!(config = %args.config, "kntx starting");

    if args.validate {
        // actual validation comes in phase 1 with config parsing
        tracing::info!("config validation not yet implemented");
        return Ok(());
    }

    // proxy startup comes in phase 1
    tracing::info!("proxy not yet implemented");

    Ok(())
}
