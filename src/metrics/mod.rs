use std::net::SocketAddr;

use metrics::{describe_counter, describe_gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

pub fn install(address: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    describe_counter!("kntx_connections_total", "total accepted connections");
    describe_gauge!("kntx_connections_active", "currently active connections");
    describe_counter!("kntx_forwarded_bytes_total", "total bytes forwarded");
    describe_counter!(
        "kntx_connections_rejected_total",
        "connections rejected due to limit"
    );
    describe_counter!(
        "kntx_idle_timeouts_total",
        "connections closed due to idle timeout"
    );

    PrometheusBuilder::new()
        .with_http_listener(address)
        .install()?;

    Ok(())
}
