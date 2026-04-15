use std::net::SocketAddr;

use metrics::{describe_counter, describe_gauge, describe_histogram};
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
    describe_counter!(
        "kntx_connect_retries_total",
        "total backend connect retry attempts"
    );
    describe_gauge!(
        "kntx_backend_health",
        "backend health status (1=healthy, 0=unhealthy)"
    );
    describe_gauge!(
        "kntx_circuit_breaker_state",
        "circuit breaker state (0=closed, 1=open, 2=half-open)"
    );
    describe_histogram!(
        "kntx_health_check_duration_seconds",
        "health check probe duration in seconds"
    );
    describe_counter!("kntx_tls_handshakes_total", "successful TLS handshakes");
    describe_counter!(
        "kntx_tls_handshake_failures_total",
        "failed TLS handshakes by reason"
    );
    describe_histogram!(
        "kntx_tls_handshake_duration_seconds",
        "TLS handshake duration in seconds"
    );

    PrometheusBuilder::new()
        .with_http_listener(address)
        .install()?;

    Ok(())
}
