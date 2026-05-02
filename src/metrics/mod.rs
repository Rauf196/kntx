use std::net::SocketAddr;

use metrics::{describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

pub fn install(address: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    describe_counter!(
        "kntx_connections_total",
        "total accepted connections (labels: listener)"
    );
    describe_gauge!(
        "kntx_connections_active",
        "currently active connections (labels: listener)"
    );
    describe_counter!(
        "kntx_forwarded_bytes_total",
        "total bytes forwarded (labels: direction, listener)"
    );
    describe_counter!(
        "kntx_connections_rejected_total",
        "connections rejected due to limit (labels: listener)"
    );
    describe_counter!(
        "kntx_idle_timeouts_total",
        "connections closed due to idle timeout (labels: listener)"
    );
    describe_counter!(
        "kntx_connect_retries_total",
        "total backend connect retry attempts (labels: pool, listener)"
    );
    describe_gauge!(
        "kntx_backend_health",
        "backend health status 1=healthy 0=unhealthy (labels: pool, backend)"
    );
    describe_gauge!(
        "kntx_circuit_breaker_state",
        "circuit breaker state 0=closed 1=open 2=half-open (labels: pool, backend)"
    );
    describe_histogram!(
        "kntx_health_check_duration_seconds",
        "health check probe duration in seconds (labels: pool, backend)"
    );
    describe_counter!(
        "kntx_tls_handshakes_total",
        "successful TLS handshakes (labels: listener)"
    );
    describe_counter!(
        "kntx_tls_handshake_failures_total",
        "failed TLS handshakes (labels: listener, reason)"
    );
    describe_histogram!(
        "kntx_tls_handshake_duration_seconds",
        "TLS handshake duration in seconds (labels: listener)"
    );

    describe_counter!(
        "kntx_http_requests_total",
        "L7 HTTP requests completed (any status)."
    );
    describe_counter!(
        "kntx_http_parse_errors_total",
        "L7 requests rejected due to request head parse failure."
    );
    describe_counter!(
        "kntx_http_smuggling_rejects_total",
        "L7 requests rejected by request smuggling defense."
    );
    describe_histogram!(
        "kntx_http_request_duration_seconds",
        "End-to-end L7 request duration from head-read start to response-body complete."
    );
    describe_counter!(
        "kntx_access_log_dropped_total",
        "Access log lines dropped due to file-sink channel overflow."
    );
    describe_counter!(
        "kntx_l7_buffer_pool_exhausted_total",
        "L7 requests rejected because the buffer pool was exhausted (labels: listener)."
    );
    describe_counter!(
        "kntx_http_body_parse_errors_total",
        "L7 request body forwarding aborted due to malformed framing or I/O error (labels: listener, kind)."
    );

    PrometheusBuilder::new()
        .with_http_listener(address)
        .install()?;

    Ok(())
}
