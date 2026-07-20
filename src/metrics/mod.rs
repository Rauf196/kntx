use std::net::SocketAddr;

use metrics::{describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

pub fn install(address: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    // recorder must be installed before describe_* - otherwise descriptions go to the
    // noop recorder and never reach /metrics as # HELP / # TYPE lines.
    PrometheusBuilder::new()
        // proxy-scale latency buckets: 50µs-30s, denser in the 100µs-100ms range
        .set_buckets_for_metric(
            Matcher::Full("kntx_http_request_duration_seconds".into()),
            &[
                5e-5, 1e-4, 5e-4, 1e-3, 5e-3, 1e-2, 5e-2, 0.1, 0.5, 1.0, 5.0, 30.0,
            ],
        )?
        // TLS handshake: fast-path ~ms, slow-path ~100ms
        .set_buckets_for_metric(
            Matcher::Full("kntx_tls_handshake_duration_seconds".into()),
            &[1e-3, 5e-3, 1e-2, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
        )?
        // health probe: sub-ms local, up to seconds for cross-region
        .set_buckets_for_metric(
            Matcher::Full("kntx_health_check_duration_seconds".into()),
            &[1e-4, 1e-3, 1e-2, 0.1, 1.0, 5.0],
        )?
        // keep-alive requests per connection: 1 to 1000 (default cap)
        .set_buckets_for_metric(
            Matcher::Full("kntx_http_keepalive_requests".into()),
            &[1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0],
        )?
        .with_http_listener(address)
        .install()?;

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
    describe_counter!(
        "kntx_route_matches_total",
        "Requests that resolved to a configured route, labeled by listener and route_id."
    );
    describe_counter!(
        "kntx_route_no_match_total",
        "Requests that did not match any configured route."
    );
    describe_counter!(
        "kntx_tls_passthrough_connections_total",
        "TLS passthrough connections successfully routed (labels: listener, route_id)."
    );
    describe_counter!(
        "kntx_tls_passthrough_no_sni_total",
        "TLS passthrough ClientHellos without an SNI extension (labels: listener)."
    );
    describe_counter!(
        "kntx_tls_passthrough_rejects_total",
        "TLS passthrough connections rejected before routing (labels: listener, reason=not_tls|too_large|multi_record|malformed|eof|buffer_full|io|timeout|buffer_exhausted)."
    );

    describe_counter!(
        "kntx_backend_pool_checkouts_total",
        "Backend keepalive cache checkouts (labels: pool, backend, outcome=hit|miss|stale)."
    );
    describe_counter!(
        "kntx_backend_pool_returns_total",
        "Backend keepalive cache returns (labels: pool, backend, outcome=ok|full)."
    );
    describe_gauge!(
        "kntx_backend_pool_size",
        "Current count of idle backend conns in the keepalive cache (labels: pool, backend)."
    );
    describe_counter!(
        "kntx_pool_full_failovers_total",
        "Backend checkouts that failed over to a peer because the selected backend was at max_total (labels: pool, backend)."
    );
    describe_counter!(
        "kntx_http_body_too_large_total",
        "Requests rejected because the request body exceeded max_body_size_bytes (labels: listener)."
    );
    describe_counter!(
        "kntx_http_retry_attempts_total",
        "Broken-keepalive retries - popped cache conn failed first write; request retried on a fresh conn (labels: listener, pool)."
    );
    describe_histogram!(
        "kntx_http_keepalive_requests",
        "L7 requests served on a single client connection, recorded at connection close (labels: listener)."
    );
    describe_gauge!(
        "kntx_websocket_tunnels_active",
        "Currently active WebSocket tunnels (labels: listener)."
    );
    describe_counter!(
        "kntx_websocket_tunnels_total",
        "WebSocket tunnels opened (labels: listener)."
    );
    describe_counter!(
        "kntx_rate_limit_rejected_total",
        "Connections or requests rejected by a rate limit zone (labels: listener, zone, scope=listener|route)."
    );

    Ok(())
}
