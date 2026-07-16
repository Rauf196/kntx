#!/usr/bin/env bash
# kntx L7 benchmark.
# compares kntx L7 (backend pool on / off), kntx L4, and nginx L7 across a
# couple of HTTP workloads. nginx serves as the static backend. oha is the
# load generator — open-loop with HDR latency correction for accurate p99.
#
# requires: cargo, nginx, oha
#
# usage: ./scripts/benchmark-l7.sh [duration_seconds]

set -euo pipefail

DURATION=${1:-30}
WARMUP=10
PROXY_PORT=8080
BACKEND_PORT=3010
RESULTS_BASE="benchmark-results"
KNTX="./target/release/kntx"
NGINX_BACKEND_CONF="/tmp/kntx-bench-l7-backend.conf"
NGINX_PROXY_CONF="/tmp/kntx-bench-l7-proxy.conf"
PAYLOAD_DIR="/tmp/kntx-bench-l7-payloads"
KNTX_PID=""

check_deps() {
    local missing=()
    for cmd in cargo nginx oha ss awk; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "error: missing dependencies: ${missing[*]}"
        echo "       oha install: yay -S oha (AUR)"
        exit 1
    fi
}

check_port() {
    local port="$1"
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE ":${port}\$"; then
        echo "error: port $port already in use"
        exit 1
    fi
}

write_payloads() {
    mkdir -p "$PAYLOAD_DIR"
    head -c 200 /dev/urandom | base64 | head -c 200 > "$PAYLOAD_DIR/200b"
}

# nginx as the static backend, keep-alive on. all temp paths point at writable
# locations so nginx doesn't try to mkdir /var/lib/nginx/* as a non-root user.
start_backend() {
    mkdir -p /tmp/kntx-bench-l7-backend-tmp
    cat > "$NGINX_BACKEND_CONF" <<EOF
worker_processes auto;
error_log /dev/null;
pid /tmp/kntx-bench-l7-backend.pid;
events { worker_connections 20000; }
http {
    access_log off;
    keepalive_timeout 75;
    keepalive_requests 1000000;
    sendfile on;

    client_body_temp_path /tmp/kntx-bench-l7-backend-tmp/client-body;
    proxy_temp_path       /tmp/kntx-bench-l7-backend-tmp/proxy;
    fastcgi_temp_path     /tmp/kntx-bench-l7-backend-tmp/fastcgi;
    uwsgi_temp_path       /tmp/kntx-bench-l7-backend-tmp/uwsgi;
    scgi_temp_path        /tmp/kntx-bench-l7-backend-tmp/scgi;

    server {
        # backlog raised so the backend can absorb the SYN storm we send under
        # high client concurrency. default is 511; with 10k clients hammering
        # fresh connects, that overflows and reports as 503 at the proxy.
        listen $BACKEND_PORT default_server backlog=65535;
        root $PAYLOAD_DIR;
        location = /200b { try_files /200b =404; }
        location / { return 200 "ok\n"; }
    }
}
EOF
    nginx -c "$NGINX_BACKEND_CONF"
    sleep 0.4
}

stop_backend() {
    if [[ -f /tmp/kntx-bench-l7-backend.pid ]]; then
        nginx -c "$NGINX_BACKEND_CONF" -s stop 2>/dev/null || true
        rm -f /tmp/kntx-bench-l7-backend.pid
    fi
}

write_kntx_l7_config() {
    local file="$1"
    local max_idle="$2"
    # max_total mirrors max_idle when the cache is on — this caps the number
    # of *active* in-flight conns to the backend, the same envelope nginx's
    # `keepalive 32` enforces. When max_idle is 0 (no cache), leave max_total
    # at 0 (unlimited) so that variant truly represents "open every time".
    local max_total
    if [[ "$max_idle" -gt 0 ]]; then
        max_total=$max_idle
    else
        max_total=0
    fi
    cat > "$file" <<EOF
[logging]
level = "warn"

[forwarding]
# one body-forwarding buffer per active client conn — size to the largest
# concurrency scenario this bench runs (S4 with 10k conns) + headroom.
buffer_pool_capacity = 12000

[[listeners]]
address = "0.0.0.0:$PROXY_PORT"
mode = "l7"
pool = "bench"
max_connections = 20000

[[pools]]
name = "bench"
backends = [{ address = "127.0.0.1:$BACKEND_PORT" }]

[pools.keepalive]
max_idle = $max_idle
idle_conn_ttl_secs = 60
max_total = $max_total
EOF
}

write_kntx_l4_config() {
    local file="$1"
    cat > "$file" <<EOF
[logging]
level = "warn"

[forwarding]
buffer_pool_capacity = 12000

[[listeners]]
address = "0.0.0.0:$PROXY_PORT"
mode = "l4"
pool = "bench"
max_connections = 20000

[[pools]]
name = "bench"
backends = [{ address = "127.0.0.1:$BACKEND_PORT" }]
EOF
}

write_nginx_proxy_config() {
    mkdir -p /tmp/kntx-bench-l7-proxy-tmp
    cat > "$NGINX_PROXY_CONF" <<EOF
worker_processes 1;
error_log /dev/null;
pid /tmp/kntx-bench-l7-proxy.pid;
events { worker_connections 20000; accept_mutex off; }
http {
    access_log off;

    client_body_temp_path /tmp/kntx-bench-l7-proxy-tmp/client-body;
    proxy_temp_path       /tmp/kntx-bench-l7-proxy-tmp/proxy;
    fastcgi_temp_path     /tmp/kntx-bench-l7-proxy-tmp/fastcgi;
    uwsgi_temp_path       /tmp/kntx-bench-l7-proxy-tmp/uwsgi;
    scgi_temp_path        /tmp/kntx-bench-l7-proxy-tmp/scgi;

    upstream bench {
        server 127.0.0.1:$BACKEND_PORT;
        keepalive 32;
        keepalive_requests 1000;
    }
    server {
        listen $PROXY_PORT default_server;
        location / {
            proxy_pass http://bench;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
    }
}
EOF
}

start_kntx() {
    $KNTX -c "$1" >/dev/null 2>&1 &
    KNTX_PID=$!
    sleep 0.4
}

stop_kntx() {
    if [[ -n "$KNTX_PID" ]]; then
        kill "$KNTX_PID" 2>/dev/null || true
        wait "$KNTX_PID" 2>/dev/null || true
        KNTX_PID=""
    fi
    sleep 0.2
}

start_nginx_proxy() {
    write_nginx_proxy_config
    nginx -c "$NGINX_PROXY_CONF"
    sleep 0.4
}

stop_nginx_proxy() {
    if [[ -f /tmp/kntx-bench-l7-proxy.pid ]]; then
        nginx -c "$NGINX_PROXY_CONF" -s stop 2>/dev/null || true
        rm -f /tmp/kntx-bench-l7-proxy.pid
    fi
    sleep 0.2
}

cleanup() {
    stop_kntx
    stop_nginx_proxy
    stop_backend
}

# warmup pass then measurement pass at the same load shape. closed-loop — no
# rate target — so the load generator runs at whatever pace the system supports
# and percentiles reflect actual observed service time. -u ms locks the unit.
# latency-correction was tried and dropped: with an aspirational -q target the
# correction inflates percentiles by tens of seconds of virtual queue wait,
# obscuring real proxy latency.
run_load() {
    local outfile="$1"
    local conns="$2"

    oha -z "${WARMUP}s" -c "$conns" -u ms --no-tui \
        "http://127.0.0.1:$PROXY_PORT/200b" > /dev/null 2>&1 || true
    oha -z "${DURATION}s" -c "$conns" -u ms --no-tui \
        "http://127.0.0.1:$PROXY_PORT/200b" > "$outfile" 2>&1
}

extract_rps() {
    awk '/^[[:space:]]+Requests\/sec:/ {print $2; exit}' "$1"
}

# oha prints "  50.00% in 2.5131 ms" lines under "Response time distribution".
# match the leading whole-number percentile with optional fractional digits.
extract_pct() {
    local file="$1"
    local pct="$2"
    awk -v p="$pct" '$0 ~ ("^[[:space:]]+" p "(\\.[0-9]+)?%[[:space:]]+in") {
        print $3, $4; exit
    }' "$file"
}

run_variant() {
    local results_dir="$1"
    local scenario="$2"
    local variant="$3"
    local conns="$4"

    case "$variant" in
        kntx-l7-pool32)
            write_kntx_l7_config /tmp/kntx-bench-l7-pool32.toml 32
            start_kntx /tmp/kntx-bench-l7-pool32.toml
            ;;
        kntx-l7-pool0)
            write_kntx_l7_config /tmp/kntx-bench-l7-pool0.toml 0
            start_kntx /tmp/kntx-bench-l7-pool0.toml
            ;;
        kntx-l4)
            write_kntx_l4_config /tmp/kntx-bench-l4.toml
            start_kntx /tmp/kntx-bench-l4.toml
            ;;
        nginx-l7)
            start_nginx_proxy
            ;;
    esac

    local outfile="$results_dir/${scenario}-${variant}.txt"
    run_load "$outfile" "$conns"

    case "$variant" in
        kntx-l7-pool32|kntx-l7-pool0|kntx-l4) stop_kntx ;;
        nginx-l7) stop_nginx_proxy ;;
    esac

    local rps p50 p99
    rps=$(extract_rps "$outfile")
    p50=$(extract_pct "$outfile" "50")
    p99=$(extract_pct "$outfile" "99")
    printf "  %-18s rps=%-10s p50=%-10s p99=%s\n" "$variant" "${rps:-?}" "${p50:-?}" "${p99:-?}"
}

run_scenario() {
    local results_dir="$1"
    local scenario="$2"
    local label="$3"
    local conns="$4"

    echo "$scenario: $label"
    for v in kntx-l7-pool32 kntx-l7-pool0 kntx-l4 nginx-l7; do
        run_variant "$results_dir" "$scenario" "$v" "$conns"
    done
    echo
}

main() {
    check_deps
    check_port "$BACKEND_PORT"
    check_port "$PROXY_PORT"

    local min_fds=65536
    if [[ $(ulimit -n) -lt $min_fds ]]; then
        echo "error: ulimit -n is $(ulimit -n), need at least $min_fds"
        echo "       run: ulimit -n $min_fds"
        exit 1
    fi

    local results_dir="$RESULTS_BASE/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$results_dir"

    echo "kntx L7 benchmark"
    echo "  date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  kernel:   $(uname -r)"
    echo "  cpu:      $(lscpu | awk -F: '/Model name/ {gsub(/^ +/, "", $2); print $2; exit}')"
    echo "  load gen: oha"
    echo "  duration: ${DURATION}s per run (${WARMUP}s warmup)"
    echo

    echo "building release binary..."
    cargo build --release --quiet

    write_payloads
    start_backend
    trap cleanup EXIT

    {
        echo "date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "kernel:   $(uname -r)"
        echo "cpu:      $(lscpu | awk -F: '/Model name/ {gsub(/^ +/, "", $2); print $2; exit}')"
        echo "cores:    $(nproc)"
        echo "load_gen: oha $(oha --version 2>&1 | head -1)"
        echo "nginx:    $(nginx -v 2>&1)"
        echo "rustc:    $(rustc --version)"
        echo "kntx:     $(git describe --tags --always --dirty 2>/dev/null || echo unknown)"
        echo "ulimit:   $(ulimit -n)"
        echo "duration: ${DURATION}s, warmup: ${WARMUP}s"
    } > "$results_dir/environment.txt"

    echo "results -> $results_dir/"
    echo

    run_scenario "$results_dir" S1 "1 conn, sequential GET /200b" 1
    run_scenario "$results_dir" S2 "100 conns, GET /200b" 100
    run_scenario "$results_dir" S3 "1000 conns, GET /200b" 1000
    run_scenario "$results_dir" S4 "10000 conns, GET /200b" 10000

    echo "raw oha output saved per run in $results_dir/"
}

main "$@"
