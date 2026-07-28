#!/usr/bin/env bash
# kntx load balancing strategy benchmark.
#
# Two pools, three strategies.
#
#   uniform - two identical backends. Nothing to be clever about, so all three
#             strategies should land within noise. Any gap is pure selection
#             overhead: least_conn sorts per selection, weighted sums weights.
#   skewed  - one backend throttled with nginx limit_req so it queues. This is
#             the case least_conn exists for, and the one that decides whether
#             it earns its place over round_robin.
#
# GOTCHA, cost an afternoon: the throttled backend must serve a real file, not
# `return 200`. `return` belongs to ngx_http_rewrite_module and finalizes the
# request in the REWRITE phase, while limit_req runs in PREACCESS, which comes
# after. A `return 200` location therefore silently bypasses limit_req entirely
# and the "throttled" backend serves 147k RPS at the declared 2000 r/s limit.
# Both backends here serve the same static file so the comparison stays honest.
#
# Note on variance: on a 4-core laptop over loopback this bench moves ±40% run
# to run at short durations. Use 60s+ and a quiet machine before reading
# anything into a gap smaller than that.
#
# requires: cargo, nginx, oha
#
# usage: ./scripts/benchmark-balancer.sh [duration_seconds]

set -euo pipefail

DURATION=${1:-60}
WARMUP=10
CONNS=200
PROXY_PORT=8080
METRICS_PORT=9099
BACKEND_A=3020
BACKEND_B=3021
# same backend as B, but rate limited. requests queue rather than get rejected,
# so the skew lands in latency instead of the success rate.
BACKEND_SLOW=3022
SLOW_RATE=2000
PAYLOAD_DIR="/tmp/kntx-bench-lb-www"
RESULTS_BASE="benchmark-results"
KNTX="./target/release/kntx"
NGINX_CONF="/tmp/kntx-bench-lb-backend.conf"
KNTX_CONF="/tmp/kntx-bench-lb.toml"
KNTX_PID=""

check_deps() {
    local missing=0
    for tool in cargo nginx oha; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "missing: $tool"
            missing=1
        fi
    done
    if [[ $missing -eq 1 ]]; then
        echo
        echo "install with:"
        echo "  oha:   cargo install oha"
        echo "  nginx: sudo pacman -S nginx-mainline   # or your distro equivalent"
        exit 1
    fi
}

check_port() {
    if ss -ltn "sport = :$1" 2>/dev/null | grep -q LISTEN; then
        echo "port $1 already in use"
        exit 1
    fi
}

# three backends: two identical, one rate limited. temp paths are redirected so
# nginx does not try to mkdir under /var/lib/nginx as a non-root user.
start_backends() {
    mkdir -p /tmp/kntx-bench-lb-tmp "$PAYLOAD_DIR"
    printf 'ok\n' > "$PAYLOAD_DIR/payload"
    cat > "$NGINX_CONF" <<EOF
worker_processes auto;
error_log /dev/null;
pid /tmp/kntx-bench-lb.pid;
events { worker_connections 20000; }
http {
    access_log off;
    keepalive_timeout 75;
    keepalive_requests 1000000;
    sendfile on;

    client_body_temp_path /tmp/kntx-bench-lb-tmp/client-body;
    proxy_temp_path       /tmp/kntx-bench-lb-tmp/proxy;
    fastcgi_temp_path     /tmp/kntx-bench-lb-tmp/fastcgi;
    uwsgi_temp_path       /tmp/kntx-bench-lb-tmp/uwsgi;
    scgi_temp_path        /tmp/kntx-bench-lb-tmp/scgi;

    limit_req_zone \$binary_remote_addr zone=slow:1m rate=${SLOW_RATE}r/s;

    server {
        listen $BACKEND_A default_server backlog=65535;
        root $PAYLOAD_DIR;
        location / { try_files /payload =404; }
    }

    server {
        listen $BACKEND_B backlog=65535;
        root $PAYLOAD_DIR;
        location / { try_files /payload =404; }
    }

    server {
        listen $BACKEND_SLOW backlog=65535;
        root $PAYLOAD_DIR;
        # burst is large enough that a closed-loop generator can never fill it
        # (at most \$CONNS requests are ever in flight), so this queues and
        # paces rather than rejecting. no \`nodelay\` - the delay is the point.
        limit_req zone=slow burst=10000;
        location / { try_files /payload =404; }
    }
}
EOF
    nginx -c "$NGINX_CONF"
    sleep 0.4
}

stop_backends() {
    if [[ -f /tmp/kntx-bench-lb.pid ]]; then
        nginx -c "$NGINX_CONF" -s stop 2>/dev/null || true
        rm -f /tmp/kntx-bench-lb.pid
    fi
}

# $1 strategy, $2 second backend port, $3/$4 weights
write_kntx_config() {
    local strategy="$1" second_port="$2" w1="${3:-1}" w2="${4:-1}"
    cat > "$KNTX_CONF" <<EOF
[logging]
level = "warn"

# metrics ON deliberately. nobody runs a proxy with them off, and the emission
# path is part of per-request cost: metrics::gauge! builds its Key (labels and
# all) BEFORE consulting the recorder, so omitting this section does not skip
# the work, it just discards the result. Benchmarking without it measured the
# cost and none of the benefit.
[metrics]
address = "127.0.0.1:$METRICS_PORT"

[forwarding]
strategy = "userspace"
buffer_pool_capacity = 2000

[[listeners]]
address = "127.0.0.1:$PROXY_PORT"
mode = "l7"
pool = "bench"

[[pools]]
name = "bench"
strategy = "$strategy"
backends = [
  { address = "127.0.0.1:$BACKEND_A", weight = $w1 },
  { address = "127.0.0.1:$second_port", weight = $w2 },
]

[pools.keepalive]
max_idle = 64
max_total = 64
EOF
}

start_kntx() {
    $KNTX --config "$KNTX_CONF" >/dev/null 2>&1 &
    KNTX_PID=$!
    sleep 0.5
}

stop_kntx() {
    if [[ -n "$KNTX_PID" ]]; then
        kill "$KNTX_PID" 2>/dev/null || true
        wait "$KNTX_PID" 2>/dev/null || true
        KNTX_PID=""
    fi
}

cleanup() {
    stop_kntx
    stop_backends
}
trap cleanup EXIT

# warmup pass then measurement pass at the same shape, matching benchmark-l7.sh.
run_oha() {
    local out="$1"
    oha -z "${WARMUP}s" -c "$CONNS" --no-tui -u ms \
        "http://127.0.0.1:$PROXY_PORT/" >/dev/null 2>&1 || true
    oha -z "${DURATION}s" -c "$CONNS" --no-tui -u ms \
        "http://127.0.0.1:$PROXY_PORT/" > "$out" 2>&1 || true
}

summarize() {
    local file="$1" label="$2"
    local rps p50 p99 success
    rps=$(grep 'Requests/sec:' "$file" | awk '{printf "%.0f", $2}')
    success=$(grep 'Success rate:' "$file" | awk '{print $3}')
    p50=$(grep '50.00% in' "$file" | awk '{print $3}')
    p99=$(grep '99.00% in' "$file" | awk '{print $3}')
    printf "  %-16s %10s %12s %12s %10s\n" "$label" "$rps" "${p50}ms" "${p99}ms" "$success"
}

main() {
    check_deps
    check_port "$PROXY_PORT"
    check_port "$METRICS_PORT"
    check_port "$BACKEND_A"
    check_port "$BACKEND_B"
    check_port "$BACKEND_SLOW"

    echo "building release binary"
    cargo build --release --quiet

    local stamp out_dir
    stamp=$(date +%Y%m%d-%H%M%S)
    out_dir="$RESULTS_BASE/$stamp-balancer"
    mkdir -p "$out_dir"

    {
        echo "date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "kernel:   $(uname -r)"
        echo "cpu:      $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
        echo "cores:    $(nproc)"
        echo "load_gen: $(oha --version)"
        echo "nginx:    $(nginx -v 2>&1)"
        echo "rustc:    $(rustc --version)"
        echo "kntx:     $(git describe --always --dirty 2>/dev/null || echo unknown)"
        echo "ulimit:   $(ulimit -n)"
        echo "duration: ${DURATION}s, warmup: ${WARMUP}s, conns: $CONNS"
        echo "metrics:  enabled (127.0.0.1:$METRICS_PORT)"
        echo "pool:     2 identical backends (uniform - measures selection overhead only)"
        echo
        echo "commands:"
        echo "  ./scripts/benchmark-balancer.sh $DURATION"
    } > "$out_dir/environment.txt"

    start_backends

    echo
    echo "uniform pool - 2 identical backends, $CONNS conns"
    printf "  %-16s %10s %12s %12s %10s\n" "strategy" "RPS" "p50" "p99" "success"
    for strategy in round_robin least_conn weighted; do
        write_kntx_config "$strategy" "$BACKEND_B"
        start_kntx
        run_oha "$out_dir/uniform-$strategy.txt"
        stop_kntx
        summarize "$out_dir/uniform-$strategy.txt" "$strategy"
    done

    echo
    echo "skewed pool - second backend capped at ${SLOW_RATE} r/s, $CONNS conns"
    printf "  %-16s %10s %12s %12s %10s\n" "strategy" "RPS" "p50" "p99" "success"
    for strategy in round_robin least_conn; do
        write_kntx_config "$strategy" "$BACKEND_SLOW"
        start_kntx
        run_oha "$out_dir/skewed-$strategy.txt"
        stop_kntx
        summarize "$out_dir/skewed-$strategy.txt" "$strategy"
    done
    # weighted only helps here if the operator already knows the skew, which is
    # exactly what separates it from least_conn: static intent vs measured load.
    write_kntx_config weighted "$BACKEND_SLOW" 9 1
    start_kntx
    run_oha "$out_dir/skewed-weighted-9-1.txt"
    stop_kntx
    summarize "$out_dir/skewed-weighted-9-1.txt" "weighted 9:1"

    echo
    echo "results: $out_dir"
}

main
