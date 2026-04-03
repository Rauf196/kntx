#!/usr/bin/env bash
# kntx forwarding strategy benchmark
#
# compares throughput across: direct, userspace, vectored, splice
# optionally benchmarks nginx stream mode if nginx is installed
#
# requires: iperf3, cargo, jq
# optional: nginx with stream module (nginx-mainline + nginx-mainline-mod-stream on arch)
#
# usage: ./scripts/benchmark.sh [duration_seconds]

set -euo pipefail

DURATION=${1:-10}
PROXY_PORT=8080
IPERF_PORT=3001
RESULTS_DIR="benchmark-results"
KNTX="./target/release/kntx"
NGINX_CONF="/tmp/kntx-nginx-benchmark.conf"

# --- dependency checks ---

check_deps() {
    local missing=()

    command -v iperf3 >/dev/null 2>&1 || missing+=("iperf3")
    command -v cargo >/dev/null 2>&1 || missing+=("cargo")
    command -v jq >/dev/null 2>&1 || missing+=("jq")

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "error: missing required dependencies: ${missing[*]}"
        exit 1
    fi
}

check_port() {
    local port="$1"
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        echo "error: port $port is already in use"
        exit 1
    fi
}

has_nginx_stream() {
    command -v nginx >/dev/null 2>&1 || return 1
    # check if stream module exists
    local mod_path="/usr/lib/nginx/modules/ngx_stream_module.so"
    [[ -f "$mod_path" ]] || return 1
    return 0
}

# --- helpers ---

extract_gbps() {
    local file="$1"
    jq -r '.end.sum_sent.bits_per_second / 1e9 | . * 100 | round / 100' "$file"
}

run_iperf_test() {
    local label="$1"
    local port="$2"
    local output_file="$RESULTS_DIR/${label}.json"

    echo -n "  $(printf '%-20s' "$label")"
    iperf3 -c 127.0.0.1 -p "$port" -t "$DURATION" -J > "$output_file" 2>/dev/null
    local gbps
    gbps=$(extract_gbps "$output_file")
    echo "$gbps Gbps"
}

cleanup() {
    pkill -f "iperf3 -s -p $IPERF_PORT" 2>/dev/null || true
    [[ -n "${KNTX_PID:-}" ]] && kill "$KNTX_PID" 2>/dev/null || true
    if [[ -f /tmp/nginx-benchmark.pid ]]; then
        kill "$(cat /tmp/nginx-benchmark.pid)" 2>/dev/null || true
    fi
}

# --- main ---

check_deps
check_port "$IPERF_PORT"
check_port "$PROXY_PORT"

# pipe pool allocates 512 pairs = 1024 fds at startup
MIN_FDS=1280
if [[ $(ulimit -n) -lt $MIN_FDS ]]; then
    echo "error: ulimit -n is $(ulimit -n), need at least $MIN_FDS"
    echo "run:   ulimit -n $MIN_FDS"
    exit 1
fi

# timestamp the results directory so runs don't overwrite each other
RESULTS_DIR="$RESULTS_DIR/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== kntx forwarding benchmark ==="
echo "date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "kernel:   $(uname -r)"
echo "cpu:      $(lscpu | grep 'Model name' | sed 's/.*: *//')"
echo "duration: ${DURATION}s per test"
if has_nginx_stream; then
    echo "nginx:    $(nginx -v 2>&1 | sed 's/.*\///')"
else
    echo "nginx:    not found (skipping nginx benchmark)"
fi
echo ""

# build
echo "building release binary..."
cargo build --release --quiet 2>/dev/null

# start iperf3 server
echo "starting iperf3 server on port $IPERF_PORT..."
iperf3 -s -p "$IPERF_PORT" -D 2>/dev/null
sleep 0.5
trap cleanup EXIT

# write environment metadata for reproducibility
cat > "$RESULTS_DIR/environment.txt" <<EOF
date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)
kernel:   $(uname -r)
cpu:      $(lscpu | grep 'Model name' | sed 's/.*: *//')
cores:    $(nproc)
memory:   $(free -h | awk '/Mem:/{print $2}')
iperf3:   $(iperf3 --version 2>&1 | head -1)
rustc:    $(rustc --version)
kntx:     $(git describe --tags --always --dirty 2>/dev/null || echo "unknown")
ulimit:   $(ulimit -n)
duration: ${DURATION}s
$(if has_nginx_stream; then echo "nginx:    $(nginx -v 2>&1)"; fi)

commands:
  ./scripts/benchmark.sh $DURATION
EOF

echo ""
echo "--- throughput (single stream, ${DURATION}s) ---"

# 1. direct baseline
run_iperf_test "direct" "$IPERF_PORT"

# 2. kntx forwarding strategies
KNTX_PID=""
for strategy in userspace vectored splice; do
    cat > /tmp/kntx-bench-${strategy}.toml <<EOF
[listener]
address = "0.0.0.0:$PROXY_PORT"

[[backends]]
address = "127.0.0.1:$IPERF_PORT"

[forwarding]
strategy = "$strategy"

[logging]
level = "warn"
EOF

    $KNTX -c "/tmp/kntx-bench-${strategy}.toml" &
    KNTX_PID=$!
    sleep 0.5

    run_iperf_test "kntx-$strategy" "$PROXY_PORT"

    kill "$KNTX_PID" 2>/dev/null
    wait "$KNTX_PID" 2>/dev/null || true
    KNTX_PID=""
    sleep 0.3
done

# 3. nginx stream mode (if available)
if has_nginx_stream; then
    cat > "$NGINX_CONF" <<EOF
load_module /usr/lib/nginx/modules/ngx_stream_module.so;

worker_processes auto;
error_log /dev/null;
pid /tmp/nginx-benchmark.pid;

events {
    worker_connections 1024;
}

stream {
    server {
        listen $PROXY_PORT;
        proxy_pass 127.0.0.1:$IPERF_PORT;
        proxy_buffer_size 64k;
        tcp_nodelay on;
    }
}
EOF

    nginx -c "$NGINX_CONF" 2>/dev/null
    sleep 0.5

    run_iperf_test "nginx-stream" "$PROXY_PORT"

    nginx -s stop -c "$NGINX_CONF" 2>/dev/null
    sleep 0.3
fi

# --- summary ---

echo ""
echo "--- summary ---"
echo ""
printf "  %-20s %s\n" "PATH" "THROUGHPUT"
printf "  %-20s %s\n" "----" "----------"

for f in "$RESULTS_DIR"/*.json; do
    label=$(basename "$f" .json)
    gbps=$(extract_gbps "$f")
    printf "  %-20s %s Gbps\n" "$label" "$gbps"
done

echo ""
echo "results saved to $RESULTS_DIR/"
