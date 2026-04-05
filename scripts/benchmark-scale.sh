#!/usr/bin/env bash
# kntx multi-stream scaling benchmark
# multi-stream scaling — how throughput changes with concurrent connections
#
# requires: iperf3, cargo, jq
# optional: nginx with stream module (nginx-mainline + nginx-mainline-mod-stream on arch)
#
# usage: ./scripts/benchmark-scale.sh [duration_seconds]

set -euo pipefail

DURATION=${1:-5}
PROXY_PORT=8080
IPERF_PORT=3001
STREAM_COUNTS="1 10 50 100"
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
    local mod_path="/usr/lib/nginx/modules/ngx_stream_module.so"
    [[ -f "$mod_path" ]] || return 1
    return 0
}

# --- helpers ---

extract_gbps() {
    local file="$1"
    jq -r '.end.sum_sent.bits_per_second / 1e9 | . * 100 | round / 100' "$file"
}

run_scaled_test() {
    local label="$1"
    local port="$2"
    local streams="$3"
    local output_file="$RESULTS_DIR/scale-${label}-P${streams}.json"
    iperf3 -c 127.0.0.1 -p "$port" -t "$DURATION" -P "$streams" -J > "$output_file" 2>/dev/null
    jq -r '.end.sum_sent.bits_per_second / 1e9 | . * 100 | round / 100' "$output_file"
}

print_scaling_row() {
    local label="$1"
    printf "  %-20s" "$label"
    for streams in $STREAM_COUNTS; do
        local f="$RESULTS_DIR/scale-${label}-P${streams}.json"
        if [[ -f "$f" ]]; then
            local gbps
            gbps=$(jq -r '.end.sum_sent.bits_per_second / 1e9 | . * 100 | round / 100' "$f")
            printf " %-10s" "$gbps"
        else
            printf " %-10s" "n/a"
        fi
    done
    echo ""
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

echo "=== kntx multi-stream scaling benchmark ==="
echo "date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "kernel:   $(uname -r)"
echo "cpu:      $(lscpu | grep 'Model name' | sed 's/.*: *//')"
echo "duration: ${DURATION}s per test"
echo "streams:  $STREAM_COUNTS"
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
streams:  $STREAM_COUNTS
$(if has_nginx_stream; then echo "nginx:    $(nginx -v 2>&1)"; fi)

commands:
  ./scripts/benchmark-scale.sh $DURATION
EOF

echo "note: default pools — buffer: 1024 (userspace: 2/conn, vectored: 8/conn), pipe: 512 (splice: 2/conn)"
echo "note: kntx log level set to 'error' — expected teardown warnings at high P are suppressed"
echo ""

# --- direct baseline ---

echo "--- direct baseline ---"
for streams in $STREAM_COUNTS; do
    gbps=$(run_scaled_test "direct" "$IPERF_PORT" "$streams")
    printf "    P=%-4s %s Gbps\n" "$streams" "$gbps"
done

# --- scaling tests ---

echo ""
echo "--- throughput scaling (multi-stream, ${DURATION}s per test) ---"
echo ""

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
level = "error"
EOF

    echo "  kntx-${strategy}:"
    $KNTX -c "/tmp/kntx-bench-${strategy}.toml" &
    KNTX_PID=$!
    sleep 0.5

    for streams in $STREAM_COUNTS; do
        gbps=$(run_scaled_test "kntx-${strategy}" "$PROXY_PORT" "$streams")
        printf "    P=%-4s %s Gbps\n" "$streams" "$gbps"
    done

    kill "$KNTX_PID" 2>/dev/null
    wait "$KNTX_PID" 2>/dev/null || true
    KNTX_PID=""
    sleep 0.3
done

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

    echo "  nginx-stream:"
    nginx -c "$NGINX_CONF" 2>/dev/null
    sleep 0.5

    for streams in $STREAM_COUNTS; do
        gbps=$(run_scaled_test "nginx-stream" "$PROXY_PORT" "$streams")
        printf "    P=%-4s %s Gbps\n" "$streams" "$gbps"
    done

    nginx -s stop -c "$NGINX_CONF" 2>/dev/null
    sleep 0.3
fi

# --- scaling summary ---

echo ""
echo "--- scaling summary ---"
echo ""
printf "  %-20s" "STRATEGY"
for streams in $STREAM_COUNTS; do
    printf " %-10s" "P=${streams}"
done
printf " %s\n" "Gbps"
printf "  %-20s" "----"
for streams in $STREAM_COUNTS; do
    printf " %-10s" "----"
done
echo ""

print_scaling_row "direct"
for strategy in userspace vectored splice; do
    print_scaling_row "kntx-${strategy}"
done

if has_nginx_stream; then
    print_scaling_row "nginx-stream"
fi

echo ""
echo "results saved to $RESULTS_DIR/"
