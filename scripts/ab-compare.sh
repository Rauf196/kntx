#!/usr/bin/env bash
# Paired A/B comparison of two kntx builds, measured in work per request.
#
# RPS is unusable for this on a thermally-throttled laptop: across ten rounds
# the same binary drifted from 35k to 17k, a spread far larger than any change
# worth measuring. Instructions and cycles per request do not have that
# problem - frequency scaling changes how long a request takes but not how much
# work it is - and they are what "this build does less" actually means.
# Measured side by side, instructions/request repeats to within 0.1% where RPS
# swings tens of percent.
#
# Runs still alternate round by round, and the order flips every other round
# (ABBA), so any drift that does survive lands on both sides.
#
# RPS is reported alongside but should be read as context, not as the result.
#
# requires: nginx, oha, jq, perf
#
# usage: ./scripts/ab-compare.sh <binary-a> <binary-b> <config.toml> [rounds] [seconds]

set -euo pipefail

BIN_A=${1:?usage: ab-compare.sh <binary-a> <binary-b> <config.toml> [rounds] [seconds]}
BIN_B=${2:?missing binary-b}
CONFIG=${3:?missing config.toml}
ROUNDS=${4:-10}
DURATION=${5:-10}

PROXY_PORT=8080
BACKEND_PORT=3010
CONNS=50
WARMUP=3
WORKDIR=$(mktemp -d /tmp/kntx-ab.XXXXXX)
BACKEND_CONF="$WORKDIR/backend.conf"

check_deps() {
    local missing=()
    for cmd in nginx oha jq perf; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "error: missing dependencies: ${missing[*]}" >&2
        exit 1
    fi
    for f in "$BIN_A" "$BIN_B" "$CONFIG"; do
        [[ -e "$f" ]] || { echo "error: no such file: $f" >&2; exit 1; }
    done
}

start_backend() {
    mkdir -p "$WORKDIR/tmp" "$WORKDIR/payloads"
    head -c 200 /dev/urandom | base64 | head -c 200 > "$WORKDIR/payloads/200b"
    cat > "$BACKEND_CONF" <<EOF
worker_processes 2;
error_log /dev/null;
pid $WORKDIR/backend.pid;
events { worker_connections 20000; }
http {
    access_log off;
    keepalive_timeout 75;
    keepalive_requests 1000000;
    sendfile on;
    client_body_temp_path $WORKDIR/tmp/client-body;
    proxy_temp_path       $WORKDIR/tmp/proxy;
    fastcgi_temp_path     $WORKDIR/tmp/fastcgi;
    uwsgi_temp_path       $WORKDIR/tmp/uwsgi;
    scgi_temp_path        $WORKDIR/tmp/scgi;
    server {
        listen $BACKEND_PORT default_server backlog=65535;
        root $WORKDIR/payloads;
        location = /200b { try_files /200b =404; }
    }
}
EOF
    nginx -c "$BACKEND_CONF"
    sleep 0.4
}

stop_backend() {
    [[ -f "$WORKDIR/backend.pid" ]] && nginx -c "$BACKEND_CONF" -s stop 2>/dev/null || true
}

cleanup() {
    [[ -n "${KNTX_PID:-}" ]] && kill -TERM "$KNTX_PID" 2>/dev/null || true
    stop_backend
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# One measured run of one binary. Prints "instr_per_req cycles_per_req rps".
#
# The perf window and the load window are both DURATION and start together, so
# the counters cover the loaded period rather than a loaded period plus an idle
# tail that would dilute the per-request figures.
#
# The pid comes from $! rather than pgrep: pgrep -f also matches the shell
# running this script, and pgrep -x cannot see names past 15 characters.
measure() {
    local bin="$1"
    "$bin" -c "$CONFIG" >/dev/null 2>&1 &
    KNTX_PID=$!
    sleep 1

    if ! kill -0 "$KNTX_PID" 2>/dev/null; then
        echo "error: $bin exited during startup" >&2
        exit 1
    fi

    oha -z "${WARMUP}s" -c "$CONNS" --no-tui --output-format quiet \
        "http://127.0.0.1:$PROXY_PORT/200b" >/dev/null 2>&1 || true

    local statfile="$WORKDIR/perf.txt"
    perf stat -p "$KNTX_PID" -e cycles,instructions -o "$statfile" \
        -- sleep "$DURATION" 2>/dev/null &
    local perf_pid=$!
    local out
    out=$(oha -z "${DURATION}s" -c "$CONNS" --no-tui --output-format json \
        "http://127.0.0.1:$PROXY_PORT/200b" 2>/dev/null)
    wait "$perf_pid" 2>/dev/null || true

    kill -TERM "$KNTX_PID" 2>/dev/null || true
    wait "$KNTX_PID" 2>/dev/null || true
    KNTX_PID=""
    sleep 0.5

    # a run that dropped requests is not comparable to one that did not
    local ok
    ok=$(jq -r '.summary.successRate' <<<"$out")
    if [[ "$ok" != "1" && "$ok" != "1.0" ]]; then
        echo "error: success rate $ok on $bin, run not comparable" >&2
        exit 1
    fi

    local reqs rps cyc ins
    reqs=$(jq -r '[.statusCodeDistribution[]] | add' <<<"$out")
    rps=$(jq -r '.summary.requestsPerSec' <<<"$out")
    cyc=$(awk '/ cycles/{gsub(",","",$1); print $1; exit}' "$statfile")
    ins=$(awk '/ instructions/{gsub(",","",$1); print $1; exit}' "$statfile")

    if [[ -z "$cyc" || -z "$ins" || "$cyc" == "<not" || "$ins" == "<not" ]]; then
        echo "error: perf did not report counters (check perf_event_paranoid)" >&2
        exit 1
    fi

    awk -v i="$ins" -v c="$cyc" -v r="$reqs" -v s="$rps" \
        'BEGIN{printf "%.0f %.0f %.0f\n", i/r, c/r, s}'
}

check_deps
start_backend

echo "A = $BIN_A"
echo "B = $BIN_B"
echo "$ROUNDS rounds, ${DURATION}s each, $CONNS connections, order alternates per round"
echo
printf "%-6s %11s %11s %8s   %11s %11s %8s\n" \
    round "A instr" "B instr" "delta" "A rps" "B rps" "delta"

b_wins=0
deltas=()
rps_deltas=()
for ((i = 1; i <= ROUNDS; i++)); do
    if (( i % 2 == 1 )); then
        read -r ai ac ar <<<"$(measure "$BIN_A")"
        read -r bi bc br <<<"$(measure "$BIN_B")"
    else
        read -r bi bc br <<<"$(measure "$BIN_B")"
        read -r ai ac ar <<<"$(measure "$BIN_A")"
    fi
    ipct=$(awk -v a="$ai" -v b="$bi" 'BEGIN{printf "%.2f", (b-a)/a*100}')
    rpct=$(awk -v a="$ar" -v b="$br" 'BEGIN{printf "%.2f", (b-a)/a*100}')
    deltas+=("$ipct")
    rps_deltas+=("$rpct")
    awk -v p="$ipct" 'BEGIN{exit !(p<0)}' && b_wins=$((b_wins + 1))
    printf "%-6s %11s %11s %7s%%   %11s %11s %7s%%\n" \
        "$i" "$ai" "$bi" "$ipct" "$ar" "$br" "$rpct"
    echo "$i $ac $bc" >> "$WORKDIR/cycles.txt"
done

summarize() {
    printf '%s\n' "${@:2}" | sort -n | awk -v n="$ROUNDS" -v label="$1" '
    { d[NR] = $1 }
    END {
        median = (n % 2) ? d[(n+1)/2] : (d[n/2] + d[n/2+1]) / 2
        printf "%-22s median %+.2f%%   range %+.2f%% .. %+.2f%%\n", label, median, d[1], d[n]
    }'
}

echo
summarize "instructions/request" "${deltas[@]}"
summarize "requests/sec" "${rps_deltas[@]}"
echo
echo "B did less work per request in $b_wins of $ROUNDS rounds"
awk '{ac+=$2; bc+=$3; n++} END{printf "cycles/request        A %.0f   B %.0f   %+.2f%%\n", ac/n, bc/n, (bc-ac)/ac*100}' \
    "$WORKDIR/cycles.txt"
