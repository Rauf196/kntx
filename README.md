<p align="center">
  <img src="docs/logo/kntx_no_bg.png" alt="kntx Logo" width="350">
</p>

<p align="center">
  <strong>L4/L7 reverse proxy in Rust. Raw bytes first, HTTP when you need it.</strong>
</p>

<p align="center">
  <a href="https://github.com/Rauf196/kntx/actions/workflows/ci.yml"><img src="https://github.com/Rauf196/kntx/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust"></a>
  <img src="https://img.shields.io/badge/platform-linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/tests-625-brightgreen.svg" alt="Tests">
</p>

---

> **Pre-release.** Config schema, metrics, and APIs may change without notice.

The fast path moves bytes with `splice(2)` and never parses them. HTTP is a mode you turn on per
listener. L4 measures 66% faster than nginx `stream`; L7 ties nginx `proxy_pass` at one connection
and leads 1.5x to 2.3x under concurrency.

```
                          ┌── mode = "l4" ───────────► splice(2), bytes never enter userspace
                          │
client ──► TCP accept ────┼── mode = "tls-passthrough" ► peek ClientHello for SNI, route, splice
                          │
                          └── mode = "l7" ───────────► parse HTTP/1.1, route on host/path/method,
                                                        pooled backend keep-alive
                          ▲
           [listeners.tls]│  optional rustls termination, sits before the mode decision
```

Every listener picks its own mode, routes, and backend pool, in one process.

## Features

| | |
|---|---|
| **L4 forwarding** | `splice(2)` zero-copy with a pooled pipe allocator and `TCP_CORK` batching; vectored and userspace paths as alternatives |
| **L7 HTTP/1.1** | parse, route, header injection, chunked and Content-Length pass-through, 100-continue, keep-alive both sides, WebSocket tunneling |
| **Routing** | host, path prefix, method, SNI matchers composed per route; first match wins; wildcards (`*.example.com`) |
| **Load balancing** | round-robin, least-connections, weighted; weights live-reloadable, so `weight = 0` drains a backend without a restart |
| **TLS** | rustls termination with multi-cert SNI, or SNI-routed passthrough where kntx holds no cert |
| **Resilience** | per-backend circuit breakers, active TCP probes, passive failure tracking, connect retries with failover |
| **Rate limiting** | GCRA on a lock-free set-associative cache; named zones attached per listener or per route |
| **Hot reload** | `SIGHUP` swaps pools, routes, listeners, certs, and rate-limit zones with no restart and no dropped connections |
| **PROXY protocol** | v1 and v2 ingress, any listener mode, including the `splice(2)` path |
| **Admin** | token-gated socket: pool state, config dump, live log level, two-phase drain, and a JS-free HTML panel |
| **Observability** | 43 Prometheus metrics, JSON access logs, W3C `traceparent` propagation |

Not implemented: HTTP/2, HTTP/3, backend TLS, request-body buffering, forward-proxy `CONNECT`.
See [Limits](#limits).

## Quick start

```bash
cargo build --release
./target/release/kntx --config config.toml
```

```toml
[[listeners]]
address = "0.0.0.0:8080"
mode    = "l4"
pool    = "web"

[[pools]]
name     = "web"
backends = [
  { address = "127.0.0.1:3001" },
  { address = "127.0.0.1:3002" },
]

[metrics]
address = "0.0.0.0:9090"
```

`config/example.toml` is the full option catalogue. `--validate` checks a config without starting.

### File descriptor limit

kntx checks `RLIMIT_NOFILE` at startup and refuses to start with the exact number it needs:

```
file descriptor limit too low: current=1024, required=21280
(pipe pool: 1024, max connections: 20000, base: 256).
raise it with: ulimit -n 21280
```

Budget is `1024` (pipe pool) + `2 × max_connections` per listener + `256`. The common 1024 default
is not enough to start. Use `LimitNOFILE=` in the systemd unit; a service does not inherit your
shell's limit.

## Configuration

Precedence: defaults → config file → env vars → CLI flags.

The four per-call timeouts bound the gap between two successful I/O operations, not total phase
duration, which is what makes them a progress invariant against slowloris.

| Setting | Scope | On expiry | Default |
|---|---|---|---:|
| `client_header_timeout_secs` | gap reading request head | 408 + close | 60 |
| `client_body_timeout_secs` | gap reading request body | close | 60 |
| `proxy_send_timeout_secs` | gap writing to backend | 504 if pre-response | 60 |
| `proxy_read_timeout_secs` | gap reading backend response | 504 if pre-response | 60 |
| `request_timeout_secs` | whole request | 504 if pre-response | 60 |
| `keepalive_idle_timeout_secs` | between keep-alive requests | close | 60 |
| `clienthello_timeout_secs` | passthrough ClientHello peek | close | 10 |
| `connect_timeout_secs` | TCP connect to backend | next backend, then 504 | 5 |
| `drain_timeout_secs` | shutdown drain | force close | 30 |
| pool `idle_conn_ttl_secs` | idle backend conn in cache | drop conn | 60 |

Backend keep-alive is on by default (`max_idle = 32`); set `max_idle = 0` to opt out.

Restart-only fields log a `WARN` and keep the running value on reload: pool `strategy`,
`[admin] address`, `metrics.address`, buffer pool sizes, and the per-listener connection settings.

## Admin

A second socket, separate from `[metrics]` by exposure class. Binding off-loopback without a token
is a validation error. The token gates reads as well as writes, and rotates on `SIGHUP`.

```toml
[admin]
address = "127.0.0.1:9901"
# token = "..."   # required to bind anywhere but loopback
```

| route | method | |
|---|---|---|
| `/` | GET | HTML panel, or a plain-text route table for curl |
| `/server_info` | GET | version, uptime, config version, pool count, serving or draining |
| `/pools` | GET | per backend: circuit, weight, in-flight, failures, keep-alive cache, sockets |
| `/config_dump` | GET | running config as JSON, `[admin] token` redacted |
| `/logging` | GET, POST | read the log filter, or POST an `EnvFilter` directive |
| `/healthcheck/fail`, `/ok` | POST | force `/ready` to 503 without stopping the process |
| `/drain_listeners` | POST | stop accepting, stay alive, `SIGHUP` re-binds |

```bash
curl -s :9901/pools | jq '.pools[].backends[] | {address, circuit, active}'
curl -X POST --data 'kntx::proxy::l7=debug,info' :9901/logging
```

`/config_dump` reports what is **running**: restart-only fields are pinned to their live values, so
an edited-but-ignored setting shows the value actually in effect.

`/logging` takes a filter directive, not a level, so one module can be turned up alone. Bad
directives are rejected before the swap. A runtime filter outranks `[logging] level` and survives
`SIGHUP`.

The panel is one self-contained page: no JavaScript, no external assets, no auto-refresh. Its
buttons are plain forms, safe because mutating routes reject any `Sec-Fetch-Site` that is not
`same-origin` (`same-site` included: another port on loopback is not the same origin). Requests
with no such header, like curl, are allowed. With a token set the panel is unreachable from a
browser by design; it is a curl surface.

## Observability

`/metrics`, `/healthz` and `/ready` share the `[metrics]` socket. Histogram buckets are set for
proxy timescales: 50 µs to 30 s, dense in the 100 µs to 100 ms band.

| endpoint | means |
|---|---|
| `/healthz` | the process is alive. A crashed listener takes the process down, so it cannot lie. |
| `/ready` | this instance should receive traffic. 200 unless draining or the health override is set. |

**`/ready` ignores backend health.** One kntx fronts many services, so a dead pool must not
deregister the listener serving the healthy ones, and every replica would report identically
anyway. Requests to a dead pool get a clean 503; alert on the metric instead:

```promql
sum by (pool) (kntx_backend_health) == 0                    # pool down everywhere - page
count by (pool) (kntx_backend_health == 0) > 0
  unless sum by (pool) (kntx_backend_health) == 0           # one replica cannot reach it - warn
kntx_config_last_reload_success == 0                        # replica serving stale config
```

Access logs are one JSON line per request: timestamp, listener, client IP, method, host, path,
query, status, bytes each way, durations, backend, pool, route ID, request ID, trace ID,
keep-alive index. File sinks flush every second or 64 lines.

Inbound `traceparent`, `tracestate` and B3 headers pass through unchanged. kntx does not emit its
own spans yet.

## Deployment

### Behind an L4 load balancer

The balancer spreads load and survives an AZ loss; kntx decides what happens to each request.
Because the balancer terminates TCP, the peer kntx sees is the balancer, so `X-Forwarded-For`,
access logs and **per-IP rate limiting** all key on it unless PROXY protocol is enabled.

Enable it on the sender (AWS `proxy_protocol_v2.enabled`; HAProxy `send-proxy-v2`; nginx
`proxy_protocol on` inside a `stream` block, as the `http` upstream cannot send it) and on the
listener:

```toml
[[listeners]]
address             = "0.0.0.0:8443"
mode                = "l7"
pool                = "web"
proxy_protocol      = true
proxy_protocol_from = ["10.0.0.0/16"]   # balancer subnets only
```

> **Once `proxy_protocol` is on, the header is mandatory on that listener.** A port accepting either
> a header or a bare connection lets any client claim any source address. Give plain clients their
> own listener.

Empty `proxy_protocol_from` trusts anything that can reach the port. A `LOCAL` header keeps the
socket peer. Works in every listener mode and does not cost the zero-copy path.

On a `proxy_protocol` listener the listener-level `rate_limit` runs after the header is read, so a
rejected connection has already taken a `max_connections` slot; that limit bounds a flood there.

### Health checks and draining

Point the target group at `/ready` over HTTP on the `[metrics]` port, not a TCP check on the traffic
port. A TCP check cannot see a drain: sockets close at the same instant new connections start being
refused, too late to deregister gracefully.

Order these three or graceful shutdown is defeated:

```
deregistration delay  >=  drain_timeout_secs  <  TimeoutStopSec
```

```ini
[Service]
ExecStart=/usr/local/bin/kntx --config /etc/kntx/config.toml
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
TimeoutStopSec=45      # must exceed drain_timeout_secs (default 30)
LimitNOFILE=21280
Restart=on-failure
User=kntx
```

To take one instance out of rotation and put it back without a restart:

```bash
curl -X POST :9901/healthcheck/fail    # 1. /ready -> 503. balancer stops sending NEW work.
                                       #    :8080 keeps serving what is already routed to it.
# 2. wait out the deregistration delay. kntx_connections_active reaching 0 means drained.
curl -X POST :9901/drain_listeners     # 3. stop accepting. sockets close, new connects refused.
#    deploy / edit config
kill -HUP $(pidof kntx)                # 4. re-bind.
curl -X POST :9901/healthcheck/ok      # 5. rejoin rotation.
```

Step 5 is required: `SIGHUP` clears the drain but deliberately not the health override, so skipping
it leaves an instance serving while the balancer sends it nothing. Going straight to step 3 cuts
connections the balancer was still routing to you.

### Common mistakes

| symptom | cause |
|---|---|
| `X-Forwarded-For` shows one IP for everyone | `proxy_protocol` off behind an L4 balancer |
| all connections refused right after enabling `proxy_protocol` | sender not configured to send the header, which is mandatory once on |
| connections refused during a rolling deploy | deregistration delay shorter than `drain_timeout_secs` |
| requests cut mid-flight on restart | `TimeoutStopSec` at or below `drain_timeout_secs` |
| instance stays in rotation with backends dead | expected; alert on `kntx_backend_health` |
| serves fine but gets no traffic after a deploy | missed `POST /healthcheck/ok` |
| reload appears to do nothing | the field is restart-only; the log says so |
| `Too many open files` | see [File descriptor limit](#file-descriptor-limit) |

## Benchmarks

Reproducible from this repo. Raw output in `benchmark-results/`, scripts in `scripts/`. Intel
i7-8550U (4C/8T) over loopback. Tables note their own kernel and nginx build.

### L4 throughput

`./scripts/benchmark-single.sh 10` - iperf3, single stream, Linux 7.1.4, nginx 1.31.3.

| Path | Throughput | vs direct | vs nginx |
|---|---:|---:|---:|
| Direct, no proxy | 39.41 Gbps | 100% | - |
| **kntx splice** | **32.43 Gbps** | 82% | **+66%** |
| kntx vectored | 21.98 Gbps | 56% | +12% |
| kntx userspace (64 KB pooled) | 19.40 Gbps | 49% | -1% |
| nginx `stream` | 19.55 Gbps | 50% | baseline |

nginx `stream` has no splice option, so it copies through userspace. kntx's own userspace path
(19.40) versus its splice path (32.43) is the cost of data touching userspace: +67%.

Under parallel streams (Linux 6.19.9, nginx 1.29.7), splice holds ~51 Gbps flat from 10 to 100
streams while nginx plateaus around 32 Gbps.

### L7 HTTP

`./scripts/benchmark-l7.sh` - oha, 200-byte static response, 30s after warmup. Linux 7.0.3, nginx
1.29.8. Backend is nginx throughout. Predates the hot-path work below and has not been re-measured.

| Concurrency | | RPS | p50 | p99 | success |
|---|---|---:|---:|---:|---:|
| 1 conn | kntx-l7 | 12,090 | 73 µs | **153 µs** | 100% |
| | nginx-l7 | 12,093 | 71 µs | 202 µs | 100% |
| 100 conns | **kntx-l7** | **38,917** | **2.4 ms** | 5.6 ms | 100% |
| | nginx-l7 | 26,322 | 3.7 ms | 5.1 ms | 100% |
| 1,000 conns | **kntx-l7** | **32,229** | **30.7 ms** | **39.8 ms** | 100% |
| | nginx-l7 | 19,524 | 49.4 ms | 80.7 ms | 100% |
| 10,000 conns | **kntx-l7** | **30,012** | **327.9 ms** | **392.6 ms** | **100%** |
| | nginx-l7 | 13,011 | 470.3 ms | 650.2 ms | 99.86% |

Read the success column with the percentiles. At 10k conns nginx dropped 10,282 requests, and
dropped requests never enter its histogram, so its p99 of 650 ms covers only what it served; its
worst case was 29,766 ms. kntx queues on a FIFO semaphore instead of shedding: 100% served, every
response between 258 ms and 514 ms. Higher median, bounded tail.

### Rate limiter

`cargo bench --bench rate_limit` - criterion, release. Comparator is a `Mutex<HashMap>` token
bucket. Threaded rows are wall time per check across 8 threads.

| Scenario | kntx `KeyedLimiter` | `Mutex<HashMap>` | ratio |
|---|---:|---:|---:|
| Uncontended, 1 thread | 45.0 ns | 64.4 ns | 1.4x |
| Same key, 8 threads | 106.9 ns | 352.2 ns | 3.3x |
| Distinct keys, 8 threads | **15.9 ns** | 457.9 ns | **29x** |

Distinct keys is the production case: independent keys land on independent cache lines, so per-check
cost drops below the single-threaded figure.

### Load balancing

`./scripts/benchmark-balancer.sh 30` - oha, 200 connections. Skewed caps one backend at 2000 r/s so
it queues rather than rejecting. Metrics enabled.

| pool | strategy | RPS | p50 | p99 |
|---|---|---:|---:|---:|
| uniform | round_robin | 37,875 | 5.05ms | 10.76ms |
| uniform | least_conn | 28,309 | 6.78ms | 13.91ms |
| uniform | weighted | 28,880 | 6.65ms | 13.61ms |
| skewed | round_robin | 4,003 | 2.68ms | 100.85ms |
| skewed | **least_conn** | **29,046** | 4.40ms | **42.93ms** |
| skewed | weighted 9:1 | 20,059 | 0.43ms | 97.78ms |

**least_conn is 7.3x round-robin under skew**: strict alternation pins total throughput at twice the
slowest member, not half. The skewed rows reproduce exactly because the cap determines them.

**The uniform rows are noise on this hardware and should not be read as a ranking.** Across three
runs of that identical config round_robin measured 30,689 / 29,081 / 37,875. Treat them as evidence
that no strategy collapses when there is nothing to optimize, nothing finer.

Weighted's 0.43ms p50 beside a 98ms p99 is bimodal: 90% goes to the healthy backend, 10% still
queues behind the cap. It also needed the 9:1 ratio known in advance, which least_conn measured at
runtime.

## Limits

- **HTTP/2 and HTTP/3.** HTTP/1.1 only.
- **Backend TLS.** kntx speaks plain TCP upstream.
- **No body buffering, so no body transforms.** Bodies stream through untouched, which bounds memory
  by `max_body_size_bytes` rather than `concurrency × max_body_size_bytes`, and is why mid-body
  retry is impossible.
- **WebSocket frames are opaque.** Tunnels forward bytes; no per-frame metrics.
- **`CONNECT` returns 405.** kntx is a reverse proxy.
- **No HTTP pipelining.** Next request is read after the previous response completes.
- **PROXY protocol is ingress only.** On `l4` and `tls-passthrough` there is no way to tell the
  backend the client address; use an L7 listener if it needs one.
- **No session affinity.** No consistent hashing or sticky sessions yet.
- **Linux only.** `splice(2)` and `SO_LINGER` handling are Linux-specific.

## Development

```bash
cargo test                                  # 625 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check                            # advisories, licenses, sources
cargo +nightly fuzz run parse_request        # four parser targets under fuzz/
```

CI runs fmt, clippy and tests on stable, plus `cargo-deny`.

## Roadmap

Consistent hashing for session affinity, then OpenTelemetry span emission with Prometheus exemplars.

Longer term kntx targets programmable proxy logic, the space Cloudflare Workers and Envoy filters
occupy, with the priority order inverted: performance first. The `Matcher` and `Router` traits are
the plug-in surface a routing DSL compiles down to. kntx is the data plane, not an edge platform.

## License

MIT
