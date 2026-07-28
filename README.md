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
  <img src="https://img.shields.io/badge/tests-551-brightgreen.svg" alt="Tests">
</p>

---

> **Pre-release.** Config schema, metrics, and APIs may change without notice.

Most proxies parse HTTP first and treat raw TCP as a special case. kntx does it the other way
around: the fast path moves bytes with `splice(2)` and never looks at them, and HTTP parsing is a
mode you turn on per listener. That ordering is what makes the L4 path 66% faster than nginx
`stream`, while the L7 path matches nginx `proxy_pass` on single-connection overhead and pulls
ahead by 1.5x to 2.3x once concurrency arrives.

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

Every listener picks its own mode, its own routes, and its own backend pool, in one process.

## What works today

| | |
|---|---|
| **L4 forwarding** | `splice(2)` zero-copy with a pre-allocated pipe pool and `TCP_CORK` batching; vectored `readv/writev` and a pooled-buffer userspace path as alternatives |
| **L7 HTTP/1.1** | parse, route, header injection, chunked and Content-Length pass-through, 100-continue, keep-alive both sides, WebSocket tunneling |
| **Routing** | host, path prefix, method, SNI matchers composed per route; first match wins; wildcards (`*.example.com`) |
| **Load balancing** | round-robin, least-connections, or weighted per pool; weights are live-reloadable, so `weight = 0` drains a backend without a restart |
| **TLS** | termination via rustls (multi-cert SNI), or SNI-routed passthrough where kntx never holds a cert |
| **Resilience** | per-backend circuit breakers, active TCP probes, passive failure tracking, connect retries with failover |
| **Rate limiting** | GCRA on a lock-free set-associative cache; nginx-style named zones attached per listener or per route |
| **Hot reload** | `SIGHUP` swaps pools, routes, listeners, TLS certs, and rate-limit zones with no restart and no dropped connections |
| **Observability** | 42 Prometheus metrics, structured JSON access logs, W3C `traceparent` propagation |

Not implemented: HTTP/2, HTTP/3, backend TLS, request-body buffering, forward-proxy `CONNECT`.
See [Limits](#limits).

## Quick start

```bash
cargo build --release
```

Minimal `config.toml`:

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

```bash
./target/release/kntx --config config.toml
```

`config/example.toml` is the full option catalogue: every listener mode, TLS, routes, health
overrides, keep-alive tuning, and rate-limit zones, each with a comment explaining what it does.

### File descriptor limit

A proxy holds two sockets per connection, and the splice pipe pool claims 1024 descriptors at
startup. The common default soft limit of 1024 is therefore not enough to start at all, let alone
serve traffic. kntx checks `RLIMIT_NOFILE` before allocating anything and refuses to start with the
exact number it needs, rather than dying later with a bare `Too many open files` under load:

```
file descriptor limit too low: current=1024, required=21280
(pipe pool: 1024, max connections: 20000, base: 256).
raise it with: ulimit -n 21280
```

The budget is `1024` (pipe pool) + `2 × max_connections` per listener + `256` base, so the floor is
**1280** with no connection caps configured. Raise it for the shell with `ulimit -n <n>`, permanently
in `/etc/security/limits.conf`, or under systemd with `LimitNOFILE=` in the unit file - which is the
one that matters in production, because a systemd service does not inherit your shell's limit.

Sizing the limit down is the wrong fix. The defaults are chosen for a production server, and shrinking
the pipe pool to fit a small limit trades away the zero-copy fast path to work around a misconfigured
host.

## Benchmarks

Every number below is reproducible from this repo. Raw tool output is committed under
`benchmark-results/`; the scripts that produced it are in `scripts/`. All runs are on the same
machine, an Intel i7-8550U (4C/8T) over loopback. Each table notes its own kernel and nginx build,
because they were captured at different points in the project.

### L4 throughput (iperf3, single stream, 10s)

```bash
./scripts/benchmark-single.sh 10
```

Linux 7.1.4, nginx 1.31.3.

| Path | Throughput | vs direct | vs nginx |
|---|---:|---:|---:|
| Direct, no proxy | 39.41 Gbps | 100% | - |
| **kntx splice** | **32.43 Gbps** | 82% | **+66%** |
| kntx vectored | 21.98 Gbps | 56% | +12% |
| kntx userspace (64 KB pooled) | 19.40 Gbps | 49% | -1% |
| nginx `stream` | 19.55 Gbps | 50% | baseline |

nginx `stream` has no splice option (only its HTTP module does `sendfile`), so it copies through
userspace. `proxy_buffer_size 64k` was set to match kntx's buffer size. The gap between kntx's own
userspace path (19.40) and its splice path (32.43) is the cost of data touching userspace: +67%.
That gap is the entire argument for the L4-first design, and it is why kntx's plainest path merely
ties nginx while its fast path does not.

Under parallel streams (`benchmark-scale.sh`, Linux 6.19.9, nginx 1.29.7), splice holds ~51 Gbps
flat from 10 to 100 streams while nginx plateaus around 32 Gbps.

### L7 HTTP (oha, 200-byte static response, 30s after 10s warmup)

```bash
./scripts/benchmark-l7.sh
```

Linux 7.0.3, nginx 1.29.8, `oha` 1.14. Backend is nginx in all cases. `kntx-l7` runs with the
backend keep-alive cache at `max_idle = 32`.

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

At one connection the two are dead even, which is the honest per-request-overhead result. kntx
pulls ahead as concurrency rises because of the backend keep-alive cache, worth 1.5x RPS at one
connection and 3.8x at ten thousand.

**On nginx's 99.86%.** At 10k connections nginx dropped 10,282 requests: 9,751 deadline aborts,
325 connection errors, 206 timeouts. Dropped requests never enter the percentile histogram, so
nginx's p99 of 650 ms is computed only over requests it managed to serve. Its actual worst case
was 29,766 ms. kntx queues on a FIFO semaphore instead of shedding, so every request is held and
served: 100% success, and every single response landed between 258 ms and 514 ms. That is a
deliberate trade, higher median in exchange for a bounded tail, and it is only visible if you read
the success rate next to the percentiles.

Getting there took work. The first cut of the L7 path had no cap on backend connections, which at
10k clients produced a SYN storm against the backend, a 23% 503 rate, and a **3,514 ms** p99. Adding
the permit semaphore, interning metric labels to kill four heap allocations per request, streaming
access-log JSON with `to_writer` instead of an intermediate `String`, and making the buffer pool
sizable brought that to 424 ms and zero errors.

### Rate limiter (criterion, release profile)

```bash
cargo bench --bench rate_limit
```

Comparator is a `Mutex<HashMap<u64, (f64, Instant)>>` token bucket, the design the keyed limiter
exists to refuse. Threaded rows are wall time per check with 8 threads in parallel.

| Scenario | kntx `KeyedLimiter` | `Mutex<HashMap>` bucket | ratio |
|---|---:|---:|---:|
| Uncontended, 1 thread | 45.0 ns | 64.4 ns | 1.4x |
| Same key, 8 threads (attacker on one key) | 106.9 ns | 352.2 ns | 3.3x |
| Distinct keys, 8 threads (production spread) | **15.9 ns** | 457.9 ns | **29x** |

Distinct keys is the production case and where the designs diverge hardest. Independent keys land
on independent cache lines, so checks scale across cores and the per-check wall time drops *below*
the single-threaded cost. The mutexed map gets worse under spread load than under same-key load,
because more distinct keys means map growth, rehashing, and allocation inside the critical section
while every thread still funnels through one lock.

### Load balancing (oha, 30s, 200 connections)

```bash
./scripts/benchmark-balancer.sh 30
```

Two pools. Uniform is two identical backends. Skewed caps one backend at 2000 r/s with nginx
`limit_req`, so it queues rather than rejecting. Metrics are enabled, because the emission path is
part of per-request cost and benchmarking with them off measures a configuration nobody runs.

| pool | strategy | RPS | p50 | p99 |
|---|---|---:|---:|---:|
| uniform | round_robin | 37,875 | 5.05ms | 10.76ms |
| uniform | least_conn | 28,309 | 6.78ms | 13.91ms |
| uniform | weighted | 28,880 | 6.65ms | 13.61ms |
| skewed | round_robin | 4,003 | 2.68ms | 100.85ms |
| skewed | **least_conn** | **29,046** | 4.40ms | **42.93ms** |
| skewed | weighted 9:1 | 20,059 | 0.43ms | 97.78ms |

**least_conn is 7.3x round-robin under skew**, and the mechanism is worth stating precisely: strict
alternation forces the healthy backend to match the throttled one's rate, so total throughput is
pinned at *twice the slowest member* rather than merely reduced by half. Load-aware selection is not
an optimization here, it is the difference between 4k and 29k RPS.

The skewed rows are highly reproducible: round_robin measured 4,003 RPS in three separate runs and
weighted landed within 19 RPS of itself, because both are arithmetically determined by the cap
rather than by proxy speed.

**The uniform rows are not resolvable on this hardware, and the table should not be read as
"round_robin is 34% faster".** Across three runs of that identical config, round_robin measured
30,689, 29,081 and 37,875 while least_conn measured 29,452, 30,887 and 28,309 - so the same
comparison came out anywhere from 4% against round_robin to 34% in its favour. A 4-core laptop over
loopback cannot separate per-selection costs this small from noise. Treat the uniform pool as
evidence that no strategy collapses when there is nothing to optimize, and nothing finer. Isolating
real selection overhead needs a criterion micro-benchmark, not a macro load test.

Read weighted's row carefully. Best p50 of any run at 0.43ms, next to a p99 of 98ms that is
essentially round-robin's. The distribution is bimodal: 90% of traffic goes sub-millisecond to the
healthy backend and the remaining 10% still queues behind the cap. A good p50 beside a bad p99 means
two populations averaged together. It also only helped because the 9:1 ratio was configured in
advance; least_conn measured the same skew at runtime. Static intent versus observed load is the
real difference between the two, not the throughput.

## Design notes

The decisions that took the most thought, and what they cost.

**splice is the ceiling, and io_uring is not the answer.** io_uring was evaluated properly and
rejected. `tokio-uring` has been unmaintained since November 2022 and benchmarked 11-15% *slower*
than plain Tokio. Its completion model needs owned buffers and `!Send` futures, which is
fundamentally incompatible with `#[tokio::main]` and the `AsyncRead`/`AsyncWrite` ecosystem.
Dropping a future with operations in flight is a documented unsolved cancellation-safety problem
across every Rust io_uring runtime. And no production proxy uses it: not Pingora, nginx, HAProxy,
or Envoy. Expected gain over splice for streaming is 0-15%. Writing that analysis down was worth
more than a broken integration.

**Retry has two axes, not one.** kntx streams request bodies rather than buffering them, so once a
body byte reaches the backend it is gone. A retry therefore needs *both* an idempotent method
(RFC 7231 §4.2.2) *and* zero body bytes flushed. nginx can be more aggressive because it buffers
first. The trade: kntx cannot replay a PUT mid-body even though the spec calls PUT idempotent.
Buying that back would mean a per-request memory budget, which is a real cost for a case that has
not come up.

**Paths are forwarded byte-for-byte.** No `%2F` decoding, no `..` resolution, no `//` collapsing.
Normalization is a policy decision, not a transport responsibility, and applying it silently can
flip an auth or ACL outcome on the backend. The proxy carries what the client sent and refuses only
when the framing itself is ambiguous, which is the same principle behind the smuggling defenses
(CL+TE, multiple CL, `TE` other than `chunked`, and obs-fold are all rejected with 400).

**Passthrough uses a hand-rolled ClientHello parser, deliberately.** ~120 bounds-checked lines that
read framing only: record header, handshake header, body walk, `server_name` extension. rustls's
`Acceptor` would have been less code but it applies rustls's protocol policy, which means it can
reject a hello the *backend* would have accepted. That is the wrong failure mode for a proxy that
is not a TLS endpoint on those connections. nginx's `ssl_preread` makes the same call.

**Hot reload is Envoy's model, not nginx's.** nginx forks fresh workers because it is
multi-process. kntx is one process, so there is nothing to fork, and re-binding in-process to
imitate the fork model would need `SO_REUSEPORT` for no gain. Instead a versioned config snapshot
sits behind an `arc-swap` pointer; readers on the hot path load it without a lock. Two properties
carry the design: reload is a **transaction**, with every fallible step (router build, cert load,
zone build, socket bind) completing before anything mutates, so a bad config leaves the running one
untouched exactly like `nginx -t`; and state is **preserved by identity**, so a backend present in
both configs keeps its circuit breaker and warm connections, and an unchanged rate-limit zone keeps
its accumulated budget. That second one is correctness, not optimization: otherwise an operator
could reset a flooding client's rate-limit budget by touching an unrelated field.

**A knob is only live-reloadable if a restart would be unacceptable.** Capability is not a reason.
Pool membership, routes, certs, rate limits, and health thresholds each map to a concrete 3am
incident. Buffer pool sizes, `metrics.address`, and forwarding strategy do not, so they are
restart-only and a changed value logs a `WARN` rather than silently half-applying.

**Least-connections has to count queued work, not just in-flight work.** The in-flight counter was
first claimed where a checked-out backend connection is born, which is one `await` too late:
checkout acquires the per-backend concurrency permit first, and that blocks when the backend is
saturated. So requests queued behind a slow backend counted as zero load on it, every saturated
backend read exactly its cap, and least-connections saw a permanent tie and silently degenerated
into round-robin at precisely the load where it was supposed to help. The fix was one line moved
above the permit gate. What caught it was the benchmark, not the tests: least-connections measured
*worse* than round-robin under a skewed pool, which a correct implementation cannot do. Every unit
test passed throughout, because they set the counter directly and never exercised the saturation
path. The general rule is that a load signal must answer "what have I already committed here",
not "what is running here" - queued work is committed, idle pooled sockets are not.

**Metric labels are bounded by rule, not by habit.** `method`, `status`, `pool`, `listener`,
`route_id`, `backend` are allowed. `host` and `sni` only when enumerable from config. `path`,
`query`, `user_agent`, and client IP are never metric labels, they go to access logs and traces.
The original spec for the passthrough metrics had an `sni` label; it violated this rule and was
corrected before it shipped.

**Two lock-free bugs found by an exact-count stress test.** The keyed rate limiter's 8-thread test
asserts the admit count is *exactly* `burst + 1` under a frozen clock, rather than within some
epsilon. That precision caught two real protocol races: a blind TAT store after claiming a slot
could roll back concurrent admits, and a two-pass scan/select duplicated hot new keys across empty
ways about 1% of runs. Both are fixed; every admit is now exactly one successful CAS. An epsilon
bound would have hidden both.

## Configuration

Precedence: defaults → config file → env vars → CLI flags.

The timeout surface is larger than most proxies expose, because there are genuinely several
different things to bound. The four per-call timeouts limit the gap between two successful I/O
operations rather than the total phase duration, which is what makes them a real progress invariant
against slowloris.

| Setting | Scope | On expiry | Default |
|---|---|---|---:|
| `client_header_timeout_secs` | gap reading request head | 408 + close | 60 |
| `client_body_timeout_secs` | gap reading request body | close | 60 |
| `proxy_send_timeout_secs` | gap writing to backend | 504 if pre-response | 60 |
| `proxy_read_timeout_secs` | gap reading backend response | 504 if pre-response | 60 |
| `request_timeout_secs` | whole request | 504 if pre-response | 60 |
| `keepalive_idle_timeout_secs` | between requests on a kept-alive conn | close | 60 |
| `clienthello_timeout_secs` | passthrough ClientHello peek | close | 10 |
| `connect_timeout_secs` | TCP connect to backend | next backend, then 504 | 5 |
| `drain_timeout_secs` | shutdown drain | force close | 30 |
| pool `idle_conn_ttl_secs` | idle backend conn in cache | drop conn | 60 |

Backend keep-alive is **on by default** (`max_idle = 32`), unlike nginx's opt-in `keepalive`
directive. Discovering that a connection cache exists but has to be enabled is a worse first
experience than discovering `max_idle = 0` exists as an opt-out.

## Observability

**Metrics** at `/metrics`, Prometheus format. Connections, bytes by direction, backend health and
circuit state, TLS handshake outcomes and duration, HTTP requests by method and status, parse and
smuggling rejects, keep-alive cache hits/misses/stale, WebSocket tunnels, rate-limit rejections,
passthrough routing, and config reload status. Histogram buckets are set for proxy timescales, not
library defaults: request duration spans 50 µs to 30 s with the density in the 100 µs to 100 ms
band where proxy-induced cost actually lives.

**Access logs**, one JSON line per completed request, to stdout, stderr, or a file. Carries
timestamp, listener, client IP, method, host, path, query, status, bytes each way, total and
backend-wait duration, backend, pool, route ID, request ID, trace ID, and keep-alive index. Pre-route
rejects log `pool` and `route_id` as `-` following common-log-format convention, because an empty
string is visually ambiguous in Grafana. File sinks flush every second or 64 lines, whichever comes
first, so tailing a low-traffic deployment shows lines when they happen.

**Tracing.** Inbound `traceparent`, `tracestate`, and B3 headers pass through unchanged, so requests
stay visible end to end even though kntx does not emit its own spans yet. Nothing is synthesized
when absent. OTLP span emission is planned.

`kntx_config_last_reload_success` is the alert to wire up: 0 means a replica rejected a reload and
is serving stale config. `kntx_config_version` confirms a fleet has converged.

## Limits

Honest list of what kntx does not do.

- **HTTP/2 and HTTP/3.** HTTP/1.1 only. Binary framing, HPACK, flow control, and multiplexed streams
  are a large protocol surface; nginx and HAProxy each took years to ship stable implementations.
- **Backend TLS.** kntx speaks plain TCP upstream. Terminating at the edge and re-encrypting to the
  backend needs upstream cert validation, SNI selection, and rotation semantics of its own.
- **Body buffering, and therefore body transforms.** Bodies stream through untouched. This bounds
  memory by `max_body_size_bytes` instead of `concurrent_requests × max_body_size_bytes`, but it is
  also why mid-body retry is impossible and why there is no filter chain yet. The `BodyForwarder`
  trait boundary exists for a decoding implementation when a concrete use case arrives.
- **WebSocket frames.** Tunnels are byte-opaque. No per-frame metrics or frame-size enforcement.
- **`CONNECT`.** kntx is a reverse proxy, so 405 is the correct answer. Forward-proxy tunneling is
  out of scope.
- **HTTP pipelining.** Deprecated by browsers and replaced by HTTP/2 multiplexing. kntx reads the
  next request only after the previous response completes, which is current industry behavior.
- **No PROXY protocol, so the client IP is wrong behind an L4 load balancer.** kntx reads the client
  address from the socket. Put an AWS NLB (or any L4 balancer) in front and that address is the
  balancer's, which means `X-Forwarded-For`, `X-Real-IP`, access logs, and **per-IP rate limiting**
  all key on the balancer rather than the client. kntx deliberately refuses `X-Forwarded-For` as a
  rate-limit key because it is spoofable at the edge, so today there is no correct way to per-IP rate
  limit in that topology. Behind an L7 balancer that sets `X-Forwarded-For` the logging story is
  fine; the rate-limiting one still is not. PROXY protocol support is the fix and is planned.
- **No session affinity.** No consistent hashing or sticky sessions, so stateful backends, shard
  routing, and cache-locality workloads are not served. Round-robin, least-connections and weighted
  all assume any backend can take any request.
- **Linux is the target, not a supported-platform matrix.** kntx is built for Linux servers.
  `splice(2)` and the startup fd-limit preflight are both Linux-gated; other platforms compile and
  fall back to the vectored or userspace forwarding paths, but they are not tested or benchmarked
  and CI does not build them.
- **Reload commit is a sequence of atomic operations, not one global atomic.** There is a
  sub-microsecond window where new routes can pair with an about-to-update pool. Both backend sets
  are valid targets so there is no correctness bug, and pools reconcile before routers publish to
  minimize it. This is the same eventual consistency Envoy has mid-xDS-apply, and it is the price of
  not taking a lock on the hot path.

## Development

```bash
cargo test                                  # 551 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
kntx --config config.toml --validate        # check a config without binding anything
```

Tests cover unit-level protocol logic and integration paths end to end: real TLS handshakes with
`rcgen`-generated certs, per-byte truncation property tests on the ClientHello parser, byte-exact
fragmented-hello forwarding proven against a recording backend, exact-count concurrent rate-limit
stress, live `apply_reload` against a serving listener, and the full forwarding strategy matrix
including splice.

## Roadmap

Near term: PROXY protocol, which closes the client-IP gap above and is what makes running behind an
L4 load balancer correct rather than merely functional. Admin endpoints (`/healthz`, `/ready`,
`/config_dump`) so an orchestrator or a cloud target group can drain an instance properly. Then
consistent hashing for session affinity, and OpenTelemetry span emission with Prometheus exemplars.

Longer term, kntx is aiming at programmable proxy logic, the space Cloudflare Workers, Envoy
filters, and nginx+Lua occupy, but with the priority order inverted: performance first,
programmability layered on without compromising the L4 path. The `Matcher` and `Router` traits
already in the codebase are the plug-in surface. A routing expression DSL (`host == "api.example.com"
&& path.startsWith("/v1") && time.is_peak() → fast_pool`) compiles down to them; scripted filters
(Lua, Wasm) come after that model is validated.

kntx is the data plane, not a full edge platform. No KV store, no durable objects, no cron triggers,
no built-in dashboards.

## License

[MIT](LICENSE)
