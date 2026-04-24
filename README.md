<p align="center">
  <img src="docs/logo/kntx_no_bg.png" alt="kntx Logo" width="350">
</p>

<p align="center">
  <strong>L4/L7 reverse proxy in Rust. Raw bytes first, HTTP when you need it.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust"></a>
  <img src="https://img.shields.io/badge/platform-linux-lightgrey.svg" alt="Platform">
</p>

---

Most proxies start at HTTP and treat TCP as a boring pipe. kntx starts at the pipe and makes it fast. The L4 fast path moves raw bytes using zero-copy techniques (splice, io_uring), and L7 HTTP-aware routing is an opt-in layer on top for when you need it.

## How It Works

kntx runs as an async, multi-threaded TCP server on Tokio. When a connection arrives, kntx picks a backend using the configured load balancing strategy and forwards traffic in one of two modes:

- **L4 mode** forwards raw bytes between client and backend without inspecting them. This is the fast path. Zero-copy forwarding via splice(2), vectored I/O, or io_uring keeps data in kernel space and out of the proxy's memory.

- **L7 mode** parses HTTP/1.1 requests and routes based on Host headers, URL paths, or other rules. Headers can be injected or stripped, and backend connections are pooled for reuse.

TLS termination sits between the listener and the mode decision. After decryption, kntx decides whether to forward raw bytes or parse HTTP based on the listener configuration.

```
Client
  |
  v
TCP Listener (Tokio)
  |
  +-- L4 Mode: raw byte forwarding (zero-copy when possible)
  |     |
  |     v
  |   Backend Servers
  |
  +-- L7 Mode: HTTP parsing + smart routing
        |
        v
      Route Resolution (host/path/header rules)
        |
        v
      Backend Servers
```

## Features

- **L4 TCP proxy** with zero-copy forwarding (splice, io_uring exploration, vectored I/O)
- **L7 HTTP/1.1 proxy** with host-based and path-based routing
- **TLS termination** with SNI-based routing and multi-cert support (rustls)
- **Fault tolerance** with circuit breakers, health checks, retries with backoff
- **Rate limiting** with lock-free token bucket (per-IP and global)
- **Dynamic configuration** with hot reload via SIGHUP
- **Observability** with Prometheus metrics and structured logging from day one

## Getting Started

### Prerequisites

- Rust (stable)
- Linux (splice/io_uring are Linux-specific)

### Build and run

```bash
cargo build --release
cp config/example.toml config.toml
./target/release/kntx --config config.toml
```

### Configuration

```toml
[logging]
level = "info"

[metrics]
address = "0.0.0.0:9090"

[[listeners]]
address = "0.0.0.0:8080"
pool = "web"

[[pools]]
name = "web"
backends = [
  { address = "127.0.0.1:3001" },
  { address = "127.0.0.1:3002" },
]
```

See `config/example.toml` for TLS listeners, per-pool health overrides, and multi-certificate SNI.

## Design Priorities

1. **L4 raw TCP proxying + zero-copy optimization.** The foundation.
2. **Fault tolerance** (circuit breakers, retries, failover). Production-aware resilience.
3. **TLS termination + certificate management.** The bridge between L4 and L7.
4. **L7 HTTP-aware routing + header manipulation.** Necessary, but not the star.

## Benchmarks

*Coming after initial implementation.*

Every benchmark report includes hardware specs, load test configuration, exact commands used, and comparison against nginx in equivalent mode. If kntx is slower, the report explains where and why.

## Project Structure

```
kntx/
├── src/
|   ├── main.rs
|   ├── config/          # TOML parsing, config types
|   ├── listener/        # TCP listener, connection acceptance
|   ├── proxy/
|   |   ├── l4/         # L4 byte forwarding (userspace, splice, io_uring)
|   |   └── l7/         # HTTP parsing, routing, headers, connection pooling
|   ├── tls/             # TLS termination, SNI routing
|   ├── balancer/        # Load balancing strategies
|   ├── health/          # Health checks (active + passive)
|   ├── resilience/      # Circuit breaker, retry, timeout
|   ├── rate_limit/      # Token bucket rate limiting
|   └── metrics/         # Prometheus exposition
├── config/
|   └── example.toml
├── docs/
└── tests/
```

## Limitations

These are deliberately out of scope:

- **HTTP/2 and HTTP/3.** Possible future extensions after HTTP/1.1 is solid.
- **Kernel bypass (DPDK, AF_XDP).** Different I/O model, not the goal of this project.
- **Full HTTP spec compliance.** Common cases covered, diminishing returns beyond that.
- **Production replacement** for nginx/haproxy/envoy. Understanding the gap is the goal.

## License

[MIT](LICENSE)
