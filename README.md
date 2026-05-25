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
  <img src="https://img.shields.io/badge/status-under%20construction-yellow.svg" alt="Status">
</p>

---

> **Under construction.** Pre-release. APIs, config schema, and metrics may change without notice.

L4-first architecture: the fast path forwards raw bytes via splice(2). L7 HTTP-aware routing is an opt-in layer on top. TLS termination sits between the listener and the mode decision.

```
Client
  |
  v
TCP Listener (Tokio)
  |
  +-- L4 Mode: zero-copy byte forwarding (splice / vectored I/O)
  |     |
  |     v
  |   Backend Servers
  |
  +-- L7 Mode: HTTP parsing + routing (host / path / method / SNI)
        |
        v
      Backend Servers
```

## Status

Implemented:

- L4 forwarding (splice, vectored I/O, userspace fallback with pooled buffers)
- TLS termination (rustls, multi-cert SNI)
- Multi-listener + named backend pools
- Circuit breakers, active + passive health checks, connect retries
- L7 HTTP/1.1 parse, route (host / path / method / SNI), header injection, structured JSON access logs
- Prometheus metrics

In progress: client + backend keep-alive, WebSocket tunneling, benchmark harness.

Planned: rate limiting, hot config reload, programmable routing DSL.

## Build

```bash
cargo build --release
cp config/example.toml config.toml
./target/release/kntx --config config.toml
```

See `config/example.toml` for the full config surface (listeners, pools, TLS, routes, health overrides).

## License

[MIT](LICENSE)
