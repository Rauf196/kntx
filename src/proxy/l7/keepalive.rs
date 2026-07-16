use std::io::ErrorKind;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crossbeam_queue::ArrayQueue;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use crate::config::KeepaliveConfig;
use crate::health::{BackendPool, BackendState};
use crate::util::CacheLinePadded;

#[derive(Debug)]
pub enum CheckoutError {
    /// Semaphore closed mid-acquire (defensive — never closed in practice).
    Saturated,
    ConnectFailed(std::io::Error),
    ConnectTimeout,
}

#[derive(Debug, PartialEq)]
enum ProbeResult {
    Healthy,
    Dead,
}

// non-blocking peek to detect whether an idle conn is still alive.
// WouldBlock → healthy (no data, no EOF). Anything else → dead.
fn probe(stream: &TcpStream) -> ProbeResult {
    let mut buf = [0u8; 1];
    match stream.try_read(&mut buf) {
        Ok(0) => ProbeResult::Dead, // EOF — backend FIN
        Ok(_) => ProbeResult::Dead, // unexpected data — broken pipeline
        Err(e) if e.kind() == ErrorKind::WouldBlock => ProbeResult::Healthy,
        Err(_) => ProbeResult::Dead,
    }
}

#[derive(Debug)]
struct IdleConn {
    stream: TcpStream,
    last_used: Instant,
}

/// per-backend cache of idle TCP connections.
pub struct KeepaliveCache {
    queue: Option<ArrayQueue<IdleConn>>,
    pub idle_conn_ttl: Duration,
    pub(crate) max_total: Option<NonZeroUsize>,
    // when `max_total` is set, this semaphore caps the number of *active*
    // (in-flight) conns to a single backend. Idle conns sitting in the cache
    // do NOT hold permits — they are existing TCP sockets, not in-flight work.
    // Every checkout (cache hit OR fresh connect) acquires a permit and holds
    // it until the conn is returned or discarded. nginx's `keepalive`
    // directive applies the same semantic.
    permits: Option<Arc<Semaphore>>,
}

impl KeepaliveCache {
    pub fn new(cfg: KeepaliveConfig) -> Self {
        let queue = if cfg.max_idle > 0 {
            Some(ArrayQueue::new(cfg.max_idle))
        } else {
            None
        };
        let max_total = if cfg.max_total > 0 {
            NonZeroUsize::new(cfg.max_total as usize)
        } else {
            None
        };
        let permits = max_total.map(|n| Arc::new(Semaphore::new(n.get())));
        Self {
            queue,
            idle_conn_ttl: Duration::from_secs(cfg.idle_conn_ttl_secs),
            max_total,
            permits,
        }
    }

    /// drain all idle conns from the cache, dropping each and decrementing total_count.
    /// called on the backend's Closed→Open circuit transition so that subsequent
    /// requests do not pop cached conns to a backend that has just been marked unhealthy.
    pub(crate) fn flush_all(
        &self,
        total_count: &CacheLinePadded<AtomicU64>,
        pool: &str,
        backend: SocketAddr,
    ) {
        if let Some(q) = &self.queue {
            while q.pop().is_some() {
                total_count.0.fetch_sub(1, Ordering::Release);
                metrics::gauge!(
                    "kntx_backend_pool_size",
                    "pool" => pool.to_string(),
                    "backend" => backend.to_string(),
                )
                .decrement(1.0);
            }
        }
    }

    /// pop and drop stale entries up to the queue capacity bound.
    /// returns the number of conns dropped so the caller can decrement total_count.
    pub(crate) fn sweep_stale(&self, ttl: Duration) -> usize {
        let Some(q) = &self.queue else { return 0 };

        // iterate at most cap times to bound work per sweep tick
        let cap = q.capacity();
        let mut dropped = 0;
        let mut kept = Vec::new();

        for _ in 0..cap {
            let Some(idle) = q.pop() else { break };
            if idle.last_used.elapsed() > ttl {
                // dropping `idle` also releases its permit (if any) back to
                // the cache semaphore — capacity is recovered automatically.
                drop(idle);
                dropped += 1;
            } else {
                kept.push(idle);
            }
        }
        // put healthy ones back
        for idle in kept {
            // if push fails the queue is full (unlikely since we just drained it)
            // just drop the conn in that case
            if q.push(idle).is_err() {
                dropped += 1;
            }
        }
        dropped
    }

    fn push(&self, idle: IdleConn) -> Result<(), IdleConn> {
        match &self.queue {
            Some(q) => q.push(idle),
            None => Err(idle),
        }
    }

    /// true when this cache holds an idle queue (max_idle > 0).
    /// used by the sweeper to skip pools with keepalive disabled.
    pub fn is_enabled(&self) -> bool {
        self.queue.is_some()
    }

    /// push an idle conn with a custom timestamp. test-only helper used by health/mod.rs tests.
    #[cfg(test)]
    pub fn push_test_idle(&self, stream: TcpStream, last_used: Instant) {
        let idle = IdleConn { stream, last_used };
        let _ = self.push(idle);
    }

    #[cfg(test)]
    pub fn queue_len(&self) -> usize {
        self.queue.as_ref().map(|q| q.len()).unwrap_or(0)
    }
}

/// a backend conn checked out for one request cycle.
///
/// explicit paths: `return_to_cache` or `discard`.
/// drop without explicit handling decrements total_count but does not push to cache.
pub struct KeepaliveConn {
    stream: Option<TcpStream>,
    state: Arc<BackendState>,
    pub reused: bool,
    // Request-body bytes successfully flushed to the backend socket.
    // `AtomicU64` because the body-forwarding loop reads this counter
    // while the TcpStream half is mutably borrowed via the stream split.
    // The fields are disjoint, but the borrow checker still rejects
    // mixed-mode access through accessor methods. Interior mutability is
    // the cleanest way to keep the counter's granule semantics intact
    // without restructuring the body-forwarding loop.
    body_bytes_sent: AtomicU64,
    // Permit from the cache's max_total semaphore (Some iff the cache caps
    // total conns). Held for the lifetime of this active checkout, then
    // either transferred into the queue on `return_to_cache` or dropped to
    // release capacity on `discard` / Drop.
    permit: Option<OwnedSemaphorePermit>,
}

impl KeepaliveConn {
    fn fresh(
        stream: TcpStream,
        state: Arc<BackendState>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            stream: Some(stream),
            state,
            reused: false,
            body_bytes_sent: AtomicU64::new(0),
            permit,
        }
    }

    fn reused(
        stream: TcpStream,
        state: Arc<BackendState>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            stream: Some(stream),
            state,
            reused: true,
            body_bytes_sent: AtomicU64::new(0),
            permit,
        }
    }

    /// borrow the underlying stream for I/O.
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        self.stream.as_mut().expect("stream already consumed")
    }

    /// Split borrow used by the body-forwarding loop: yields a
    /// `&mut TcpStream` (for the split into read/write halves) and a
    /// `&AtomicU64` reference to the body counter, so the per-chunk
    /// increment can fire while the stream halves are still alive. The
    /// borrow checker accepts this via direct field access on disjoint
    /// fields.
    pub fn stream_and_body_counter_mut(&mut self) -> (&mut TcpStream, &AtomicU64) {
        let stream = self.stream.as_mut().expect("stream already consumed");
        (stream, &self.body_bytes_sent)
    }

    /// Snapshot of request-body bytes fully flushed to the backend's
    /// kernel send buffer. Drives broken-keepalive retry eligibility:
    /// only zero qualifies, since the proxy cannot replay body bytes it
    /// has already consumed from the client. Updated at the outer
    /// iteration boundary per `write_all(chunk)` success, never
    /// per-syscall.
    pub fn body_bytes_sent(&self) -> u64 {
        self.body_bytes_sent.load(Ordering::Relaxed)
    }

    /// take the stream out and decrement total_count atomically.
    /// equivalent to `discard()` but yields the stream first so the caller
    /// can use it (e.g. for WebSocket tunneling). after this call, conn's
    /// Drop sees stream=None and does NOT decrement again.
    pub fn take_stream_and_release(mut self) -> TcpStream {
        let stream = self.stream.take().expect("stream already consumed");
        self.state.total_count.0.fetch_sub(1, Ordering::Release);
        stream
        // self drops: stream=None → Drop skip; Arc<BackendState> drops normally
    }

    /// backend address this conn is connected to.
    pub fn backend_address(&self) -> SocketAddr {
        self.state.address()
    }
}

impl Drop for KeepaliveConn {
    fn drop(&mut self) {
        if self.stream.is_some() {
            // fell through without explicit handling — decrement the counter.
            // stream's own Drop closes the fd.
            self.state.total_count.0.fetch_sub(1, Ordering::Release);
        }
        // Arc<BackendState> drops normally — refcount correct in every path.
    }
}

impl KeepaliveCache {
    /// check out a conn for one request cycle.
    ///
    /// Phase 1: drain cache (probe for liveness, skip stale). If healthy idle found, return it.
    /// Phase 2: fresh-connect with optimistic increment + saturation gate.
    /// saturation is checked ONLY on the fresh-connect path — never before cache pop.
    pub async fn checkout(
        state: &Arc<BackendState>,
        addr: std::net::SocketAddr,
        connect_timeout: Duration,
    ) -> Result<KeepaliveConn, CheckoutError> {
        // Permit gate — acquire ONE active slot before either popping from
        // cache or opening a fresh conn. nginx-style queueing: idle conns
        // sitting in cache do not consume a permit; only active in-flight
        // requests do. acquire_owned awaits if max_total is reached; the
        // outer request_timeout bounds the wait.
        let permit = if let Some(sem) = state.keepalive.permits.clone() {
            match sem.acquire_owned().await {
                Ok(p) => Some(p),
                Err(_) => return Err(CheckoutError::Saturated),
            }
        } else {
            None
        };

        // Phase 1 — cache drain. Probe + stale check; healthy hit transfers
        // the existing conn out of the queue. The permit acquired above
        // covers the active-state slot for the lifetime of this checkout.
        if let Some(q) = &state.keepalive.queue {
            loop {
                let Some(idle) = q.pop() else { break };

                if idle.last_used.elapsed() > state.keepalive.idle_conn_ttl {
                    drop(idle);
                    state.total_count.0.fetch_sub(1, Ordering::Release);
                    metrics::gauge!(
                        "kntx_backend_pool_size",
                        "pool" => state.pool_name().to_string(),
                        "backend" => addr.to_string(),
                    )
                    .decrement(1.0);
                    continue;
                }

                match probe(&idle.stream) {
                    ProbeResult::Healthy => {
                        metrics::counter!(
                            "kntx_backend_pool_checkouts_total",
                            "pool" => state.pool_name().to_string(),
                            "outcome" => "hit",
                            "backend" => addr.to_string(),
                        )
                        .increment(1);
                        metrics::gauge!(
                            "kntx_backend_pool_size",
                            "pool" => state.pool_name().to_string(),
                            "backend" => addr.to_string(),
                        )
                        .decrement(1.0);
                        return Ok(KeepaliveConn::reused(
                            idle.stream,
                            Arc::clone(state),
                            permit,
                        ));
                    }
                    ProbeResult::Dead => {
                        drop(idle);
                        state.total_count.0.fetch_sub(1, Ordering::Release);
                        metrics::counter!(
                            "kntx_backend_pool_checkouts_total",
                            "pool" => state.pool_name().to_string(),
                            "outcome" => "stale",
                            "backend" => addr.to_string(),
                        )
                        .increment(1);
                        metrics::gauge!(
                            "kntx_backend_pool_size",
                            "pool" => state.pool_name().to_string(),
                            "backend" => addr.to_string(),
                        )
                        .decrement(1.0);
                    }
                }
            }
        }

        // Phase 2 — cache empty (or all entries stale/dead). Connect fresh
        // under the permit we already hold.
        state.total_count.0.fetch_add(1, Ordering::AcqRel);

        match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                metrics::counter!(
                    "kntx_backend_pool_checkouts_total",
                    "pool" => state.pool_name().to_string(),
                    "outcome" => "miss",
                    "backend" => addr.to_string(),
                )
                .increment(1);
                Ok(KeepaliveConn::fresh(stream, Arc::clone(state), permit))
            }
            Ok(Err(e)) => {
                state.total_count.0.fetch_sub(1, Ordering::Release);
                Err(CheckoutError::ConnectFailed(e))
            }
            Err(_elapsed) => {
                state.total_count.0.fetch_sub(1, Ordering::Release);
                Err(CheckoutError::ConnectTimeout)
            }
        }
    }

    /// return conn to cache after a successful response cycle.
    /// if pool disabled (max_idle=0) or queue is full, drops the conn and decrements counter.
    pub fn return_to_cache(mut conn: KeepaliveConn) {
        let addr = conn.state.address().to_string();
        let pool = conn.state.pool_name().to_string();
        if let Some(stream) = conn.stream.take() {
            // The active-state slot is released the moment the request is
            // done; the next waiting checkout can wake up and run, even if
            // this stream stays cached for reuse. Idle conns don't occupy
            // active-permit slots.
            drop(conn.permit.take());

            let idle = IdleConn {
                stream,
                last_used: Instant::now(),
            };
            match conn.state.keepalive.push(idle) {
                Ok(()) => {
                    metrics::counter!(
                        "kntx_backend_pool_returns_total",
                        "pool" => pool.clone(),
                        "outcome" => "ok",
                        "backend" => addr.clone(),
                    )
                    .increment(1);
                    metrics::gauge!(
                        "kntx_backend_pool_size",
                        "pool" => pool,
                        "backend" => addr,
                    )
                    .increment(1.0);
                }
                Err(rejected) => {
                    drop(rejected);
                    conn.state.total_count.0.fetch_sub(1, Ordering::Release);
                    metrics::counter!(
                        "kntx_backend_pool_returns_total",
                        "pool" => pool,
                        "outcome" => "full",
                        "backend" => addr,
                    )
                    .increment(1);
                }
            }
        }
        // stream = None → Drop sees None → no double-decrement
    }

    /// explicitly drop a conn without returning it to cache.
    /// always decrements total_count. used on Connection: close, body-poisoned conns, tunnels.
    pub fn discard(mut conn: KeepaliveConn) {
        if let Some(stream) = conn.stream.take() {
            drop(stream);
            drop(conn.permit.take());
            conn.state.total_count.0.fetch_sub(1, Ordering::Release);
        }
        // stream = None → Drop sees None → no double-decrement
    }
}

/// compute the sweeper tick interval: max(idle_conn_ttl / 4, 5s).
pub fn sweeper_interval(idle_conn_ttl: Duration) -> Duration {
    idle_conn_ttl.div_f32(4.0).max(Duration::from_secs(5))
}

/// background task that periodically drops stale idle conns from a pool's keepalive caches.
///
/// one sweeper per `BackendPool`. spawned in `main::run` alongside the per-pool
/// `HealthChecker`. exits cleanly on shutdown signal.
pub struct KeepaliveSweeper {
    pool: Arc<BackendPool>,
    interval: Duration,
}

impl KeepaliveSweeper {
    /// returns `None` when keepalive is disabled for this pool (max_idle = 0) —
    /// no caches to sweep, nothing worth spawning a task for.
    pub fn new(pool: Arc<BackendPool>) -> Option<Self> {
        let cfg = pool.keepalive_cfg();
        if cfg.max_idle == 0 {
            return None;
        }
        let interval = sweeper_interval(Duration::from_secs(cfg.idle_conn_ttl_secs));
        Some(Self { pool, interval })
    }

    /// spawn the sweeper as a background task. returns the JoinHandle for lifecycle management.
    pub fn spawn(self, mut shutdown: watch::Receiver<()>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let pool_name = self.pool.name().to_string();
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // first tick fires immediately; skip — nothing to sweep at startup
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        for backend in self.pool.iter() {
                            backend.sweep_stale_keepalive();
                        }
                    }
                    _ = shutdown.changed() => {
                        tracing::info!(pool = %pool_name, "keepalive sweeper exiting");
                        return;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;

    use crate::config::KeepaliveConfig;

    fn default_cfg() -> KeepaliveConfig {
        KeepaliveConfig {
            max_idle: 4,
            idle_conn_ttl_secs: 60,
            max_total: 0,
        }
    }

    fn make_state(cfg: KeepaliveConfig) -> Arc<BackendState> {
        let addr: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        Arc::new(BackendState::new(addr, "test".into(), cfg))
    }

    #[test]
    fn probe_healthy_on_would_block() {
        // real TcpStream with nothing to read → WouldBlock
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let stream = TcpStream::connect(addr).await.unwrap();
            // nothing written — should be WouldBlock
            assert_eq!(probe(&stream), ProbeResult::Healthy);
        });
    }

    #[test]
    fn probe_dead_on_closed_peer() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).await.unwrap();
            // accept and immediately drop → peer FIN
            let (server, _) = listener.accept().await.unwrap();
            drop(server);
            // give the FIN a moment to arrive
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert_eq!(probe(&client), ProbeResult::Dead);
        });
    }

    #[test]
    fn probe_dead_on_data_present() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            // server writes one byte — unexpected data is treated as Dead
            server.writable().await.unwrap();
            server.try_write(b"x").unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert_eq!(probe(&client), ProbeResult::Dead);
        });
    }

    #[test]
    fn checkout_cache_first_at_saturation_boundary() {
        // Cache-first ordering canary: one-backend pool with max_total = max_idle = 1.
        // push 1 idle to cache, set total_count = 1 (as if it was counted on push).
        // checkout should return the cached idle (reused=true) WITHOUT consulting saturation,
        // leaving total_count unchanged at 1.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let cfg = KeepaliveConfig {
                max_idle: 1,
                idle_conn_ttl_secs: 60,
                max_total: 1,
            };
            let state = make_state(cfg);

            // build an idle conn and push to cache
            let stream = TcpStream::connect(addr).await.unwrap();
            let _server_side = listener.accept().await.unwrap();
            let idle = IdleConn {
                stream,
                last_used: Instant::now(),
            };
            state.keepalive.push(idle).unwrap();
            // manually set total_count = 1 (as if conn was counted when put in cache)
            state.total_count.0.store(1, Ordering::SeqCst);

            // checkout must reuse the cached conn, not consult saturation
            let conn = KeepaliveCache::checkout(&state, addr, Duration::from_secs(1))
                .await
                .unwrap();

            assert!(conn.reused, "must be reused from cache");
            // total_count unchanged: was 1, cache-pop does not decrement it
            assert_eq!(
                state.total_count.0.load(Ordering::SeqCst),
                1,
                "total_count must not change on cache-hit checkout"
            );

            // clean up: discard the conn
            KeepaliveCache::discard(conn);
            assert_eq!(state.total_count.0.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn checkout_waits_when_permits_exhausted() {
        // With the semaphore-based permit model the old immediate-Saturated
        // path is gone: when max_total is reached and no idle conn is
        // available, checkout `.await`s on the permit until one is released
        // (nginx-style queueing). A bounded wrap with `tokio::time::timeout`
        // is how we verify the wait without hanging the test forever.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cfg = KeepaliveConfig {
                max_idle: 2,
                idle_conn_ttl_secs: 60,
                max_total: 1,
            };
            let state = make_state(cfg);

            // hold the only permit so checkout has nothing to take.
            let sem = state.keepalive.permits.clone().expect("permits enabled");
            let _held = sem.try_acquire_owned().expect("first permit acquires");

            let addr: SocketAddr = "127.0.0.1:19998".parse().unwrap();
            let started = Instant::now();
            let timed = tokio::time::timeout(
                Duration::from_millis(200),
                KeepaliveCache::checkout(&state, addr, Duration::from_millis(50)),
            )
            .await;

            // checkout never resolved within 200ms — it is waiting on the
            // permit semaphore, not returning Saturated.
            assert!(timed.is_err(), "checkout returned instead of waiting");
            assert!(
                started.elapsed() >= Duration::from_millis(190),
                "elapsed = {:?}",
                started.elapsed()
            );
        });
    }

    #[test]
    fn checkout_stale_pop_drops_and_tries_fresh() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let cfg = KeepaliveConfig {
                max_idle: 2,
                idle_conn_ttl_secs: 1, // 1s TTL
                max_total: 0,
            };
            let state = make_state(cfg);

            // push a conn that is already stale (last_used in the past)
            let stream = TcpStream::connect(addr).await.unwrap();
            let _s = listener.accept().await.unwrap();
            let idle = IdleConn {
                stream,
                last_used: Instant::now() - Duration::from_secs(10), // definitely stale
            };
            state.keepalive.push(idle).unwrap();
            state.total_count.0.store(1, Ordering::SeqCst); // counted when pushed

            // accept the upcoming fresh connect
            let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });

            let conn = KeepaliveCache::checkout(&state, addr, Duration::from_secs(1))
                .await
                .unwrap();

            // stale was dropped (total went 1→0), then fresh connected (0→1)
            assert!(!conn.reused, "must be a fresh conn, not the stale one");
            assert_eq!(state.total_count.0.load(Ordering::SeqCst), 1);

            accept_task.await.unwrap();
            KeepaliveCache::discard(conn);
            assert_eq!(state.total_count.0.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn return_to_cache_keeps_counter_unchanged() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let state = make_state(default_cfg());

            let stream = TcpStream::connect(addr).await.unwrap();
            let _s = listener.accept().await.unwrap();

            state.total_count.0.store(1, Ordering::SeqCst);
            let conn = KeepaliveConn::fresh(stream, Arc::clone(&state), None);
            KeepaliveCache::return_to_cache(conn);

            // counter unchanged — conn is now idle in queue
            assert_eq!(state.total_count.0.load(Ordering::SeqCst), 1);
            // queue has one idle
            assert_eq!(state.keepalive.queue.as_ref().unwrap().len(), 1);
        });
    }

    #[test]
    fn return_to_cache_full_queue_drops_and_decrements() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let cfg = KeepaliveConfig {
                max_idle: 1, // tiny queue
                idle_conn_ttl_secs: 60,
                max_total: 0,
            };
            let state = make_state(cfg);

            // fill the queue
            let s1 = TcpStream::connect(addr).await.unwrap();
            let _ss1 = listener.accept().await.unwrap();
            let idle = IdleConn {
                stream: s1,
                last_used: Instant::now(),
            };
            state.keepalive.push(idle).unwrap();
            state.total_count.0.store(2, Ordering::SeqCst); // 1 idle + 1 active

            // try to return the active conn — queue full, must drop + decrement
            let s2 = TcpStream::connect(addr).await.unwrap();
            let _ss2 = listener.accept().await.unwrap();
            let conn = KeepaliveConn::fresh(s2, Arc::clone(&state), None);
            KeepaliveCache::return_to_cache(conn);

            assert_eq!(state.total_count.0.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn discard_decrements_counter_once() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = make_state(default_cfg());
            let stream = TcpStream::connect(addr).await.unwrap();
            let _s = listener.accept().await.unwrap();
            state.total_count.0.store(1, Ordering::SeqCst);
            let conn = KeepaliveConn::fresh(stream, Arc::clone(&state), None);
            KeepaliveCache::discard(conn);
            assert_eq!(state.total_count.0.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn drop_with_stream_some_decrements_counter() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = make_state(default_cfg());
            let stream = TcpStream::connect(addr).await.unwrap();
            let _s = listener.accept().await.unwrap();
            state.total_count.0.store(1, Ordering::SeqCst);
            {
                let _conn = KeepaliveConn::fresh(stream, Arc::clone(&state), None);
                // conn drops here without explicit return/discard
            }
            assert_eq!(
                state.total_count.0.load(Ordering::SeqCst),
                0,
                "Drop must decrement when stream is Some"
            );
        });
    }

    #[test]
    fn drop_after_discard_no_double_decrement() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = make_state(default_cfg());
            let stream = TcpStream::connect(addr).await.unwrap();
            let _s = listener.accept().await.unwrap();
            state.total_count.0.store(1, Ordering::SeqCst);
            let conn = KeepaliveConn::fresh(stream, Arc::clone(&state), None);
            KeepaliveCache::discard(conn); // sets stream = None
            assert_eq!(state.total_count.0.load(Ordering::SeqCst), 0);
            // Arc strong count: conn dropped inside discard, state has count=1 (the one above)
            assert_eq!(Arc::strong_count(&state), 1);
        });
    }

    #[test]
    fn drop_after_return_no_double_decrement() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = make_state(default_cfg());
            let stream = TcpStream::connect(addr).await.unwrap();
            let _s = listener.accept().await.unwrap();
            state.total_count.0.store(1, Ordering::SeqCst);
            let conn = KeepaliveConn::fresh(stream, Arc::clone(&state), None);
            KeepaliveCache::return_to_cache(conn); // sets stream = None
            assert_eq!(state.total_count.0.load(Ordering::SeqCst), 1); // still 1 (now idle)
        });
    }

    #[test]
    fn flush_all_empties_queue_and_decrements() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let cfg = KeepaliveConfig {
                max_idle: 5,
                idle_conn_ttl_secs: 60,
                max_total: 0,
            };
            let state = make_state(cfg);

            // push 3 idles
            for _ in 0..3 {
                let stream = TcpStream::connect(addr).await.unwrap();
                let _s = listener.accept().await.unwrap();
                let idle = IdleConn {
                    stream,
                    last_used: Instant::now(),
                };
                state.keepalive.push(idle).unwrap();
            }
            state.total_count.0.store(3, Ordering::SeqCst);

            state
                .keepalive
                .flush_all(&state.total_count, "test", state.address());

            assert_eq!(state.total_count.0.load(Ordering::SeqCst), 0);
            assert_eq!(state.keepalive.queue.as_ref().unwrap().len(), 0);
        });
    }

    #[test]
    fn sweep_drops_stale_keeps_fresh() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let cfg = KeepaliveConfig {
                max_idle: 4,
                idle_conn_ttl_secs: 60,
                max_total: 0,
            };
            let state = make_state(cfg);

            // push 2 stale + 2 fresh
            for _ in 0..2 {
                let stream = TcpStream::connect(addr).await.unwrap();
                let _s = listener.accept().await.unwrap();
                let idle = IdleConn {
                    stream,
                    last_used: Instant::now() - Duration::from_secs(120),
                };
                state.keepalive.push(idle).unwrap();
            }
            for _ in 0..2 {
                let stream = TcpStream::connect(addr).await.unwrap();
                let _s = listener.accept().await.unwrap();
                let idle = IdleConn {
                    stream,
                    last_used: Instant::now(),
                };
                state.keepalive.push(idle).unwrap();
            }
            state.total_count.0.store(4, Ordering::SeqCst);

            let ttl = Duration::from_secs(60);
            let dropped = state.keepalive.sweep_stale(ttl);
            state
                .total_count
                .0
                .fetch_sub(dropped as u64, Ordering::Release);

            assert_eq!(dropped, 2, "two stale conns must be dropped");
            assert_eq!(
                state.total_count.0.load(Ordering::SeqCst),
                2,
                "total_count must reflect remaining idles"
            );
            assert_eq!(state.keepalive.queue.as_ref().unwrap().len(), 2);
        });
    }

    #[test]
    fn sweeper_interval_clamps_to_5s_when_ttl_short() {
        // idle_conn_ttl = 8s → ttl/4 = 2s → clamped to 5s
        let iv = sweeper_interval(Duration::from_secs(8));
        assert_eq!(iv, Duration::from_secs(5));
    }

    #[test]
    fn sweeper_interval_returns_quarter_when_ttl_long() {
        // idle_conn_ttl = 60s → ttl/4 = 15s → not clamped
        let iv = sweeper_interval(Duration::from_secs(60));
        assert_eq!(iv, Duration::from_secs(15));
    }

    fn make_pool(cfg: KeepaliveConfig) -> Arc<BackendPool> {
        let addr: SocketAddr = "127.0.0.1:19997".parse().unwrap();
        Arc::new(BackendPool::new(
            "sweep_test".into(),
            vec![addr],
            3,
            Duration::from_secs(10),
            cfg,
        ))
    }

    #[test]
    fn sweeper_new_disabled_pool_returns_none() {
        let cfg = KeepaliveConfig {
            max_idle: 0, // disabled
            idle_conn_ttl_secs: 60,
            max_total: 0,
        };
        let pool = make_pool(cfg);
        assert!(
            KeepaliveSweeper::new(pool).is_none(),
            "sweeper must not spawn when keepalive is disabled"
        );
    }

    #[test]
    fn sweeper_new_enabled_pool_uses_clamped_interval() {
        let cfg = KeepaliveConfig {
            max_idle: 32,
            idle_conn_ttl_secs: 60, // → ttl/4 = 15s
            max_total: 0,
        };
        let pool = make_pool(cfg);
        let sweeper = KeepaliveSweeper::new(pool).expect("must spawn");
        assert_eq!(sweeper.interval, Duration::from_secs(15));
    }

    #[test]
    fn sweeper_exits_on_shutdown_signal() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cfg = KeepaliveConfig {
                max_idle: 4,
                idle_conn_ttl_secs: 60,
                max_total: 0,
            };
            let pool = make_pool(cfg);
            let sweeper = KeepaliveSweeper::new(pool).expect("must spawn");

            let (tx, rx) = tokio::sync::watch::channel(());
            let handle = sweeper.spawn(rx);

            // immediately signal shutdown; task should exit promptly
            tx.send(()).unwrap();

            // bound the wait so a stuck sweeper fails the test instead of hanging CI
            let res = tokio::time::timeout(Duration::from_secs(2), handle).await;
            assert!(res.is_ok(), "sweeper did not exit within 2s of shutdown");
            res.unwrap().expect("sweeper task panicked");
        });
    }
}
