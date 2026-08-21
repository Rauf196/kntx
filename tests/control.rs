//! The two control sockets: `/metrics`, `/healthz` and `/ready` on the metrics
//! socket, `/server_info` and the token gate on the admin socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use kntx::config::Config;
use kntx::control::{AdminHandle, Surface};

const CONFIG: &str = "\
[[listeners]]
address = \"127.0.0.1:19998\"
mode = \"l4\"
pool = \"web\"

[[pools]]
name = \"web\"
backends = [{ address = \"127.0.0.1:9\" }]

[health]
failure_threshold = 1
";

async fn request(addr: SocketAddr, method: &str, path: &str) -> String {
    send(addr, method, path, "").await
}

async fn request_with_token(addr: SocketAddr, path: &str, token: &str) -> String {
    send(addr, "GET", path, &format!("x-kntx-token: {token}\r\n")).await
}

async fn send(addr: SocketAddr, method: &str, path: &str, extra: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(format!("{method} {path} HTTP/1.1\r\nhost: probe\r\n{extra}\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

fn body_of(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or("")
}

async fn spawn_admin(
    config: &Config,
    token: Option<&str>,
) -> (
    SocketAddr,
    Arc<ArcSwap<kntx::runtime::Snapshot>>,
    AdminHandle,
) {
    let state = Arc::new(ArcSwap::from_pointee(kntx::runtime::build_snapshot(config)));
    let listener = kntx::control::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = AdminHandle::new(addr, token);
    kntx::control::spawn(
        listener,
        Surface::Admin {
            handle: handle.clone(),
            state: Arc::clone(&state),
            started: Instant::now(),
        },
    );
    (addr, state, handle)
}

#[tokio::test]
async fn metrics_routes_and_readiness() {
    let config = Config::from_toml(CONFIG, "<test>").unwrap();
    let state = Arc::new(ArcSwap::from_pointee(kntx::runtime::build_snapshot(
        &config,
    )));
    let handle = kntx::metrics::install().unwrap();

    let (pool, _) = &state.load().pools["web"];
    let pool = Arc::clone(pool);
    pool.emit_initial_metrics();

    let listener = kntx::control::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    kntx::control::spawn(
        listener,
        Surface::Metrics {
            handle,
            state: Arc::clone(&state),
        },
    );

    let healthz = request(addr, "GET", "/healthz").await;
    assert!(healthz.starts_with("HTTP/1.1 200 OK"), "{healthz}");

    let ready = request(addr, "GET", "/ready").await;
    assert!(ready.starts_with("HTTP/1.1 200 OK"), "{ready}");

    let metrics = request(addr, "GET", "/metrics").await;
    assert!(metrics.starts_with("HTTP/1.1 200 OK"), "{metrics}");
    assert!(
        metrics.contains("kntx_backend_health"),
        "scrape payload missing seeded metric: {metrics}"
    );

    let missing = request(addr, "GET", "/nope").await;
    assert!(missing.starts_with("HTTP/1.1 404 Not Found"), "{missing}");

    let posted = request(addr, "POST", "/healthz").await;
    assert!(
        posted.starts_with("HTTP/1.1 405 Method Not Allowed"),
        "{posted}"
    );

    // failure_threshold = 1, so one recorded failure opens the pool's only circuit
    pool.record_failure("127.0.0.1:9".parse().unwrap());

    let ready = request(addr, "GET", "/ready").await;
    assert!(
        ready.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{ready}"
    );
    assert!(
        ready.contains("pool \"web\" has no healthy backend"),
        "{ready}"
    );

    // liveness is independent of backend health - the process is still up
    let healthz = request(addr, "GET", "/healthz").await;
    assert!(healthz.starts_with("HTTP/1.1 200 OK"), "{healthz}");
}

#[tokio::test]
async fn server_info_reports_running_state() {
    let config = Config::from_toml(CONFIG, "<test>").unwrap();
    let (addr, state, _handle) = spawn_admin(&config, None).await;

    let info = request(addr, "GET", "/server_info").await;
    assert!(info.starts_with("HTTP/1.1 200 OK"), "{info}");
    assert!(info.contains("content-type: application/json"), "{info}");

    let body = body_of(&info);
    assert!(
        body.contains(&format!("\"version\":\"{}\"", env!("CARGO_PKG_VERSION"))),
        "{body}"
    );
    assert!(body.contains("\"config_version\":0"), "{body}");
    assert!(body.contains("\"pools\":1"), "{body}");
    assert!(body.contains("\"uptime_secs\":"), "{body}");

    // a committed reload bumps the version the endpoint reads
    let mut next = kntx::runtime::build_snapshot(&config);
    next.version = 7;
    state.store(Arc::new(next));

    let info = request(addr, "GET", "/server_info").await;
    assert!(body_of(&info).contains("\"config_version\":7"), "{info}");
}

#[tokio::test]
async fn admin_socket_rejects_unknown_routes_and_methods() {
    let config = Config::from_toml(CONFIG, "<test>").unwrap();
    let (addr, _state, _handle) = spawn_admin(&config, None).await;

    // the metrics routes do not exist here: separate socket, separate exposure class
    for path in ["/metrics", "/healthz", "/ready", "/nope"] {
        let response = request(addr, "GET", path).await;
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found"),
            "{path}: {response}"
        );
    }

    let posted = request(addr, "POST", "/server_info").await;
    assert!(
        posted.starts_with("HTTP/1.1 405 Method Not Allowed"),
        "{posted}"
    );
}

#[tokio::test]
async fn token_gates_every_admin_route() {
    let config = Config::from_toml(CONFIG, "<test>").unwrap();
    let (addr, _state, _handle) = spawn_admin(&config, Some("s3cret")).await;

    let missing = request(addr, "GET", "/server_info").await;
    assert!(
        missing.starts_with("HTTP/1.1 401 Unauthorized"),
        "{missing}"
    );

    for wrong in ["", "s3cre", "s3cretx", "S3CRET", "s3creT"] {
        let response = request_with_token(addr, "/server_info", wrong).await;
        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized"),
            "token {wrong:?} accepted: {response}"
        );
    }

    let ok = request_with_token(addr, "/server_info", "s3cret").await;
    assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");

    // the gate runs before routing, so a bad token cannot probe which routes exist
    let unknown = request(addr, "GET", "/nope").await;
    assert!(
        unknown.starts_with("HTTP/1.1 401 Unauthorized"),
        "{unknown}"
    );
}

#[tokio::test]
async fn token_rotates_without_a_restart() {
    let config = Config::from_toml(CONFIG, "<test>").unwrap();
    let (addr, _state, handle) = spawn_admin(&config, Some("old")).await;

    let ok = request_with_token(addr, "/server_info", "old").await;
    assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");

    handle.set_token(Some("new"));

    let stale = request_with_token(addr, "/server_info", "old").await;
    assert!(
        stale.starts_with("HTTP/1.1 401 Unauthorized"),
        "leaked token still works: {stale}"
    );
    let rotated = request_with_token(addr, "/server_info", "new").await;
    assert!(rotated.starts_with("HTTP/1.1 200 OK"), "{rotated}");

    // loopback needs no token, so clearing it here is allowed
    handle.set_token(None);
    let open = request(addr, "GET", "/server_info").await;
    assert!(open.starts_with("HTTP/1.1 200 OK"), "{open}");
}

#[tokio::test]
async fn token_cannot_be_cleared_on_a_non_loopback_socket() {
    // the bound socket is loopback, but the handle's address is what the check
    // reads - a reload must not un-auth a socket serving off-loopback
    let config = Config::from_toml(CONFIG, "<test>").unwrap();
    let state = Arc::new(ArcSwap::from_pointee(kntx::runtime::build_snapshot(
        &config,
    )));
    let listener = kntx::control::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let public = SocketAddr::new("192.0.2.1".parse().unwrap(), addr.port());
    let handle = AdminHandle::new(public, Some("s3cret"));
    kntx::control::spawn(
        listener,
        Surface::Admin {
            handle: handle.clone(),
            state,
            started: Instant::now(),
        },
    );

    handle.set_token(None);

    let unauthenticated = request(addr, "GET", "/server_info").await;
    assert!(
        unauthenticated.starts_with("HTTP/1.1 401 Unauthorized"),
        "clearing the token opened a non-loopback socket: {unauthenticated}"
    );
    let ok = request_with_token(addr, "/server_info", "s3cret").await;
    assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");
}
