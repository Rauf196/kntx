//! `/metrics`, `/healthz` and `/ready` served on the metrics socket.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use kntx::config::Config;

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
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(format!("{method} {path} HTTP/1.1\r\nhost: probe\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn admin_routes_and_readiness() {
    let config = Config::from_toml(CONFIG, "<test>").unwrap();
    let state = Arc::new(ArcSwap::from_pointee(kntx::runtime::build_snapshot(
        &config,
    )));
    let handle = kntx::metrics::install().unwrap();

    let (pool, _) = &state.load().pools["web"];
    let pool = Arc::clone(pool);
    pool.emit_initial_metrics();

    let listener = kntx::metrics::endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    kntx::metrics::endpoint::spawn(listener, handle, Arc::clone(&state));

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
