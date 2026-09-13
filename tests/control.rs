//! The two control sockets: `/metrics`, `/healthz` and `/ready` on the metrics
//! socket, `/server_info` and the token gate on the admin socket.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use arc_swap::ArcSwap;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

use kntx::config::Config;
use kntx::control::{AdminHandle, RuntimeFlags, Surface};

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

// the recorder is global and installs once per process, so tests share one handle
static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

fn metrics_handle() -> PrometheusHandle {
    METRICS_HANDLE
        .get_or_init(|| kntx::metrics::install().expect("install prometheus recorder"))
        .clone()
}

// the subscriber is global too, and it has to be a real one: the handle reaches the
// filter through the layer, which only stays alive once the registry owns it.
static LOG_FILTER: OnceLock<kntx::control::LogFilterHandle> = OnceLock::new();

fn log_filter() -> kntx::control::LogFilterHandle {
    LOG_FILTER
        .get_or_init(|| {
            let (layer, handle) =
                kntx::control::log_filter_layer(EnvFilter::new("kntx=info"), false);
            let _ = tracing_subscriber::registry().with(layer).try_init();
            handle
        })
        .clone()
}

async fn spawn_admin(
    config: &Arc<Config>,
    token: Option<&str>,
) -> (
    SocketAddr,
    Arc<ArcSwap<kntx::runtime::Snapshot>>,
    AdminHandle,
) {
    let state = Arc::new(ArcSwap::from_pointee(kntx::runtime::build_snapshot(
        Arc::clone(config),
    )));
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
            flags: Arc::new(RuntimeFlags::new()),
            log_filter: log_filter(),
            listeners: Default::default(),
        },
    );
    (addr, state, handle)
}

#[tokio::test]
async fn metrics_routes_and_readiness() {
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
    let state = Arc::new(ArcSwap::from_pointee(kntx::runtime::build_snapshot(
        Arc::clone(&config),
    )));
    let handle = metrics_handle();

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
            flags: Arc::new(RuntimeFlags::new()),
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

    // and readiness does not move. kntx fronts many unrelated services from one
    // process, so a dead pool must not deregister every listener - and since every
    // replica sees the same dead pool, the signal could not tell them apart anyway.
    // requests to that pool already get a 503, and kntx_backend_health alerts on it.
    let ready = request(addr, "GET", "/ready").await;
    assert!(ready.starts_with("HTTP/1.1 200 OK"), "{ready}");

    let healthz = request(addr, "GET", "/healthz").await;
    assert!(healthz.starts_with("HTTP/1.1 200 OK"), "{healthz}");

    // the fact is still reported, on the channel that can express it per backend
    let metrics = request(addr, "GET", "/metrics").await;
    assert!(metrics.contains("kntx_backend_health"), "{metrics}");
}

#[tokio::test]
async fn server_info_reports_running_state() {
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
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
    let mut next = kntx::runtime::build_snapshot(Arc::clone(&config));
    next.version = 7;
    state.store(Arc::new(next));

    let info = request(addr, "GET", "/server_info").await;
    assert!(body_of(&info).contains("\"config_version\":7"), "{info}");
}

#[tokio::test]
async fn admin_socket_rejects_unknown_routes_and_methods() {
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
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
    // RFC 9110 makes Allow mandatory on a 405, and it is what tells a caller the verb
    assert!(posted.contains("\r\nallow: GET\r\n"), "{posted}");
    assert!(posted.contains("\r\ncontent-length: 19\r\n"), "{posted}");
    assert_eq!(body_of(&posted), "method not allowed\n");

    // "/" is the panel route; it serves the table every other route is listed in
    let root = request(addr, "GET", "/").await;
    assert!(root.starts_with("HTTP/1.1 200 OK"), "{root}");
    assert!(body_of(&root).contains("/server_info"), "{root}");
}

#[tokio::test]
async fn pools_reports_runtime_state() {
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
    let (addr, state, _handle) = spawn_admin(&config, None).await;

    let response = request(addr, "GET", "/pools").await;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.contains("content-type: application/json"),
        "{response}"
    );

    let body = body_of(&response);
    assert!(body.contains("\"name\":\"web\""), "{body}");
    assert!(body.contains("\"address\":\"127.0.0.1:9\""), "{body}");
    assert!(body.contains("\"circuit\":\"closed\""), "{body}");
    assert!(body.contains("\"strategy\":\"round_robin\""), "{body}");

    // failure_threshold = 1, so one failure opens the only circuit, and the endpoint
    // exists to answer "why is traffic not going there"
    let (pool, _) = &state.load().pools["web"];
    pool.record_failure("127.0.0.1:9".parse().unwrap());

    let body = request(addr, "GET", "/pools").await;
    let body = body_of(&body).to_owned();
    assert!(body.contains("\"circuit\":\"open\""), "{body}");
    assert!(body.contains("\"consecutive_failures\":1"), "{body}");
}

#[tokio::test]
async fn the_panel_renders_only_for_browsers_and_its_forms_work() {
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
    let (addr, _state, _handle) = spawn_admin(&config, None).await;

    // curl gets the route table, not markup
    let text = request(addr, "GET", "/").await;
    assert!(text.contains("content-type: text/plain"), "{text}");
    assert!(!body_of(&text).contains("<html"), "{text}");

    let browser = send(addr, "GET", "/", "accept: text/html,*/*\r\n").await;
    assert!(browser.contains("content-type: text/html"), "{browser}");
    let page = body_of(&browser);
    assert!(page.starts_with("<!doctype html>"), "{page}");
    // static: a self-reloading page discards a half-typed filter directive and
    // collapses the config dump, which is two of the three things on the page
    assert!(!page.contains("http-equiv=\"refresh\""), "{page}");
    // no script tag, no external asset: the page must work with nothing fetched
    assert!(!page.contains("<script"), "{page}");
    assert!(
        !page.contains("http://") && !page.contains("https://"),
        "{page}"
    );

    // the same values the JSON routes serve, rendered
    assert!(page.contains("127.0.0.1:9"), "{page}");
    assert!(page.contains("serving"), "{page}");
    assert!(page.contains("<details"), "{page}");
    // the fail/ok buttons change readiness, so the page has to show it: without
    // this, clicking one reloads a page that looks identical
    assert!(page.contains(">ready<"), "{page}");
    assert!(!page.contains(">not ready<"), "{page}");
    // form actions must stay relative or the panel's own POST reads as cross-site
    assert!(page.contains("action=\"/drain_listeners\""), "{page}");

    // a real browser POST, header for header. the hand-built 4-header version of
    // this test passed while every button on the page returned 400: Chrome sends
    // about 20 headers on a form POST and the parser was sized for 16.
    let posted = send(
        addr,
        "POST",
        "/logging",
        "cache-control: max-age=0\r\n\
         sec-ch-ua: \"Chromium\";v=\"140\", \"Not=A?Brand\";v=\"24\"\r\n\
         sec-ch-ua-mobile: ?0\r\n\
         sec-ch-ua-platform: \"Linux\"\r\n\
         upgrade-insecure-requests: 1\r\n\
         origin: http://127.0.0.1:9901\r\n\
         content-type: application/x-www-form-urlencoded\r\n\
         user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n\
         accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         sec-fetch-site: same-origin\r\n\
         sec-fetch-mode: navigate\r\n\
         sec-fetch-user: ?1\r\n\
         sec-fetch-dest: document\r\n\
         referer: http://127.0.0.1:9901/\r\n\
         accept-encoding: gzip, deflate, br, zstd\r\n\
         accept-language: en-US,en;q=0.9\r\n\
         cookie: leftover_from_another_localhost_devserver=1\r\n\
         content-length: 45\r\n\r\n\
         filter=kntx%3A%3Aproxy%3A%3Al7%3Ddebug%2Cinfo",
    )
    .await;
    assert!(posted.starts_with("HTTP/1.1 303 See Other"), "{posted}");
    assert!(posted.contains("location: /"), "{posted}");

    let filter = request(addr, "GET", "/logging").await;
    assert!(
        body_of(&filter).contains("kntx::proxy::l7=debug"),
        "the form value did not survive urlencoding: {filter}"
    );

    // and the same route still answers curl with a body rather than a redirect
    let curl = send(
        addr,
        "POST",
        "/healthcheck/fail",
        "content-length: 0\r\n\r\n",
    )
    .await;
    assert!(curl.starts_with("HTTP/1.1 200 OK"), "{curl}");
}

#[tokio::test]
async fn draining_outranks_every_other_readiness_answer() {
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
    let state = Arc::new(ArcSwap::from_pointee(kntx::runtime::build_snapshot(
        Arc::clone(&config),
    )));
    let flags = Arc::new(RuntimeFlags::new());
    let listeners: kntx::runtime::ListenerRegistry = Default::default();

    let listener = kntx::control::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let metrics_addr = listener.local_addr().unwrap();
    kntx::control::spawn(
        listener,
        Surface::Metrics {
            handle: metrics_handle(),
            flags: Arc::clone(&flags),
        },
    );

    let listener = kntx::control::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let admin_addr = listener.local_addr().unwrap();
    kntx::control::spawn(
        listener,
        Surface::Admin {
            handle: AdminHandle::new(admin_addr, None),
            state,
            started: Instant::now(),
            flags: Arc::clone(&flags),
            log_filter: log_filter(),
            listeners,
        },
    );

    let info = request(admin_addr, "GET", "/server_info").await;
    assert!(body_of(&info).contains("\"state\":\"serving\""), "{info}");

    let drained = request(admin_addr, "POST", "/drain_listeners").await;
    assert!(drained.starts_with("HTTP/1.1 200 OK"), "{drained}");
    assert!(body_of(&drained).contains("SIGHUP"), "{drained}");

    let ready = request(metrics_addr, "GET", "/ready").await;
    assert!(
        ready.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{ready}"
    );
    assert!(body_of(&ready).contains("listeners drained"), "{ready}");

    // drained beats the health override in the reason string: with no socket open,
    // nothing further about this instance matters
    let failed = request(admin_addr, "POST", "/healthcheck/fail").await;
    assert!(failed.starts_with("HTTP/1.1 200 OK"), "{failed}");
    let ready = request(metrics_addr, "GET", "/ready").await;
    assert!(body_of(&ready).contains("listeners drained"), "{ready}");

    // liveness stays 200: the process is alive and one SIGHUP from serving
    let healthz = request(metrics_addr, "GET", "/healthz").await;
    assert!(healthz.starts_with("HTTP/1.1 200 OK"), "{healthz}");

    let info = request(admin_addr, "GET", "/server_info").await;
    assert!(body_of(&info).contains("\"state\":\"draining\""), "{info}");

    // and the panel says the same thing the probe does, with the reason
    let page = send(admin_addr, "GET", "/", "accept: text/html\r\n").await;
    let page = body_of(&page);
    assert!(page.contains(">not ready<"), "{page}");
    assert!(page.contains("listeners drained"), "{page}");
}

#[tokio::test]
async fn logging_reads_and_sets_the_filter() {
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
    let (addr, _state, _handle) = spawn_admin(&config, None).await;

    let response = request(addr, "GET", "/logging").await;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    let before = body_of(&response).trim().to_owned();
    assert!(!before.is_empty(), "GET returned no filter");

    let posted = send(
        addr,
        "POST",
        "/logging",
        "content-length: 26\r\n\r\nkntx::proxy::l7=debug,info",
    )
    .await;
    assert!(posted.starts_with("HTTP/1.1 200 OK"), "{posted}");

    let response = request(addr, "GET", "/logging").await;
    let after = body_of(&response).trim().to_owned();
    assert!(after.contains("kntx::proxy::l7=debug"), "{after}");
    assert_ne!(before, after);

    // a directive EnvFilter cannot parse is refused and the filter does not move
    let bad = send(addr, "POST", "/logging", "content-length: 1\r\n\r\n=").await;
    assert!(bad.starts_with("HTTP/1.1 400 Bad Request"), "{bad}");
    let response = request(addr, "GET", "/logging").await;
    assert_eq!(body_of(&response).trim(), after, "a rejected POST moved it");

    // an empty body gets the usage line rather than a silent no-op
    let empty = send(addr, "POST", "/logging", "content-length: 0\r\n\r\n").await;
    assert!(empty.starts_with("HTTP/1.1 400 Bad Request"), "{empty}");
    assert!(body_of(&empty).contains("EnvFilter directive"), "{empty}");

    // both verbs live on one path, so 405 must advertise both
    let bad_method = request(addr, "DELETE", "/logging").await;
    assert!(
        bad_method.starts_with("HTTP/1.1 405 Method Not Allowed"),
        "{bad_method}"
    );
    assert!(bad_method.contains("allow: GET, POST"), "{bad_method}");
}

#[tokio::test]
async fn config_dump_redacts_the_token_and_nothing_else() {
    const WITH_SECRETS: &str = "\
[[listeners]]
address = \"127.0.0.1:19996\"
mode = \"l4\"
pool = \"web\"
proxy_protocol = true
proxy_protocol_from = [\"10.0.0.0/8\"]

[[pools]]
name = \"web\"
strategy = \"least_conn\"
backends = [{ address = \"127.0.0.1:9\", weight = 3 }]

[admin]
address = \"127.0.0.1:19995\"
token = \"sup3r-s3cret-value\"
";
    let config = Arc::new(Config::from_toml(WITH_SECRETS, "<test>").unwrap());
    let (addr, _state, _handle) = spawn_admin(&config, Some("sup3r-s3cret-value")).await;

    let response = request_with_token(addr, "/config_dump", "sup3r-s3cret-value").await;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    let body = body_of(&response);

    // the dump is gated by this token, so returning it would hand over the credential
    // for every route behind the gate, including the mutating ones
    assert!(
        !body.contains("sup3r-s3cret-value"),
        "the [admin] token leaked into /config_dump: {body}"
    );
    assert!(body.contains("\"token\":\"<redacted>\""), "{body}");

    // everything else ships verbatim: a dump that hides the running values answers
    // nothing. cert/key paths are not secrets, they are paths.
    assert!(body.contains("\"strategy\":\"least_conn\""), "{body}");
    assert!(body.contains("\"weight\":3"), "{body}");
    assert!(body.contains("\"address\":\"127.0.0.1:19996\""), "{body}");
    assert!(body.contains("\"proxy_protocol\":true"), "{body}");
    // TrustedCidr round-trips through its Display rather than leaking its fields
    assert!(body.contains("\"10.0.0.0/8\""), "{body}");
    assert!(!body.contains("\"bits\""), "cidr internals leaked: {body}");
    assert!(body.contains("\"config_version\":0"), "{body}");
}

#[tokio::test]
async fn health_override_forces_ready_while_process_stays_live() {
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
    let state = Arc::new(ArcSwap::from_pointee(kntx::runtime::build_snapshot(
        Arc::clone(&config),
    )));
    // one value across two sockets: /healthcheck/* is on admin, /ready is on metrics
    let flags = Arc::new(RuntimeFlags::new());

    let listener = kntx::control::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let metrics_addr = listener.local_addr().unwrap();
    kntx::control::spawn(
        listener,
        Surface::Metrics {
            handle: metrics_handle(),
            flags: Arc::clone(&flags),
        },
    );

    let listener = kntx::control::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let admin_addr = listener.local_addr().unwrap();
    kntx::control::spawn(
        listener,
        Surface::Admin {
            handle: AdminHandle::new(admin_addr, None),
            state,
            started: Instant::now(),
            flags,
            log_filter: log_filter(),
            listeners: Default::default(),
        },
    );

    let ready = request(metrics_addr, "GET", "/ready").await;
    assert!(ready.starts_with("HTTP/1.1 200 OK"), "{ready}");

    let failed = request(admin_addr, "POST", "/healthcheck/fail").await;
    assert!(failed.starts_with("HTTP/1.1 200 OK"), "{failed}");

    let ready = request(metrics_addr, "GET", "/ready").await;
    assert!(
        ready.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{ready}"
    );
    assert!(ready.contains("health override"), "{ready}");

    // the whole point of the override: out of rotation, still alive and serving
    let healthz = request(metrics_addr, "GET", "/healthz").await;
    assert!(healthz.starts_with("HTTP/1.1 200 OK"), "{healthz}");

    let ok = request(admin_addr, "POST", "/healthcheck/ok").await;
    assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");

    let ready = request(metrics_addr, "GET", "/ready").await;
    assert!(ready.starts_with("HTTP/1.1 200 OK"), "{ready}");

    // setting it twice is not an error; an operator retrying must not get a 4xx
    for _ in 0..2 {
        let again = request(admin_addr, "POST", "/healthcheck/fail").await;
        assert!(again.starts_with("HTTP/1.1 200 OK"), "{again}");
    }
    let ready = request(metrics_addr, "GET", "/ready").await;
    assert!(
        ready.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{ready}"
    );
}

#[tokio::test]
async fn cross_origin_post_is_refused() {
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
    let (addr, _state, _handle) = spawn_admin(&config, None).await;

    // same-site is here deliberately: another port on 127.0.0.1 is same-site
    for site in ["cross-site", "same-site", "none", "garbage"] {
        let response = send(
            addr,
            "POST",
            "/healthcheck/fail",
            &format!("sec-fetch-site: {site}\r\n"),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden"),
            "{site} accepted: {response}"
        );
    }

    // the panel's own form button
    let same_origin = send(
        addr,
        "POST",
        "/healthcheck/fail",
        "sec-fetch-site: same-origin\r\n",
    )
    .await;
    assert!(same_origin.starts_with("HTTP/1.1 200 OK"), "{same_origin}");

    // curl and scripts send no such header
    let absent = request(addr, "POST", "/healthcheck/ok").await;
    assert!(absent.starts_with("HTTP/1.1 200 OK"), "{absent}");

    // reads are never checked: a cross-site GET cannot mutate anything
    let read = send(
        addr,
        "GET",
        "/server_info",
        "sec-fetch-site: cross-site\r\n",
    )
    .await;
    assert!(read.starts_with("HTTP/1.1 200 OK"), "{read}");
}

#[tokio::test]
async fn token_gates_every_admin_route() {
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
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
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
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
    let config = Arc::new(Config::from_toml(CONFIG, "<test>").unwrap());
    let state = Arc::new(ArcSwap::from_pointee(kntx::runtime::build_snapshot(
        Arc::clone(&config),
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
            flags: Arc::new(RuntimeFlags::new()),
            log_filter: log_filter(),
            listeners: Default::default(),
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
