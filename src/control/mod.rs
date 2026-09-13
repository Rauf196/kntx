//! The `[metrics]` and `[admin]` control-plane sockets.
//!
//! Split by exposure class: `[metrics]` is scraped and probed from the network
//! and carries no secrets, `[admin]` dumps config and mutates the instance, so
//! it binds loopback unless a token is set.
//!
//! One hand-rolled GET responder serves both. The exporter's
//! `with_http_listener` cannot: it owns its socket and answers every path with
//! the scrape payload.

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use metrics::gauge;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::runtime::{ListenerRegistry, Snapshot};

pub mod logging;
pub mod panel;
pub mod report;

pub use logging::{LogFilterHandle, log_filter_layer};

const MAX_HEAD: usize = 8192;
/// a browser POST from the panel sends around 20 (sec-ch-ua*, sec-fetch-*, origin,
/// referer, content-type, cookies for 127.0.0.1 left by other local dev servers).
/// 16 was enough for a GET and not for a POST, which made every panel button 400.
const MAX_HEADERS: usize = 64;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);
const TOKEN_HEADER: &str = "x-kntx-token";
const FETCH_SITE_HEADER: &str = "sec-fetch-site";
const ACCEPT_HEADER: &str = "accept";
const CONTENT_TYPE_HEADER: &str = "content-type";
const FORM_TYPE: &str = "application/x-www-form-urlencoded";
const TEXT: &str = "text/plain; charset=utf-8";
const HTML: &str = "text/html; charset=utf-8";

/// `path()` is the only list of paths; `from_path` searches it so the two cannot drift.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AdminRoute {
    Panel,
    ServerInfo,
    Pools,
    ConfigDump,
    Logging,
    HealthcheckFail,
    HealthcheckOk,
    DrainListeners,
}

impl AdminRoute {
    const ALL: [Self; 8] = [
        Self::Panel,
        Self::ServerInfo,
        Self::Pools,
        Self::ConfigDump,
        Self::Logging,
        Self::HealthcheckFail,
        Self::HealthcheckOk,
        Self::DrainListeners,
    ];

    fn from_path(path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.path() == path)
    }

    fn path(self) -> &'static str {
        match self {
            Self::Panel => "/",
            Self::ServerInfo => "/server_info",
            Self::Pools => "/pools",
            Self::ConfigDump => "/config_dump",
            Self::Logging => "/logging",
            Self::HealthcheckFail => "/healthcheck/fail",
            Self::HealthcheckOk => "/healthcheck/ok",
            Self::DrainListeners => "/drain_listeners",
        }
    }

    /// gates the method and fills `Allow` on a 405.
    fn methods(self) -> &'static [&'static str] {
        match self {
            Self::Panel | Self::ServerInfo | Self::Pools | Self::ConfigDump => &["GET"],
            Self::Logging => &["GET", "POST"],
            Self::HealthcheckFail | Self::HealthcheckOk | Self::DrainListeners => &["POST"],
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Panel => "this table",
            Self::ServerInfo => "version, uptime, config version, pool count",
            Self::Pools => "per-backend circuit, weight, in-flight and cache state",
            Self::ConfigDump => "running config as JSON, [admin] token redacted",
            Self::Logging => "read the log filter, or POST an EnvFilter directive",
            Self::HealthcheckFail => "force /ready to 503, keep serving",
            Self::HealthcheckOk => "clear the /ready override",
            Self::DrainListeners => "stop accepting, stay alive, SIGHUP to re-bind",
        }
    }
}

/// operator-forced state that has to outlive a reload. deliberately not on `Snapshot`,
/// which is rebuilt from scratch on every SIGHUP: an override set during an incident
/// must not be undone by an unrelated config push. Relaxed throughout, since the flag
/// is the whole payload and nothing is published alongside it.
#[derive(Debug)]
pub struct RuntimeFlags {
    health_override: AtomicBool,
    draining: AtomicBool,
}

impl RuntimeFlags {
    pub fn new() -> Self {
        // seed the series so they exist before the first override rather than appearing
        gauge!("kntx_admin_health_override").set(0.0);
        gauge!("kntx_admin_draining").set(0.0);
        Self {
            health_override: AtomicBool::new(false),
            draining: AtomicBool::new(false),
        }
    }

    pub fn set_health_override(&self, on: bool) {
        self.health_override.store(on, Ordering::Relaxed);
        gauge!("kntx_admin_health_override").set(if on { 1.0 } else { 0.0 });
    }

    pub fn health_overridden(&self) -> bool {
        self.health_override.load(Ordering::Relaxed)
    }

    pub fn set_draining(&self, on: bool) {
        self.draining.store(on, Ordering::Relaxed);
        gauge!("kntx_admin_draining").set(if on { 1.0 } else { 0.0 });
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }
}

impl Default for RuntimeFlags {
    fn default() -> Self {
        Self::new()
    }
}

/// which route set a socket serves. fixed at spawn; the two never share a port.
pub enum Surface {
    Metrics {
        handle: PrometheusHandle,
        flags: Arc<RuntimeFlags>,
    },
    Admin {
        handle: AdminHandle,
        state: Arc<ArcSwap<Snapshot>>,
        started: Instant,
        flags: Arc<RuntimeFlags>,
        log_filter: LogFilterHandle,
        listeners: ListenerRegistry,
    },
}

/// the running admin socket, as a reload sees it. the address is fixed by the
/// bound listener, but the token swaps live: a leaked one has to be revocable
/// without dropping traffic.
#[derive(Clone)]
pub struct AdminHandle {
    pub address: SocketAddr,
    // arc-swap needs a sized payload, so Arc<String> rather than Arc<str>
    token: Arc<ArcSwapOption<String>>,
}

impl AdminHandle {
    pub fn new(address: SocketAddr, token: Option<&str>) -> Self {
        Self {
            address,
            token: Arc::new(ArcSwapOption::new(token.map(|t| Arc::new(t.to_owned())))),
        }
    }

    /// applies a reloaded token. clearing it is refused while the socket is
    /// bound off-loopback - config validation enforces that pairing against the
    /// configured address, and this enforces it against the one actually serving.
    pub fn set_token(&self, token: Option<&str>) {
        if token.is_none() && !self.address.ip().is_loopback() {
            tracing::warn!(
                address = %self.address,
                "refusing to clear the [admin] token on a non-loopback socket, keeping the running one",
            );
            return;
        }
        // every reload calls this, so log only a real change: an operator
        // grepping for a rotation needs it to mean one happened.
        let changed = self.token.load().as_deref().map(String::as_str) != token;
        self.token.store(token.map(|t| Arc::new(t.to_owned())));
        if changed {
            match token {
                Some(_) => tracing::info!(address = %self.address, "[admin] token rotated"),
                None => tracing::warn!(address = %self.address, "[admin] token removed"),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn token_is(&self, expected: Option<&str>) -> bool {
        self.token.load().as_deref().map(String::as_str) == expected
    }
}

pub async fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(address).await
}

/// takes the listener already bound at startup, so a port conflict fails the
/// process before pools and listeners are built rather than after.
pub fn spawn(listener: TcpListener, surface: Surface) {
    // `install_recorder` leaves upkeep to the caller; `with_http_listener` did it
    if let Surface::Metrics { handle, .. } = &surface {
        let handle = handle.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(UPKEEP_INTERVAL);
            loop {
                ticker.tick().await;
                handle.run_upkeep();
            }
        });
    }

    let surface = Arc::new(surface);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let surface = Arc::clone(&surface);
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(stream, &surface).await {
                            tracing::debug!(error = %e, "control request failed");
                        }
                    });
                }
                Err(e) => tracing::warn!(error = %e, "control accept failed"),
            }
        }
    });
}

async fn handle_conn(mut stream: TcpStream, surface: &Surface) -> std::io::Result<()> {
    let mut buf = [0u8; MAX_HEAD];
    let (head_len, filled) =
        match tokio::time::timeout(READ_TIMEOUT, read_request(&mut stream, &mut buf)).await {
            Ok(Ok(Some(split))) => split,
            Ok(Ok(None)) => return respond(&mut stream, "400 Bad Request", "bad request\n").await,
            Ok(Err(e)) => return Err(e),
            Err(_) => return respond(&mut stream, "408 Request Timeout", "timeout\n").await,
        };
    let (head, body) = buf.split_at(head_len);
    let body = &body[..filled - head_len];

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(head).is_err() {
        return respond(&mut stream, "400 Bad Request", "bad request\n").await;
    }
    let method = req.method.unwrap_or("");

    // query strings are not used by any route; strip so `/ready?x=1` still routes
    let path = req.path.unwrap_or("/");
    let path = path.split('?').next().unwrap_or(path);

    match surface {
        Surface::Metrics { handle, flags } => {
            if method != "GET" {
                return method_not_allowed(&mut stream, &["GET"]).await;
            }
            match path {
                "/metrics" => respond(&mut stream, "200 OK", &handle.render()).await,
                "/healthz" => respond(&mut stream, "200 OK", "ok\n").await,
                "/ready" => match readiness(flags) {
                    Ok(()) => respond(&mut stream, "200 OK", "ready\n").await,
                    Err(reason) => {
                        respond(
                            &mut stream,
                            "503 Service Unavailable",
                            &format!("{reason}\n"),
                        )
                        .await
                    }
                },
                _ => respond(&mut stream, "404 Not Found", "not found\n").await,
            }
        }
        Surface::Admin {
            handle,
            state,
            started,
            flags,
            log_filter,
            listeners,
        } => {
            // gated per socket, not per route: reading /config_dump leaks as much
            // as draining mutates, so both sit behind the same token.
            let token = handle.token.load();
            if let Some(expected) = token.as_ref() {
                let presented = header(&req, TOKEN_HEADER).unwrap_or(b"");
                if !token_matches(expected.as_bytes(), presented) {
                    // a browser hitting a tokenized socket gets no other clue
                    return respond(
                        &mut stream,
                        "401 Unauthorized",
                        "unauthorized: this socket requires the x-kntx-token header\n",
                    )
                    .await;
                }
            }

            let Some(route) = AdminRoute::from_path(path) else {
                return respond(&mut stream, "404 Not Found", "not found\n").await;
            };
            if !route.methods().contains(&method) {
                return method_not_allowed(&mut stream, route.methods()).await;
            }
            // the request's method, not the route's: a GET/POST route still lets GET through
            if method == "POST" && !same_origin_or_absent(header(&req, FETCH_SITE_HEADER)) {
                return respond(
                    &mut stream,
                    "403 Forbidden",
                    "forbidden: sec-fetch-site names a cross-origin caller\n",
                )
                .await;
            }

            let html = panel::wants_html(header(&req, ACCEPT_HEADER));

            match route {
                AdminRoute::Panel if html => {
                    let snapshot = state.load();
                    let info = report::server_info(&snapshot, *started, flags.is_draining());
                    let config = serde_json::to_string_pretty(&*snapshot.config)
                        .unwrap_or_else(|e| e.to_string());
                    // the same call `/ready` makes, so the page cannot claim a
                    // readiness the probe would disagree with
                    let not_ready = readiness(flags).err();
                    let body = panel::render(
                        &info,
                        &report::pools_report(&snapshot),
                        &log_filter.current(),
                        &config,
                        not_ready.as_deref(),
                    );
                    write_response(&mut stream, "200 OK", HTML, "", &body).await
                }
                AdminRoute::Panel => respond(&mut stream, "200 OK", &route_table()).await,
                AdminRoute::ServerInfo => {
                    let info = report::server_info(&state.load(), *started, flags.is_draining());
                    write_response(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        "",
                        &info.to_json(),
                    )
                    .await
                }
                AdminRoute::Pools => {
                    let body = serde_json::to_string(&report::pools_report(&state.load()))
                        .expect("pools report is plain data and cannot fail to serialize");
                    write_response(&mut stream, "200 OK", "application/json", "", &body).await
                }
                AdminRoute::ConfigDump => {
                    let snapshot = state.load();
                    let body = serde_json::json!({
                        "config_version": snapshot.version,
                        "config": &*snapshot.config,
                    });
                    write_response(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        "",
                        &body.to_string(),
                    )
                    .await
                }
                AdminRoute::Logging if method == "GET" => {
                    respond(
                        &mut stream,
                        "200 OK",
                        &format!("{}\n", log_filter.current()),
                    )
                    .await
                }
                AdminRoute::Logging => {
                    // the panel posts a form; curl posts the directive raw
                    let form = header(&req, CONTENT_TYPE_HEADER)
                        .and_then(|v| std::str::from_utf8(v).ok())
                        .is_some_and(|v| v.starts_with(FORM_TYPE));
                    let decoded = form
                        .then(|| form_value(body, "filter"))
                        .flatten()
                        .unwrap_or_else(|| String::from_utf8_lossy(body));
                    let directive = decoded.trim();
                    if directive.is_empty() {
                        return respond(
                            &mut stream,
                            "400 Bad Request",
                            "post an EnvFilter directive as the body, e.g. kntx::proxy::l7=debug,info\n",
                        )
                        .await;
                    }
                    match log_filter.set(directive) {
                        Ok(()) => {
                            mutation_response(&mut stream, html, &format!("{directive}\n")).await
                        }
                        Err(e) => respond(&mut stream, "400 Bad Request", &format!("{e}\n")).await,
                    }
                }
                AdminRoute::HealthcheckFail => {
                    flags.set_health_override(true);
                    tracing::warn!("/ready forced unhealthy by /healthcheck/fail");
                    mutation_response(&mut stream, html, "health override set\n").await
                }
                AdminRoute::HealthcheckOk => {
                    flags.set_health_override(false);
                    tracing::info!("/ready override cleared by /healthcheck/ok");
                    mutation_response(&mut stream, html, "health override cleared\n").await
                }
                AdminRoute::DrainListeners => {
                    flags.set_draining(true);
                    let drained = crate::runtime::drain_listeners(listeners);
                    tracing::warn!(drained, "listeners drained by admin request");
                    // returns as soon as the signal is sent. in-flight work is still
                    // finishing; kntx_connections_active reaching 0 is that signal,
                    // and there is no second counter for it.
                    mutation_response(
                        &mut stream,
                        html,
                        &format!(
                            "drained {drained} listener(s), still serving in-flight work\n\
                             send SIGHUP to re-bind\n"
                        ),
                    )
                    .await
                }
            }
        }
    }
}

fn header<'a>(req: &'a httparse::Request<'_, '_>, name: &str) -> Option<&'a [u8]> {
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value)
}

/// blocks a page the operator is visiting from POSTing to the admin socket. browsers
/// stamp this and script cannot forge it, so the panel keeps plain form buttons with
/// no token or session. absent means a non-browser caller. `same-site` is refused
/// too: loopback has no registrable domain, so another port of `127.0.0.1` is
/// same-site and still not ours.
fn same_origin_or_absent(value: Option<&[u8]>) -> bool {
    match value {
        None => true,
        Some(v) => v.trim_ascii().eq_ignore_ascii_case(b"same-origin"),
    }
}

/// a browser posting a form and getting a plain-text body back is left staring at it
/// with the panel gone, so HTML callers are sent back to `/`. 303 rather than 302 so
/// a reload does not re-submit the form.
async fn mutation_response(stream: &mut TcpStream, html: bool, text: &str) -> std::io::Result<()> {
    if html {
        write_response(stream, "303 See Other", TEXT, "location: /\r\n", text).await
    } else {
        respond(stream, "200 OK", text).await
    }
}

/// pulls one field out of a form body. `/logging` is the only route with a form, and
/// an EnvFilter directive is full of `=` and `,`, so the split is on the first `=`
/// only and the value is percent-decoded.
fn form_value<'a>(body: &'a [u8], name: &str) -> Option<Cow<'a, str>> {
    let body = std::str::from_utf8(body).ok()?;
    body.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| percent_decode(value))
    })
}

fn percent_decode(s: &str) -> Cow<'_, str> {
    if !s.contains(['%', '+']) {
        return Cow::Borrowed(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    // a stray '%' is more likely a typo in a directive than an
                    // escape, so keep it rather than dropping the character
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

fn route_table() -> String {
    let mut out = String::from("kntx admin\n\n");
    for route in AdminRoute::ALL {
        out.push_str(&format!(
            "{:<6}{:<14}{}\n",
            route.methods().join(","),
            route.path(),
            route.description(),
        ));
    }
    out
}

async fn method_not_allowed(stream: &mut TcpStream, allowed: &[&str]) -> std::io::Result<()> {
    let extra = format!("allow: {}\r\n", allowed.join(", "));
    write_response(
        stream,
        "405 Method Not Allowed",
        TEXT,
        &extra,
        "method not allowed\n",
    )
    .await
}

/// reads the head, then whatever body its `content-length` announces. returns
/// `(head_len, filled)` as offsets rather than a slice: the caller parses the head
/// with `httparse`, which borrows the buffer, and a borrowed return would make the
/// body unreachable behind that borrow.
///
/// `None` means the peer closed early or the whole request exceeded `MAX_HEAD`.
/// content-length is found by a throwaway parse here for the same borrow reason.
/// nothing chunked is accepted; this is an operator surface, not a protocol.
async fn read_request(
    stream: &mut TcpStream,
    buf: &mut [u8; MAX_HEAD],
) -> std::io::Result<Option<(usize, usize)>> {
    let mut filled = 0;
    let head_len = loop {
        if filled == buf.len() {
            return Ok(None);
        }
        let n = stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Ok(None);
        }
        filled += n;
        if let Some(at) = buf[..filled].windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut probe = httparse::Request::new(&mut headers);
    if probe.parse(&buf[..head_len]).is_err() {
        return Ok(Some((head_len, filled)));
    }
    let want: usize = match probe
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
    {
        None => return Ok(Some((head_len, filled))),
        Some(h) => match std::str::from_utf8(h.value)
            .ok()
            .and_then(|v| v.trim().parse().ok())
        {
            Some(n) => n,
            None => return Ok(Some((head_len, filled))),
        },
    };
    let end = match head_len.checked_add(want) {
        Some(end) if end <= buf.len() => end,
        _ => return Ok(None),
    };
    while filled < end {
        let n = stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Ok(None);
        }
        filled += n;
    }
    Ok(Some((head_len, end)))
}

/// constant-time; an early return would leak the matched prefix. length is not
/// secret, it comes from config rather than from the guess.
fn token_matches(expected: &[u8], presented: &[u8]) -> bool {
    if expected.len() != presented.len() {
        return false;
    }
    expected
        .iter()
        .zip(presented)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// answers "should traffic come to *this instance*", which is only ever about state
/// this instance controls: draining, or an operator override.
///
/// **Backend health is deliberately not consulted.** kntx is an ingress proxy, so one
/// process fronts many unrelated services; a dead pool would take every listener out
/// of rotation over one broken upstream. Worse, every replica sees the same dead pool,
/// so the signal is identical across the target group and carries no routing
/// information at all - while an ASG on ELB health checks would happily terminate the
/// whole proxy tier mid-incident. A request to that pool already gets a clean 503, and
/// `kntx_backend_health{pool,backend}` is what alerts on it. Same reasoning as Envoy's
/// `/ready`; HAProxy makes it opt-in per rule and nobody makes it the default.
fn readiness(flags: &RuntimeFlags) -> Result<(), String> {
    if flags.is_draining() {
        return Err("not ready: listeners drained".to_owned());
    }
    if flags.health_overridden() {
        return Err("not ready: health override set via /healthcheck/fail".to_owned());
    }
    Ok(())
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    write_response(stream, status, TEXT, "", body).await
}

/// `extra` is pre-formatted CRLF-terminated header lines, or empty.
async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    extra: &str,
    body: &str,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         content-type: {content_type}\r\n\
         content-length: {}\r\n\
         {extra}\
         connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_lookup_round_trips_every_variant() {
        for route in AdminRoute::ALL {
            assert_eq!(AdminRoute::from_path(route.path()), Some(route));
            assert!(!route.methods().is_empty());
        }
        assert_eq!(AdminRoute::from_path("/nope"), None);
        assert_eq!(AdminRoute::from_path(""), None);
        // the panel is "/", so a lookup must not treat a prefix as a hit
        assert_eq!(AdminRoute::from_path("/server_info/x"), None);
    }

    #[test]
    fn sec_fetch_site_allows_only_absent_or_same_origin() {
        assert!(same_origin_or_absent(None));
        assert!(same_origin_or_absent(Some(b"same-origin")));
        assert!(same_origin_or_absent(Some(b"  same-origin  ")));
        assert!(same_origin_or_absent(Some(b"Same-Origin")));
        // same-site is the loopback-neighbour case and must still be refused
        assert!(!same_origin_or_absent(Some(b"same-site")));
        assert!(!same_origin_or_absent(Some(b"cross-site")));
        assert!(!same_origin_or_absent(Some(b"none")));
        assert!(!same_origin_or_absent(Some(b"")));
        assert!(!same_origin_or_absent(Some(b"same-originx")));
    }

    #[test]
    fn route_table_lists_every_route() {
        let table = route_table();
        for route in AdminRoute::ALL {
            assert!(table.contains(route.path()), "{} missing", route.path());
            assert!(table.contains(route.description()));
        }
    }

    #[test]
    fn form_decoding_survives_a_real_envfilter_directive() {
        // what the panel's form actually sends: every '=' and ',' percent-encoded
        let body = b"filter=kntx%3A%3Aproxy%3A%3Al7%3Ddebug%2Cinfo";
        assert_eq!(
            form_value(body, "filter").as_deref(),
            Some("kntx::proxy::l7=debug,info"),
        );

        // splitting on the first '=' only is what makes an unencoded directive work
        assert_eq!(
            form_value(b"filter=kntx=debug,info", "filter").as_deref(),
            Some("kntx=debug,info"),
        );
        assert_eq!(form_value(b"other=x", "filter"), None);
        assert_eq!(form_value(b"", "filter"), None);
        assert_eq!(form_value(b"filter=", "filter").as_deref(), Some(""));
    }

    #[test]
    fn percent_decoding_handles_the_malformed_tail() {
        assert_eq!(percent_decode("plain"), "plain");
        assert!(matches!(percent_decode("plain"), Cow::Borrowed(_)));
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%41%42"), "AB");
        // a truncated or non-hex escape is far likelier to be a typo in a directive
        // than an escape, so it survives rather than eating the next characters
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%4"), "%4");
    }

    #[test]
    fn token_compare_rejects_near_misses() {
        assert!(token_matches(b"s3cret", b"s3cret"));
        assert!(!token_matches(b"s3cret", b"s3creT"));
        assert!(!token_matches(b"s3cret", b"s3cre"));
        assert!(!token_matches(b"s3cret", b"s3cretx"));
        assert!(!token_matches(b"s3cret", b""));
        assert!(token_matches(b"", b""));
    }
}
