//! The admin page: one self-contained HTML file rendering the same reports the
//! JSON routes serve.
//!
//! No JavaScript, no framework, no build step, no external assets. The buttons are
//! plain forms, which is what the `sec-fetch-site` check in `mod.rs` buys: no token
//! in a URL and no session to manage.
//!
//! It renders `ServerInfo` and `PoolsReport` rather than a `Snapshot`, so a field
//! added to `/pools` and forgotten here is a missing column, not a disagreement.

use std::borrow::Cow;

use super::report::{PoolsReport, ServerInfo};

const STYLE: &str = "\
:root{color-scheme:light dark}\
body{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;margin:2rem auto;max-width:60rem;padding:0 1rem}\
h1{font-size:1.2rem;margin:0 0 .2rem}\
h2{font-size:.85rem;text-transform:uppercase;letter-spacing:.08em;opacity:.6;margin:2rem 0 .5rem;font-weight:600}\
.meta{opacity:.6;margin:0 0 .5rem}\
.tag{border:1px solid;border-radius:3px;padding:0 .4em;font-size:.8em;vertical-align:.15em}\
.draining,.notready{color:#b45309}\
.ready{color:#16a34a}\
table{border-collapse:collapse;width:100%}\
th{text-align:left;font-weight:600;opacity:.6;font-size:.85em}\
th,td{padding:.25rem .6rem .25rem 0;border-bottom:1px solid rgba(128,128,128,.25)}\
.n{text-align:right;font-variant-numeric:tabular-nums}\
.open{color:#dc2626;font-weight:600}\
.half_open{color:#b45309}\
.drained{opacity:.5}\
form{display:inline}\
button,input{font:inherit;padding:.25rem .6rem;border:1px solid rgba(128,128,128,.5);border-radius:3px;background:transparent;color:inherit}\
button{cursor:pointer}\
input{width:24rem;max-width:100%}\
pre{overflow-x:auto;border:1px solid rgba(128,128,128,.25);padding:.75rem;border-radius:3px}\
a{color:inherit}\
summary{cursor:pointer;opacity:.6}\
";

/// escapes into element text and double-quoted attributes. pool names, addresses and
/// filter directives are operator-authored rather than attacker-supplied, so this is
/// hygiene - but a pool name containing `<` would silently break the page.
pub fn escape_html(s: &str) -> Cow<'_, str> {
    if !s.contains(['&', '<', '>', '"']) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// browsers send `text/html` in `Accept`; curl sends `*/*` or nothing. anything that
/// does not ask for HTML gets the plain-text branch.
pub fn wants_html(accept: Option<&[u8]>) -> bool {
    accept.is_some_and(|v| {
        std::str::from_utf8(v).is_ok_and(|v| v.to_ascii_lowercase().contains("text/html"))
    })
}

fn uptime(secs: u64) -> String {
    match (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60) {
        (0, 0, m) => format!("{m}m"),
        (0, h, m) => format!("{h}h {m}m"),
        (d, h, _) => format!("{d}d {h}h"),
    }
}

/// deliberately static. an earlier version reloaded itself every 5s, which discarded
/// whatever was half-typed in the filter box and collapsed the config dump - two of
/// the three things on the page. this is a control surface, not a wallboard, and
/// drain progress lives on `/metrics` rather than here.
pub fn render(
    info: &ServerInfo,
    pools: &PoolsReport<'_>,
    log_filter: &str,
    config_json: &str,
    not_ready: Option<&str>,
) -> String {
    let mut h = String::with_capacity(8192);
    h.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    h.push_str("<title>kntx admin</title><style>");
    h.push_str(STYLE);
    h.push_str("</style></head><body>");

    let draining = info.state == "draining";
    h.push_str("<h1>kntx <span class=\"tag");
    if draining {
        h.push_str(" draining");
    }
    h.push_str("\">");
    h.push_str(info.state);
    h.push_str("</span> ");
    // the fail/ok buttons below change exactly this, so the page has to show it or
    // clicking one produces no visible result
    match not_ready {
        None => h.push_str("<span class=\"tag ready\">ready</span>"),
        Some(_) => h.push_str("<span class=\"tag notready\">not ready</span>"),
    }
    h.push_str("</h1>");
    if let Some(reason) = not_ready {
        h.push_str(&format!(
            "<p class=\"meta notready\">{}</p>",
            escape_html(reason),
        ));
    }
    h.push_str(&format!(
        "<p class=\"meta\">v{} &middot; up {} &middot; config v{} &middot; {} pool{}</p>",
        escape_html(info.version),
        uptime(info.uptime_secs),
        info.config_version,
        info.pools,
        if info.pools == 1 { "" } else { "s" },
    ));

    h.push_str("<h2>pools</h2>");
    if pools.pools.is_empty() {
        h.push_str("<p class=\"meta\">no pools configured</p>");
    } else {
        // the numeric headers carry the same class as their cells; without it the
        // column reads left-aligned over right-aligned figures
        h.push_str(
            "<table><thead><tr><th>pool<th>strategy<th>backend<th>circuit\
             <th class=\"n\">weight<th class=\"n\">active<th class=\"n\">fails\
             <th class=\"n\">idle<th class=\"n\">conns</tr></thead><tbody>",
        );
        for pool in &pools.pools {
            let strategy = serde_json::to_string(&pool.strategy).unwrap_or_default();
            for (i, b) in pool.backends.iter().enumerate() {
                h.push_str("<tr><td>");
                // repeating the pool name on every row would make the table harder
                // to scan than leaving the continuation rows blank
                if i == 0 {
                    h.push_str(&escape_html(pool.name));
                }
                h.push_str("<td>");
                if i == 0 {
                    h.push_str(&escape_html(strategy.trim_matches('"')));
                }
                h.push_str(&format!(
                    "<td>{}<td class=\"{}\">{}<td class=\"n\">{}<td class=\"n\">{}\
                     <td class=\"n\">{}<td class=\"n\">{}<td class=\"n\">{}</tr>",
                    b.address,
                    b.circuit,
                    b.circuit,
                    b.weight,
                    b.active,
                    b.consecutive_failures,
                    b.keepalive_idle,
                    b.total_conns,
                ));
            }
        }
        h.push_str("</tbody></table>");
    }

    // relative actions: an absolute URL naming a different host spelling than the
    // address bar turns the panel's own POST into a cross-site one and it is refused
    h.push_str("<h2>actions</h2>");
    h.push_str(
        "<form method=\"post\" action=\"/healthcheck/fail\"><button>fail health</button></form> ",
    );
    h.push_str("<form method=\"post\" action=\"/healthcheck/ok\"><button>ok</button></form> ");
    h.push_str(
        "<form method=\"post\" action=\"/drain_listeners\"><button>drain listeners</button></form>",
    );
    if draining {
        // same amber as the tag and the readiness reason, and at full opacity: the
        // `meta` style this used to carry is 0.6 and read as page furniture
        h.push_str(
            "<p class=\"notready\">in-flight work finishes on its own. \
             kntx_connections_active on the metrics socket reaches 0 when it has. \
             SIGHUP re-binds.</p>",
        );
    }

    h.push_str("<h2>log filter</h2>");
    h.push_str(&format!(
        "<form method=\"post\" action=\"/logging\">\
         <input name=\"filter\" value=\"{}\" aria-label=\"log filter directive\">\
         <button>apply</button></form>",
        escape_html(log_filter),
    ));

    h.push_str(
        "<h2>config</h2><details><summary>running config, [admin] token redacted</summary><pre>",
    );
    h.push_str(&escape_html(config_json));
    h.push_str("</pre></details></body></html>");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_every_metacharacter_and_borrows_when_it_can() {
        assert_eq!(escape_html("plain"), "plain");
        assert!(matches!(escape_html("plain"), Cow::Borrowed(_)));
        assert_eq!(
            escape_html("<script>&\"x\""),
            "&lt;script&gt;&amp;&quot;x&quot;"
        );
        // the realistic break: a pool name or directive that closes the tag early
        assert_eq!(escape_html("a\"><b"), "a&quot;&gt;&lt;b");
    }

    #[test]
    fn html_is_wanted_only_when_asked_for() {
        assert!(wants_html(Some(b"text/html,application/xhtml+xml")));
        assert!(wants_html(Some(b"TEXT/HTML")));
        // curl's default, and the absent case
        assert!(!wants_html(Some(b"*/*")));
        assert!(!wants_html(None));
        assert!(!wants_html(Some(b"application/json")));
    }

    #[test]
    fn uptime_reads_at_every_scale() {
        assert_eq!(uptime(0), "0m");
        assert_eq!(uptime(59), "0m");
        assert_eq!(uptime(60), "1m");
        assert_eq!(uptime(3599), "59m");
        assert_eq!(uptime(3600), "1h 0m");
        assert_eq!(uptime(86_399), "23h 59m");
        assert_eq!(uptime(86_400), "1d 0h");
        assert_eq!(uptime(200_000), "2d 7h");
    }
}
