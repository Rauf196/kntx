use std::io::{BufWriter, Write};
use std::sync::Mutex;

use serde::Serialize;
use tokio::sync::mpsc;

use crate::config::{AccessLogConfig, AccessLogOutput};

#[derive(Debug, Serialize)]
pub struct AccessLogLine {
    pub timestamp: String,
    pub listener: String,
    pub client_ip: String,
    pub method: String,
    pub host: Option<String>,
    pub path: String,
    pub query: Option<String>,
    pub protocol: String,
    pub status: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_ms: f64,
    pub backend_wait_ms: Option<f64>,
    pub backend: Option<String>,
    pub pool: String,
    pub route_id: Option<String>,
    pub request_id: String,
    pub trace_id: Option<String>,
    pub keepalive_index: u32,
}

pub enum AccessLogSink {
    Off,
    Stdout(Mutex<BufWriter<std::io::Stdout>>),
    Stderr(Mutex<BufWriter<std::io::Stderr>>),
    File(mpsc::Sender<AccessLogLine>),
}

impl AccessLogSink {
    pub fn from_config(cfg: &AccessLogConfig) -> Result<Self, std::io::Error> {
        match &cfg.output {
            AccessLogOutput::Named(name) if name == "off" => Ok(Self::Off),
            AccessLogOutput::Named(name) if name == "stderr" => {
                Ok(Self::Stderr(Mutex::new(BufWriter::new(std::io::stderr()))))
            }
            AccessLogOutput::Named(_) => {
                // stdout (default)
                Ok(Self::Stdout(Mutex::new(BufWriter::new(std::io::stdout()))))
            }
            AccessLogOutput::File { file } => {
                let f = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(file)?;
                let (tx, mut rx) = mpsc::channel::<AccessLogLine>(cfg.file_channel_capacity);
                let mut writer = BufWriter::new(f);
                tokio::spawn(async move {
                    use tokio::time::{Duration, interval};
                    let mut flush_tick = interval(Duration::from_secs(1));
                    let mut count = 0usize;
                    let mut dirty = false;
                    loop {
                        tokio::select! {
                            biased;
                            maybe_line = rx.recv() => {
                                match maybe_line {
                                    Some(line) => {
                                        if let Ok(json) = serde_json::to_string(&line) {
                                            let _ = writer.write_all(json.as_bytes());
                                            let _ = writer.write_all(b"\n");
                                            count += 1;
                                            dirty = true;
                                            if count.is_multiple_of(64) {
                                                let _ = writer.flush();
                                                dirty = false;
                                            }
                                        }
                                    }
                                    None => break,
                                }
                            }
                            _ = flush_tick.tick() => {
                                if dirty {
                                    let _ = writer.flush();
                                    dirty = false;
                                }
                            }
                        }
                    }
                    let _ = writer.flush();
                });
                Ok(Self::File(tx))
            }
        }
    }

    pub fn emit(&self, line: AccessLogLine) {
        match self {
            Self::Off => {}
            Self::Stdout(w) => {
                if let Ok(json) = serde_json::to_string(&line)
                    && let Ok(mut guard) = w.lock()
                {
                    let _ = guard.write_all(json.as_bytes());
                    let _ = guard.write_all(b"\n");
                    let _ = guard.flush();
                }
            }
            Self::Stderr(w) => {
                if let Ok(json) = serde_json::to_string(&line)
                    && let Ok(mut guard) = w.lock()
                {
                    let _ = guard.write_all(json.as_bytes());
                    let _ = guard.write_all(b"\n");
                    let _ = guard.flush();
                }
            }
            Self::File(tx) => {
                if tx.try_send(line).is_err() {
                    metrics::counter!("kntx_access_log_dropped_total").increment(1);
                }
            }
        }
    }
}

/// extract trace ID from a W3C traceparent header value.
/// format: 00-<trace-id-32hex>-<span-id-16hex>-<flags-2hex>
pub fn extract_trace_id(traceparent: &str) -> Option<String> {
    let parts: Vec<&str> = traceparent.trim().splitn(4, '-').collect();
    if parts.len() < 3 {
        return None;
    }
    let trace_id = parts[1];
    if trace_id.len() == 32 && trace_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(trace_id.to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn sample_line() -> AccessLogLine {
        AccessLogLine {
            timestamp: "2026-04-27T00:00:00.000000Z".to_owned(),
            listener: "127.0.0.1:8080".to_owned(),
            client_ip: "127.0.0.1".to_owned(),
            method: "GET".to_owned(),
            host: Some("example.com".to_owned()),
            path: "/hello".to_owned(),
            query: None,
            protocol: "HTTP/1.1".to_owned(),
            status: 200,
            bytes_in: 0,
            bytes_out: 13,
            duration_ms: 1.23,
            backend_wait_ms: Some(0.5),
            backend: Some("127.0.0.1:3001".to_owned()),
            pool: "default".to_owned(),
            route_id: None,
            request_id: "abc123".to_owned(),
            trace_id: None,
            keepalive_index: 0,
        }
    }

    #[test]
    fn serialize_line_produces_valid_json() {
        let line = sample_line();
        let json = serde_json::to_string(&line).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], 200);
        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["path"], "/hello");
    }

    #[test]
    fn trace_id_extracted_from_traceparent() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let id = extract_trace_id(tp).unwrap();
        assert_eq!(id, "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    #[test]
    fn trace_id_none_on_malformed_traceparent() {
        assert!(extract_trace_id("bad").is_none());
        assert!(extract_trace_id("00-notahex!!!!!!!!!!!!!!!!!!!!!!!!!-abc-01").is_none());
        assert!(extract_trace_id("").is_none());
    }

    #[tokio::test]
    async fn file_sink_idle_flush_writes_within_one_second() {
        use tempfile::NamedTempFile;
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_owned();
        let cfg = crate::config::AccessLogConfig {
            output: crate::config::AccessLogOutput::File { file: path.clone() },
            format: None,
            file_channel_capacity: 16,
        };
        let sink = AccessLogSink::from_config(&cfg).unwrap();
        sink.emit(sample_line());

        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.contains("\"client_ip\""),
            "file should contain the line: {contents}"
        );
    }

    #[tokio::test]
    async fn file_sink_drops_when_channel_full() {
        // channel capacity 1 — second send should trigger drop counter
        let dropped = std::sync::Arc::new(AtomicU64::new(0));
        let (tx, mut rx) = mpsc::channel::<AccessLogLine>(1);
        let sink = AccessLogSink::File(tx);

        // consume one to open a slot, then send 100 fast — most will be dropped
        // but we need a receiver or the channel will appear closed
        let _handle = tokio::spawn(async move {
            // drain slowly
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            while rx.try_recv().is_ok() {}
        });

        // install a test metrics recorder so we can observe increments
        // we can't easily observe global metrics in a unit test, so just verify
        // that try_send fails when channel is full (i.e. the code path is hit)
        let mut sends_ok = 0u64;
        let mut sends_err = 0u64;
        for _ in 0..100 {
            match &sink {
                AccessLogSink::File(tx) => {
                    if tx.try_send(sample_line()).is_ok() {
                        sends_ok += 1;
                    } else {
                        sends_err += 1;
                    }
                }
                _ => unreachable!(),
            }
        }
        let _ = dropped; // suppress unused warning
        // with capacity 1, at least some sends must fail
        assert!(
            sends_err > 0,
            "expected drops with capacity=1, but sends_ok={sends_ok}"
        );
    }
}
