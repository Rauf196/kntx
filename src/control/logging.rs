//! Runtime log filter, behind `GET`/`POST /logging`.
//!
//! The incident this exists for: something is wrong at 3am and the debug output is
//! on a process that cannot be bounced.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::registry::Registry;
use tracing_subscriber::reload;

/// wrapped and attached to the registry *before* the fmt layer, which pins `S` to
/// `Registry` in both output formats. attaching it after the fmt layer would make
/// the handle type depend on which format was chosen.
pub type FilterLayer = reload::Layer<EnvFilter, Registry>;

#[derive(Debug, Error)]
pub enum LogFilterError {
    #[error("'{directive}' is not a valid filter directive")]
    Parse { directive: String },
    #[error("the subscriber is gone")]
    Detached,
}

#[derive(Clone)]
pub struct LogFilterHandle {
    handle: reload::Handle<EnvFilter, Registry>,
    /// true once something outside the config file owns the filter: `RUST_LOG` at
    /// startup, or a `POST /logging`. a reload then leaves the filter alone, so a
    /// config push during an incident cannot silence debug output someone just
    /// turned on, and cannot override an explicit environment setting either.
    overridden: Arc<AtomicBool>,
}

pub fn log_filter_layer(initial: EnvFilter, overridden: bool) -> (FilterLayer, LogFilterHandle) {
    let (layer, handle) = reload::Layer::new(initial);
    (
        layer,
        LogFilterHandle {
            handle,
            overridden: Arc::new(AtomicBool::new(overridden)),
        },
    )
}

impl LogFilterHandle {
    pub fn current(&self) -> String {
        self.handle
            .with_current(|f| f.to_string())
            .unwrap_or_default()
    }

    /// parses before swapping, so a typo at 3am cannot silence the process.
    pub fn set(&self, directive: &str) -> Result<(), LogFilterError> {
        let filter = EnvFilter::try_new(directive).map_err(|_| LogFilterError::Parse {
            directive: directive.to_owned(),
        })?;
        // logged before the swap: after it, the new filter may exclude this event
        tracing::warn!(
            from = %self.current(),
            to = directive,
            "log filter changed at runtime, config reloads will no longer move it",
        );
        self.handle
            .reload(filter)
            .map_err(|_| LogFilterError::Detached)?;
        self.overridden.store(true, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(test)]
    fn is_overridden(&self) -> bool {
        self.overridden.load(Ordering::Relaxed)
    }

    /// applies the reloaded file's `[logging] level`. a no-op once anything has
    /// overridden the filter, which is what makes the override outlive SIGHUP.
    pub fn apply_config_level(&self, level: &str) {
        if self.overridden.load(Ordering::Relaxed) || self.current() == level {
            return;
        }
        match EnvFilter::try_new(level) {
            // config validation does not check the directive grammar, so a bad
            // level here is a live config the process is already running under
            Err(_) => tracing::warn!(
                level,
                "[logging] level is not a valid filter, keeping the running one"
            ),
            Ok(filter) => {
                tracing::info!(level, "[logging] level applied from reloaded config");
                let _ = self.handle.reload(filter);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// the layer owns the filter the handle reaches through, so every test holds it
    /// for as long as it uses the handle.
    fn handle(initial: &str, overridden: bool) -> (FilterLayer, LogFilterHandle) {
        log_filter_layer(EnvFilter::new(initial), overridden)
    }

    #[test]
    fn set_rejects_a_bad_directive_without_touching_the_filter() {
        let (_layer, h) = handle("info", false);

        // the failure mode this guards: a typo at 3am silencing the process.
        // note `kntx::l7=` is NOT here - a bare target with no level is valid
        // EnvFilter syntax, so rejecting it would be wrong.
        for bad in ["=", "kntx=nonsense", "==info", "kntx=debug,=,"] {
            assert!(
                matches!(h.set(bad), Err(LogFilterError::Parse { .. })),
                "{bad} was accepted"
            );
            assert_eq!(h.current(), "info", "{bad} moved the filter");
        }
        assert!(
            !h.is_overridden(),
            "a rejected directive claimed the filter"
        );
    }

    #[test]
    fn set_installs_a_directive_and_claims_the_filter() {
        let (_layer, h) = handle("info", false);
        assert_eq!(h.current(), "info");

        h.set("kntx::proxy::l7=debug,info")
            .expect("valid directive");
        assert!(
            h.current().contains("kntx::proxy::l7=debug"),
            "{}",
            h.current()
        );
        assert!(h.is_overridden());
    }

    #[test]
    fn a_reload_moves_the_filter_only_while_nothing_has_claimed_it() {
        let (_layer, h) = handle("info", false);

        // nothing has claimed it, so editing the file and sending SIGHUP works
        h.apply_config_level("warn");
        assert_eq!(h.current(), "warn");

        // once an operator sets one, a config push must not silence their output
        h.set("debug").unwrap();
        h.apply_config_level("error");
        assert_eq!(h.current(), "debug", "a reload undid the runtime override");
    }

    #[test]
    fn rust_log_at_startup_outranks_the_config_file() {
        let (_layer, h) = handle("trace", true);
        h.apply_config_level("error");
        assert_eq!(
            h.current(),
            "trace",
            "a reload overrode an explicit RUST_LOG setting",
        );
    }

    #[test]
    fn a_bad_config_level_leaves_the_running_filter_alone() {
        let (_layer, h) = handle("info", false);
        // config validation does not check directive grammar, so this reaches here
        h.apply_config_level("=");
        assert_eq!(h.current(), "info");
    }

    #[test]
    fn a_detached_handle_reports_an_error_rather_than_panicking() {
        let (layer, h) = handle("info", false);
        drop(layer);
        assert!(matches!(h.set("debug"), Err(LogFilterError::Detached)));
    }
}
