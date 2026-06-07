//! Shared logger initialization for the PAM modules.
//!
//! Both PAM modules (`pinpam-pam` and `pinpam-master-key-pam`) want to route
//! `log` output to syslog's `authpriv` facility and silence the noisy TSS
//! library by default. This module owns that wiring so the modules don't have
//! to keep parallel copies in sync.

use std::env;
use std::process;
use std::sync::OnceLock;

use log::LevelFilter;
use syslog::{BasicLogger, Facility, Formatter3164};

/// Install the syslog backend for the `log` crate. Subsequent calls are no-ops.
///
/// `process_name` becomes the syslog process tag.
pub fn init_syslog_logger(process_name: &'static str) {
    static LOGGER_INIT: OnceLock<()> = OnceLock::new();
    LOGGER_INIT.get_or_init(|| install(process_name));
}

/// Default `TSS2_LOG` to `all+NONE` unless the caller already set logging
/// preferences via `RUST_LOG`. Idempotent.
pub fn suppress_tss_logs() {
    static SUPPRESS_LOGS: OnceLock<()> = OnceLock::new();
    SUPPRESS_LOGS.get_or_init(|| {
        if env::var_os("RUST_LOG").is_none() {
            // SAFETY: set early, before any spawned threads observe the env.
            unsafe {
                env::set_var("TSS2_LOG", "all+NONE");
            }
        }
    });
}

fn install(process_name: &'static str) {
    let rust_log = env::var("RUST_LOG").ok();

    let mut env_builder = env_logger::Builder::new();
    env_builder.filter_level(LevelFilter::Info);
    if let Some(ref value) = rust_log {
        env_builder.parse_filters(value);
    }

    let max_level = rust_log
        .as_deref()
        .map(|value| {
            if value.contains('=') || value.contains(',') {
                LevelFilter::Trace
            } else {
                value.parse::<LevelFilter>().unwrap_or(LevelFilter::Trace)
            }
        })
        .unwrap_or(LevelFilter::Info);

    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTHPRIV,
        hostname: None,
        process: process_name.to_owned(),
        pid: process::id(),
    };

    let Ok(writer) = syslog::unix(formatter) else {
        let _ = env_builder.try_init();
        return;
    };

    if log::set_boxed_logger(Box::new(BasicLogger::new(writer))).is_ok() {
        log::set_max_level(max_level);
    } else {
        let _ = env_builder.try_init();
    }
}
