//! Resource limits, all in one place.
//!
//! Every bound the network-facing code enforces lives here so the defaults can
//! be reviewed (and overridden in tests) from a single module. Values are read
//! once at first use into a `static`; env overrides are parsed then too, so a
//! change requires a restart rather than re-reading the environment per
//! request.

use std::sync::LazyLock;
use std::time::Duration;

/// Upper bound for one request line plus headers, comparable to nginx's
/// `large_client_header_buffers`.
const DEFAULT_MAX_HEAD: usize = 16 * 1024;

/// nginx's default for `keepalive_requests`.
const DEFAULT_KEEPALIVE_REQUESTS: usize = 1000;

/// Maximum number of ranges published in one multipart response.
const DEFAULT_MAX_RANGES: usize = 100;

/// Concurrent connections. Excess connections are closed on accept, not
/// queued.
const DEFAULT_MAX_CONNS: usize = 512;

/// 8 MiB request body bound; larger bodies are refused with 413.
const DEFAULT_MAX_BODY: usize = 8 * 1024 * 1024;

/// 100 request headers, nginx's `large_client_header_buffers` count.
const DEFAULT_MAX_HEADERS: usize = 100;

pub struct Limits {
    pub max_conns: usize,
    /// Idle keep-alive wait before a silent close (nginx `keepalive_timeout`).
    pub idle: Duration,
    /// Time to receive a full request head once the first byte arrived.
    pub header: Duration,
    /// Time to receive a declared request body.
    pub body: Duration,
    /// Time to write one response.
    pub write: Duration,
    pub max_body: usize,
    pub max_ranges: usize,
    pub max_head: usize,
    pub max_headers: usize,
    pub keepalive_requests: usize,
}

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(v) => v.trim().parse().unwrap_or(default),
        Err(_) => default,
    }
}

fn build() -> Limits {
    // One knob overrides every phase timeout at once; meant for tests and for
    // operators who want a single tighter value. Invalid values fall back to
    // the defaults.
    let timeout_ms = std::env::var("SUBGATE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    let phase = |default: u64| Duration::from_millis(timeout_ms.unwrap_or(default));

    Limits {
        max_conns: env_usize("SUBGATE_MAX_CONNS", DEFAULT_MAX_CONNS),
        idle: phase(65_000),
        header: phase(60_000),
        body: phase(60_000),
        write: phase(60_000),
        max_body: DEFAULT_MAX_BODY,
        max_ranges: DEFAULT_MAX_RANGES,
        max_head: DEFAULT_MAX_HEAD,
        max_headers: DEFAULT_MAX_HEADERS,
        keepalive_requests: env_usize("SUBGATE_KEEPALIVE_REQUESTS", DEFAULT_KEEPALIVE_REQUESTS),
    }
}

static LIMITS: LazyLock<Limits> = LazyLock::new(build);

pub fn limits() -> &'static Limits {
    &LIMITS
}
