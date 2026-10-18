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

pub(crate) fn parse_env_usize(val: Option<&str>, default: usize, min: usize, max: usize) -> usize {
    match val {
        Some(s) => match s.trim().parse::<usize>() {
            Ok(0) => default,
            Ok(v) => v.clamp(min, max),
            Err(_) => default,
        },
        None => default,
    }
}

pub(crate) fn parse_timeout_ms(val: Option<&str>) -> Option<u64> {
    match val {
        Some(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(ms) => Some(ms.clamp(50, 600_000)),
            Err(_) => None,
        },
        None => None,
    }
}

fn env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    let var = std::env::var(name).ok();
    parse_env_usize(var.as_deref(), default, min, max)
}

fn build() -> Limits {
    // One knob overrides every phase timeout at once; meant for tests and for
    // operators who want a single tighter value. Invalid or zero values fall
    // back to the defaults.
    let var = std::env::var("SUBGATE_TIMEOUT_MS").ok();
    let timeout_ms = parse_timeout_ms(var.as_deref());
    let phase = |default: u64| Duration::from_millis(timeout_ms.unwrap_or(default));

    Limits {
        max_conns: env_usize("SUBGATE_MAX_CONNS", DEFAULT_MAX_CONNS, 1, 65_535),
        idle: phase(65_000),
        header: phase(60_000),
        body: phase(60_000),
        write: phase(60_000),
        max_body: DEFAULT_MAX_BODY,
        max_ranges: DEFAULT_MAX_RANGES,
        max_head: DEFAULT_MAX_HEAD,
        max_headers: DEFAULT_MAX_HEADERS,
        keepalive_requests: env_usize(
            "SUBGATE_KEEPALIVE_REQUESTS",
            DEFAULT_KEEPALIVE_REQUESTS,
            1,
            100_000,
        ),
    }
}

static LIMITS: LazyLock<Limits> = LazyLock::new(build);

pub fn limits() -> &'static Limits {
    &LIMITS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_usize_clamps_and_handles_bad_values() {
        // Zero falls back to default
        assert_eq!(parse_env_usize(Some("0"), 512, 1, 65535), 512);
        // Negative / invalid falls back to default
        assert_eq!(parse_env_usize(Some("-10"), 512, 1, 65535), 512);
        assert_eq!(parse_env_usize(Some("not-a-number"), 512, 1, 65535), 512);
        assert_eq!(parse_env_usize(None, 512, 1, 65535), 512);
        // In-range value kept
        assert_eq!(parse_env_usize(Some("128"), 512, 1, 65535), 128);
        // Huge value clamped
        assert_eq!(parse_env_usize(Some("999999999"), 512, 1, 65535), 65535);
    }

    #[test]
    fn timeout_ms_clamps_and_handles_bad_values() {
        // Zero is invalid, falls back to None (which uses defaults)
        assert_eq!(parse_timeout_ms(Some("0")), None);
        // Negative / garbage falls back to None
        assert_eq!(parse_timeout_ms(Some("-1")), None);
        assert_eq!(parse_timeout_ms(Some("abc")), None);
        assert_eq!(parse_timeout_ms(None), None);
        // Very small value clamped to minimum (50ms)
        assert_eq!(parse_timeout_ms(Some("10")), Some(50));
        // Normal value kept
        assert_eq!(parse_timeout_ms(Some("5000")), Some(5000));
        // Pathologically large value clamped to maximum (600,000ms = 10 min)
        assert_eq!(parse_timeout_ms(Some("100000000")), Some(600_000));
    }
}
