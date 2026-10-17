//! Generate HTTP headers and HTTP times by nginx's rules.

use crate::assets;
use std::time::{SystemTime, UNIX_EPOCH};

/// Format a timestamp as RFC 1123 (the format used by `Date` and `Last-Modified`).
///
/// No chrono: a single fixed format does not justify the dependency.
pub fn rfc1123(unix: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days = unix.div_euclid(86400);
    let secs_of_day = unix.rem_euclid(86400);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // 1970-01-01 is a Thursday, and index 0 is Thu.
    let weekday = WEEKDAYS[days.rem_euclid(7) as usize];

    // Howard Hinnant's civil_from_days algorithm.
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        weekday,
        d,
        MONTHS[(m - 1) as usize],
        year,
        hour,
        minute,
        second
    )
}

/// Parse one of the three HTTP date formats nginx accepts, or return `None`.
///
/// Supported formats:
/// - IMF-fixdate：`Sun, 06 Nov 1994 08:49:37 GMT`
/// - RFC 850：`Sunday, 06-Nov-94 08:49:37 GMT`
/// - asctime：`Sun Nov  6 08:49:37 1994`
///
/// A subset of `ngx_parse_http_time()` that covers the real inputs of
/// `If-Modified-Since` and `If-Range`.
pub fn parse_http_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(v) = parse_imf_fixdate(s) {
        return Some(v);
    }
    if let Some(v) = parse_rfc850(s) {
        return Some(v);
    }
    parse_asctime(s)
}

fn month_index(m: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    MONTHS.iter().position(|x| *x == m).map(|i| i as i64)
}

/// Convert a civil date to Unix seconds, UTC.
fn to_unix(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hour * 3600 + minute * 60 + second
}

fn parse_time_of_day(t: &str) -> Option<(i64, i64, i64)> {
    let mut it = t.split(':');
    let h: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let s: i64 = it.next()?.parse().ok()?;
    if it.next().is_some() || h > 23 || m > 59 || s > 60 {
        return None;
    }
    Some((h, m, s))
}

fn parse_imf_fixdate(s: &str) -> Option<i64> {
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    let (_, rest) = s.split_once(", ")?;
    let mut it = rest.split(' ');
    let day: i64 = it.next()?.parse().ok()?;
    let month = month_index(it.next()?)?;
    let year: i64 = it.next()?.parse().ok()?;
    let (h, mi, se) = parse_time_of_day(it.next()?)?;
    if it.next()? != "GMT" || it.next().is_some() {
        return None;
    }
    Some(to_unix(year, month + 1, day, h, mi, se))
}

fn parse_rfc850(s: &str) -> Option<i64> {
    // "Sunday, 06-Nov-94 08:49:37 GMT"
    let (_, rest) = s.split_once(", ")?;
    let mut it = rest.split(' ');
    let date = it.next()?;
    let (d, mo, y) = {
        let mut p = date.split('-');
        (p.next()?, p.next()?, p.next()?)
    };
    let day: i64 = d.parse().ok()?;
    let month = month_index(mo)?;
    let mut year: i64 = y.parse().ok()?;
    if year < 100 {
        year += if year < 70 { 2000 } else { 1900 };
    }
    let (h, mi, se) = parse_time_of_day(it.next()?)?;
    if it.next()? != "GMT" || it.next().is_some() {
        return None;
    }
    Some(to_unix(year, month + 1, day, h, mi, se))
}

fn parse_asctime(s: &str) -> Option<i64> {
    // "Sun Nov  6 08:49:37 1994"
    let mut it = s.split_whitespace();
    it.next()?; // weekday, ignored
    let month = month_index(it.next()?)?;
    let day: i64 = it.next()?.parse().ok()?;
    let (h, mi, se) = parse_time_of_day(it.next()?)?;
    let year: i64 = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some(to_unix(year, month + 1, day, h, mi, se))
}

/// The current time in seconds.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// nginx's ETag: `"<mtime in hex>-<size in hex>"`.
///
/// See `ngx_http_set_etag()`, which formats the file's mtime and size exactly
/// this way.
pub fn etag(mtime: u64, size: u64) -> String {
    format!("\"{:x}-{:x}\"", mtime, size)
}

/// The ETag of the home page, with static-file semantics.
pub fn index_etag() -> String {
    etag(assets::INDEX_MTIME, assets::INDEX_SIZE as u64)
}

/// The `Last-Modified` of the home page.
pub fn index_last_modified() -> String {
    rfc1123(assets::INDEX_MTIME as i64)
}

/// The `Date` header for the current time.
pub fn date_now() -> String {
    rfc1123(now_unix())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_timestamps() {
        assert_eq!(rfc1123(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(rfc1123(784111777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(rfc1123(951782400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(rfc1123(1709164800), "Thu, 29 Feb 2024 00:00:00 GMT");
        // The real mtime of Ubuntu's home page: Thu, 02 Jul 2026 19:09:05 GMT
        assert_eq!(rfc1123(1783019345), "Thu, 02 Jul 2026 19:09:05 GMT");
    }

    #[test]
    fn month_end_and_year_end() {
        assert_eq!(rfc1123(1735603200), "Tue, 31 Dec 2024 00:00:00 GMT");
        assert_eq!(rfc1123(1735689599), "Tue, 31 Dec 2024 23:59:59 GMT");
        assert_eq!(rfc1123(1735689600), "Wed, 01 Jan 2025 00:00:00 GMT");
    }

    #[test]
    fn roundtrip_all_formats() {
        let t = 784111777; // Sun, 06 Nov 1994 08:49:37 GMT
        assert_eq!(parse_http_time("Sun, 06 Nov 1994 08:49:37 GMT"), Some(t));
        assert_eq!(parse_http_time("Sunday, 06-Nov-94 08:49:37 GMT"), Some(t));
        assert_eq!(parse_http_time("Sun Nov  6 08:49:37 1994"), Some(t));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse_http_time("yesterday"), None);
        assert_eq!(parse_http_time("Sun, 06 Foo 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_time("Sun, 06 Nov 1994 08:49:37 UTC"), None);
    }

    #[test]
    fn etag_format() {
        assert_eq!(etag(0x6a46b751, 0x267), "\"6a46b751-267\"");
    }
}
