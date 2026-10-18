//! `Range` request parsing and response construction, aligned with
//! `ngx_http_range_filter_module.c`.
//!
//! Only a single resource (the home page) is handled, and `max_ranges` is
//! treated as unlimited (Ubuntu's default leaves it unset).
//!
//! Rules taken from the source:
//! - the value must start with `bytes=` and be at least 7 bytes long.
//! - spaces are allowed around numbers; `0-` means to the end; `-N` means the
//!   last N bytes.
//! - a malformed single range (non-numeric, bad shape) yields 416.
//! - an empty range such as `0-0` falls back to a full 200.
//! - ranges are clamped to the resource length; a start >= length is empty.
//! - if every range is empty, the result is 416.
//! - the boundary is a process-wide atomic counter, zero-padded to 20 decimal
//!   digits.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::limits::limits;

/// nginx's `ngx_next_temp_number()`: starts at 1, zero-padded to 20 digits.
static BOUNDARY: AtomicU64 = AtomicU64::new(1);

fn next_boundary() -> u64 {
    BOUNDARY.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Ignore `Range` and send the full 200 body.
    Full,
    /// A single range.
    Single { start: usize, end: usize },
    /// Multiple ranges.
    Multipart(Vec<(usize, usize)>),
    /// Not satisfiable.
    Unsatisfiable,
}

/// Parse a `Range` header value.
pub fn parse(value: &str, len: usize) -> Outcome {
    // Byte-wise prefix check: slicing `value[..6]` would panic when byte 6
    // falls inside a multi-byte character (release builds abort on panic, so a
    // remote request must never reach that path).
    if value.len() < 7 || !value.as_bytes()[..6].eq_ignore_ascii_case(b"bytes=") {
        return Outcome::Full;
    }

    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let body = &value[6..];

    for part in body.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Bound the number of published ranges so a header full of commas
        // cannot amplify into a huge multipart body.
        if ranges.len() >= limits().max_ranges {
            return Outcome::Full;
        }

        let Some((first, last)) = part.split_once('-') else {
            return Outcome::Unsatisfiable;
        };
        let first = first.trim();
        let last = last.trim();

        if first.is_empty() && last.is_empty() {
            // `bytes=-` is invalid; nginx returns 416.
            return Outcome::Unsatisfiable;
        }

        let (start, end) = if first.is_empty() {
            // Suffix form: -N. For n=0 the source yields start=len and
            // end=len-1, which is empty -> 416.
            let Some(n) = parse_num(last) else {
                return Outcome::Unsatisfiable;
            };
            if n == 0 {
                (len, len.saturating_sub(1))
            } else {
                (len.saturating_sub(n), len)
            }
        } else {
            let Some(start) = parse_num(first) else {
                return Outcome::Unsatisfiable;
            };
            if last.is_empty() {
                (start, len)
            } else {
                let Some(end) = parse_num(last) else {
                    return Outcome::Unsatisfiable;
                };
                if end < start {
                    return Outcome::Unsatisfiable;
                }
                (start, end.saturating_add(1))
            }
        };

        let start = start.min(len);
        let end = end.min(len);

        if start < end {
            ranges.push((start, end));
        } else if start == 0 {
            return Outcome::Full;
        }
    }

    match ranges.len() {
        0 => Outcome::Unsatisfiable,
        1 => Outcome::Single {
            start: ranges[0].0,
            end: ranges[0].1,
        },
        _ => Outcome::Multipart(ranges),
    }
}

fn parse_num(s: &str) -> Option<usize> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `If-Range` check: an entity tag must match strongly, a date must be equal.
///
/// Returns `true` when the `Range` header should be honoured.
pub fn if_range_allows(if_range: &str, etag: &str, last_modified: i64) -> bool {
    let v = if_range.trim();

    if v.len() >= 2 && v.ends_with('"') {
        // Must equal the current ETag byte for byte; `W/` is not stripped.
        return v == etag;
    }

    crate::stealth::parse_http_time(v) == Some(last_modified)
}

/// Build a multipart body and its matching `Content-Type`.
pub fn multipart_body(
    ranges: &[(usize, usize)],
    len: usize,
    content_type: &str,
    data: &str,
) -> (String, Vec<u8>) {
    let boundary = next_boundary();
    let ct = format!("multipart/byteranges; boundary={:020}", boundary);

    // Each part is CRLF "--boundary" CRLF headers CRLF CRLF data.
    // The terminator is CRLF "--boundary--" CRLF.
    // The CRLF between a part's data and the next part (or the terminator) is
    // supplied by that next part or by the terminator itself.
    let mut out = Vec::new();
    for (start, end) in ranges {
        out.extend_from_slice(
            format!(
                "\r\n--{:020}\r\nContent-Type: {content_type}\r\nContent-Range: bytes {}-{}/{len}\r\n\r\n",
                boundary,
                start,
                end - 1
            )
            .as_bytes(),
        );
        out.extend_from_slice(&data.as_bytes()[*start..*end]);
    }
    out.extend_from_slice(format!("\r\n--{:020}--\r\n", boundary).as_bytes());

    (ct, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEN: usize = 615;

    #[test]
    fn plain_range() {
        assert_eq!(
            parse("bytes=0-9", LEN),
            Outcome::Single { start: 0, end: 10 }
        );
    }

    #[test]
    fn open_ended_range() {
        assert_eq!(
            parse("bytes=10-", LEN),
            Outcome::Single {
                start: 10,
                end: 615
            }
        );
    }

    #[test]
    fn suffix_range() {
        assert_eq!(
            parse("bytes=-10", LEN),
            Outcome::Single {
                start: 605,
                end: 615
            }
        );
    }

    #[test]
    fn range_beyond_end_is_clamped() {
        assert_eq!(
            parse("bytes=600-9999", LEN),
            Outcome::Single {
                start: 600,
                end: 615
            }
        );
    }

    #[test]
    fn start_beyond_end_is_unsatisfiable() {
        assert_eq!(parse("bytes=99999-", LEN), Outcome::Unsatisfiable);
    }

    #[test]
    fn single_byte_range_is_206() {
        // Observed on nginx: bytes=0-0 -> 206 with Content-Length: 1
        assert_eq!(
            parse("bytes=0-0", LEN),
            Outcome::Single { start: 0, end: 1 }
        );
    }

    #[test]
    fn zero_suffix_is_unsatisfiable() {
        // Observed on nginx: bytes=-0 -> 416
        assert_eq!(parse("bytes=-0", LEN), Outcome::Unsatisfiable);
    }

    #[test]
    fn malformed_is_unsatisfiable() {
        assert_eq!(parse("bytes=abc", LEN), Outcome::Unsatisfiable);
        assert_eq!(parse("bytes=1-0", LEN), Outcome::Unsatisfiable);
        assert_eq!(parse("bytes=-", LEN), Outcome::Unsatisfiable);
    }

    #[test]
    fn non_bytes_unit_is_ignored() {
        assert_eq!(parse("items=0-9", LEN), Outcome::Full);
        // "bytes=" is 6 bytes, below nginx's 7-byte minimum.
        assert_eq!(parse("bytes=", LEN), Outcome::Full);
    }

    #[test]
    fn multipart_ranges() {
        assert_eq!(
            parse("bytes=0-1,5-6", LEN),
            Outcome::Multipart(vec![(0, 2), (5, 7)])
        );
    }

    #[test]
    fn suffix_longer_than_file_starts_at_zero() {
        assert_eq!(
            parse("bytes=-9999", LEN),
            Outcome::Single { start: 0, end: 615 }
        );
    }

    #[test]
    fn multipart_body_matches_golden() {
        // The golden sample uses boundary 00000000000000000002; only the
        // structure is checked here.
        let (ct, body) = multipart_body(&[(0, 2), (5, 7)], LEN, "text/html", "abcdefghij");
        assert!(ct.starts_with("multipart/byteranges; boundary="));
        let s = String::from_utf8(body).unwrap();
        assert!(s.starts_with("\r\n--"));
        assert!(s.contains("Content-Range: bytes 0-1/615\r\n\r\nab\r\n--"));
        assert!(s.contains("Content-Range: bytes 5-6/615\r\n\r\nfg\r\n--"));
        assert!(s.ends_with("--\r\n"));
    }

    #[test]
    fn boundary_increments() {
        let (a, _) = multipart_body(&[(0, 1), (2, 3)], LEN, "text/html", "abcd");
        let (b, _) = multipart_body(&[(0, 1), (2, 3)], LEN, "text/html", "abcd");
        assert_ne!(a, b);
    }

    #[test]
    fn if_range_requires_exact_etag() {
        assert!(if_range_allows("\"6a46b751-267\"", "\"6a46b751-267\"", 1));
        assert!(!if_range_allows("\"x\"", "\"6a46b751-267\"", 1));
        assert!(!if_range_allows(
            "W/\"6a46b751-267\"",
            "\"6a46b751-267\"",
            1
        ));
    }

    #[test]
    fn if_range_date_must_equal_last_modified() {
        let lm = 1783019345;
        assert!(if_range_allows(
            "Thu, 02 Jul 2026 19:09:05 GMT",
            "\"e\"",
            lm
        ));
        assert!(!if_range_allows(
            "Thu, 02 Jul 2026 19:09:04 GMT",
            "\"e\"",
            lm
        ));
    }

    #[test]
    fn non_ascii_value_does_not_panic() {
        // Byte 6 of `bytes=0-9,é` sits inside `é`'s UTF-8 encoding under the
        // old `value[..6]` slice; this must parse without panicking. The `é`
        // part itself has no `-`, so the header is unsatisfiable.
        assert_eq!(parse("bytes=0-9,é", LEN), Outcome::Unsatisfiable);
        // Non-ASCII before the dash must not panic either.
        assert_eq!(parse("bytes=é-9", LEN), Outcome::Unsatisfiable);
        // A multi-byte character replacing the `=` still fails the prefix.
        assert_eq!(parse("bytesé0-9", LEN), Outcome::Full);
    }

    #[test]
    fn range_count_is_capped() {
        let many: String = (0..200).map(|i| format!("{i}-{},", i + 1)).collect();
        assert_eq!(parse(&format!("bytes={many}"), LEN), Outcome::Full);
        // At the cap the ranges parse as multipart, not Full.
        let at_cap: String = (0..100).map(|i| format!("{i}-{},", i + 1)).collect();
        assert!(matches!(
            parse(&format!("bytes={at_cap}"), LEN),
            Outcome::Multipart(_)
        ));
    }

    #[test]
    fn comma_flood_terminates() {
        // 16 KiB of commas must terminate and yield a bounded outcome.
        let flood = format!("bytes={}", ",".repeat(16 * 1024));
        assert_eq!(parse(&flood, LEN), Outcome::Unsatisfiable);
    }
}
