//! Conditional request evaluation, aligned with
//! `ngx_http_not_modified_filter_module.c`.
//!
//! Evaluation order, matching nginx:
//! 1. `If-Unmodified-Since`: time < last_modified -> 412
//! 2. `If-Match`: no match -> 412
//! 3. `If-Modified-Since`: time == last_modified -> 304
//! 4. `If-None-Match`: match -> 304
//!
//! Note that `If-Modified-Since` uses **exact** semantics (nginx defaults to
//! `if_modified_since exact`): only an **exactly equal** time yields 304.
//! Earlier or later both yield 200.

use crate::stealth;

#[derive(Debug, PartialEq, Eq)]
pub enum Precondition {
    Proceed,
    NotModified,
    Failed,
}

/// Whether an `If-None-Match` entity-tag list matches `etag`.
///
/// nginx compares weakly here: it strips the `W/` prefix and the quotes, and
/// supports `*`.
pub fn etag_matches(list: &str, etag: &str) -> bool {
    let list = list.trim();
    if list == "*" {
        return true;
    }

    let target = strip_weak(etag);
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|candidate| strip_weak(candidate) == target)
}

fn strip_weak(tag: &str) -> &str {
    let tag = tag.trim();
    let tag = tag.strip_prefix("W/").unwrap_or(tag);
    tag.trim_matches('"')
}

/// Check the four conditional headers in nginx's order.
pub fn evaluate(
    if_unmodified_since: Option<&str>,
    if_match: Option<&str>,
    if_modified_since: Option<&str>,
    if_none_match: Option<&str>,
    last_modified: i64,
    etag: &str,
) -> Precondition {
    if let Some(v) = if_unmodified_since {
        if let Some(t) = stealth::parse_http_time(v) {
            if t < last_modified {
                return Precondition::Failed;
            }
        }
    }

    if let Some(v) = if_match {
        if !etag_matches(v, etag) {
            return Precondition::Failed;
        }
    }

    if let Some(v) = if_modified_since {
        if let Some(t) = stealth::parse_http_time(v) {
            if t == last_modified {
                return Precondition::NotModified;
            }
        }
    }

    if let Some(v) = if_none_match {
        if etag_matches(v, etag) {
            return Precondition::NotModified;
        }
    }

    Precondition::Proceed
}

#[cfg(test)]
mod tests {
    use super::*;

    const ETAG: &str = "\"6a46b751-267\"";
    const LM: i64 = 1783019345; // Thu, 02 Jul 2026 19:09:05 GMT

    #[test]
    fn no_headers_proceeds() {
        assert_eq!(
            evaluate(None, None, None, None, LM, ETAG),
            Precondition::Proceed
        );
    }

    #[test]
    fn if_none_match_hit_gives_304() {
        assert_eq!(
            evaluate(None, None, None, Some(ETAG), LM, ETAG),
            Precondition::NotModified
        );
    }

    #[test]
    fn if_none_match_star_gives_304() {
        assert_eq!(
            evaluate(None, None, None, Some("*"), LM, ETAG),
            Precondition::NotModified
        );
    }

    #[test]
    fn weak_etag_matches() {
        assert_eq!(
            evaluate(None, None, None, Some("W/\"6a46b751-267\""), LM, ETAG),
            Precondition::NotModified
        );
        assert_eq!(
            evaluate(None, None, None, Some(ETAG), LM, "W/\"6a46b751-267\""),
            Precondition::NotModified
        );
    }

    #[test]
    fn etag_list_matches() {
        assert_eq!(
            evaluate(
                None,
                None,
                None,
                Some("\"a\", \"b\", \"6a46b751-267\""),
                LM,
                ETAG
            ),
            Precondition::NotModified
        );
    }

    #[test]
    fn if_none_match_miss_proceeds() {
        assert_eq!(
            evaluate(None, None, None, Some("\"deadbeef-1\""), LM, ETAG),
            Precondition::Proceed
        );
    }

    #[test]
    fn if_modified_since_exact_gives_304() {
        assert_eq!(
            evaluate(
                None,
                None,
                Some("Thu, 02 Jul 2026 19:09:05 GMT"),
                None,
                LM,
                ETAG
            ),
            Precondition::NotModified
        );
    }

    #[test]
    fn if_modified_since_earlier_or_later_proceeds() {
        // Exact semantics: neither earlier nor later yields 304.
        assert_eq!(
            evaluate(
                None,
                None,
                Some("Thu, 02 Jul 2026 19:09:04 GMT"),
                None,
                LM,
                ETAG
            ),
            Precondition::Proceed
        );
        assert_eq!(
            evaluate(
                None,
                None,
                Some("Thu, 02 Jul 2026 19:09:06 GMT"),
                None,
                LM,
                ETAG
            ),
            Precondition::Proceed
        );
    }

    #[test]
    fn if_match_miss_gives_412() {
        assert_eq!(
            evaluate(None, Some("\"nope\""), None, None, LM, ETAG),
            Precondition::Failed
        );
    }

    #[test]
    fn if_unmodified_since_older_gives_412() {
        assert_eq!(
            evaluate(
                Some("Thu, 02 Jul 2026 19:09:04 GMT"),
                None,
                None,
                None,
                LM,
                ETAG
            ),
            Precondition::Failed
        );
    }

    #[test]
    fn if_unmodified_since_equal_proceeds() {
        assert_eq!(
            evaluate(
                Some("Thu, 02 Jul 2026 19:09:05 GMT"),
                None,
                None,
                None,
                LM,
                ETAG
            ),
            Precondition::Proceed
        );
    }

    #[test]
    fn unparsable_header_is_ignored() {
        assert_eq!(
            evaluate(None, None, Some("garbage"), None, LM, ETAG),
            Precondition::Proceed
        );
    }
}
