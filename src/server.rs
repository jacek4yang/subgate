//! A minimal HTTP/1.1 server.
//!
//! Why no framework: headers must go out in an arbitrary order and with
//! arbitrary casing (nginx writes `ETag`, not `Etag`). axum and hyper both
//! reorder or normalise headers and cannot do that.
//!
//! Only the subset a default nginx site actually exercises is implemented:
//! - request line plus headers; a request body is read and discarded so that it
//!   cannot be mistaken for the next request on a persistent connection
//! - persistent connections (HTTP/1.1 keeps alive by default, HTTP/1.0 needs
//!   an explicit keep-alive)
//! - `Transfer-Encoding: chunked` request bodies are not decoded; such a
//!   request is rejected rather than mis-parsed

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::limits::limits;

#[derive(Debug)]
pub struct ParsedRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    /// Header names keep their original casing; values are untouched.
    pub headers: Vec<(String, String)>,
}

/// The result of one read.
#[derive(Debug)]
pub enum ReadOutcome {
    Request(ParsedRequest),
    /// The peer closed cleanly, or no request could be parsed.
    Closed,
    /// Malformed request: reply 400 and close.
    BadRequest,
    /// Headers exceeded the limit. nginx replies 400 in this case, so we do too.
    TooLarge,
    /// A body shape we do not decode (`Transfer-Encoding` present). The
    /// connection must close instead of treating the remainder as a new
    /// request.
    UnsupportedBody,
    /// A body larger than the configured bound: reply 413 and close.
    BodyTooLarge,
}

pub async fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<ReadOutcome> {
    loop {
        if let Some(pos) = find_head_end(buf) {
            if pos > limits().max_head {
                return Ok(ReadOutcome::TooLarge);
            }
            let head = buf[..pos].to_vec();
            buf.drain(..pos + 4);

            let text = String::from_utf8_lossy(&head);
            let parsed = match parse_head(&text) {
                ReadOutcome::Request(r) => r,
                other => return Ok(other),
            };

            // This service never inspects a body, but it must still consume it.
            // Leaving it in the buffer would make the next read parse the body
            // as a request line.
            match body_framing(&parsed) {
                BodyFraming::None => {}
                BodyFraming::Unsupported => return Ok(ReadOutcome::UnsupportedBody),
                BodyFraming::Bad => return Ok(ReadOutcome::BadRequest),
                BodyFraming::TooLarge => return Ok(ReadOutcome::BodyTooLarge),
                BodyFraming::Length(len) => {
                    // Bound the body read so a slow client cannot stall a
                    // keep-alive connection forever.
                    match tokio::time::timeout(limits().body, discard_body(stream, buf, len)).await
                    {
                        Ok(r) => r?,
                        Err(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "timed out reading request body",
                            ))
                        }
                    }
                }
            }

            return Ok(ReadOutcome::Request(parsed));
        }

        if buf.len() > limits().max_head {
            return Ok(ReadOutcome::TooLarge);
        }

        let n = stream.read_buf(buf).await?;
        if n == 0 {
            return Ok(if buf.is_empty() {
                ReadOutcome::Closed
            } else {
                ReadOutcome::BadRequest
            });
        }
    }
}

/// Drop `len` bytes of body, reading more from the socket if needed.
///
/// The size bound is enforced by `body_framing` before this runs.
async fn discard_body(stream: &mut TcpStream, buf: &mut Vec<u8>, len: usize) -> io::Result<()> {
    let from_buf = len.min(buf.len());
    buf.drain(..from_buf);
    let mut remaining = len - from_buf;

    let mut scratch = [0u8; 8192];
    while remaining > 0 {
        let want = remaining.min(scratch.len());
        let n = stream.read(&mut scratch[..want]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed inside a request body",
            ));
        }
        remaining -= n;
    }

    Ok(())
}

enum BodyFraming {
    /// No body.
    None,
    /// `Transfer-Encoding` present: we never decode it, so the connection
    /// must close after the 400.
    Unsupported,
    /// Duplicate or malformed `Content-Length`: reply 400.
    Bad,
    /// `Content-Length` above `limits().max_body`: reply 413.
    TooLarge,
    /// A `Content-Length` body of this many bytes.
    Length(usize),
}

/// Determine how a request body is framed.
///
/// Any `Transfer-Encoding` header rejects the request outright: decoding
/// chunked bodies is a whole parser worth of edge cases, and a wrong
/// assumption there desynchronises the keep-alive stream. nginx in front of
/// this service decodes chunked bodies, so direct clients only see the
/// rejection.
///
/// Duplicate `Content-Length` headers are rejected even when identical: RFC
/// 9110 8.6 requires rejecting or replacing them, and "identical" is exactly
/// the shape a request-smuggling probe uses.
fn body_framing(req: &ParsedRequest) -> BodyFraming {
    if req
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
    {
        return BodyFraming::Unsupported;
    }

    let mut count = 0usize;
    let mut value: Option<&str> = None;
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("content-length") {
            count += 1;
            value = Some(v);
        }
    }
    if count == 0 {
        return BodyFraming::None;
    }
    if count > 1 {
        // Duplicates are rejected even when identical (RFC 9110 8.6); this is
        // a 400, not a 413.
        return BodyFraming::Bad;
    }
    let v = value.unwrap();
    // Digits only, must fit in `usize`. OWS is already trimmed at parse.
    // Malformed values are 400s; only a well-formed value above the bound is
    // a 413.
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return BodyFraming::Bad;
    }
    match v.parse::<usize>() {
        Ok(len) if len <= limits().max_body => {
            if len == 0 {
                BodyFraming::None
            } else {
                BodyFraming::Length(len)
            }
        }
        Ok(_) => BodyFraming::TooLarge,
        Err(_) => BodyFraming::Bad,
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// A `tchar`: the characters RFC 9110 allows in a token (method, header
/// name).
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Reject anything that is not a visible ASCII character, HTAB or SP.
fn is_safe_visible(c: char) -> bool {
    matches!(c, '\t' | '\x20'..='\x7e')
}

pub fn parse_head(text: &str) -> ReadOutcome {
    let mut lines = text.split("\r\n");
    let Some(request_line) = lines.next() else {
        return ReadOutcome::BadRequest;
    };

    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return ReadOutcome::BadRequest;
    };
    if parts.next().is_some() {
        return ReadOutcome::BadRequest;
    }
    // Method: an RFC token, non-empty.
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return ReadOutcome::BadRequest;
    }
    // Target: non-empty, origin-form (starts with '/'), no fragment '#', printable ASCII.
    if target.is_empty()
        || !target.starts_with('/')
        || target.contains('#')
        || !target.chars().all(is_safe_visible)
    {
        return ReadOutcome::BadRequest;
    }
    // Version: exactly one of the two HTTP/1.x forms. Everything else,
    // including `HTTP/1.2`, `HTTP/0.9` and a bare `HTTP/`, is rejected.
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return ReadOutcome::BadRequest;
    }

    let mut headers = Vec::new();
    let mut host_count = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        // Obsolete line folding: a continuation line would silently merge
        // into the previous header, so reject it.
        if line.starts_with(' ') || line.starts_with('\t') {
            return ReadOutcome::BadRequest;
        }
        let Some((name, value)) = line.split_once(':') else {
            return ReadOutcome::BadRequest;
        };
        // No whitespace before the colon: `Host : x` is a smuggling vector
        // (RFC 9112 5.1), not a header to trim into shape.
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return ReadOutcome::BadRequest;
        }
        // Values keep nginx's OWS handling: leading and trailing SP/HTAB are
        // trimmed, control characters other than HTAB are rejected.
        let value = value.trim_matches([' ', '\t']);
        if !value.chars().all(is_safe_visible) {
            return ReadOutcome::BadRequest;
        }
        if name.eq_ignore_ascii_case("host") {
            host_count += 1;
        }
        headers.push((name.to_string(), value.to_string()));
        if headers.len() > limits().max_headers {
            return ReadOutcome::TooLarge;
        }
    }

    // RFC 9112 7.1.1: HTTP/1.1 requires exactly one Host header; HTTP/1.0
    // allows at most one. Smuggling probes with multiple Hosts are 400.
    if (version == "HTTP/1.1" && host_count != 1) || (version == "HTTP/1.0" && host_count > 1) {
        return ReadOutcome::BadRequest;
    }

    ReadOutcome::Request(ParsedRequest {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        headers,
    })
}

/// Write the bytes to the connection.
pub async fn write_response(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(bytes).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_request() {
        let text = "GET / HTTP/1.1\r\nHost: x\r\nAccept: */*";
        match parse_head(text) {
            ReadOutcome::Request(r) => {
                assert_eq!(r.method, "GET");
                assert_eq!(r.target, "/");
                assert_eq!(r.version, "HTTP/1.1");
                assert_eq!(r.headers.len(), 2);
                assert_eq!(r.headers[0], ("Host".into(), "x".into()));
            }
            _ => panic!("expected a successful parse"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(parse_head("garbage"), ReadOutcome::BadRequest));
        assert!(matches!(
            parse_head("GET / HTTP/1.1 extra"),
            ReadOutcome::BadRequest
        ));
        assert!(matches!(
            parse_head("GET / HTTP/1.1\r\nbad-header"),
            ReadOutcome::BadRequest
        ));
    }

    fn framing(head: &str) -> BodyFraming {
        let full = if !head.contains("Host:") && !head.contains("host:") {
            head.replace("HTTP/1.1\r\n", "HTTP/1.1\r\nHost: localhost\r\n")
        } else {
            head.to_string()
        };
        match parse_head(&full) {
            ReadOutcome::Request(r) => body_framing(&r),
            other => panic!("unexpected parse outcome: {other:?}"),
        }
    }

    #[test]
    fn header_end_detection() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(14));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn body_framing_shapes() {
        assert!(matches!(framing("POST / HTTP/1.1\r\n"), BodyFraming::None));
        assert!(matches!(
            framing("POST / HTTP/1.1\r\nContent-Length: 42\r\n"),
            BodyFraming::Length(42)
        ));
        // `Content-Length: 0` is a bodyless request.
        assert!(matches!(
            framing("POST / HTTP/1.1\r\nContent-Length: 0\r\n"),
            BodyFraming::None
        ));
        assert!(matches!(
            framing("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n"),
            BodyFraming::Unsupported
        ));
        assert!(matches!(
            framing("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n"),
            BodyFraming::Unsupported
        ));
        // TE together with CL: unsupported wins.
        assert!(matches!(
            framing("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n"),
            BodyFraming::Unsupported
        ));
    }

    #[test]
    fn duplicate_content_length_is_rejected() {
        // Even when identical: this is the smuggling probe shape (a 400).
        assert!(matches!(
            framing("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n"),
            BodyFraming::Bad
        ));
        assert!(matches!(
            framing("POST / HTTP/1.1\r\nContent-Length: 5\r\ncontent-length: 6\r\n"),
            BodyFraming::Bad
        ));
    }

    #[test]
    fn malformed_content_length_is_rejected() {
        for v in ["abc", "+5", "0x5", "99999999999999999999"] {
            let head = format!("POST / HTTP/1.1\r\nContent-Length: {v}\r\n");
            assert!(
                matches!(framing(&head), BodyFraming::Bad),
                "accepted Content-Length: {v:?}"
            );
        }
        // Surrounding OWS is trimmed at parse, so `  5  ` is a valid `5`.
        assert!(matches!(
            framing("POST / HTTP/1.1\r\nContent-Length:   5  \r\n"),
            BodyFraming::Length(5)
        ));
    }

    #[test]
    fn oversized_body_is_too_large() {
        let big = limits().max_body + 1;
        let head = format!("POST / HTTP/1.1\r\nContent-Length: {big}\r\n");
        assert!(matches!(framing(&head), BodyFraming::TooLarge));
        // Exactly at the limit is fine.
        let at = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n",
            limits().max_body
        );
        assert!(matches!(framing(&at), BodyFraming::Length(_)));
    }

    #[test]
    fn rejects_folded_header() {
        assert!(matches!(
            parse_head("GET / HTTP/1.1\r\nHost: x\r\n extra\r\n"),
            ReadOutcome::BadRequest
        ));
        assert!(matches!(
            parse_head("GET / HTTP/1.1\r\nHost: x\r\n\tmore\r\n"),
            ReadOutcome::BadRequest
        ));
    }

    #[test]
    fn rejects_space_before_colon() {
        assert!(matches!(
            parse_head("GET / HTTP/1.1\r\nHost : x\r\n"),
            ReadOutcome::BadRequest
        ));
    }

    #[test]
    fn rejects_control_char_in_value() {
        assert!(matches!(
            parse_head("GET / HTTP/1.1\r\nHost: localhost\r\nX-A: a\u{1}b\r\n"),
            ReadOutcome::BadRequest
        ));
        // HTAB is the one allowed control byte.
        assert!(matches!(
            parse_head("GET / HTTP/1.1\r\nHost: localhost\r\nX-A: a\tb\r\n"),
            ReadOutcome::Request(_)
        ));
    }

    #[test]
    fn rejects_empty_header_name() {
        assert!(matches!(
            parse_head("GET / HTTP/1.1\r\nHost: localhost\r\n: value\r\n"),
            ReadOutcome::BadRequest
        ));
    }

    #[test]
    fn rejects_too_many_headers() {
        let mut head = String::from("GET / HTTP/1.1\r\nHost: localhost\r\n");
        for i in 0..150 {
            head.push_str(&format!("X-H{i}: v\r\n"));
        }
        assert!(matches!(parse_head(&head), ReadOutcome::TooLarge));
    }

    #[test]
    fn rejects_unknown_versions() {
        assert!(matches!(
            parse_head("GET / HTTP/1.2\r\nHost: localhost\r\n"),
            ReadOutcome::BadRequest
        ));
        assert!(matches!(
            parse_head("GET / HTTP/0.9\r\nHost: localhost\r\n"),
            ReadOutcome::BadRequest
        ));
        assert!(matches!(
            parse_head("GET / HTTP/2.0\r\nHost: localhost\r\n"),
            ReadOutcome::BadRequest
        ));
    }

    #[test]
    fn rejects_bad_methods() {
        assert!(matches!(
            parse_head("GE T / HTTP/1.1\r\nHost: localhost\r\n"),
            ReadOutcome::BadRequest
        ));
        assert!(matches!(
            parse_head("GE(T) / HTTP/1.1\r\nHost: localhost\r\n"),
            ReadOutcome::BadRequest
        ));
        assert!(matches!(
            parse_head("MØTHOD / HTTP/1.1\r\nHost: localhost\r\n"),
            ReadOutcome::BadRequest
        ));
    }

    #[test]
    fn rejects_control_char_in_target() {
        assert!(matches!(
            parse_head("GET /\u{7} HTTP/1.1\r\nHost: localhost\r\n"),
            ReadOutcome::BadRequest
        ));
        assert!(matches!(
            parse_head("GET /a b HTTP/1.1\r\nHost: localhost\r\n"),
            ReadOutcome::BadRequest
        ));
    }

    #[test]
    fn rejects_missing_or_duplicate_host() {
        // HTTP/1.1 requires exactly one Host header.
        assert!(matches!(
            parse_head("GET / HTTP/1.1\r\n"),
            ReadOutcome::BadRequest
        ));
        assert!(matches!(
            parse_head("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n"),
            ReadOutcome::BadRequest
        ));
        assert!(matches!(
            parse_head("GET / HTTP/1.1\r\nhost: a\r\nHost: b\r\n"),
            ReadOutcome::BadRequest
        ));

        // HTTP/1.0 accepts 0 or 1 Host, rejects multiple.
        assert!(matches!(
            parse_head("GET / HTTP/1.0\r\n"),
            ReadOutcome::Request(_)
        ));
        assert!(matches!(
            parse_head("GET / HTTP/1.0\r\nHost: a\r\n"),
            ReadOutcome::Request(_)
        ));
        assert!(matches!(
            parse_head("GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n"),
            ReadOutcome::BadRequest
        ));
    }

    #[test]
    fn rejects_non_origin_target_and_fragments() {
        assert!(matches!(
            parse_head("GET foo HTTP/1.1\r\nHost: localhost\r\n"),
            ReadOutcome::BadRequest
        ));
        assert!(matches!(
            parse_head("GET /path#fragment HTTP/1.1\r\nHost: localhost\r\n"),
            ReadOutcome::BadRequest
        ));
    }
}
