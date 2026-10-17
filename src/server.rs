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

/// Upper bound for one request line plus headers, comparable to nginx's
/// `large_client_header_buffers`.
const MAX_HEAD: usize = 16 * 1024;

/// nginx's default for `keepalive_requests`.
const MAX_REQUESTS: usize = 1000;

pub struct ParsedRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    /// Header names keep their original casing; values are untouched.
    pub headers: Vec<(String, String)>,
}

/// The result of one read.
pub enum ReadOutcome {
    Request(ParsedRequest),
    /// The peer closed cleanly, or no request could be parsed.
    Closed,
    /// Malformed request: reply 400 and close.
    BadRequest,
    /// Headers exceeded the limit. nginx replies 400 in this case, so we do too.
    TooLarge,
    /// A chunked body was sent. We do not decode it, so the connection must
    /// close instead of treating the remainder as a new request.
    UnsupportedBody,
}

pub async fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<ReadOutcome> {
    loop {
        if let Some(pos) = find_head_end(buf) {
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
            if has_chunked_encoding(&parsed) {
                return Ok(ReadOutcome::UnsupportedBody);
            }

            let body_len = content_length(&parsed);
            if body_len > 0 {
                discard_body(stream, buf, body_len).await?;
            }

            return Ok(ReadOutcome::Request(parsed));
        }

        if buf.len() > MAX_HEAD {
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
async fn discard_body(stream: &mut TcpStream, buf: &mut Vec<u8>, len: usize) -> io::Result<()> {
    // Bounded so a bogus `Content-Length` cannot pin a connection forever.
    const MAX_DISCARD: usize = 64 * 1024 * 1024;
    if len > MAX_DISCARD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }

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

fn has_chunked_encoding(req: &ParsedRequest) -> bool {
    req.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    })
}

/// `Content-Length`, or 0 when absent or unparseable.
///
/// An unparseable value is treated as no body rather than an error: the
/// request is still answered, and the connection closes afterwards if the
/// framing was wrong.
fn content_length(req: &ParsedRequest) -> usize {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0)
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
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
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return ReadOutcome::BadRequest;
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return ReadOutcome::BadRequest;
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
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

pub const MAX_KEEPALIVE_REQUESTS: usize = MAX_REQUESTS;

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

    fn req_with(headers: &str) -> ParsedRequest {
        match parse_head(&format!("POST / HTTP/1.1\r\n{headers}")) {
            ReadOutcome::Request(r) => r,
            _ => panic!("expected a parsed request"),
        }
    }

    #[test]
    fn content_length_is_read() {
        assert_eq!(content_length(&req_with("Content-Length: 42\r\n")), 42);
        assert_eq!(content_length(&req_with("content-length:7\r\n")), 7);
        assert_eq!(content_length(&req_with("")), 0);
        // A value that does not parse is treated as no body.
        assert_eq!(content_length(&req_with("Content-Length: abc\r\n")), 0);
    }

    #[test]
    fn chunked_body_is_detected() {
        assert!(has_chunked_encoding(&req_with(
            "Transfer-Encoding: chunked\r\n"
        )));
        assert!(has_chunked_encoding(&req_with(
            "transfer-encoding: Chunked\r\n"
        )));
        assert!(!has_chunked_encoding(&req_with("Content-Length: 3\r\n")));
    }

    #[test]
    fn header_end_detection() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(14));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }
}
