//! A minimal HTTP/1.1 server.
//!
//! Why no framework: headers must go out in an arbitrary order and with
//! arbitrary casing (nginx writes `ETag`, not `Etag`). axum and hyper both
//! reorder or normalise headers and cannot do that.
//!
//! Only the subset a default nginx site actually exercises is implemented:
//! - request line plus headers, with the request body ignored
//! - persistent connections (HTTP/1.1 keeps alive by default, HTTP/1.0 needs
//!   an explicit keep-alive)
//! - no chunked request body support (this service never reads a body)

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
}

pub async fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<ReadOutcome> {
    loop {
        if let Some(pos) = find_head_end(buf) {
            let head = buf[..pos].to_vec();
            // Drop the consumed bytes. This service never reads a request body,
            // so any `Content-Length` is ignored.
            buf.drain(..pos + 4);

            let text = String::from_utf8_lossy(&head);
            let out = parse_head(&text);
            return Ok(out);
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

    #[test]
    fn header_end_detection() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(14));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }
}
