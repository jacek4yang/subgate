//! Serialise HTTP/1.1 response bytes directly.
//!
//! Why no framework: axum's `RouteFuture` unconditionally adds
//! `Content-Length: 0` to empty-body responses and offers no way to control
//! header write order. Either difference makes 304 and 200 responses
//! observably different from real nginx.
//!
//! So the status line and headers are written by hand, in exactly the order
//! `ngx_http_header_filter_module.c` emits them:
//!
//! `Server -> Date -> Content-Type -> Content-Length -> Last-Modified ->`
//! `Connection -> [Keep-Alive] -> ETag -> Accept-Ranges -> Content-Range`
//!
//! `ETag`, `Accept-Ranges` and `Content-Range` are appended through nginx's
//! `headers_out.headers` list, which is why they follow the fixed headers.

/// A fully constructed response.
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Write the status line and headers in order, terminated by a blank line.
    pub fn write_head(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", self.status, self.reason).as_bytes());
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
    }

    pub fn into_bytes(self, include_body: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        self.write_head(&mut out);
        if include_body {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_in_insertion_order() {
        let r = Response::new(200, "OK")
            .header("Server", "nginx/1.28.3 (Ubuntu)")
            .header("Date", "Thu, 02 Jul 2026 19:09:05 GMT")
            .body("hi");
        assert_eq!(
            r.into_bytes(true),
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.28.3 (Ubuntu)\r\n\
              Date: Thu, 02 Jul 2026 19:09:05 GMT\r\n\r\nhi"
        );
    }

    #[test]
    fn head_only_omits_body() {
        let r = Response::new(404, "Not Found").body("x");
        assert_eq!(r.into_bytes(false), b"HTTP/1.1 404 Not Found\r\n\r\n");
    }

    #[test]
    fn crlf_terminated() {
        let out = Response::new(304, "Not Modified")
            .header("ETag", "\"a-b\"")
            .into_bytes(false);
        assert!(out.ends_with(b"\r\n\r\n"));
    }
}
