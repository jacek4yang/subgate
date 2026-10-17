//! Routing: impersonate a static site only; subscription routes come later.
//!
//! `handle()` is a pure function: it takes a parsed request view and returns a
//! response ready to serialise. Tests assert on the serialised bytes against
//! the golden samples.
//!
//! Header order follows what real nginx actually writes:
//!
//! `Server → Date → Content-Type → Content-Length → Last-Modified →`
//! `Connection → ETag → Accept-Ranges → Content-Range`
//!
//! Note: Ubuntu's default `nginx.conf` does not set the second argument of
//! `keepalive_timeout`, so `clcf->keepalive_header` is 0 in
//! `ngx_http_header_filter_module.c` and **no `Keep-Alive` header is sent**.
//! This was verified against a real nginx running under WSL.

use crate::assets;
use crate::condition::{self, Precondition};
use crate::config::Config;
use crate::errors;
use crate::range::{self, Outcome};
use crate::render;
use crate::serialize::Response;
use crate::stealth;

/// The parts of a request this module cares about.
pub struct RequestView<'a> {
    pub method: &'a str,
    pub path: &'a str,
    /// The HTTP version, for example `HTTP/1.1`.
    pub version: &'a str,
    /// Header names are lowercased for easy lookup.
    pub headers: &'a [(String, String)],
}

impl<'a> RequestView<'a> {
    fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The result of nginx's `r->keepalive` determination.
    ///
    /// HTTP/1.0 keeps the connection only when the client explicitly sends
    /// `Connection: keep-alive`; HTTP/1.1 keeps it unless the client asks for
    /// `Connection: close`.
    pub fn wants_keepalive(&self) -> bool {
        let conn = self.header("connection").unwrap_or("");
        let has_keepalive = conn.split(',').any(|t| t.trim().eq_ignore_ascii_case("keep-alive"));
        let has_close = conn.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"));

        if has_close {
            return false;
        }

        if self.version.eq_ignore_ascii_case("HTTP/1.0") {
            has_keepalive
        } else {
            true
        }
    }

    pub fn connection_value(&self) -> &'static str {
        if self.wants_keepalive() {
            "keep-alive"
        } else {
            "close"
        }
    }
}

/// The 400 response for a malformed request; the connection closes after it.
pub fn bad_request(cfg: &Config, body: &str) -> Response {
    leading(cfg, Response::new(400, "Bad Request"))
        .header("Content-Type", "text/html")
        .header("Content-Length", body.len().to_string())
        .header("Connection", "close")
        .body(body.as_bytes().to_vec())
}

/// The 503 served while no valid config is loaded.
///
/// There is no live config to read `server_token` from, so the compiled-in
/// default is used. That keeps the response shaped like the rest of the site
/// instead of advertising a misconfiguration.
pub fn service_unavailable() -> Response {
    let body = errors::page_503(crate::config::DEFAULT_SERVER_TOKEN);
    Response::new(503, "Service Temporarily Unavailable")
        .header("Server", crate::config::DEFAULT_SERVER_TOKEN)
        .header("Date", stealth::date_now())
        .header("Content-Type", "text/html")
        .header("Content-Length", body.len().to_string())
        .header("Connection", "close")
        .header("Retry-After", "5")
        .body(body.into_bytes())
}

pub fn handle(cfg: &Config, req: &RequestView<'_>) -> Response {
    let head_only = req.method.eq_ignore_ascii_case("HEAD");
    let is_get = req.method.eq_ignore_ascii_case("GET");

    // Subscription paths are matched first. An unknown token returns `None`
    // here and falls through to the same 404 as any other unknown path, so the
    // two are indistinguishable.
    if is_get || head_only {
        if let Some(payload) = subscription(cfg, req.path) {
            return subscription_response(cfg, req, payload, head_only);
        }
    }

    if req.path == "/" {
        if is_get || head_only {
            return home(cfg, req, head_only);
        }
        // nginx's static module returns 405 for POST and for anything outside
        // GET/HEAD/POST.
        return error(cfg, req, (405, "Not Allowed"), errors::page_405(&cfg.server_token), head_only);
    }

    error(cfg, req, (404, "Not Found"), errors::page_404(&cfg.server_token), head_only)
}

/// The rendered body of `/<token>/clash` or `/<token>/v2ray`.
///
/// `None` means the path is not a subscription: either the shape does not
/// match or the token is unknown. Callers must treat that exactly like any
/// other unknown path.
fn subscription(cfg: &Config, path: &str) -> Option<(String, &'static str)> {
    let rest = path.strip_prefix('/')?;
    let (token, format) = rest.split_once('/')?;

    if format.contains('/') {
        return None;
    }

    let group = cfg.group_for_token(token)?;

    match format {
        "clash" => Some((render::clash::render(cfg, group), "text/yaml; charset=utf-8")),
        "v2ray" => Some((render::v2ray::render(cfg, group), "text/plain; charset=utf-8")),
        _ => None,
    }
}

/// Wrap a rendered subscription in a response.
///
/// These responses are not part of the nginx disguise: they exist only on paths
/// a client already has to know, and they carry `Cache-Control: no-store` so a
/// rotated token takes effect immediately.
fn subscription_response(
    cfg: &Config,
    req: &RequestView<'_>,
    (body, content_type): (String, &'static str),
    head_only: bool,
) -> Response {
    let len = body.len();
    leading(cfg, Response::new(200, "OK"))
        .header("Content-Type", content_type)
        .header("Content-Length", len.to_string())
        .header("Connection", req.connection_value())
        .header("Cache-Control", "no-store")
        .body(if head_only { Vec::new() } else { body.into_bytes() })
}

/// The first half of nginx's fixed headers: `Server` and `Date`.
fn leading(cfg: &Config, r: Response) -> Response {
    r.header("Server", cfg.server_token.clone())
        .header("Date", stealth::date_now())
}

fn home(cfg: &Config, req: &RequestView<'_>, head_only: bool) -> Response {
    let etag = stealth::index_etag();
    let last_modified = assets::INDEX_MTIME as i64;

    match condition::evaluate(
        req.header("if-unmodified-since"),
        req.header("if-match"),
        req.header("if-modified-since"),
        req.header("if-none-match"),
        last_modified,
        &etag,
    ) {
        Precondition::NotModified => {
            // A 304 clears Content-Type/Content-Length/Accept-Ranges, keeps
            // Last-Modified and ETag, and sends **no** Content-Length.
            return leading(cfg, Response::new(304, "Not Modified"))
                .header("Last-Modified", stealth::index_last_modified())
                .header("Connection", req.connection_value())
                .header("ETag", etag);
        }
        Precondition::PreconditionFailed => {
            let body = errors::page_400(&cfg.server_token);
            return error(cfg, req, (412, "Precondition Failed"), body, head_only);
        }
        Precondition::Proceed => {}
    }

    let outcome = match req.header("range") {
        Some(value) => {
            let allowed = match req.header("if-range") {
                Some(ir) => range::if_range_allows(ir, &etag, last_modified),
                None => true,
            };
            if allowed {
                range::parse(value, assets::INDEX_SIZE)
            } else {
                Outcome::Full
            }
        }
        None => Outcome::Full,
    };

    match outcome {
        Outcome::Single { start, end } => {
            let len = end - start;
            let body = assets::INDEX_HTML[start..end].as_bytes().to_vec();
            leading(cfg, Response::new(206, "Partial Content"))
                .header("Content-Type", "text/html")
                .header("Content-Length", len.to_string())
                .header("Last-Modified", stealth::index_last_modified())
                .header("Connection", req.connection_value())
                .header("ETag", etag)
                .header(
                    "Content-Range",
                    format!("bytes {}-{}/{}", start, end - 1, assets::INDEX_SIZE),
                )
                .body(if head_only { Vec::new() } else { body })
        }
        Outcome::Multipart(ranges) => {
            let (ct, body) =
                range::multipart_body(&ranges, assets::INDEX_SIZE, "text/html", assets::INDEX_HTML);
            let len = body.len();
            leading(cfg, Response::new(206, "Partial Content"))
                .header("Content-Type", ct)
                .header("Content-Length", len.to_string())
                .header("Last-Modified", stealth::index_last_modified())
                .header("Connection", req.connection_value())
                .header("ETag", etag)
                .body(if head_only { Vec::new() } else { body })
        }
        Outcome::Unsatisfiable => {
            let body = errors::page_416(&cfg.server_token);
            let len = body.len();
            leading(cfg, Response::new(416, "Requested Range Not Satisfiable"))
                .header("Content-Type", "text/html")
                .header("Content-Length", len.to_string())
                .header("Connection", req.connection_value())
                .header("Content-Range", format!("bytes */{}", assets::INDEX_SIZE))
                .body(if head_only { Vec::new() } else { body.into_bytes() })
        }
        Outcome::Full => {
            leading(cfg, Response::new(200, "OK"))
                .header("Content-Type", "text/html")
                .header("Content-Length", assets::INDEX_SIZE.to_string())
                .header("Last-Modified", stealth::index_last_modified())
                .header("Connection", req.connection_value())
                .header("ETag", etag)
                .header("Accept-Ranges", "bytes")
                .body(if head_only {
                    Vec::new()
                } else {
                    assets::INDEX_HTML.as_bytes().to_vec()
                })
        }
    }
}

fn error(
    cfg: &Config,
    req: &RequestView<'_>,
    (status, reason): (u16, &'static str),
    body: String,
    head_only: bool,
) -> Response {
    let len = body.len();
    leading(cfg, Response::new(status, reason))
        .header("Content-Type", "text/html")
        .header("Content-Length", len.to_string())
        .header("Connection", req.connection_value())
        .body(if head_only {
            Vec::new()
        } else {
            body.into_bytes()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn cfg() -> Config {
        Config::load(Path::new("config.json")).unwrap()
    }

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn req<'a>(method: &'a str, path: &'a str, headers: &'a [(String, String)]) -> RequestView<'a> {
        RequestView {
            method,
            path,
            version: "HTTP/1.1",
            headers,
        }
    }

    fn text(r: Response, body: bool) -> String {
        String::from_utf8_lossy(&r.into_bytes(body)).into_owned()
    }

    fn header_names(out: &str) -> Vec<&str> {
        out.lines()
            .skip(1)
            .take_while(|l| !l.is_empty())
            .map(|l| l.split(':').next().unwrap())
            .collect()
    }

    #[test]
    fn root_200_matches_golden() {
        let out = text(handle(&cfg(), &req("GET", "/", &[])), true);
        let golden = include_str!("../tests/golden/200.hdr");
        let body = include_str!("../tests/golden/200.body");

        let mut got = out.lines().map(|l| l.trim_end_matches('\r'));
        for line in golden.lines().map(|l| l.trim_end_matches('\r')) {
            let g = got.next().unwrap();
            if line.starts_with("Date: ") {
                assert!(g.starts_with("Date: "), "{g}");
                continue;
            }
            if line.starts_with("Last-Modified: ") {
                assert_eq!(g, format!("Last-Modified: {}", stealth::index_last_modified()));
                continue;
            }
            if line.starts_with("ETag: ") {
                assert_eq!(g, format!("ETag: {}", stealth::index_etag()));
                continue;
            }
            assert_eq!(g, line);
        }
        // `lines()` skips the blank line, so what remains is the body.
        let rest: String = got.collect::<Vec<_>>().join("\n");
        assert_eq!(
            rest,
            body.trim_end_matches("\r\n").trim_end().replace("\r\n", "\n")
        );
    }

    #[test]
    fn header_order_matches_nginx() {
        let out = text(handle(&cfg(), &req("GET", "/", &[])), false);
        assert_eq!(
            header_names(&out),
            vec![
                "Server",
                "Date",
                "Content-Type",
                "Content-Length",
                "Last-Modified",
                "Connection",
                "ETag",
                "Accept-Ranges",
            ]
        );
    }

    #[test]
    fn no_keep_alive_header_by_default() {
        // Ubuntu leaves keepalive_timeout's second argument unset, so no
        // Keep-Alive header is sent.
        let out = text(handle(&cfg(), &req("GET", "/", &[])), false);
        assert!(!out.to_lowercase().contains("keep-alive: "));
    }

    #[test]
    fn not_found_matches_golden() {
        let out = text(handle(&cfg(), &req("GET", "/nope", &[])), true);
        let golden = include_str!("../tests/golden/404.hdr");
        let mut got = out.lines();
        for line in golden.lines() {
            let l = line.trim_end_matches('\r');
            let g = got.next().unwrap();
            if l.starts_with("Date: ") {
                assert!(g.starts_with("Date: "));
                continue;
            }
            assert_eq!(g, l);
        }
        let body: String = got.collect::<Vec<_>>().join("\n");
        assert_eq!(
            body,
            include_str!("../tests/golden/404.body")
                .replace("\r\n", "\n")
                .trim_end()
        );
    }

    #[test]
    fn post_is_405() {
        let out = text(handle(&cfg(), &req("POST", "/", &[])), true);
        assert!(out.starts_with("HTTP/1.1 405 Not Allowed\r\n"));
        assert!(out.contains("Content-Length: 166\r\n"));
    }

    #[test]
    fn http10_without_keepalive_is_close() {
        let mut r = req("GET", "/", &[]);
        r.version = "HTTP/1.0";
        let out = text(handle(&cfg(), &r), false);
        assert!(out.contains("Connection: close\r\n"));
    }

    #[test]
    fn http10_with_keepalive_is_keep_alive() {
        let headers = h(&[("connection", "keep-alive")]);
        let mut r = req("GET", "/", &headers);
        r.version = "HTTP/1.0";
        let out = text(handle(&cfg(), &r), false);
        assert!(out.contains("Connection: keep-alive\r\n"));
    }

    #[test]
    fn http11_with_close_is_close() {
        let headers = h(&[("connection", "close")]);
        let out = text(handle(&cfg(), &req("GET", "/", &headers)), false);
        assert!(out.contains("Connection: close\r\n"));
    }

    #[test]
    fn etag_hit_is_304_without_content_length() {
        let etag = stealth::index_etag();
        let headers = h(&[("if-none-match", &etag)]);
        let out = text(handle(&cfg(), &req("GET", "/", &headers)), true);
        assert!(out.starts_with("HTTP/1.1 304 Not Modified\r\n"));
        let lower = out.to_lowercase();
        assert!(!lower.contains("content-length"));
        assert!(!lower.contains("content-type"));
        assert!(!lower.contains("accept-ranges"));
        assert!(out.contains(&format!("ETag: {etag}\r\n")));
    }

    #[test]
    fn single_range_is_206() {
        let headers = h(&[("range", "bytes=0-9")]);
        let out = text(handle(&cfg(), &req("GET", "/", &headers)), true);
        assert!(out.starts_with("HTTP/1.1 206 Partial Content\r\n"));
        assert!(out.contains("Content-Length: 10\r\n"));
        assert!(out.contains("Content-Range: bytes 0-9/615\r\n"));
        assert!(out.ends_with("<!DOCTYPE "));
    }

    #[test]
    fn unsatisfiable_is_416() {
        let headers = h(&[("range", "bytes=99999-")]);
        let out = text(handle(&cfg(), &req("GET", "/", &headers)), true);
        assert!(out.starts_with("HTTP/1.1 416 Requested Range Not Satisfiable\r\n"));
        assert!(out.contains("Content-Range: bytes */615\r\n"));
    }

    fn sub_cfg() -> Config {
        let dir = std::env::temp_dir().join("subgate-route-tests");
        std::fs::create_dir_all(&dir).unwrap();
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = dir.join(format!("r{n}.json"));
        std::fs::write(
            &path,
            r#"{
                "listen": "127.0.0.1:1",
                "nodes": [{
                    "name": "hk-1", "address": "example.com", "port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "public-key": "PUBKEY", "short-id": "ab",
                    "server-name": "www.example.com"
                }],
                "groups": [{"token": "secret123", "name": "main", "nodes": ["hk-1"]}]
            }"#,
        )
        .unwrap();
        Config::load(&path).unwrap()
    }

    #[test]
    fn clash_endpoint_serves_yaml() {
        let out = text(handle(&sub_cfg(), &req("GET", "/secret123/clash", &[])), true);
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(out.contains("Content-Type: text/yaml; charset=utf-8\r\n"));
        assert!(out.contains("Cache-Control: no-store\r\n"));
        assert!(out.contains("type: vless"));
        assert!(out.contains("name: hk-1"));
    }

    #[test]
    fn v2ray_endpoint_serves_base64() {
        let out = text(handle(&sub_cfg(), &req("GET", "/secret123/v2ray", &[])), true);
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(out.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        // The body is base64; decoding it must yield a vless link.
        let body = out.split("\r\n\r\n").nth(1).unwrap();
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(body).unwrap();
        assert!(String::from_utf8(decoded).unwrap().starts_with("vless://"));
    }

    #[test]
    fn unknown_token_is_the_same_404_as_any_other_path() {
        let cfg = sub_cfg();
        let unknown = text(handle(&cfg, &req("GET", "/wrongtoken/clash", &[])), true);
        let other = text(handle(&cfg, &req("GET", "/nope", &[])), true);

        // Identical status, headers, and body: the two must not be tellable
        // apart, or a token could be brute-forced by response shape.
        let strip = |s: &str| -> String {
            s.lines()
                .map(|l| if l.starts_with("Date: ") { "Date: X" } else { l })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(strip(&unknown), strip(&other));
        assert!(unknown.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn token_without_format_is_404() {
        let out = text(handle(&sub_cfg(), &req("GET", "/secret123", &[])), true);
        assert!(out.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn unknown_format_is_404() {
        let out = text(handle(&sub_cfg(), &req("GET", "/secret123/singbox", &[])), true);
        assert!(out.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn extra_path_segments_are_404() {
        let out = text(handle(&sub_cfg(), &req("GET", "/secret123/clash/x", &[])), true);
        assert!(out.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn head_subscription_has_no_body() {
        let out = text(handle(&sub_cfg(), &req("HEAD", "/secret123/clash", &[])), true);
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn multipart_has_expected_boundary_format() {
        let headers = h(&[("range", "bytes=0-1,5-6")]);
        let out = text(handle(&cfg(), &req("GET", "/", &headers)), true);
        assert!(out.starts_with("HTTP/1.1 206 Partial Content\r\n"));
        assert!(out.contains("Content-Type: multipart/byteranges; boundary=000000000000000000"));
    }
}
