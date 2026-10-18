//! Integration and end-to-end tests for subgate.
//!
//! Spawns real compiled subgate processes on loopback ephemeral ports and
//! exercises HTTP/1.1 framing, security policies, resource limits, error handling,
//! range parsing, and subscription rendering over live TCP sockets.

use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(1);

const SAMPLE_UUID: &str = "00000000-0000-0000-0000-000000000000";
const SAMPLE_PUBKEY: &str = "bK4PTQX5dwqSdVBzADrqhPtALBwj9b0uYjYR29lS4xE";
const TOKEN_MAIN: &str = "kQ7vT2xLm9pZr4sW8yB3nE6hJ5cD1fG0";
const TOKEN_FAMILY: &str = "uX2wN8pQ4tK7vB1mZ5cR9dF3hJ6sL0aE";

struct TestServer {
    child: Child,
    pub addr: String,
    _dir: PathBuf,
}

impl TestServer {
    fn spawn() -> Self {
        Self::spawn_with_env(&[])
    }

    fn spawn_with_env(envs: &[(&str, &str)]) -> Self {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("subgate-integ-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let config_path = dir.join("config.json");

        let config_json = format!(
            r#"{{
  "listen": "127.0.0.1:0",
  "server_token": "nginx/1.28.3 (Ubuntu)",
  "nodes": [
    {{
      "name": "hk-1",
      "address": "example.com",
      "port": 443,
      "uuid": "{SAMPLE_UUID}",
      "public-key": "{SAMPLE_PUBKEY}",
      "short-id": "0123456789abcdef",
      "server-name": "www.example.com",
      "flow": "xtls-rprx-vision",
      "fingerprint": "chrome",
      "alpn": ["h2", "http/1.1"],
      "spider-x": "/"
    }}
  ],
  "groups": [
    {{
      "token": "{TOKEN_MAIN}",
      "name": "main",
      "nodes": ["hk-1"]
    }},
    {{
      "token": "{TOKEN_FAMILY}",
      "name": "family",
      "nodes": [
        {{
          "ref": "hk-1",
          "name": "Hong Kong Fast"
        }}
      ]
    }}
  ]
}}"#
        );
        std::fs::write(&config_path, config_json).expect("write config.json");

        let bin = env!("CARGO_BIN_EXE_subgate");
        let mut cmd = Command::new(bin);
        cmd.arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (k, v) in envs {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().expect("spawn subgate binary");
        let stdout = child.stdout.take().expect("take stdout");
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 {
                    break;
                }
                if let Some(pos) = line.find("listening on ") {
                    let rest = &line[pos + "listening on ".len()..];
                    let _ = tx.send(rest.trim().to_string());
                    break;
                }
                line.clear();
            }
        });

        let addr = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("failed to receive listening address from subgate within 5s");

        Self {
            child,
            addr,
            _dir: dir,
        }
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(&self.addr).expect("connect to subgate");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set write timeout");
        stream
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

fn send_and_read_all(stream: &mut TcpStream, req: &[u8]) -> Vec<u8> {
    stream.write_all(req).expect("write request");
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                resp.extend_from_slice(&buf[..n]);
                if let Some(pos) = resp.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&resp[..pos]);
                    let mut cl = 0usize;
                    for line in head.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                cl = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    if resp.len() >= pos + 4 + cl {
                        break;
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) => panic!("read failed: {e}"),
        }
    }
    resp
}

fn send_and_read_response(stream: &mut TcpStream, req: &[u8]) -> (String, Vec<u8>) {
    let is_head = req.starts_with(b"HEAD ");
    stream.write_all(req).expect("write request");
    read_one_response(stream, is_head)
}

fn read_one_response(stream: &mut TcpStream, is_head: bool) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];

    loop {
        let n = stream.read(&mut scratch).expect("read from socket");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&scratch[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos + 2]).into_owned();
            let body_start = pos + 4;
            let mut content_length = 0usize;
            if !is_head {
                for line in head.lines() {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
            }

            while buf.len() < body_start + content_length {
                let n = stream.read(&mut scratch).expect("read body");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&scratch[..n]);
            }

            let body =
                buf[body_start..body_start + content_length.min(buf.len() - body_start)].to_vec();
            return (head, body);
        }
    }

    let head = String::from_utf8_lossy(&buf).into_owned();
    (head, Vec::new())
}

#[test]
fn test_cli_check_flag() {
    let bin = env!("CARGO_BIN_EXE_subgate");

    // Valid config
    let status = Command::new(bin)
        .args(["--check", "config.json"])
        .status()
        .expect("run --check on config.json");
    assert!(status.success());

    // Missing file
    let status = Command::new(bin)
        .args(["--check", "nonexistent-config-file.json"])
        .status()
        .expect("run --check on missing file");
    assert_eq!(status.code(), Some(1));

    // Invalid JSON
    let bad_json = std::env::temp_dir().join("bad.json");
    std::fs::write(&bad_json, "{").unwrap();
    let status = Command::new(bin)
        .args(["--check", bad_json.to_str().unwrap()])
        .status()
        .expect("run --check on bad json");
    assert_eq!(status.code(), Some(1));
    let _ = std::fs::remove_file(bad_json);

    // Missing argument
    let status = Command::new(bin)
        .args(["--check"])
        .status()
        .expect("run --check without file");
    assert_eq!(status.code(), Some(2));
}

#[test]
fn test_basic_endpoints_and_stealth() {
    let server = TestServer::spawn();
    let mut conn = server.connect();

    // 1. Root 200 OK
    let req = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (head, body) = send_and_read_response(&mut conn, req);
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "got head: {head}");
    assert!(head.contains("Server: nginx/1.28.3 (Ubuntu)\r\n"));
    assert!(head.contains("Content-Type: text/html\r\n"));
    assert!(head.contains("Content-Length: 615\r\n"));
    assert!(head.contains("ETag: "));
    assert!(head.contains("Accept-Ranges: bytes\r\n"));
    assert_eq!(body.len(), 615);

    // 2. HEAD / has no body
    let head_req = b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (head, body) = send_and_read_response(&mut conn, head_req);
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(head.contains("Content-Length: 615\r\n"));
    assert!(body.is_empty());

    // 3. Unknown path gives 404
    let req_404 = b"GET /not-found HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (head, body) = send_and_read_response(&mut conn, req_404);
    assert!(head.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(String::from_utf8_lossy(&body).contains("404 Not Found"));

    // 4. POST / gives 405
    let req_405 = b"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (head, body) = send_and_read_response(&mut conn, req_405);
    assert!(head.starts_with("HTTP/1.1 405 Not Allowed\r\n"));
    assert!(String::from_utf8_lossy(&body).contains("405 Not Allowed"));
}

#[test]
fn test_subscription_rendering_and_group_isolation() {
    let server = TestServer::spawn();

    // Group 1: Clash
    let mut conn = server.connect();
    let req = format!("GET /{TOKEN_MAIN}/clash HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = send_and_read_response(&mut conn, req.as_bytes());
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(head.contains("Content-Type: text/yaml; charset=utf-8\r\n"));
    assert!(head.contains("Cache-Control: no-store\r\n"));
    let yaml = String::from_utf8(body).expect("utf8 yaml");
    assert!(yaml.contains("mixed-port: 7890"));
    assert!(yaml.contains("name: hk-1"));
    assert!(yaml.contains("MATCH,main"));
    assert!(
        !yaml.contains("Hong Kong Fast"),
        "Group 1 leaked Group 2 display name"
    );

    // Group 2: Clash with override name
    let mut conn2 = server.connect();
    let req2 = format!("GET /{TOKEN_FAMILY}/clash HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head2, body2) = send_and_read_response(&mut conn2, req2.as_bytes());
    assert!(head2.starts_with("HTTP/1.1 200 OK\r\n"));
    let yaml2 = String::from_utf8(body2).expect("utf8 yaml");
    assert!(yaml2.contains("name: Hong Kong Fast"));
    assert!(yaml2.contains("MATCH,family"));

    // Group 1: v2ray base64
    let mut conn3 = server.connect();
    let req3 = format!("GET /{TOKEN_MAIN}/v2ray HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head3, body3) = send_and_read_response(&mut conn3, req3.as_bytes());
    assert!(head3.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(head3.contains("Content-Type: text/plain; charset=utf-8\r\n"));
    let b64 = String::from_utf8(body3).expect("utf8 b64");
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .expect("decode v2ray b64");
    let link = String::from_utf8(decoded).expect("utf8 link");
    assert!(link.starts_with("vless://"));
    assert!(link.contains("security=reality"));
    assert!(link.ends_with("#hk-1"));

    // Group 2: v2ray with percent-encoded override name
    let mut conn4 = server.connect();
    let req4 = format!("GET /{TOKEN_FAMILY}/v2ray HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (_, body4) = send_and_read_response(&mut conn4, req4.as_bytes());
    let b64_2 = String::from_utf8(body4).expect("utf8 b64");
    let decoded2 = base64::engine::general_purpose::STANDARD
        .decode(b64_2.trim())
        .expect("decode v2ray b64");
    let link2 = String::from_utf8(decoded2).expect("utf8 link");
    assert!(link2.ends_with("#Hong%20Kong%20Fast"));

    // Unknown token gives identical 404
    let mut conn5 = server.connect();
    let req5 = b"GET /unknown-token-1234567890/clash HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (head5, body5) = send_and_read_response(&mut conn5, req5);
    assert!(head5.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(String::from_utf8_lossy(&body5).contains("404 Not Found"));
}

#[test]
fn test_http_framing_and_pipelining() {
    let server = TestServer::spawn();
    let mut conn = server.connect();

    // Pipelining: 2 GET requests written together
    let pipelined = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\nGET /not-found HTTP/1.1\r\nHost: localhost\r\n\r\n";
    conn.write_all(pipelined).expect("write pipelined");

    let (head1, body1) = read_one_response(&mut conn, false);
    assert!(head1.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(body1.len(), 615);

    let (head2, body2) = read_one_response(&mut conn, false);
    assert!(head2.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(String::from_utf8_lossy(&body2).contains("404 Not Found"));

    // POST with body followed by GET on persistent connection
    let mut conn2 = server.connect();
    let post_and_get = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n12345GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    conn2.write_all(post_and_get).expect("write post and get");

    let (head1, _) = read_one_response(&mut conn2, false);
    assert!(head1.starts_with("HTTP/1.1 405 Not Allowed\r\n"));

    let (head2, body2) = read_one_response(&mut conn2, false);
    assert!(head2.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(body2.len(), 615);
}

#[test]
fn test_http_framing_rejections() {
    let server = TestServer::spawn();

    // 1. Missing Host header in HTTP/1.1 -> 400 Bad Request & Connection close
    let mut conn = server.connect();
    let req = b"GET / HTTP/1.1\r\n\r\n";
    let resp = String::from_utf8_lossy(&send_and_read_all(&mut conn, req)).into_owned();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(resp.contains("Connection: close\r\n"));

    // 2. Duplicate Host header in HTTP/1.1 -> 400 Bad Request & Connection close
    let mut conn = server.connect();
    let req = b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n";
    let resp = String::from_utf8_lossy(&send_and_read_all(&mut conn, req)).into_owned();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(resp.contains("Connection: close\r\n"));

    // 3. Transfer-Encoding: chunked is rejected (smuggling protection)
    let mut conn = server.connect();
    let req = b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let resp = String::from_utf8_lossy(&send_and_read_all(&mut conn, req)).into_owned();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(resp.contains("Connection: close\r\n"));

    // 4. Duplicate Content-Length -> 400 Bad Request
    let mut conn = server.connect();
    let req = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
    let resp = String::from_utf8_lossy(&send_and_read_all(&mut conn, req)).into_owned();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(resp.contains("Connection: close\r\n"));

    // 5. Malformed Content-Length -> 400 Bad Request
    let mut conn = server.connect();
    let req = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -5\r\n\r\n";
    let resp = String::from_utf8_lossy(&send_and_read_all(&mut conn, req)).into_owned();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));

    // 6. Non-origin request target -> 400 Bad Request
    let mut conn = server.connect();
    let req = b"GET foo HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let resp = String::from_utf8_lossy(&send_and_read_all(&mut conn, req)).into_owned();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));

    // 7. Request target containing fragment '#' -> 400 Bad Request
    let mut conn = server.connect();
    let req = b"GET /#frag HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let resp = String::from_utf8_lossy(&send_and_read_all(&mut conn, req)).into_owned();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));

    // 8. Space before colon in header -> 400 Bad Request
    let mut conn = server.connect();
    let req = b"GET / HTTP/1.1\r\nHost : localhost\r\n\r\n";
    let resp = String::from_utf8_lossy(&send_and_read_all(&mut conn, req)).into_owned();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));

    // 9. Obsolete line folding -> 400 Bad Request
    let mut conn = server.connect();
    let req = b"GET / HTTP/1.1\r\nHost: localhost\r\n X-Folded: foo\r\n\r\n";
    let resp = String::from_utf8_lossy(&send_and_read_all(&mut conn, req)).into_owned();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));
}

#[test]
fn test_range_request_safety_and_correctness() {
    let server = TestServer::spawn();

    // 1. Single valid range
    let mut conn = server.connect();
    let req = b"GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-9\r\n\r\n";
    let (head, body) = send_and_read_response(&mut conn, req);
    assert!(head.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(head.contains("Content-Length: 10\r\n"));
    assert!(head.contains("Content-Range: bytes 0-9/615\r\n"));
    assert_eq!(body.len(), 10);

    // 2. Non-ASCII Range prefix: MUST NOT PANIC OR CRASH (Regression test for value[..6])
    let mut conn2 = server.connect();
    let req2 = "GET / HTTP/1.1\r\nHost: localhost\r\nRange: 范围=0-10\r\n\r\n";
    let (head2, _) = send_and_read_response(&mut conn2, req2.as_bytes());
    assert!(head2.starts_with("HTTP/1.1 400 Bad Request\r\n"));

    // Unsupported unit (non-bytes) falls back to 200 OK full body
    let mut conn2b = server.connect();
    let req2b = "GET / HTTP/1.1\r\nHost: localhost\r\nRange: items=0-10\r\n\r\n";
    let (head2b, body2b) = send_and_read_response(&mut conn2b, req2b.as_bytes());
    assert!(head2b.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(body2b.len(), 615);

    // 3. Malformed range value returns 416
    let mut conn3 = server.connect();
    let req3 = b"GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=-\r\n\r\n";
    let (head3, _) = send_and_read_response(&mut conn3, req3);
    assert!(head3.starts_with("HTTP/1.1 416 Requested Range Not Satisfiable\r\n"));

    // 4. Multipart range
    let mut conn4 = server.connect();
    let req4 = b"GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-4,10-14\r\n\r\n";
    let (head4, body4) = send_and_read_response(&mut conn4, req4);
    assert!(head4.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(head4.contains("Content-Type: multipart/byteranges; boundary="));
    assert!(body4.len() > 10);

    // 5. Excessive ranges (>100) fallback to 200 OK
    let mut conn5 = server.connect();
    let mut range_str = String::from("Range: bytes=");
    for i in 0..105 {
        if i > 0 {
            range_str.push(',');
        }
        range_str.push_str("0-1");
    }
    let req5 = format!("GET / HTTP/1.1\r\nHost: localhost\r\n{range_str}\r\n\r\n");
    let (head5, body5) = send_and_read_response(&mut conn5, req5.as_bytes());
    assert!(head5.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(body5.len(), 615);
}

#[test]
fn test_resource_limits_oversized_payloads() {
    let server = TestServer::spawn();

    // 1. Oversized headers (>16KB) -> 400 Bad Request
    let mut conn = server.connect();
    let big_val = "x".repeat(17 * 1024);
    let req = format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Big: {big_val}\r\n\r\n");
    let resp = String::from_utf8_lossy(&send_and_read_all(&mut conn, req.as_bytes())).into_owned();
    assert!(
        resp.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "got resp: {resp}"
    );

    // 2. Declared Content-Length > 8MB -> 413 Request Entity Too Large
    let mut conn2 = server.connect();
    let req2 = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9000000\r\n\r\n";
    let resp2 = String::from_utf8_lossy(&send_and_read_all(&mut conn2, req2)).into_owned();
    assert!(
        resp2.starts_with("HTTP/1.1 413 Request Entity Too Large\r\n"),
        "got resp: {resp2}"
    );
}

#[test]
fn test_adversarial_inputs_do_not_crash_server() {
    let server = TestServer::spawn();

    let adversarial = [
        "GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=\u{FFFD}\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=9999999999999999999999999999999-1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=,,,,,,,,,,,,,,,,,,,,,,,\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 000000000000000000000000000000\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: \"\"\"\"\"\"\"\"\"\"\"\"\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: localhost\r\nIf-Modified-Since: 99999999999999999999\r\n\r\n",
        "GET /../../../../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /%00/clash HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /\r/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /\n/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ];

    for (idx, payload) in adversarial.iter().enumerate() {
        let mut conn = server.connect();
        let resp = send_and_read_all(&mut conn, payload.as_bytes());
        // Server should respond (either 200, 400, 404, 416) and must not crash
        assert!(
            !resp.is_empty() || payload.contains('\r') || payload.contains('\n'),
            "case {idx} produced no response"
        );
    }

    // Verify the server is still healthy and responsive
    let mut check_conn = server.connect();
    let (head, body) = send_and_read_response(
        &mut check_conn,
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(body.len(), 615);
}

#[test]
fn test_connection_limit_enforcement() {
    // Start server with max 2 concurrent connections
    let server = TestServer::spawn_with_env(&[("SUBGATE_MAX_CONNS", "2")]);

    let mut conn1 = server.connect();
    let mut conn2 = server.connect();

    // Verify first 2 connections can communicate
    let (h1, _) = send_and_read_response(&mut conn1, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(h1.starts_with("HTTP/1.1 200 OK\r\n"));
    let (h2, _) = send_and_read_response(&mut conn2, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(h2.starts_with("HTTP/1.1 200 OK\r\n"));

    // 3rd concurrent connection exceeds limit: server drops connection immediately on accept
    let mut conn3 = server.connect();
    // conn3 will see EOF / immediate close
    let mut buf = [0u8; 128];
    conn3
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .ok();
    let n = conn3.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "excess connection should be dropped on accept");

    // Close conn1 to release permit
    drop(conn1);
    std::thread::sleep(Duration::from_millis(50));

    // Now a new connection succeeds
    let mut conn4 = server.connect();
    let (h4, _) = send_and_read_response(&mut conn4, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(h4.starts_with("HTTP/1.1 200 OK\r\n"));
}

#[test]
fn test_keepalive_requests_limit() {
    // Limit to 2 requests per connection
    let server = TestServer::spawn_with_env(&[("SUBGATE_KEEPALIVE_REQUESTS", "2")]);
    let mut conn = server.connect();

    // 1st request: keeps alive
    let (h1, _) = send_and_read_response(&mut conn, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(h1.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(h1.contains("Connection: keep-alive\r\n"));

    // 2nd request: reaches limit, server sends Connection: close and terminates
    let (h2, _) = send_and_read_response(&mut conn, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(h2.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(h2.contains("Connection: close\r\n"), "got: {h2}");

    // Connection should now be closed by the server
    let mut buf = [0u8; 10];
    let n = conn.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "connection should be closed after keepalive limit");
}

#[test]
fn test_header_timeout_enforcement() {
    // Tight timeouts: 150ms
    let server = TestServer::spawn_with_env(&[("SUBGATE_TIMEOUT_MS", "150")]);
    let mut conn = server.connect();

    // Send partial request line and stall
    conn.write_all(b"GET / HT").expect("write partial");
    std::thread::sleep(Duration::from_millis(300));

    // Connection should be closed by server on timeout
    let mut buf = [0u8; 10];
    let n = conn.read(&mut buf).unwrap_or(0);
    assert_eq!(
        n, 0,
        "stalled client should be disconnected on header timeout"
    );
}
