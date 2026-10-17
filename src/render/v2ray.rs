//! v2rayN / v2rayNG subscription rendering.
//!
//! The subscription format is a base64-encoded newline-separated list of share
//! links. Standard base64 with padding is what v2rayN accepts, and it is what
//! most panels emit.
//!
//! Each link is a `vless://` URI with the Reality parameters in the query
//! string.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::config::Config;
use crate::model::{Group, Node};

/// Render a group as a base64 subscription payload.
pub fn render(cfg: &Config, group: &Group) -> String {
    let nodes = cfg.group_nodes(group);
    let mut plain = String::with_capacity(nodes.len() * 256);

    for (i, (node, display)) in nodes.iter().enumerate() {
        if i > 0 {
            plain.push('\n');
        }
        plain.push_str(&link(node, display));
    }

    STANDARD.encode(plain.as_bytes())
}

/// Build one `vless://` share link.
pub fn link(node: &Node, display: &str) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("vless://");
    out.push_str(&node.uuid);
    out.push('@');
    out.push_str(&host(&node.address));
    out.push(':');
    out.push_str(&node.port.to_string());
    out.push('?');

    let mut params: Vec<(&str, String)> = vec![
        ("encryption", "none".to_string()),
        ("type", "tcp".to_string()),
        ("security", "reality".to_string()),
        ("sni", node.server_name.clone()),
        ("fp", node.fingerprint.clone()),
        ("pbk", node.public_key.clone()),
    ];

    if !node.flow.is_empty() {
        params.push(("flow", node.flow.clone()));
    }
    if !node.short_id.is_empty() {
        params.push(("sid", node.short_id.clone()));
    }
    if !node.alpn.is_empty() {
        params.push(("alpn", node.alpn.join(",")));
    }
    if !node.spider_x.is_empty() {
        params.push(("spx", node.spider_x.clone()));
    }

    // Fixed order keeps the output stable and readable; every value is
    // percent-encoded, so a `/` in spiderX or a comma in ALPN is safe.
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(&percent_encode(v));
    }

    out.push('#');
    out.push_str(&percent_encode(display));
    out
}

/// Bracket a literal IPv6 address so the port separator stays unambiguous.
fn host(address: &str) -> String {
    if address.contains(':') && !address.starts_with('[') {
        format!("[{address}]")
    } else {
        address.to_string()
    }
}

/// Percent-encode everything outside the URI unreserved set plus the
/// sub-delimiters that clients expect to see verbatim.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> Node {
        Node {
            name: "hk-1".to_string(),
            address: "example.com".to_string(),
            port: 443,
            uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            public_key: "PUBKEY".to_string(),
            short_id: "0123456789abcdef".to_string(),
            server_name: "www.example.com".to_string(),
            flow: "xtls-rprx-vision".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: "/".to_string(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }

    #[test]
    fn link_contains_every_parameter() {
        let l = link(&node(), "hk-1");
        assert!(l.starts_with("vless://11111111-2222-3333-4444-555555555555@example.com:443?"));
        assert!(l.contains("encryption=none"));
        assert!(l.contains("security=reality"));
        assert!(l.contains("sni=www.example.com"));
        assert!(l.contains("pbk=PUBKEY"));
        assert!(l.contains("sid=0123456789abcdef"));
        assert!(l.contains("flow=xtls-rprx-vision"));
        assert!(l.contains("fp=chrome"));
        assert!(l.contains("alpn=h2%2Chttp%2F1.1"));
        assert!(l.contains("spx=%2F"));
        assert!(l.ends_with("#hk-1"));
    }

    #[test]
    fn ipv6_is_bracketed() {
        let mut n = node();
        n.address = "2001:db8::1".to_string();
        assert!(link(&n, "x").contains("@[2001:db8::1]:443"));
    }

    #[test]
    fn already_bracketed_ipv6_is_left_alone() {
        let mut n = node();
        n.address = "[2001:db8::1]".to_string();
        assert!(link(&n, "x").contains("@[2001:db8::1]:443"));
    }

    #[test]
    fn empty_optionals_are_omitted() {
        let mut n = node();
        n.short_id = String::new();
        n.flow = String::new();
        n.spider_x = String::new();
        let l = link(&n, "x");
        assert!(!l.contains("sid="));
        assert!(!l.contains("flow="));
        assert!(!l.contains("spx="));
    }

    #[test]
    fn display_name_is_encoded() {
        let l = link(&node(), "Hong Kong 01");
        assert!(l.ends_with("#Hong%20Kong%2001"));
    }

    #[test]
    fn percent_encode_keeps_unreserved() {
        assert_eq!(percent_encode("aZ09-._~"), "aZ09-._~");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("a,b"), "a%2Cb");
        assert_eq!(percent_encode("a/b"), "a%2Fb");
    }
}
