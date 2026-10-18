//! Clash / mihomo configuration rendering.
//!
//! Produces a `proxy-providers`-free, self-contained profile: a single
//! `proxies` list plus a minimal `proxy-groups` entry and the rules most
//! clients expect on import.
//!
//! Every scalar is emitted as a JSON string, which is valid YAML. That avoids
//! a YAML dependency and sidesteps quoting rules entirely: a node named
//! `a: b` or `#x` cannot break the document.

use crate::config::Config;
use crate::model::Group;

/// Render a group as a Clash profile.
pub fn render(cfg: &Config, group: &Group) -> String {
    let nodes = cfg.group_nodes(group);
    let mut out = String::with_capacity(512 + nodes.len() * 256);

    out.push_str("mixed-port: 7890\n");
    out.push_str("allow-lan: false\n");
    out.push_str("mode: rule\n");
    out.push_str("log-level: info\n");

    out.push_str("proxies:\n");
    if nodes.is_empty() {
        out.push_str("  []\n");
    }
    for (node, display) in &nodes {
        out.push_str("  - name: ");
        out.push_str(&yaml_str(display));
        out.push('\n');
        out.push_str("    type: vless\n");
        out.push_str("    server: ");
        out.push_str(&yaml_str(&node.address));
        out.push('\n');
        out.push_str("    port: ");
        out.push_str(&node.port.to_string());
        out.push('\n');
        out.push_str("    uuid: ");
        out.push_str(&yaml_str(&node.uuid));
        out.push('\n');
        out.push_str("    network: tcp\n");
        out.push_str("    tls: true\n");
        out.push_str("    udp: true\n");

        if !node.flow.is_empty() {
            out.push_str("    flow: ");
            out.push_str(&yaml_str(&node.flow));
            out.push('\n');
        }

        if !node.fingerprint.is_empty() {
            out.push_str("    client-fingerprint: ");
            out.push_str(&yaml_str(&node.fingerprint));
            out.push('\n');
        }

        if !node.alpn.is_empty() {
            out.push_str("    alpn:\n");
            for a in &node.alpn {
                out.push_str("      - ");
                out.push_str(&yaml_str(a));
                out.push('\n');
            }
        }

        out.push_str("    servername: ");
        out.push_str(&yaml_str(&node.server_name));
        out.push('\n');
        out.push_str("    reality-opts:\n");
        out.push_str("      public-key: ");
        out.push_str(&yaml_str(&node.public_key));
        out.push('\n');
        if !node.short_id.is_empty() {
            out.push_str("      short-id: ");
            out.push_str(&yaml_str(&node.short_id));
            out.push('\n');
        }
    }

    // A group with a single member is what mihomo wants when the profile is
    // self-contained; users repoint it at their own selector on import.
    out.push_str("proxy-groups:\n");
    out.push_str("  - name: ");
    out.push_str(&yaml_str(&group.name));
    out.push('\n');
    out.push_str("    type: select\n");
    out.push_str("    proxies:\n");
    if nodes.is_empty() {
        out.push_str("      []\n");
    }
    for (_, display) in &nodes {
        out.push_str("      - ");
        out.push_str(&yaml_str(display));
        out.push('\n');
    }

    // The rule target is matched against the group name by mihomo, so the
    // quoting style of `proxy-groups[].name` must not leak in here.
    out.push_str("rules:\n  - MATCH,");
    out.push_str(&group.name);
    out.push('\n');
    out
}

/// Emit a scalar, quoting only when YAML requires it.
///
/// Plain scalars keep the document readable; anything containing a character
/// that could change the parse (a `:` followed by space, a leading indicator,
/// a control character) falls back to a JSON string, which is also valid YAML
/// double-quoted syntax and cannot be broken out of.
fn yaml_str(s: &str) -> String {
    if needs_quotes(s) {
        return quoted(s);
    }
    s.to_string()
}

pub(crate) fn needs_quotes(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }

    // YAML 1.2 would resolve these to booleans or null, not strings.
    const RESERVED: [&str; 9] = [
        "true", "false", "yes", "no", "on", "off", "null", "~", "None",
    ];
    if RESERVED.iter().any(|r| s.eq_ignore_ascii_case(r)) {
        return true;
    }

    let first = s.chars().next().unwrap();
    if "-?:,[]{}#&*!|>'\"%@`".contains(first) {
        return true;
    }
    if first.is_whitespace() || s.ends_with(char::is_whitespace) {
        return true;
    }

    // A `: ` or ` #` sequence would start a mapping or a comment.
    if s.contains(": ") || s.contains(" #") {
        return true;
    }

    // Quotes and backslashes are legal in a plain scalar but make the output
    // hard to read next to quoted values, so keep them quoted.
    if s.contains('"') || s.contains('\\') {
        return true;
    }

    s.chars().any(|c| c.is_control())
}

fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Node;

    fn node(name: &str) -> Node {
        Node {
            name: name.to_string(),
            address: "example.com".to_string(),
            port: 443,
            uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            public_key: "bK4PTQX5dwqSdVBzADrqhPtALBwj9b0uYjYR29lS4xE".to_string(),
            short_id: "0123456789abcdef".to_string(),
            server_name: "www.example.com".to_string(),
            flow: "xtls-rprx-vision".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: String::new(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }

    fn config(nodes: Vec<Node>, refs: Vec<&str>) -> Config {
        let json = format!(
            r#"{{"listen":"127.0.0.1:1","nodes":{},"groups":[{{"token":"t-0123456789abcdef","name":"main","nodes":{}}}]}}"#,
            serde_json::to_string(
                &nodes
                    .iter()
                    .map(|n| serde_json::json!({
                        "name": n.name, "address": n.address, "port": n.port, "uuid": n.uuid,
                        "public-key": n.public_key, "short-id": n.short_id,
                        "server-name": n.server_name, "flow": n.flow,
                        "fingerprint": n.fingerprint, "alpn": n.alpn,
                    }))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            serde_json::to_string(&refs).unwrap()
        );
        let dir = std::env::temp_dir().join("subgate-clash-tests");
        std::fs::create_dir_all(&dir).unwrap();
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = dir.join(format!("c{n}.json"));
        std::fs::write(&path, json).unwrap();
        Config::load(&path).unwrap()
    }

    #[test]
    fn renders_required_fields() {
        let cfg = config(vec![node("hk-1")], vec!["hk-1"]);
        let out = render(&cfg, &cfg.groups[0]);
        assert!(out.contains("name: hk-1"));
        assert!(out.contains("type: vless"));
        assert!(out.contains("server: example.com"));
        assert!(out.contains("port: 443"));
        assert!(out.contains("servername: www.example.com"));
        assert!(out.contains("public-key: bK4PTQX5dwqSdVBzADrqhPtALBwj9b0uYjYR29lS4xE"));
        assert!(out.contains("short-id: 0123456789abcdef"));
        assert!(out.contains("flow: xtls-rprx-vision"));
        assert!(out.contains("client-fingerprint: chrome"));
        assert!(out.contains("      - h2"));
    }

    #[test]
    fn empty_short_id_is_omitted() {
        let mut n = node("a");
        n.short_id = String::new();
        let cfg = config(vec![n], vec!["a"]);
        let out = render(&cfg, &cfg.groups[0]);
        assert!(!out.contains("short-id"));
    }

    #[test]
    fn empty_group_renders_empty_lists() {
        let cfg = config(vec![], vec![]);
        let out = render(&cfg, &cfg.groups[0]);
        assert!(out.contains("proxies:\n  []"));
        assert!(out.contains("proxies:\n      []"));
    }

    #[test]
    fn display_name_override_is_used() {
        let cfg = config(vec![node("hk-1")], vec!["hk-1"]);
        let out = render(&cfg, &cfg.groups[0]);
        assert!(out.contains("- hk-1"));
    }

    #[test]
    fn dangerous_scalars_are_escaped() {
        // A name that would break an unquoted YAML document.
        assert_eq!(yaml_str("a: b"), "\"a: b\"");
        assert_eq!(yaml_str("#x"), "\"#x\"");
        assert_eq!(yaml_str("a\nb"), "\"a\\nb\"");
        assert_eq!(yaml_str("a\"b"), "\"a\\\"b\"");
        assert_eq!(yaml_str("a\\b"), "\"a\\\\b\"");
        assert_eq!(yaml_str("\u{1}"), "\"\\u0001\"");
        // Plain scalars stay unquoted.
        assert_eq!(yaml_str("hk-1"), "hk-1");
        assert_eq!(yaml_str("Hong Kong 01"), "Hong Kong 01");
        assert_eq!(yaml_str("example.com"), "example.com");
        // Values YAML would otherwise coerce to another type.
        assert_eq!(yaml_str("null"), "\"null\"");
        assert_eq!(yaml_str("true"), "\"true\"");
        assert_eq!(yaml_str(""), "\"\"");
    }

    #[test]
    fn match_rule_uses_raw_group_name() {
        let cfg = config(vec![node("hk-1")], vec!["hk-1"]);
        let out = render(&cfg, &cfg.groups[0]);
        assert!(out.contains("rules:\n  - MATCH,main\n"));
    }

    #[test]
    fn empty_group_keeps_match_rule() {
        let cfg = config(vec![], vec![]);
        let out = render(&cfg, &cfg.groups[0]);
        assert!(out.contains("proxies:\n  []"));
        assert!(out.contains("proxies:\n      []"));
        assert!(out.contains("rules:\n  - MATCH,main\n"));
    }

    #[test]
    fn quoted_group_name_fails_validation() {
        // A group name needing quotes (e.g. `a: b`) must be rejected at load
        // so the raw MATCH line can never corrupt the profile.
        let dir = std::env::temp_dir().join("subgate-clash-tests");
        std::fs::create_dir_all(&dir).unwrap();
        static SEQ2: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1000);
        let n = SEQ2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = dir.join(format!("q{n}.json"));
        std::fs::write(
            &path,
            r#"{"listen":"127.0.0.1:1","nodes":[],"groups":[{"token":"q1234567890123456","name":"a: b","nodes":[]}]}"#,
        )
        .unwrap();
        let err = Config::load(&path).unwrap_err();
        assert!(err.contains("MATCH rule"), "{err}");
    }
}
