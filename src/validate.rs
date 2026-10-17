//! Configuration validation.
//!
//! Kept apart from `config.rs` so the loader stays a plain "read, parse,
//! index" path and the rules that decide what is acceptable live in one place.
//!
//! Everything here is a configuration mistake that would otherwise surface as
//! a confusing runtime failure, so it is rejected at load time.

use std::collections::HashSet;

use crate::config::Config;

/// Validate the node table and the group table.
///
/// Everything here is a configuration mistake that would otherwise surface
/// as a confusing runtime failure, so it is rejected at load time.
pub fn validate(cfg: &Config) -> Result<(), String> {
    if cfg.server_token.is_empty() {
        return Err("server_token must not be empty".into());
    }

    // The value goes straight into an HTTP header and into HTML, so
    // reject control characters and quotes to rule out header injection.
    if cfg
        .server_token
        .chars()
        .any(|c| c.is_control() || c == '"' || c == '\\')
    {
        return Err("server_token contains invalid characters".into());
    }

    validate_nodes(cfg)?;
    validate_groups(cfg)
}

pub fn validate_nodes(cfg: &Config) -> Result<(), String> {
    let mut names = HashSet::new();

    for node in &cfg.nodes {
        // Required fields that must also be non-empty.
        //
        // `server-name` is the Reality SNI: an empty value would produce a
        // node that renders without error but can never complete a
        // handshake, so it is rejected here rather than at connect time.
        for (label, value) in [
            ("node name", &node.name),
            ("address", &node.address),
            ("uuid", &node.uuid),
            ("public-key", &node.public_key),
            ("server-name", &node.server_name),
        ] {
            if value.trim().is_empty() {
                return Err(format!(
                    "node {:?}: {label} must not be empty",
                    node.name
                ));
            }
            if value.chars().any(|c| c.is_control()) {
                return Err(format!(
                    "node {:?}: {label} must not contain control characters",
                    node.name
                ));
            }
        }

        // Fields that may be blank, but must never carry a control
        // character: `flow` and `fingerprint` are written into YAML, and
        // the rest are appended to subscription links.
        //
        // `short-id` belongs here rather than above: a server that does no
        // shortId matching takes an empty one, so only its content is
        // constrained, not its emptiness.
        for (label, value) in [
            ("flow", &node.flow),
            ("fingerprint", &node.fingerprint),
            ("short-id", &node.short_id),
            ("spider-x", &node.spider_x),
        ] {
            if value.chars().any(|c| c.is_control()) {
                return Err(format!(
                    "node {:?}: {label} must not contain control characters",
                    node.name
                ));
            }
        }

        for alpn in &node.alpn {
            if alpn.trim().is_empty() {
                return Err(format!(
                    "node {:?}: alpn entries must not be empty",
                    node.name
                ));
            }
            if alpn.chars().any(|c| c.is_control() || c == ',') {
                return Err(format!(
                    "node {:?}: alpn entry {alpn:?} contains an invalid character",
                    node.name
                ));
            }
        }

        if node.port == 0 {
            return Err(format!("node {:?}: port must not be 0", node.name));
        }

        if !names.insert(&node.name) {
            return Err(format!("duplicate node name {:?}", node.name));
        }
    }

    Ok(())
}

pub fn validate_groups(cfg: &Config) -> Result<(), String> {
    let mut tokens = HashSet::new();
    let mut group_names = HashSet::new();
    // Reused across groups to avoid one allocation per group.
    let mut seen = HashSet::new();

    for group in &cfg.groups {
        validate_token(&group.token)?;

        if !tokens.insert(&group.token) {
            return Err(format!("duplicate token {:?}", group.token));
        }
        if group.name.trim().is_empty() {
            return Err(format!("group with token {:?}: name must not be empty", group.token));
        }
        if group.name.chars().any(|c| c.is_control()) {
            return Err(format!(
                "group {:?}: name must not contain control characters",
                group.name
            ));
        }
        if !group_names.insert(&group.name) {
            return Err(format!("duplicate group name {:?}", group.name));
        }

        // Every reference must resolve, and a group must not publish the
        // same node twice.
        seen.clear();
        for r in &group.nodes {
            let name = &r.reference;
            if name.is_empty() {
                return Err(format!("group {:?}: node reference must not be empty", group.name));
            }
            if !cfg.node_index.contains_key(name) {
                return Err(format!(
                    "group {:?}: unknown node {name:?}",
                    group.name
                ));
            }
            if !seen.insert(name) {
                return Err(format!(
                    "group {:?}: node {name:?} listed twice",
                    group.name
                ));
            }

            if let Some(display) = &r.name {
                if display.trim().is_empty() {
                    return Err(format!(
                        "group {:?}, node {name:?}: display name must not be empty",
                        group.name
                    ));
                }
                if display.chars().any(|c| c.is_control()) {
                    return Err(format!(
                        "group {:?}, node {name:?}: display name must not contain control characters",
                        group.name
                    ));
                }
            }
        }
    }

    Ok(())
}

/// A token becomes a URL path segment, so it must survive both a raw and a
/// percent-decoded interpretation unchanged.
fn validate_token(token: &str) -> Result<(), String> {
    if token.is_empty() {
        return Err("token must not be empty".into());
    }

    let valid = token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');

    if !valid {
        return Err(format!(
            "token {token:?} must contain only ASCII letters, digits, '-' and '_'"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::io::Write;

    fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("subgate-validate-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn cfg_with(body: &str) -> Result<Config, String> {
        // Tests run in parallel, so the file name must be unique per call.
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = write_temp(&format!("groups-{n}.json"), body);
        Config::load(&p)
    }

    fn node_json(name: &str) -> String {
        format!(
            r#"{{"name":"{name}","address":"a","port":443,"uuid":"u","public-key":"k","short-id":"01","server-name":"sni.example"}}"#
        )
    }

    fn group_json(token: &str, name: &str, nodes: &[&str]) -> String {
        let list = nodes
            .iter()
            .map(|n| format!(r#""{n}""#))
            .collect::<Vec<_>>()
            .join(",");
        format!(r#"{{"token":"{token}","name":"{name}","nodes":[{list}]}}"#)
    }

    fn config_json(nodes: &[String], groups: &[String]) -> String {
        format!(
            r#"{{"listen":"127.0.0.1:1","nodes":[{}],"groups":[{}]}}"#,
            nodes.join(","),
            groups.join(",")
        )
    }

    fn one_group() -> String {
        config_json(
            &[node_json("hk-1")],
            &[group_json("abc123", "main", &["hk-1"])],
        )
    }

    #[test]
    fn groups_parse_and_lookup_by_token() {
        let cfg = cfg_with(&one_group()).unwrap();
        assert_eq!(cfg.groups.len(), 1);
        let g = cfg.group_for_token("abc123").unwrap();
        assert_eq!(g.name, "main");
        assert_eq!(g.nodes.len(), 1);
        assert_eq!(g.nodes[0].reference, "hk-1");
        assert!(cfg.group_for_token("abc124").is_none());
    }

    #[test]
    fn groups_default_to_empty() {
        let cfg = cfg_with(r#"{"listen":"127.0.0.1:1"}"#).unwrap();
        assert!(cfg.groups.is_empty());
        assert!(cfg.nodes.is_empty());
        assert!(cfg.group_for_token("anything").is_none());
    }

    #[test]
    fn node_references_resolve_in_group_order() {
        let cfg = cfg_with(&config_json(
            &[node_json("a"), node_json("b"), node_json("c")],
            &[group_json("t", "g", &["c", "a"])],
        ))
        .unwrap();
        let g = cfg.group_for_token("t").unwrap();
        let resolved: Vec<&str> = cfg.group_nodes(g).into_iter().map(|(_, d)| d).collect();
        assert_eq!(resolved, vec!["c", "a"]);
    }

    #[test]
    fn one_node_can_be_shared_by_several_groups() {
        let cfg = cfg_with(&config_json(
            &[node_json("shared")],
            &[
                group_json("t1", "g1", &["shared"]),
                group_json("t2", "g2", &["shared"]),
            ],
        ))
        .unwrap();
        assert_eq!(cfg.groups.len(), 2);
        assert_eq!(cfg.nodes.len(), 1);
    }

    #[test]
    fn unreferenced_node_is_allowed() {
        let cfg = cfg_with(&config_json(
            &[node_json("spare")],
            &[group_json("t", "g", &[])],
        ))
        .unwrap();
        assert_eq!(cfg.nodes.len(), 1);
    }

    #[test]
    fn display_name_override_applies_per_group() {
        let body = config_json(
            &[node_json("shared")],
            &[
                group_json("t1", "g1", &["shared"]),
                format!(
                    r#"{{"token":"t2","name":"g2","nodes":[{{"ref":"shared","name":"Backup Line"}}]}}"#
                ),
            ],
        );
        let cfg = cfg_with(&body).unwrap();
        let g1 = cfg.group_for_token("t1").unwrap();
        let g2 = cfg.group_for_token("t2").unwrap();

        let d1: Vec<&str> = cfg.group_nodes(g1).into_iter().map(|(_, d)| d).collect();
        let d2: Vec<&str> = cfg.group_nodes(g2).into_iter().map(|(_, d)| d).collect();
        assert_eq!(d1, vec!["shared"]);
        assert_eq!(d2, vec!["Backup Line"]);
    }

    #[test]
    fn empty_display_name_is_rejected() {
        let body = config_json(
            &[node_json("a")],
            &[r#"{"token":"t","name":"g","nodes":[{"ref":"a","name":"  "}]}"#.to_string()],
        );
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("display name must not be empty"), "{err}");
    }

    #[test]
    fn override_does_not_change_node_identity() {
        // Two references to the same node with different display names are
        // still the same node, so listing both must be rejected.
        let body = config_json(
            &[node_json("a")],
            &[r#"{"token":"t","name":"g","nodes":["a",{"ref":"a","name":"Other"}]}"#.to_string()],
        );
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("listed twice"), "{err}");
    }

    #[test]
    fn unknown_node_reference_is_rejected() {
        let body = config_json(&[node_json("a")], &[group_json("t", "g", &["a", "missing"])]);
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains(r#"unknown node "missing""#), "{err}");
    }

    #[test]
    fn duplicate_node_reference_is_rejected() {
        let body = config_json(&[node_json("a")], &[group_json("t", "g", &["a", "a"])]);
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("listed twice"), "{err}");
    }

    #[test]
    fn duplicate_node_name_is_rejected() {
        let body = config_json(
            &[node_json("a"), node_json("a")],
            &[group_json("t", "g", &["a"])],
        );
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("duplicate node name"), "{err}");
    }

    #[test]
    fn duplicate_token_is_rejected() {
        let body = config_json(
            &[node_json("a")],
            &[group_json("abc123", "a", &[]), group_json("abc123", "b", &[])],
        );
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("duplicate token"), "{err}");
    }

    #[test]
    fn duplicate_group_name_is_rejected() {
        let body = config_json(
            &[node_json("a")],
            &[group_json("abc123", "main", &[]), group_json("def456", "main", &[])],
        );
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("duplicate group name"), "{err}");
    }

    #[test]
    fn token_with_path_separator_is_rejected() {
        let body = config_json(&[], &[group_json("ab/cd", "g", &[])]);
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("must contain only"), "{err}");
    }

    #[test]
    fn empty_token_is_rejected() {
        let body = config_json(&[], &[group_json("", "g", &[])]);
        assert!(cfg_with(&body).is_err());
    }

    #[test]
    fn zero_port_is_rejected() {
        let body = config_json(
            &[node_json("a").replace(r#""port":443"#, r#""port":0"#)],
            &[],
        );
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("port must not be 0"), "{err}");
    }

    #[test]
    fn empty_node_field_is_rejected() {
        let body = config_json(
            &[node_json("a").replace(r#""uuid":"u""#, r#""uuid":"  ""#)],
            &[],
        );
        assert!(cfg_with(&body).is_err());
    }

    fn node_with(extra: &str) -> String {
        format!(
            r#"{{"name":"a","address":"x","port":443,"uuid":"u","public-key":"k","short-id":"01","server-name":"sni.example"{extra}}}"#
        )
    }

    #[test]
    fn control_characters_are_rejected_everywhere_they_are_written() {
        // These values land in a YAML document or a subscription link, so a
        // newline would corrupt the output.
        let cases = [
            node_json("a").replace(r#""address":"a""#, r#""address":"a\nb""#),
            node_json("a").replace(r#""uuid":"u""#, r#""uuid":"u\r""#),
            node_json("a").replace(r#""public-key":"k""#, r#""public-key":"k\u0000""#),
            node_with(r#","short-id":"a\tb""#),
            node_with(r#","server-name":"a\nb""#),
            node_with(r#","spider-x":"/\n""#),
            node_with(r#","alpn":["h2\n"]"#),
            node_json("a").replace(r#""name":"a""#, r#""name":"a\nb""#),
        ];
        for node in cases {
            let body = config_json(&[node.clone()], &[]);
            assert!(cfg_with(&body).is_err(), "accepted {node}");
        }

        let body = config_json(
            &[node_json("a")],
            &[r#"{"token":"t","name":"g\nh","nodes":[]}"#.to_string()],
        );
        assert!(cfg_with(&body).is_err());

        let body = config_json(
            &[node_json("a")],
            &[r#"{"token":"t","name":"g","nodes":[{"ref":"a","name":"x\ny"}]}"#.to_string()],
        );
        assert!(cfg_with(&body).is_err());
    }

    #[test]
    fn empty_server_name_is_rejected() {
        // The SNI is what the handshake impersonates; an empty one produces a
        // node that renders fine and then never connects.
        let body = config_json(
            &[node_json("a").replace(r#""server-name":"sni.example""#, r#""server-name":"""#)],
            &[],
        );
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("server-name must not be empty"), "{err}");
    }

    #[test]
    fn empty_short_id_is_accepted() {
        let body = config_json(
            &[node_json("a").replace(r#""short-id":"01""#, r#""short-id":"""#)],
            &[],
        );
        assert!(cfg_with(&body).is_ok());
    }

    #[test]
    fn missing_short_id_key_is_rejected() {
        let body = config_json(
            &[node_json("a").replace(r#","short-id":"01""#, "")],
            &[],
        );
        assert!(cfg_with(&body).is_err());
    }

    #[test]
    fn missing_server_name_key_is_rejected() {
        let body = config_json(
            &[node_json("a").replace(r#","server-name":"sni.example""#, "")],
            &[],
        );
        assert!(cfg_with(&body).is_err());
    }

    #[test]
    fn empty_group_name_is_rejected() {
        let body = config_json(&[], &[group_json("t", "", &[])]);
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("name must not be empty"), "{err}");
    }

    #[test]
    fn empty_node_reference_is_rejected() {
        let body = config_json(&[], &[r#"{"token":"t","name":"g","nodes":[""]}"#.to_string()]);
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("node reference must not be empty"), "{err}");
    }

    #[test]
    fn optional_fields_may_be_blank() {
        // A client omits flow control and Reality extras by leaving them blank.
        let body = config_json(
            &[node_with(r#","flow":"","fingerprint":"","spider-x":"""#)],
            &[],
        );
        assert!(cfg_with(&body).is_ok());

        // An empty short-id means the server does no shortId matching.
        let body = config_json(
            &[r#"{"name":"a","address":"x","port":443,"uuid":"u","public-key":"k","short-id":"","server-name":"sni.example"}"#.to_string()],
            &[],
        );
        assert!(cfg_with(&body).is_ok());
    }

    #[test]
    fn empty_alpn_entry_is_rejected() {
        let body = config_json(&[node_with(r#","alpn":["h2",""]"#)], &[]);
        let err = cfg_with(&body).unwrap_err();
        assert!(err.contains("alpn entries must not be empty"), "{err}");
    }

    #[test]
    fn alpn_entry_with_comma_is_rejected() {
        // The ALPN list is comma-joined in a link, so an embedded comma would
        // silently split into two entries.
        let body = config_json(&[node_with(r#","alpn":["h2,http/1.1"]"#)], &[]);
        assert!(cfg_with(&body).is_err());
    }

    #[test]
    fn unknown_group_field_is_rejected() {
        let body = config_json(
            &[],
            &[r#"{"token":"t","name":"g","junk":1}"#.to_string()],
        );
        assert!(cfg_with(&body).is_err());
    }

    /// Reference checking must be a hash lookup, not a scan of the node table.
    ///
    /// With the old linear search this took O(groups * refs * nodes); the
    /// assertion is only a smoke test that a large table loads quickly.
    #[test]
    fn large_table_loads_in_reasonable_time() {
        let nodes: Vec<String> = (0..2000).map(|i| node_json(&format!("n{i}"))).collect();
        let groups: Vec<String> = (0..200)
            .map(|g| {
                let refs: Vec<String> = (0..20).map(|i| format!("n{}", (g * 7 + i) % 2000)).collect();
                let list: Vec<&str> = refs.iter().map(|s| s.as_str()).collect();
                group_json(&format!("t{g}"), &format!("g{g}"), &list)
            })
            .collect();

        let started = std::time::Instant::now();
        let cfg = cfg_with(&config_json(&nodes, &groups)).unwrap();
        let elapsed = started.elapsed();

        assert_eq!(cfg.nodes.len(), 2000);
        assert_eq!(cfg.groups.len(), 200);
        assert!(elapsed.as_secs() < 5, "took {elapsed:?}");
    }

    #[test]
    fn server_token_with_crlf_is_rejected() {
        let p = write_temp(
            "inject.json",
            r#"{"listen":"127.0.0.1:1","server_token":"nginx\r\nX: y"}"#,
        );
        assert!(Config::load(&p).unwrap_err().contains("invalid characters"));
    }
}
