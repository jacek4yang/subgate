//! Node and subscription group model.
//!
//! A node is a single VLESS+Reality outbound, defined once in a top-level
//! table and referenced by name from any number of groups. A group carries a
//! token and the ordered list of node names it publishes; the token is the only
//! secret in the subscription URL, so it doubles as the rotation knob.

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use std::fmt;

/// A published subscription.
///
/// `nodes` holds **references**, not node definitions. The order is the order
/// clients receive, and a node may be referenced by several groups.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// Path segment used as `/<token>/clash` and `/<token>/v2ray`.
    pub token: String,

    /// Shown as the subscription name in the client.
    pub name: String,

    #[serde(default)]
    pub nodes: Vec<NodeRef>,
}

/// A reference to a node in the top-level table.
///
/// Accepts either a bare name or an object that overrides the name shown in the
/// client:
///
/// ```json
/// "nodes": ["hk-1", { "ref": "hk-1", "name": "Hong Kong 01" }]
/// ```
///
/// An override only affects this group, so the same node can be labelled
/// differently in each subscription that publishes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRef {
    /// The node's `name` in the top-level table.
    pub reference: String,

    /// Overrides the display name when present.
    pub name: Option<String>,
}

impl NodeRef {
    /// The name a client shows for this reference.
    pub fn display_name<'a>(&'a self, node: &'a Node) -> &'a str {
        self.name.as_deref().unwrap_or(&node.name)
    }
}

impl<'de> Deserialize<'de> for NodeRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NodeRefVisitor;

        impl<'de> Visitor<'de> for NodeRefVisitor {
            type Value = NodeRef;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(r#"a node name or {"ref": "...", "name": "..."}"#)
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<NodeRef, E> {
                Ok(NodeRef {
                    reference: v.to_string(),
                    name: None,
                })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NodeRef, A::Error> {
                let mut reference = None;
                let mut name = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "ref" => {
                            if reference.replace(map.next_value::<String>()?).is_some() {
                                return Err(de::Error::duplicate_field("ref"));
                            }
                        }
                        "name" => {
                            if name.replace(map.next_value::<String>()?).is_some() {
                                return Err(de::Error::duplicate_field("name"));
                            }
                        }
                        other => {
                            return Err(de::Error::unknown_field(other, &["ref", "name"]));
                        }
                    }
                }

                Ok(NodeRef {
                    reference: reference.ok_or_else(|| de::Error::missing_field("ref"))?,
                    name,
                })
            }
        }

        deserializer.deserialize_any(NodeRefVisitor)
    }
}

/// The client-tuning fields are only read by the renderers, which arrive in a
/// later change.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub uuid: String,

    #[serde(rename = "public-key")]
    pub public_key: String,

    /// Reality shortId. Required to be present, but may be an empty string:
    /// a server that performs no shortId matching accepts any client.
    #[serde(rename = "short-id")]
    pub short_id: String,

    /// Reality SNI. Required, and in practice never empty: it is the name the
    /// handshake impersonates.
    #[serde(rename = "server-name")]
    pub server_name: String,

    /// VLESS flow control. `xtls-rprx-vision` is the Reality default.
    #[serde(default = "default_flow")]
    pub flow: String,

    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,

    /// `spiderX` / `spx` in client configs.
    #[serde(rename = "spider-x", default)]
    pub spider_x: String,

    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
}

fn default_flow() -> String {
    "xtls-rprx-vision".to_string()
}

fn default_fingerprint() -> String {
    "chrome".to_string()
}

fn default_alpn() -> Vec<String> {
    vec!["h2".to_string(), "http/1.1".to_string()]
}

impl Group {
    /// Whether `token` matches this group, compared in constant time.
    ///
    /// Called from the routing layer in a later change.
    ///
    /// The token is the only credential in the URL, so a timing-distinguishable
    /// comparison would leak prefix information to an attacker probing paths.
    pub fn token_matches(&self, token: &str) -> bool {
        let a = self.token.as_bytes();
        let b = token.as_bytes();

        // Length is folded into the result instead of short-circuiting, so the
        // loop always runs the same number of rounds. Returning early on a
        // length mismatch would leak the token's length.
        let mut diff = if a.len() == b.len() { 0u8 } else { 1u8 };

        // Compare up to the longer of the two, treating any byte past the end
        // of either side as a mismatch. This keeps the work independent of
        // which input is shorter.
        let len = a.len().max(b.len());
        for i in 0..len {
            let x = a.get(i).copied().unwrap_or(0);
            let y = b.get(i).copied().unwrap_or(0);
            // A missing byte must never compare equal to a real one.
            let present = (i < a.len() && i < b.len()) as u8;
            diff |= (x ^ y) | (present ^ 1);
        }

        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_group(json: &str) -> Result<Group, serde_json::Error> {
        serde_json::from_str(json)
    }

    fn parse_node(json: &str) -> Result<Node, serde_json::Error> {
        serde_json::from_str(json)
    }

    const MINIMAL: &str = r#"{
        "name": "hk-1",
        "address": "example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "public-key": "PUBKEY",
        "short-id": "",
        "server-name": "www.example.com"
    }"#;

    #[test]
    fn minimal_node_gets_client_defaults() {
        let n = parse_node(MINIMAL).unwrap();
        assert_eq!(n.flow, "xtls-rprx-vision");
        assert_eq!(n.fingerprint, "chrome");
        assert_eq!(n.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(n.spider_x, "");
        // Both are required to appear, but short-id may still be empty.
        assert_eq!(n.short_id, "");
        assert_eq!(n.server_name, "www.example.com");
    }

    fn node_json(short_id: Option<&str>, server_name: Option<&str>) -> String {
        let mut fields = vec![
            r#""name":"n""#.to_string(),
            r#""address":"a""#.to_string(),
            r#""port":443"#.to_string(),
            r#""uuid":"u""#.to_string(),
            r#""public-key":"k""#.to_string(),
        ];
        if let Some(v) = short_id {
            fields.push(format!(r#""short-id":"{v}""#));
        }
        if let Some(v) = server_name {
            fields.push(format!(r#""server-name":"{v}""#));
        }
        format!("{{{}}}", fields.join(","))
    }

    #[test]
    fn short_id_key_is_required_but_may_be_empty() {
        // Missing the key entirely is a mistake: it usually means a typo, and
        // the node would silently render without a shortId.
        assert!(parse_node(&node_json(None, Some("sni"))).is_err());

        // An explicit empty string is valid: the server does no shortId match.
        let n = parse_node(&node_json(Some(""), Some("sni"))).unwrap();
        assert_eq!(n.short_id, "");
    }

    #[test]
    fn server_name_key_is_required() {
        assert!(parse_node(&node_json(Some("01"), None)).is_err());
        let n = parse_node(&node_json(Some("01"), Some("sni"))).unwrap();
        assert_eq!(n.server_name, "sni");
    }

    #[test]
    fn optional_fields_can_be_set() {
        let n = parse_node(
            r#"{
                "name": "x", "address": "a", "port": 1, "uuid": "u",
                "public-key": "pk", "short-id": "ab", "server-name": "s",
                "flow": "", "fingerprint": "firefox", "spider-x": "/",
                "alpn": ["h3"]
            }"#,
        )
        .unwrap();
        assert_eq!(n.short_id, "ab");
        assert_eq!(n.server_name, "s");
        assert_eq!(n.flow, "");
        assert_eq!(n.fingerprint, "firefox");
        assert_eq!(n.spider_x, "/");
        assert_eq!(n.alpn, vec!["h3"]);
    }

    #[test]
    fn unknown_node_field_is_rejected() {
        let bad = MINIMAL.replace(
            r#""public-key": "PUBKEY""#,
            r#""public-key": "PUBKEY", "junk": 1"#,
        );
        assert!(parse_node(&bad).is_err());
    }

    #[test]
    fn missing_required_field_is_rejected() {
        let bad = MINIMAL.replace(r#""uuid": "11111111-2222-3333-4444-555555555555","#, "");
        assert!(parse_node(&bad).is_err());
    }

    #[test]
    fn group_holds_node_names() {
        let g = parse_group(r#"{"token":"abc","name":"main","nodes":["a","b"]}"#).unwrap();
        let refs: Vec<&str> = g.nodes.iter().map(|r| r.reference.as_str()).collect();
        assert_eq!(refs, vec!["a", "b"]);
        assert!(g.nodes.iter().all(|r| r.name.is_none()));
    }

    #[test]
    fn group_nodes_default_to_empty() {
        let g = parse_group(r#"{"token":"abc","name":"main"}"#).unwrap();
        assert!(g.nodes.is_empty());
    }

    #[test]
    fn group_rejects_inline_node_objects() {
        let bad = r#"{"token":"abc","name":"main","nodes":[{"name":"a"}]}"#;
        assert!(parse_group(bad).is_err());
    }

    #[test]
    fn reference_accepts_object_with_override() {
        let g = parse_group(
            r#"{"token":"abc","name":"main","nodes":[{"ref":"a","name":"Hong Kong 01"}]}"#,
        )
        .unwrap();
        assert_eq!(g.nodes[0].reference, "a");
        assert_eq!(g.nodes[0].name.as_deref(), Some("Hong Kong 01"));
    }

    #[test]
    fn reference_object_requires_ref() {
        let bad = r#"{"token":"abc","name":"main","nodes":[{"name":"x"}]}"#;
        assert!(parse_group(bad).is_err());
    }

    #[test]
    fn reference_object_rejects_unknown_field() {
        let bad = r#"{"token":"abc","name":"main","nodes":[{"ref":"a","junk":1}]}"#;
        assert!(parse_group(bad).is_err());
    }

    #[test]
    fn reference_object_rejects_duplicate_field() {
        let bad = r#"{"token":"abc","name":"main","nodes":[{"ref":"a","ref":"b"}]}"#;
        assert!(parse_group(bad).is_err());
    }

    #[test]
    fn display_name_prefers_override() {
        let n: Node = serde_json::from_str(MINIMAL).unwrap();
        let plain = NodeRef {
            reference: "hk-1".into(),
            name: None,
        };
        let overridden = NodeRef {
            reference: "hk-1".into(),
            name: Some("Hong Kong 01".into()),
        };
        assert_eq!(plain.display_name(&n), "hk-1");
        assert_eq!(overridden.display_name(&n), "Hong Kong 01");
    }

    #[test]
    fn group_rejects_unknown_field() {
        let bad = r#"{"token":"abc","name":"main","nodes":[],"junk":1}"#;
        assert!(parse_group(bad).is_err());
    }
    #[test]
    fn token_comparison() {
        let g = parse_group(r#"{"token":"abc123","name":"main","nodes":[]}"#).unwrap();
        assert!(g.token_matches("abc123"));
        assert!(!g.token_matches("abc124"));
        assert!(!g.token_matches("abc12"));
        assert!(!g.token_matches("abc1234"));
        assert!(!g.token_matches(""));
        let big = "a".repeat(262); // 6 + 256
        assert!(!g.token_matches(&big));
    }
}
