//! Configuration loading.
//!
//! The configuration is a single mandatory JSON file whose path is the first
//! command line argument. A missing file, an unreadable file, invalid JSON, or
//! a wrong field type all abort startup; there is no fallback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

use crate::model::{Group, Node};
use crate::validate;

/// The `Server` header value a default Ubuntu 26.04 install emits.
///
/// It also determines the `<hr><center>...</center>` line of the error pages,
/// because in real nginx both come from the single `server_tokens` directive
/// and therefore can never disagree.
pub const DEFAULT_SERVER_TOKEN: &str = "nginx/1.28.3 (Ubuntu)";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,

    /// The string written to the `Server` header and the error page tail.
    #[serde(default = "default_server_token")]
    pub server_token: String,

    /// The node table. Every node is defined exactly once here and referenced
    /// by name from a group.
    #[serde(default)]
    pub nodes: Vec<Node>,

    /// Subscription groups. An empty list means every path is a 404.
    #[serde(default)]
    pub groups: Vec<Group>,

    /// Node definitions indexed by name, built once at load time.
    #[serde(skip)]
    pub(crate) node_index: HashMap<String, usize>,
}

fn default_server_token() -> String {
    DEFAULT_SERVER_TOKEN.to_string()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        // Bound the read: a config file is a few kilobytes, so anything
        // larger is a mistake (or an attack).
        let file = std::fs::File::open(path)
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;
        let size = file
            .metadata()
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?
            .len();
        if size > 1024 * 1024 {
            return Err(format!("config file exceeds 1 MiB: {}", path.display()));
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;

        let mut cfg: Config = serde_json::from_str(&raw)
            .map_err(|e| format!("failed to parse config {}: {e}", path.display()))?;

        // The index is built before validation so the reference check is a
        // hash lookup rather than a scan of the node table per reference.
        cfg.build_node_index();
        validate::validate(&cfg)?;
        Ok(cfg)
    }

    /// Build the name -> index map used by `node`.
    ///
    /// Duplicate names are not detected here; `validate_nodes` reports them
    /// with a better message. The map simply keeps the last occurrence.
    fn build_node_index(&mut self) {
        let mut index = HashMap::with_capacity(self.nodes.len());
        for (i, node) in self.nodes.iter().enumerate() {
            index.insert(node.name.clone(), i);
        }
        self.node_index = index;
    }

    /// Resolve a node name to its definition.
    pub fn node(&self, name: &str) -> Option<&Node> {
        self.node_index.get(name).map(|i| &self.nodes[*i])
    }

    /// The nodes of a group, in the order the group lists them, paired with the
    /// name a client should show.
    ///
    /// References are guaranteed to resolve because validation runs before the
    /// index is built, so a missing entry cannot occur here.
    pub fn group_nodes<'a>(&'a self, group: &'a Group) -> Vec<(&'a Node, &'a str)> {
        group
            .nodes
            .iter()
            .filter_map(|r| {
                let node = self.node(&r.reference)?;
                Some((node, r.display_name(node)))
            })
            .collect()
    }

    /// Look up a group by its URL token.
    ///
    /// All groups are scanned even after a match so the comparison cost does
    /// not depend on the token's position in the list. Called from the routing
    /// layer in a later change.
    pub fn group_for_token(&self, token: &str) -> Option<&Group> {
        let mut found = None;
        for group in &self.groups {
            if group.token_matches(token) {
                found = Some(group);
            }
        }
        found
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("subgate-config-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let p = write_temp("minimal.json", r#"{"listen":"127.0.0.1:8080"}"#);
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(cfg.server_token, DEFAULT_SERVER_TOKEN);
    }

    #[test]
    fn server_token_can_be_overridden() {
        let p = write_temp(
            "override.json",
            r#"{"listen":"127.0.0.1:8080","server_token":"nginx"}"#,
        );
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.server_token, "nginx");
    }

    #[test]
    fn missing_file_is_error() {
        let err = Config::load(Path::new("/definitely/not/here.json")).unwrap_err();
        assert!(err.contains("failed to read config"));
    }

    #[test]
    fn invalid_json_is_error() {
        let p = write_temp("bad.json", "{");
        assert!(Config::load(&p)
            .unwrap_err()
            .contains("failed to parse config"));
    }

    #[test]
    fn missing_listen_is_error() {
        let p = write_temp("no-listen.json", r#"{"server_token":"nginx"}"#);
        assert!(Config::load(&p).is_err());
    }

    #[test]
    fn unknown_field_is_error() {
        let p = write_temp("unknown.json", r#"{"listen":"127.0.0.1:1","x":1}"#);
        assert!(Config::load(&p).is_err());
    }
}
