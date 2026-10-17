//! Configuration loading.
//!
//! The configuration is a single mandatory JSON file whose path is the first
//! command line argument. A missing file, an unreadable file, invalid JSON, or
//! a wrong field type all abort startup; there is no fallback.

use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

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

}

fn default_server_token() -> String {
    DEFAULT_SERVER_TOKEN.to_string()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;

        let cfg: Config = serde_json::from_str(&raw)
            .map_err(|e| format!("failed to parse config {}: {e}", path.display()))?;

        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        if self.server_token.is_empty() {
            return Err("server_token must not be empty".into());
        }

        // The value goes straight into an HTTP header and into HTML, so
        // reject control characters and quotes to rule out header injection.
        if self
            .server_token
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return Err("server_token contains invalid characters".into());
        }

        Ok(())
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
        assert!(Config::load(&p).unwrap_err().contains("failed to parse config"));
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

    #[test]
    fn server_token_with_crlf_is_rejected() {
        let p = write_temp(
            "inject.json",
            r#"{"listen":"127.0.0.1:1","server_token":"nginx\r\nX: y"}"#,
        );
        assert!(Config::load(&p).unwrap_err().contains("invalid characters"));
    }
}
