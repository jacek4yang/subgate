//! Live configuration state with SIGHUP reload.
//!
//! The running config is swapped atomically, so in-flight requests keep using
//! the config they started with and no lock is held while rendering.
//!
//! Reload semantics:
//! - the file is re-read and fully validated before anything is swapped, so a
//!   failed reload never leaves a half-applied config;
//! - on failure the process keeps serving the **last known good config**
//!   (availability beats freshness; see README for the stale-credential
//!   implication);
//! - `listen` cannot change at runtime — a changed `listen` is an error and
//!   keeps the old config, since the socket is bound at boot.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::config::Config;

/// What a request should use.
pub enum Current {
    /// Serving normally.
    Loaded(Arc<Config>),
    /// The lock was poisoned by a panic; serve 503 until restart.
    Broken,
}

pub struct State {
    path: PathBuf,
    /// The listen address captured at boot; reloads cannot change it.
    boot_listen: SocketAddr,
    /// `None` means the lock was poisoned.
    current: RwLock<Option<Arc<Config>>>,
}

impl State {
    /// Load the initial config, aborting if it is unusable.
    ///
    /// A process that cannot start correctly must not start at all: serving
    /// 503 from boot would look like a broken server to a scanner.
    pub fn boot(path: PathBuf) -> Result<Self, String> {
        let cfg = Config::load(&path)?;
        Ok(Self {
            boot_listen: cfg.listen,
            path,
            current: RwLock::new(Some(Arc::new(cfg))),
        })
    }

    /// Read the current state. Cheap: one uncontended read lock plus an `Arc`
    /// clone.
    pub fn current(&self) -> Current {
        match self.current.read() {
            Ok(guard) => match guard.as_ref() {
                Some(cfg) => Current::Loaded(Arc::clone(cfg)),
                None => Current::Broken,
            },
            // A poisoned lock means a panic happened while holding it. Treating
            // it as broken is safer than serving whatever is behind it.
            Err(_) => Current::Broken,
        }
    }

    /// Re-read the config file.
    ///
    /// On failure the last known good config is kept and the error is
    /// returned for logging. On success the new config is swapped in.
    pub fn reload(&self) -> Result<(), String> {
        let cfg = Config::load(&self.path)?;
        if cfg.listen != self.boot_listen {
            return Err("listen cannot change at runtime; restart required".to_string());
        }
        let mut guard = self
            .current
            .write()
            .map_err(|e| format!("state lock poisoned: {e}"))?;
        *guard = Some(Arc::new(cfg));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("subgate-state-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn write(path: &Path, body: &str) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    fn valid(token: &str) -> String {
        format!(
            r#"{{"listen":"127.0.0.1:1","nodes":[{{"name":"n","address":"a","port":443,"uuid":"11111111-2222-3333-4444-555555555555","public-key":"bK4PTQX5dwqSdVBzADrqhPtALBwj9b0uYjYR29lS4xE","short-id":"","server-name":"s"}}],"groups":[{{"token":"{token}-0123456789abcdef","name":"g","nodes":["n"]}}]}}"#
        )
    }

    #[test]
    fn boot_rejects_invalid_config() {
        let p = temp("boot-bad.json");
        write(&p, "{");
        assert!(State::boot(p).is_err());
    }

    #[test]
    fn reload_swaps_to_new_config() {
        let p = temp("swap.json");
        write(&p, &valid("alpha"));
        let st = State::boot(p.clone()).unwrap();

        match st.current() {
            Current::Loaded(c) => assert!(c.group_for_token("alpha-0123456789abcdef").is_some()),
            Current::Broken => panic!("expected a loaded config"),
        }

        write(&p, &valid("beta"));
        st.reload().unwrap();

        match st.current() {
            Current::Loaded(c) => {
                assert!(c.group_for_token("beta-0123456789abcdef").is_some());
                // The old token is gone: the config was replaced, not merged.
                assert!(c.group_for_token("alpha-0123456789abcdef").is_none());
            }
            Current::Broken => panic!("expected a loaded config"),
        }
    }

    #[test]
    fn failed_reload_keeps_last_known_good_config() {
        let p = temp("retain.json");
        write(&p, &valid("alpha"));
        let st = State::boot(p.clone()).unwrap();

        write(&p, "{not json");
        assert!(st.reload().is_err());
        // The old config keeps serving.
        match st.current() {
            Current::Loaded(c) => assert!(c.group_for_token("alpha-0123456789abcdef").is_some()),
            Current::Broken => panic!("expected the old config to be retained"),
        }

        write(&p, &valid("gamma"));
        st.reload().unwrap();
        match st.current() {
            Current::Loaded(c) => {
                assert!(c.group_for_token("gamma-0123456789abcdef").is_some());
                assert!(c.group_for_token("alpha-0123456789abcdef").is_none());
            }
            Current::Broken => panic!("expected a loaded config"),
        }
    }

    #[test]
    fn missing_file_on_reload_keeps_last_known_good_config() {
        let p = temp("gone2.json");
        write(&p, &valid("alpha"));
        let st = State::boot(p.clone()).unwrap();
        std::fs::remove_file(&p).unwrap();

        assert!(st.reload().is_err());
        match st.current() {
            Current::Loaded(c) => assert!(c.group_for_token("alpha-0123456789abcdef").is_some()),
            Current::Broken => panic!("expected the old config to be retained"),
        }
    }

    #[test]
    fn listen_change_is_rejected_and_keeps_old_config() {
        let p = temp("listen-change.json");
        write(&p, &valid("alpha"));
        let st = State::boot(p.clone()).unwrap();

        write(&p, &valid("alpha").replace("127.0.0.1:1", "127.0.0.1:2"));
        let err = st.reload().unwrap_err();
        assert!(err.contains("listen cannot change at runtime"), "{err}");
        match st.current() {
            Current::Loaded(c) => assert!(c.group_for_token("alpha-0123456789abcdef").is_some()),
            Current::Broken => panic!("expected the old config to be retained"),
        }
    }
}
