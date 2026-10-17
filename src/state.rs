//! Live configuration state with SIGHUP reload.
//!
//! The running config is swapped atomically, so in-flight requests keep using
//! the config they started with and no lock is held while rendering.
//!
//! Reload semantics, matching what a fronting nginx does with a bad config:
//! - the file is re-read and fully validated before anything is swapped, so a
//!   failed reload never leaves a half-applied config;
//! - on failure the process keeps running and the **old config is discarded**,
//!   every request answers 503 until a reload succeeds;
//! - a subsequent successful reload restores service without a restart.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::config::Config;

/// What a request should use.
pub enum Current {
    /// Serving normally.
    Loaded(Arc<Config>),
    /// The last reload failed; serve 503 until one succeeds.
    Broken,
}

pub struct State {
    path: PathBuf,
    /// `None` means the last reload failed.
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
    /// Returns the outcome for logging. The caller does not branch on it; the
    /// state is updated either way.
    pub fn reload(&self) -> Result<(), String> {
        match Config::load(&self.path) {
            Ok(cfg) => {
                if let Ok(mut guard) = self.current.write() {
                    *guard = Some(Arc::new(cfg));
                }
                Ok(())
            }
            Err(e) => {
                if let Ok(mut guard) = self.current.write() {
                    *guard = None;
                }
                Err(e)
            }
        }
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
            r#"{{"listen":"127.0.0.1:1","nodes":[{{"name":"n","address":"a","port":443,"uuid":"u","public-key":"k","short-id":"","server-name":"s"}}],"groups":[{{"token":"{token}","name":"g","nodes":["n"]}}]}}"#
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
            Current::Loaded(c) => assert!(c.group_for_token("alpha").is_some()),
            Current::Broken => panic!("expected a loaded config"),
        }

        write(&p, &valid("beta"));
        st.reload().unwrap();

        match st.current() {
            Current::Loaded(c) => {
                assert!(c.group_for_token("beta").is_some());
                // The old token is gone: the config was replaced, not merged.
                assert!(c.group_for_token("alpha").is_none());
            }
            Current::Broken => panic!("expected a loaded config"),
        }
    }

    #[test]
    fn failed_reload_breaks_service_then_recovers() {
        let p = temp("break.json");
        write(&p, &valid("alpha"));
        let st = State::boot(p.clone()).unwrap();

        write(&p, "{not json");
        assert!(st.reload().is_err());
        assert!(matches!(st.current(), Current::Broken));

        write(&p, &valid("gamma"));
        st.reload().unwrap();
        match st.current() {
            Current::Loaded(c) => assert!(c.group_for_token("gamma").is_some()),
            Current::Broken => panic!("expected recovery"),
        }
    }

    #[test]
    fn missing_file_on_reload_breaks_service() {
        let p = temp("gone.json");
        write(&p, &valid("alpha"));
        let st = State::boot(p.clone()).unwrap();
        std::fs::remove_file(&p).unwrap();

        assert!(st.reload().is_err());
        assert!(matches!(st.current(), Current::Broken));
    }
}
