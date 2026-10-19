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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

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
    /// Generation counter starting at 1 on boot, incremented on every successful reload.
    generation: AtomicU64,
    /// Outcome of the most recent reload attempt: Ok(timestamp) or Err((timestamp, error)).
    last_reload: RwLock<Option<Result<SystemTime, String>>>,
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
            generation: AtomicU64::new(1),
            last_reload: RwLock::new(None),
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

    /// The active generation counter (starts at 1, increments on each successful reload).
    #[allow(dead_code)]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// The address bound at boot.
    #[allow(dead_code)]
    pub fn boot_listen(&self) -> SocketAddr {
        self.boot_listen
    }

    /// Path to the configuration file.
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Result of the last reload attempt, if any occurred.
    #[allow(dead_code)]
    pub fn last_reload(&self) -> Option<Result<SystemTime, String>> {
        self.last_reload.read().ok().and_then(|r| r.clone())
    }

    /// Check if the configuration file on disk is valid and compatible with the running process.
    #[allow(dead_code)]
    pub fn check_reload(&self) -> Result<(), String> {
        let cfg = Config::load(&self.path)?;
        if cfg.listen != self.boot_listen {
            return Err(format!(
                "listen cannot change at runtime (changed from {} to {}); restart required",
                self.boot_listen, cfg.listen
            ));
        }
        Ok(())
    }

    /// Re-read the config file.
    ///
    /// On failure the last known good config is kept and the error is
    /// returned for logging and operator response. On success the new config
    /// is swapped in and the generation counter is incremented.
    pub fn reload(&self) -> Result<u64, String> {
        let cfg = match Config::load(&self.path) {
            Ok(c) => c,
            Err(e) => {
                if let Ok(mut lr) = self.last_reload.write() {
                    *lr = Some(Err(e.clone()));
                }
                return Err(e);
            }
        };

        if cfg.listen != self.boot_listen {
            let err = format!(
                "listen cannot change at runtime (changed from {} to {}); restart required",
                self.boot_listen, cfg.listen
            );
            if let Ok(mut lr) = self.last_reload.write() {
                *lr = Some(Err(err.clone()));
            }
            return Err(err);
        }

        let mut guard = match self.current.write() {
            Ok(g) => g,
            Err(e) => {
                let err = format!("state lock poisoned: {e}");
                if let Ok(mut lr) = self.last_reload.write() {
                    *lr = Some(Err(err.clone()));
                }
                return Err(err);
            }
        };

        *guard = Some(Arc::new(cfg));
        let new_gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(mut lr) = self.last_reload.write() {
            *lr = Some(Ok(SystemTime::now()));
        }
        Ok(new_gen)
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

    #[test]
    fn generation_increments_only_on_successful_reload() {
        let p = temp("gen.json");
        write(&p, &valid("g1"));
        let st = State::boot(p.clone()).unwrap();
        assert_eq!(st.generation(), 1);
        assert!(st.last_reload().is_none());

        // Successful reload increments generation
        write(&p, &valid("g2"));
        let gen = st.reload().unwrap();
        assert_eq!(gen, 2);
        assert_eq!(st.generation(), 2);
        assert!(st.last_reload().unwrap().is_ok());

        // Failed reload preserves generation
        write(&p, "invalid json");
        assert!(st.reload().is_err());
        assert_eq!(st.generation(), 2);
        assert!(st.last_reload().unwrap().is_err());

        // Recovery increments generation
        write(&p, &valid("g3"));
        let gen = st.reload().unwrap();
        assert_eq!(gen, 3);
        assert_eq!(st.generation(), 3);
        assert!(st.last_reload().unwrap().is_ok());
    }

    #[test]
    fn check_reload_detects_listen_change_and_invalid_file() {
        let p = temp("check-reload.json");
        write(&p, &valid("tok1"));
        let st = State::boot(p.clone()).unwrap();

        // Identical / compatible config passes check_reload
        assert!(st.check_reload().is_ok());

        // Changing listen address fails check_reload
        write(&p, &valid("tok1").replace("127.0.0.1:1", "127.0.0.1:9999"));
        let err = st.check_reload().unwrap_err();
        assert!(err.contains("listen cannot change at runtime"), "{err}");

        // Invalid JSON fails check_reload
        write(&p, "{not json");
        assert!(st.check_reload().is_err());
    }
}
