//! Local control socket for synchronous reload, status inspection, and validation.
//!
//! On Unix systems, subgate opens a Unix domain socket (defaulting to
//! `/run/subgate/control.sock` or `SUBGATE_CONTROL_SOCK`) allowing operators and
//! systemd to execute synchronous reloads and verify runtime health without
//! relying on fire-and-forget signals.

use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use crate::state::{Current, State};

/// Default socket path in systemd environments with `RuntimeDirectory=subgate`.
#[allow(dead_code)]
pub const DEFAULT_SYSTEMD_SOCKET: &str = "/run/subgate/control.sock";

/// Determine the control socket path.
#[allow(dead_code)]
pub fn control_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("SUBGATE_CONTROL_SOCK") {
        return PathBuf::from(p);
    }
    let systemd_dir = Path::new("/run/subgate");
    if systemd_dir.is_dir() {
        return PathBuf::from(DEFAULT_SYSTEMD_SOCKET);
    }
    // Fall back to a user/process-specific socket in temp dir
    std::env::temp_dir().join("subgate-control.sock")
}

#[cfg(unix)]
pub async fn send_command(sock_path: &Path, cmd: &str) -> Result<String, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(sock_path).await.map_err(|e| {
        format!(
            "failed to connect to control socket {}: {e}",
            sock_path.display()
        )
    })?;

    let (reader, mut writer) = stream.into_split();
    let mut cmd_bytes = cmd.as_bytes().to_vec();
    if !cmd_bytes.ends_with(b"\n") {
        cmd_bytes.push(b'\n');
    }

    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        writer.write_all(&cmd_bytes),
    )
    .await
    .map_err(|_| "timeout sending command to control socket".to_string())?
    .map_err(|e| format!("write error on control socket: {e}"))?;

    let mut reader = BufReader::new(reader);
    let mut response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_line(&mut response),
    )
    .await
    .map_err(|_| "timeout waiting for response from control socket".to_string())?
    .map_err(|e| format!("read error on control socket: {e}"))?;

    let trimmed = response.trim_end();
    if let Some(err_msg) = trimmed.strip_prefix("ERR ") {
        Err(err_msg.to_string())
    } else if let Some(ok_msg) = trimmed.strip_prefix("OK ") {
        Ok(ok_msg.to_string())
    } else if trimmed == "OK" {
        Ok(String::new())
    } else {
        Err(format!(
            "unexpected response from control socket: {trimmed}"
        ))
    }
}

#[cfg(not(unix))]
#[allow(dead_code)]
pub async fn send_command(_sock_path: &Path, _cmd: &str) -> Result<String, String> {
    Err("control socket is only supported on Unix platforms".to_string())
}

#[cfg(unix)]
pub async fn run_control_listener(
    state: Arc<State>,
    sock_path: PathBuf,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    // Remove stale socket if it exists
    if sock_path.exists() {
        let _ = std::fs::remove_file(&sock_path);
    }

    if let Some(parent) = sock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => {
            tracing::info!("control socket listening on {}", sock_path.display());
            l
        }
        Err(e) => {
            tracing::warn!(
                "failed to bind control socket on {}: {e}; continuing without control socket",
                sock_path.display()
            );
            return;
        }
    };

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("control socket accept error: {e}");
                        continue;
                    }
                };

                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    let mut line = String::new();

                    if reader.read_line(&mut line).await.is_ok() {
                        let cmd = line.trim();
                        let reply = match cmd {
                            "RELOAD" => {
                                match state.reload() {
                                    Ok(gen) => {
                                        tracing::info!("config reloaded via control socket (generation {gen})");
                                        format!("OK generation={gen}\n")
                                    }
                                    Err(e) => {
                                        tracing::error!("reload via control socket failed: {e}");
                                        format!("ERR {e}\n")
                                    }
                                }
                            }
                            "CHECK" => {
                                match state.check_reload() {
                                    Ok(()) => "OK\n".to_string(),
                                    Err(e) => format!("ERR {e}\n"),
                                }
                            }
                            "STATUS" => {
                                let (groups, nodes) = match state.current() {
                                    Current::Loaded(cfg) => (cfg.groups.len(), cfg.nodes.len()),
                                    Current::Broken => (0, 0),
                                };
                                format!(
                                    "OK pid={} listen={} generation={} groups={} nodes={}\n",
                                    std::process::id(),
                                    state.boot_listen(),
                                    state.generation(),
                                    groups,
                                    nodes
                                )
                            }
                            other => format!("ERR unknown command: {other}\n"),
                        };
                        let _ = writer.write_all(reply.as_bytes()).await;
                    }
                });
            }
        }
    }

    // Clean up socket file on shutdown
    let _ = std::fs::remove_file(&sock_path);
}
