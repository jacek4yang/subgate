mod assets;
mod condition;
mod config;
mod control;
mod errors;
mod limits;
mod model;
mod range;
mod render;
mod routes;
mod serialize;
mod server;
mod state;
mod stealth;
mod validate;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::limits::limits;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "subgate=info".into()),
        )
        .init();

    let arg1 = std::env::args().nth(1);
    let path: PathBuf = match arg1.as_deref() {
        Some("--check") => {
            let Some(p) = std::env::args().nth(2) else {
                eprintln!("usage: subgate [--check|--reload|--status] <config.json>");
                std::process::exit(2);
            };
            let cfg_path = std::path::Path::new(&p);
            let _cfg = match config::Config::load(cfg_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e}");
                    std::process::exit(1);
                }
            };

            #[cfg(unix)]
            {
                let sock_path = control::control_socket_path();
                if sock_path.exists() {
                    if let Ok(status) = control::send_command(&sock_path, "STATUS").await {
                        for part in status.split_whitespace() {
                            if let Some(listen_str) = part.strip_prefix("listen=") {
                                if listen_str != _cfg.listen.to_string() {
                                    eprintln!(
                                        "config warning: listen address changed from {listen_str} to {}; runtime reload will reject this and require a restart",
                                        _cfg.listen
                                    );
                                }
                            }
                        }
                    }
                }
            }

            println!("config ok");
            std::process::exit(0);
        }
        Some("--reload") => {
            #[cfg(unix)]
            {
                let sock_path = control::control_socket_path();
                match control::send_command(&sock_path, "RELOAD").await {
                    Ok(msg) => {
                        println!("config reloaded ({msg})");
                        std::process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("reload failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                eprintln!("error: control socket reload is only supported on Unix systems");
                std::process::exit(1);
            }
        }
        Some("--status") => {
            #[cfg(unix)]
            {
                let sock_path = control::control_socket_path();
                match control::send_command(&sock_path, "STATUS").await {
                    Ok(msg) => {
                        println!("{msg}");
                        std::process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("status query failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                eprintln!("error: control socket is only supported on Unix systems");
                std::process::exit(1);
            }
        }
        Some(p) if !p.starts_with('-') => PathBuf::from(p),
        _ => {
            eprintln!("usage: subgate [--check|--reload|--status] <config.json>");
            std::process::exit(2);
        }
    };

    let state = match state::State::boot(path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };

    let addr = match state.current() {
        state::Current::Loaded(cfg) => cfg.listen,
        // `boot` only returns a state with a loaded config.
        state::Current::Broken => unreachable!("boot guarantees a loaded config"),
    };
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!("listening on {}", listener.local_addr().unwrap_or(addr));

    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
    #[cfg(unix)]
    {
        let sock_path = control::control_socket_path();
        let state_ctrl = Arc::clone(&state);
        tokio::spawn(async move {
            control::run_control_listener(state_ctrl, sock_path, _shutdown_rx).await;
        });
    }

    // Signal streams are registered once, before the loop: a registration
    // created per iteration could drop a signal arriving between iterations.
    let mut reload = std::pin::pin!(reload_signal());
    let mut shutdown = std::pin::pin!(shutdown_signal());

    // Connection concurrency is bounded by a semaphore: when all permits are
    // taken, new connections are dropped (client sees EOF) rather than
    // queued, so memory stays bounded under load.
    let max_conns = limits().max_conns;
    let permits = Arc::new(Semaphore::new(max_conns));
    let mut conns: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        // Commonly EMFILE; back off briefly instead of a hot
                        // spin that would only burn CPU on the same error.
                        tracing::warn!("accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    tracing::debug!("connection limit reached ({max_conns}); dropping connection");
                    continue;
                };
                let state = Arc::clone(&state);
                conns.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = serve(stream, state).await {
                        tracing::debug!("connection ended: {e}");
                    }
                });
            }
            _ = &mut reload => {
                // Reload runs on the runtime thread but does blocking file IO.
                // A config file is a few kilobytes, so the read is bounded and
                // this never meaningfully stalls accept().
                match state.reload() {
                    Ok(gen) => tracing::info!("config reloaded (generation {gen})"),
                    Err(e) => tracing::error!("reload failed, keeping last known good config: {e}"),
                }
                // Re-arm for the next SIGHUP.
                reload.set(reload_signal());
            }
            _ = &mut shutdown => {
                tracing::info!("shutting down");
                let _ = shutdown_tx.send(true);
                break;
            }
        }
    }

    // Graceful shutdown: stop accepting, then let in-flight requests finish,
    // bounded by the drain window and the per-request timeouts.
    drop(listener);
    let drain = tokio::time::timeout(Duration::from_secs(10), async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    if drain.is_err() {
        tracing::warn!("drain timed out after 10s; aborting remaining connections");
        conns.abort_all();
        while conns.join_next().await.is_some() {}
    }
}

async fn serve(mut stream: TcpStream, state: Arc<state::State>) -> std::io::Result<()> {
    let lim = limits();
    let mut buf = Vec::with_capacity(1024);

    for req_idx in 0..lim.keepalive_requests {
        let is_last_request = req_idx + 1 >= lim.keepalive_requests;
        // The config is read once per request, so a reload applies to the next
        // request on an existing connection rather than waiting for a new one.
        let cfg = match state.current() {
            state::Current::Loaded(cfg) => cfg,
            state::Current::Broken => {
                let resp = routes::service_unavailable();
                server::write_response(&mut stream, &resp.into_bytes(true)).await?;
                return Ok(());
            }
        };

        // An empty buffer means this is a fresh keep-alive wait: apply the
        // idle timeout. Once bytes are buffered (a partial head), the header
        // timeout applies. On elapse the connection closes silently, nginx-like.
        let timeout = if buf.is_empty() { lim.idle } else { lim.header };
        let outcome =
            match tokio::time::timeout(timeout, server::read_head(&mut stream, &mut buf)).await {
                Ok(v) => v?,
                Err(_) => return Ok(()),
            };

        let req = match outcome {
            server::ReadOutcome::Request(r) => r,
            server::ReadOutcome::Closed => return Ok(()),
            // Malformed request, or a body shape we do not decode: reply 400
            // and close, so the remainder cannot be read as a new request.
            server::ReadOutcome::BadRequest
            | server::ReadOutcome::TooLarge
            | server::ReadOutcome::UnsupportedBody => {
                let body = errors::page_400(&cfg.server_token);
                let resp = routes::bad_request(&cfg, &body);
                server::write_response(&mut stream, &resp.into_bytes(true)).await?;
                return Ok(());
            }
            // Body beyond the size bound: 413 and close.
            server::ReadOutcome::BodyTooLarge => {
                let body = errors::page_413(&cfg.server_token);
                let resp = routes::too_large_body(&cfg, &body);
                server::write_response(&mut stream, &resp.into_bytes(true)).await?;
                return Ok(());
            }
        };

        // If a request declared a body, consume it bounded by `lim.body`.
        if let Some(err_outcome) = server::consume_body(&mut stream, &mut buf, &req).await? {
            let (status, body) = match err_outcome {
                server::ReadOutcome::BodyTooLarge => (413, errors::page_413(&cfg.server_token)),
                _ => (400, errors::page_400(&cfg.server_token)),
            };
            let resp = if status == 413 {
                routes::too_large_body(&cfg, &body)
            } else {
                routes::bad_request(&cfg, &body)
            };
            server::write_response(&mut stream, &resp.into_bytes(true)).await?;
            return Ok(());
        }

        let headers_lower: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect();

        let view = routes::RequestView {
            method: &req.method,
            path: req.target.split('?').next().unwrap_or(&req.target),
            version: &req.version,
            headers: &headers_lower,
            force_close: is_last_request,
        };

        let resp = routes::handle(&cfg, &view);
        let keep_alive = view.wants_keepalive();

        let head_only = req.method.eq_ignore_ascii_case("HEAD");
        let bytes = resp.into_bytes(!head_only);
        match tokio::time::timeout(lim.write, server::write_response(&mut stream, &bytes)).await {
            Ok(v) => v?,
            Err(_) => return Ok(()),
        };

        if !keep_alive {
            return Ok(());
        }
    }

    Ok(())
}

/// Resolves on every SIGHUP. Registered once by the caller and re-armed after
/// each fire, so a signal can never be lost between loop iterations.
#[cfg(unix)]
async fn reload_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::hangup()) {
        Ok(mut s) => {
            s.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

#[cfg(not(unix))]
async fn reload_signal() {
    std::future::pending::<()>().await;
}

/// Resolves once, on SIGINT or SIGTERM. Registered once by the caller.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
        std::future::pending::<()>().await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
