mod assets;
mod condition;
mod config;
mod validate;
mod errors;
mod model;
mod range;
mod render;
mod routes;
mod serialize;
mod server;
mod state;
mod stealth;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "subgate=info".into()),
        )
        .init();

    // The config file is mandatory; its path is the only command line argument.
    let path: PathBuf = match std::env::args().nth(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: subgate <config.json>");
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

    tracing::info!("listening on {addr}");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("accept failed: {e}");
                        continue;
                    }
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = serve(stream, state).await {
                        tracing::debug!("connection ended: {e}");
                    }
                });
            }
            _ = reload_signal() => {
                // Reload runs on the runtime thread but does blocking file IO.
                // A config file is a few kilobytes, so the read is bounded and
                // this never meaningfully stalls accept().
                match state.reload() {
                    Ok(()) => tracing::info!("config reloaded"),
                    Err(e) => tracing::error!("reload failed, serving 503: {e}"),
                }
            }
            _ = shutdown() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }
}

async fn serve(mut stream: TcpStream, state: Arc<state::State>) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(1024);

    for _ in 0..server::MAX_KEEPALIVE_REQUESTS {
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

        let outcome = server::read_request(&mut stream, &mut buf).await?;

        let req = match outcome {
            server::ReadOutcome::Request(r) => r,
            server::ReadOutcome::Closed => return Ok(()),
            // Malformed request: nginx replies 400 and closes the connection.
            server::ReadOutcome::BadRequest | server::ReadOutcome::TooLarge => {
                let body = errors::page_400(&cfg.server_token);
                let resp = routes::bad_request(&cfg, &body);
                server::write_response(&mut stream, &resp.into_bytes(true)).await?;
                return Ok(());
            }
        };

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
        };

        let resp = routes::handle(&cfg, &view);
        let keep_alive = view.wants_keepalive();

        let head_only = req.method.eq_ignore_ascii_case("HEAD");
        server::write_response(&mut stream, &resp.into_bytes(!head_only)).await?;

        if !keep_alive {
            return Ok(());
        }
    }

    Ok(())
}

/// Resolves on every future SIGHUP.
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

async fn shutdown() {
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
