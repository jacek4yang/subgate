mod assets;
mod condition;
mod config;
mod errors;
mod range;
mod routes;
mod serialize;
mod server;
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

    let config = match config::Config::load(&path) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };

    let addr = config.listen;
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
                let cfg = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(e) = serve(stream, cfg).await {
                        tracing::debug!("connection ended: {e}");
                    }
                });
            }
            _ = shutdown() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }
}

async fn serve(mut stream: TcpStream, cfg: Arc<config::Config>) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(1024);

    for _ in 0..server::MAX_KEEPALIVE_REQUESTS {
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
