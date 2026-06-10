//! `greentic-operator-store-server` binary: serve the environment store
//! over HTTP, backed by an embedded SQLite file.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use greentic_operator_store_server::http::router;
use greentic_operator_store_server::sqlite::SqliteEnvironmentStore;

/// Operator store server: HTTP front for the Greentic environment store.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Address to bind the HTTP listener on.
    #[arg(long, env = "GREENTIC_STORE_BIND", default_value = "127.0.0.1:8787")]
    bind: SocketAddr,
    /// SQLite database file (created, with parent directories, if missing).
    #[arg(long, env = "GREENTIC_STORE_DB")]
    db: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    if let Some(parent) = args.db.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let store = SqliteEnvironmentStore::open(&args.db).await?;
    let app = router(Arc::new(store));

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(
        bind = %args.bind,
        db = %args.db.display(),
        "operator store server listening"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let ctrl_c = async {
            if let Err(err) = tokio::signal::ctrl_c().await {
                tracing::warn!(%err, "failed to install ctrl-c handler; running until killed");
                std::future::pending::<()>().await;
            }
        };
        let sigterm = async {
            match signal(SignalKind::terminate()) {
                Ok(mut s) => {
                    s.recv().await;
                }
                Err(err) => {
                    tracing::warn!(%err, "failed to install SIGTERM handler; running until killed");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            () = ctrl_c => {}
            () = sigterm => {}
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(%err, "failed to install ctrl-c handler; running until killed");
            std::future::pending::<()>().await;
        }
    }
}
