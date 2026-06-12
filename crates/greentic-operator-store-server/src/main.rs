//! `greentic-operator-store-server` binary: serve the environment store
//! over HTTP, backed by an embedded SQLite file.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use greentic_operator_store_server::http::{router, router_with_operator_key};
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
    /// Path of the server's operator signing key (PEM, created on first
    /// trust-root bootstrap/seed if missing). Defaults to the standard
    /// operator-key resolution: `GTC_OPERATOR_KEY_PATH`, else
    /// `~/.greentic/operator/key.pem`.
    #[arg(long, env = "GREENTIC_STORE_OPERATOR_KEY")]
    operator_key: Option<PathBuf>,
    /// Allow binding to a non-loopback address. Dev-only escape hatch: the
    /// server has no authentication yet (RBAC = PR-4.4). This flag will be
    /// removed or replaced with a proper auth gate when RBAC lands.
    #[arg(
        long,
        env = "GREENTIC_STORE_INSECURE_ALLOW_NON_LOOPBACK",
        default_value_t = false
    )]
    insecure_allow_non_loopback: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    if !args.bind.ip().is_loopback() {
        if !args.insecure_allow_non_loopback {
            return Err(format!(
                "refusing to bind to non-loopback address `{}`: the server has no \
                 authentication yet (RBAC = PR-4.4). Pass --insecure-allow-non-loopback \
                 or set GREENTIC_STORE_INSECURE_ALLOW_NON_LOOPBACK=true to override.",
                args.bind.ip()
            )
            .into());
        }
        tracing::warn!(
            bind = %args.bind,
            "binding to non-loopback address WITHOUT authentication — \
             the server has no RBAC yet (PR-4.4)"
        );
    }

    // `open` creates the parent directory and the database file if missing.
    let store = SqliteEnvironmentStore::open(&args.db).await?;
    let storage = Arc::new(store);
    let app = match args.operator_key {
        Some(path) => router_with_operator_key(storage, path),
        None => router(storage),
    };

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
