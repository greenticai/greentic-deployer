//! `greentic-operator-store-server` binary: serve the environment store
//! over HTTP, backed by an embedded SQLite file.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use greentic_operator_store_server::http::{RouterOptions, router_with_options};
use greentic_operator_store_server::rbac::RbacEngine;
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
    /// RBAC token file (JSON, schema `greentic.store-rbac.v1`): SHA-256
    /// token digests mapped to named actors and roles
    /// (`admin`/`operator`/`read-only`). When set, every request must
    /// carry a matching `Authorization: Bearer` token (fail closed); when
    /// unset, the server runs the open-dev allow-all policy and refuses
    /// non-loopback binds without the insecure escape hatch.
    #[arg(long, env = "GREENTIC_STORE_RBAC_TOKENS")]
    rbac_tokens: Option<PathBuf>,
    /// Allow binding to a non-loopback address WITHOUT RBAC tokens.
    /// Dev-only escape hatch — with `--rbac-tokens` configured,
    /// non-loopback binds are allowed without it.
    #[arg(
        long,
        env = "GREENTIC_STORE_INSECURE_ALLOW_NON_LOOPBACK",
        default_value_t = false
    )]
    insecure_allow_non_loopback: bool,
    /// Opt-in per-environment audit-log retention: keep at most this many
    /// audit rows per environment, pruning the oldest beyond the cap (the
    /// prune is recorded in the `audit_retention` watermark). Unset (the
    /// default) keeps the audit log append-only without bound.
    #[arg(long, env = "GREENTIC_STORE_AUDIT_MAX_ROWS", value_parser = clap::value_parser!(u32).range(1..))]
    audit_max_rows_per_env: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    // Fail fast on a malformed policy — it must never silently degrade to
    // open-dev.
    let rbac = match &args.rbac_tokens {
        Some(path) => RbacEngine::from_token_file(path)?,
        None => RbacEngine::open_dev(),
    };

    if !args.bind.ip().is_loopback() && !rbac.is_enforcing() {
        if !args.insecure_allow_non_loopback {
            return Err(format!(
                "refusing to bind to non-loopback address `{}` without authentication: \
                 configure --rbac-tokens (or GREENTIC_STORE_RBAC_TOKENS), or pass \
                 --insecure-allow-non-loopback / set \
                 GREENTIC_STORE_INSECURE_ALLOW_NON_LOOPBACK=true to override.",
                args.bind.ip()
            )
            .into());
        }
        tracing::warn!(
            bind = %args.bind,
            "binding to non-loopback address WITHOUT authentication \
             (open-dev RBAC; --rbac-tokens not configured)"
        );
    }
    if !args.bind.ip().is_loopback() && rbac.is_enforcing() {
        // Plain-HTTP bearer tokens travel in cleartext; the deployer
        // client refuses that combination outright. Production puts a
        // TLS-terminating proxy in front.
        tracing::warn!(
            bind = %args.bind,
            "serving bearer-token auth over plain HTTP on a non-loopback \
             address — terminate TLS in front of this server"
        );
    }

    // `open` creates the parent directory and the database file if missing.
    let store = SqliteEnvironmentStore::open(&args.db)
        .await?
        .with_audit_max_rows_per_env(args.audit_max_rows_per_env);
    if let Some(cap) = args.audit_max_rows_per_env {
        tracing::info!(
            audit_max_rows_per_env = cap,
            "audit-log retention enabled: pruning oldest audit rows beyond the \
             per-environment cap (recorded in the audit_retention watermark)"
        );
        store.reconcile_audit_retention().await?;
    }
    let storage = Arc::new(store);
    let app = router_with_options(
        storage,
        RouterOptions {
            operator_key_path: args.operator_key,
            rbac,
        },
    );

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
