//! The Redis URL's own env-owned Secret Manager secret (P5 follow-up to PD4).
//!
//! The URL carries the Memorystore AUTH string. PD4 staged it as one more
//! version of the environment seed secret, beside `environment.json`, the
//! dev-store and the telemetry header — so when the password changed, the
//! versions holding the old one could never be told apart from seed versions
//! live revisions still mount, and nothing ever destroyed them.
//!
//! It now lives in its OWN secret, [`redis_url_secret_name`], stamped with the
//! same env owner as the seed secret, and the rule is:
//!
//! 1. **Reuse an unchanged value.** Before staging, every ENABLED version is
//!    read back; one whose payload equals the URL is reused (the newest such),
//!    so an unchanged URL mints nothing and every deployment shares one
//!    version. That is what makes pruning safe: an older version can only hold
//!    a value that is no longer the answer.
//! 2. **A new value is a new version.** Only when no enabled version matches.
//! 3. **Prune only after the new revision is ready** (the warm's final commit,
//!    after the invoker grant), and only when this warm minted the version:
//!    keep the new version, every version newer than it (a concurrent warm's),
//!    and the IMMEDIATELY PREVIOUS enabled version — the one revisions still
//!    serving 100 % pin, since a warm adds its revision at 0 %, and the one a
//!    rollback boots with. Disable + destroy every older enabled version.
//! 4. **Best effort.** `list` / `disable` / `destroy` are optional permissions
//!    ([`SECRET_VERSION_PRUNE_PERMISSIONS`]); a prune that fails leaves the old
//!    versions in place with a `warn`, never fails a deploy that succeeded.
//!    Without `list`, reuse falls back to reading `latest` alone.
//!
//! Only a secret this environment created (stamped with its own owner) is ever
//! written or pruned: an existing secret stamped by another environment OR by
//! nobody is refused — this name never existed before the stamp did, so an
//! unstamped one is not ours.
//!
//! A deployment that has not been re-warmed across TWO URL changes pins a
//! destroyed version, and its new instances cannot start. That is accepted:
//! the value it pinned was superseded twice, so for a password rotation it no
//! longer authenticates anyway. Redis URL versions staged into the seed secret
//! by PD4 before this change stay there until `op env destroy`.
//!
//! [`SECRET_VERSION_PRUNE_PERMISSIONS`]: super::credentials::SECRET_VERSION_PRUNE_PERMISSIONS

use crate::env_packs::deployer::DeployerError;

use super::deploy_target::{CloudRunTarget, EnsuredSecret, SecretVersionInfo};
use super::deployer::{
    SecretOwnership, classify_owner, env_owner_stamp, provider, secret_conflict,
};

/// The Secret Manager secret holding an env's Redis URL:
/// `<secret_prefix>-redis-url`. Shared so `op env destroy` deletes exactly
/// what warm staged.
pub fn redis_url_secret_name(secret_prefix: &str) -> String {
    format!("{secret_prefix}-redis-url")
}

/// What [`stage`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedRedisUrl {
    /// The numeric version the revision pins.
    pub version: String,
    /// `true` when this warm minted `version` (a new value): only then may
    /// [`prune_after_ready`] run.
    pub minted: bool,
}

/// Ensure the env-owned Redis URL secret, then reuse the newest enabled
/// version already holding `url` or add one. Grants `runtime_service_account`
/// read on the secret.
pub(crate) async fn stage(
    target: &dyn CloudRunTarget,
    name: &str,
    env_id: &str,
    url: &[u8],
    runtime_service_account: &str,
) -> Result<StagedRedisUrl, DeployerError> {
    let ensured = target
        .ensure_secret(name, &env_owner_stamp(env_id))
        .await
        .map_err(provider)?;
    if let EnsuredSecret::Existed { owner } = ensured {
        match classify_owner(owner, env_id) {
            SecretOwnership::Ours => {}
            SecretOwnership::Conflict { owner } => {
                return Err(secret_conflict(name, &owner, env_id));
            }
            // This secret name post-dates ownership stamping, so an unstamped
            // one was created by something else: never write into it.
            SecretOwnership::Legacy | SecretOwnership::Absent => {
                return Err(secret_conflict(name, "(no owner stamp)", env_id));
            }
        }
    }
    let staged = match reusable_version(target, name, url).await {
        Some(version) => StagedRedisUrl {
            version,
            minted: false,
        },
        None => StagedRedisUrl {
            version: target
                .add_secret_version(name, url)
                .await
                .map_err(provider)?
                .version,
            minted: true,
        },
    };
    target
        .grant_secret_accessor(name, runtime_service_account)
        .await
        .map_err(provider)?;
    Ok(staged)
}

/// The newest ENABLED version whose payload is `url`, if any. Every failure
/// reads as "none" — the caller then mints a version, which is always safe.
async fn reusable_version(target: &dyn CloudRunTarget, name: &str, url: &[u8]) -> Option<String> {
    let candidates = match target.list_secret_versions(name).await {
        Ok(listed) => {
            let mut enabled: Vec<u64> = listed
                .iter()
                .filter(|v| v.enabled)
                .filter_map(|v| v.version.parse().ok())
                .collect();
            enabled.sort_unstable_by(|a, b| b.cmp(a));
            enabled.into_iter().map(|v| v.to_string()).collect()
        }
        Err(e) => {
            tracing::warn!(
                secret = name,
                error = %e,
                "cannot list Redis URL secret versions (secretmanager.versions.list); \
                 comparing against `latest` only"
            );
            vec!["latest".to_string()]
        }
    };
    for candidate in candidates {
        match target.access_secret_version(name, &candidate).await {
            Ok((resolved, payload)) if payload == url => return Some(resolved.version),
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(secret = name, version = %candidate, error = %e,
                    "Redis URL version not readable; not reused");
            }
        }
    }
    None
}

/// The enabled versions to disable + destroy once `current` is ready: every
/// enabled version older than the newest enabled version below `current`.
/// Versions newer than `current` (a concurrent warm's) are never touched.
pub(crate) fn versions_to_destroy(listed: &[SecretVersionInfo], current: &str) -> Vec<String> {
    let Ok(current) = current.parse::<u64>() else {
        return Vec::new();
    };
    let mut older: Vec<u64> = listed
        .iter()
        .filter(|v| v.enabled)
        .filter_map(|v| v.version.parse::<u64>().ok())
        .filter(|v| *v < current)
        .collect();
    older.sort_unstable();
    // The immediately previous one stays (rollback, and the revisions still
    // serving while the new one sits at 0 %).
    older.pop();
    older.into_iter().map(|v| v.to_string()).collect()
}

/// Outcome of [`prune_after_ready`], for the caller's report and for tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PruneReport {
    pub destroyed: Vec<String>,
    pub failed: Vec<String>,
}

/// Disable + destroy the Redis URL versions [`versions_to_destroy`] selects.
/// Best effort: every failure is a `warn` and a `failed` entry, never an error.
pub(crate) async fn prune_after_ready(
    target: &dyn CloudRunTarget,
    name: &str,
    current: &str,
) -> PruneReport {
    let mut report = PruneReport::default();
    let listed = match target.list_secret_versions(name).await {
        Ok(listed) => listed,
        Err(e) => {
            tracing::warn!(
                secret = name,
                error = %e,
                "Redis URL changed but its older secret versions were not pruned: cannot list \
                 them (grant secretmanager.versions.list/disable/destroy to the deployer)"
            );
            return report;
        }
    };
    for version in versions_to_destroy(&listed, current) {
        match target.destroy_secret_version(name, &version).await {
            Ok(()) => report.destroyed.push(version),
            Err(e) => {
                tracing::warn!(
                    secret = name,
                    version = %version,
                    error = %e,
                    "could not disable+destroy a superseded Redis URL secret version \
                     (grant secretmanager.versions.disable/destroy to the deployer)"
                );
                report.failed.push(version);
            }
        }
    }
    if !report.destroyed.is_empty() {
        tracing::info!(secret = name, destroyed = ?report.destroyed,
            "destroyed superseded Redis URL secret versions");
    }
    report
}

#[cfg(test)]
#[path = "redis_secret_tests.rs"]
mod tests;
