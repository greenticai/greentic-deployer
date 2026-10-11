//! Pre-mint every `generated` secret a Cloud Run revision's packs declare into
//! the env's dev store, then prove the STAGED seed carries them.
//!
//! greentic-start's `revision_secrets` mints a declared `generated` secret
//! (e.g. the webchat `jwt_signing_key`) at boot when the seeded dev store lacks
//! it. On Cloud Run every instance boots from the same seed into its own
//! in-memory `/tmp`, so with `max_instances > 1` each instance mints its OWN
//! value — a token signed by one fails verification on the next, with nothing
//! red at any layer. Minting once, here, before the seed is staged, is what
//! makes boot find the value and mint nothing.
//!
//! Mirrors greentic-start's reader exactly so the two agree on where a value
//! lives: the revision's `pack-list.lock` names the packs; each pack's
//! `secret-requirements.json` names the secrets; the tenant/team come from the
//! deployment's route binding; the team of a generated secret is its declared
//! scope (`generated_scope_team`); the writer uses the canonical (underscored)
//! provider segment, and existence checks both provider spellings plus every
//! alias. **A value already present is never re-minted** — not even for a pack
//! declaring `regenerate_if_present`, because a re-mint here would rotate a live
//! signing key on every deploy.
//!
//! The value is persisted into the operator's dev store (not only the staged
//! copy) so it is stable across deploys: every revision and every instance
//! then share one key, as they would on a single long-lived host.

use std::path::Path;

use greentic_deploy_spec::{Environment, PackListLock, Revision};
use greentic_secrets_lib::{
    GeneratedSecretRequirement, canonical_secret_name, generated_scope_team,
};

#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
use crate::env_packs::gcp_cloudrun::shared_state::GeneratedSecretSeed;
use crate::environment::LocalFsStore;
use crate::runtime_secrets::{RuntimeSecretContext, canonical_secret_uri, collect_requirements};

use super::OpError;
use super::secrets::{DevStoreWriteLock, dev_store_get_value};

/// One generated secret the revision needs: where greentic-start would write
/// it, and every URI under which it would find an existing value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GeneratedSecretPlan {
    pub write_uri: String,
    pub candidates: Vec<String>,
    pub requirement: GeneratedSecretRequirement,
}

/// Every generated secret `revision`'s pinned packs declare. `Err` carries a
/// human reason the plan could not be established (the gate then refuses a
/// multi-instance warm naming it) — never a partial list read as complete.
pub(crate) fn plan_generated(
    env_dir: &Path,
    env: &Environment,
    revision: &Revision,
) -> Result<Vec<GeneratedSecretPlan>, String> {
    let deployment = env
        .bundles
        .iter()
        .find(|d| d.deployment_id == revision.deployment_id)
        .ok_or_else(|| {
            format!(
                "deployment `{}` of revision `{}` is not in the environment",
                revision.deployment_id, revision.revision_id
            )
        })?;
    let tenant = deployment.route_binding.tenant_selector.tenant.clone();
    let team = deployment.route_binding.tenant_selector.team.clone();

    let lock_path = env_dir.join(&revision.pack_list_lock_ref);
    let bytes = std::fs::read(&lock_path).map_err(|e| {
        format!(
            "revision `{}` has no readable pack-list.lock at `{}` ({e}); stage it first",
            revision.revision_id,
            lock_path.display()
        )
    })?;
    let lock: PackListLock = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "pack-list.lock `{}` is unreadable: {e}",
            lock_path.display()
        )
    })?;
    if lock.revision_id != revision.revision_id {
        return Err(format!(
            "pack-list.lock `{}` pins revision `{}`, not `{}`",
            lock_path.display(),
            lock.revision_id,
            revision.revision_id
        ));
    }

    let env_name = env.environment_id.as_str();
    let mut plans: Vec<GeneratedSecretPlan> = Vec::new();
    for pack in &lock.packs {
        let abs = crate::path_safety::normalize_under_root(env_dir, &pack.path)
            .map_err(|e| format!("pinned pack `{}`: {e}", pack.path.display()))?;
        // greentic-start skips a lock entry that is not a file; so do we.
        if !abs.is_file() {
            continue;
        }
        let pack_id = pack.pack_id.to_string();
        let ctx = RuntimeSecretContext {
            bundle_root: env_dir.to_path_buf(),
            pack_paths: vec![abs],
            environment: env_name.to_string(),
            tenant: tenant.clone(),
            team: Some(team.clone()),
            extra_dev_store_roots: Vec::new(),
        };
        let requirements = collect_requirements(&ctx)
            .map_err(|e| format!("reading secret requirements of pack `{pack_id}`: {e}"))?;
        let canonical_pack = canonical_secret_name(&pack_id);
        let mut providers = vec![pack_id.clone()];
        if canonical_pack != pack_id {
            providers.push(canonical_pack.clone());
        }
        for req in requirements {
            let Some(generated) = req.generated else {
                continue;
            };
            let scope_team = generated_scope_team(&generated, Some(team.as_str()));
            let uri = |provider: &str, key: &str| {
                canonical_secret_uri(env_name, &tenant, scope_team, provider, key)
            };
            let mut candidates = Vec::new();
            for key in std::iter::once(&req.key).chain(req.aliases.iter()) {
                for provider in &providers {
                    let c = uri(provider, key);
                    if !candidates.contains(&c) {
                        candidates.push(c);
                    }
                }
            }
            let write_uri = uri(&canonical_pack, &req.key);
            if plans.iter().all(|p| p.write_uri != write_uri) {
                plans.push(GeneratedSecretPlan {
                    write_uri,
                    candidates,
                    requirement: generated,
                });
            }
        }
    }
    Ok(plans)
}

/// Mint every planned secret that no candidate URI already holds, writing it
/// to `dev_path`. Returns, per plan, the URI the value now lives at (the
/// existing one when found — never re-minted).
///
/// The whole read-check-write runs under the dev store's writer flock: two
/// concurrent stages of one env (two revisions, or two hosts on a shared
/// store) would otherwise both read "absent", both mint, and the loser's key
/// would ship in its revision while the store keeps the winner's — a silent
/// signing-key rotation, which is the thing this module exists to prevent.
pub(crate) fn mint_missing(
    dev_path: &Path,
    plans: &[GeneratedSecretPlan],
) -> Result<Vec<String>, OpError> {
    if plans.is_empty() {
        return Ok(Vec::new());
    }
    let lock = DevStoreWriteLock::acquire(dev_path)?;
    let mut held = Vec::with_capacity(plans.len());
    for plan in plans {
        let mut found = None;
        if dev_path.exists() {
            for candidate in &plan.candidates {
                if dev_store_get_value(dev_path, candidate)?.is_some() {
                    found = Some(candidate.clone());
                    break;
                }
            }
        }
        let uri = match found {
            Some(uri) => uri,
            None => {
                let (bytes, _) = greentic_secrets_lib::generate_secret_value(&plan.requirement)
                    .map_err(|e| {
                        OpError::Conflict(format!(
                            "generating `{}` for the staged seed: {e}",
                            plan.write_uri
                        ))
                    })?;
                let value = String::from_utf8(bytes).map_err(|e| {
                    OpError::Conflict(format!(
                        "generated `{}` is not valid UTF-8: {e}",
                        plan.write_uri
                    ))
                })?;
                lock.put(dev_path, &plan.write_uri, &value)?;
                plan.write_uri.clone()
            }
        };
        held.push(uri);
    }
    Ok(held)
}

/// The URIs in `expected` that the staged seed bytes do NOT carry. Reads a
/// private copy, so the check sees exactly what will be uploaded.
pub(crate) fn staged_missing(
    staged: Option<&[u8]>,
    expected: &[String],
) -> Result<Vec<String>, OpError> {
    if expected.is_empty() {
        return Ok(Vec::new());
    }
    let Some(staged) = staged else {
        return Ok(expected.to_vec());
    };
    let dir = tempfile::tempdir()
        .map_err(|e| OpError::Conflict(format!("checking the staged seed: {e}")))?;
    let path = dir.path().join(".dev.secrets.env");
    std::fs::write(&path, staged).map_err(|source| OpError::Io {
        path: path.clone(),
        source,
    })?;
    let mut missing = Vec::new();
    for uri in expected {
        if dev_store_get_value(&path, uri)?.is_none() {
            missing.push(uri.clone());
        }
    }
    Ok(missing)
}

/// Pre-mint every generated secret the env's revisions declare into the env dev
/// store at `dev_path`, for a lane whose runtime is more than one process — the
/// k8s router runs at least two replicas, and each used to mint its own webchat
/// `jwt_signing_key` at boot, so a token signed by one replica failed on the
/// other (`invalid token signature`) with nothing red at any layer.
///
/// Best effort per revision: one whose plan cannot be established (no staged
/// `pack-list.lock`, an unreadable pack) is skipped with a warning rather than
/// failing the reconcile, and `Ok(n)` reports how many secrets are now held.
/// A value already present is never re-minted (see the module doc).
pub(crate) fn premint_for_env(
    store: &LocalFsStore,
    env: &Environment,
    dev_path: &Path,
) -> Result<usize, OpError> {
    let env_dir = store
        .env_dir(&env.environment_id)
        .map_err(|e| OpError::Conflict(format!("resolving env dir: {e}")))?;
    let mut held = 0;
    for revision in &env.revisions {
        match plan_generated(&env_dir, env, revision) {
            Ok(plans) => held += mint_missing(dev_path, &plans)?.len(),
            Err(reason) => tracing::warn!(
                revision = %revision.revision_id,
                %reason,
                "not pre-minting generated secrets for this revision"
            ),
        }
    }
    Ok(held)
}

/// Pre-mint the revision's generated secrets into the env dev store at
/// `dev_path`, stage the seed through `read_staged` (the caller's
/// `read_dev_secrets_bytes`), and report whether the staged bytes carry every
/// one. The staged bytes are returned so the caller uploads exactly what was
/// checked.
///
/// `dev_path` MUST be the file `read_staged` reads — the caller resolves both
/// through one helper. Minting into another file (an override path the staging
/// read ignores) would report every secret missing, forever.
#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
pub(crate) fn premint_and_stage(
    store: &LocalFsStore,
    env: &Environment,
    revision: &Revision,
    dev_path: &Path,
    read_staged: impl FnOnce() -> Result<Option<Vec<u8>>, OpError>,
) -> Result<(GeneratedSecretSeed, Option<Vec<u8>>), OpError> {
    let env_dir = store
        .env_dir(&env.environment_id)
        .map_err(|e| OpError::Conflict(format!("resolving env dir: {e}")))?;
    let plans = match plan_generated(&env_dir, env, revision) {
        Ok(plans) => plans,
        Err(reason) => return Ok((GeneratedSecretSeed::Unestablished(reason), read_staged()?)),
    };
    let held = mint_missing(dev_path, &plans)?;
    let staged = read_staged()?;
    let missing = staged_missing(staged.as_deref(), &held)?;
    let seed = if missing.is_empty() {
        GeneratedSecretSeed::Complete
    } else {
        GeneratedSecretSeed::Missing(missing)
    };
    Ok((seed, staged))
}

#[cfg(test)]
#[path = "cloudrun_generated_secrets_tests.rs"]
mod tests;
