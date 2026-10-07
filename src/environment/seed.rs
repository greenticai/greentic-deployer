//! The environment SEED document: what a deployed worker boots from.
//!
//! A Cloud Run revision does not read the on-disk store; it reads one
//! `environment.json` mounted from a Secret Manager version, which Secret
//! Manager caps at 65,536 bytes. The store keeps every revision an environment
//! ever staged (about 1.8 KB each), so an environment with a handful of units
//! outgrows the cap after a few redeploys and can no longer be deployed at all.
//!
//! The seed is a *copy* made for the worker, and the worker does not read all of
//! it. [`prune_for_seed`] drops the part it provably never reads — revisions
//! that nothing routes to — and leaves the on-disk store
//! complete. It is the same idea as `DevStore::copy_excluding` for the dev-store
//! seed.
//!
//! ## What the runtime reads (greentic-start, checked against `origin/develop`
//! at `bf9f6f8`, 2026-10-07)
//!
//! * `revision_pull::pull_with` pulls only **routed** revisions — those a
//!   traffic split references (`routed_revision_ids`, `traffic_splits` entries)
//!   — and `FailurePolicy::resolve` finds the process's own revision
//!   (`GREENTIC_REVISION_ID`) among the routed ones.
//! * `materialize_runtime_config` (`src/environment/runtime_config.rs`) emits one
//!   block per split entry and joins it to its revision; every later stage
//!   (`revision_boot`, `revision_dispatcher`, `revision_serve`, `warmup`) works
//!   off those blocks, never off `Environment.revisions`.
//! * `doctor_env` counts revisions and, per split, asks for a `Ready` revision
//!   among them.
//! * Everything else it reads from the document — `bundles`, `messaging_endpoints`,
//!   `extensions`, `host_config`, `packs` — is untouched here.
//!
//! Nothing reads an unrouted revision, whatever its lifecycle, so every
//! unrouted revision is a candidate. The one thing that must survive is what
//! `Environment::validate` (run on every store load) checks against the
//! revision list: see [`protect_override_coverage`].

use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};

use greentic_deploy_spec::{Environment, Revision, RevisionId, RevisionLifecycle};

/// The environment as the seed should carry it.
///
/// Drops every revision — `Archived` or not — that no traffic split entry, no
/// bundle's `current_revisions` and no entry of `keep` names, except those
/// [`protect_override_coverage`] keeps so validation still passes. Borrows
/// `env` unchanged when there is nothing to drop, so the serialized bytes are
/// identical to the full document's. Also borrows it unchanged if the pruned
/// document would not validate — a seed the worker would refuse is worse than
/// an oversize one, and an oversize one fails loudly at the secret write (or
/// is staged as a pointer, see `gcp_cloudrun::seed_pointer`).
///
/// `keep` is for revisions the caller knows the worker needs regardless of
/// state; the Cloud Run deployer passes the revision it is creating.
pub fn prune_for_seed<'a>(env: &'a Environment, keep: &[RevisionId]) -> Cow<'a, Environment> {
    let mut referenced: HashSet<RevisionId> = keep.iter().copied().collect();
    referenced.extend(
        env.traffic_splits
            .iter()
            .flat_map(|split| split.entries.iter().map(|entry| entry.revision_id)),
    );
    referenced.extend(
        env.bundles
            .iter()
            .flat_map(|bundle| bundle.current_revisions.iter().copied()),
    );

    let mut drop: HashSet<RevisionId> = env
        .revisions
        .iter()
        .filter(|r| !referenced.contains(&r.revision_id))
        .map(|r| r.revision_id)
        .collect();
    protect_override_coverage(env, &mut drop);
    if drop.is_empty() {
        return Cow::Borrowed(env);
    }

    let mut pruned = env.clone();
    pruned.revisions.retain(|r| !drop.contains(&r.revision_id));
    match pruned.validate() {
        Ok(()) => Cow::Owned(pruned),
        Err(err) => {
            tracing::warn!(
                env = %env.environment_id,
                error = %err,
                "pruned environment seed failed validation; staging the full document"
            );
            Cow::Borrowed(env)
        }
    }
}

/// Take back out of `drop` the revisions `Environment::validate` still needs.
///
/// `validate` requires every key of a bundle's `config_overrides` to appear in
/// the pack list of a **non-archived** revision of that deployment (and
/// forward-accepts the check when no such revision lists any pack). So for
/// each deployment with overrides, any override pack that no surviving
/// non-archived revision lists is restored from the dropped set: the newest
/// revision (highest `sequence`) listing it. A pack no revision lists at all
/// makes the original document invalid already, and is left alone.
fn protect_override_coverage(env: &Environment, drop: &mut HashSet<RevisionId>) {
    for bundle in env
        .bundles
        .iter()
        .filter(|b| !b.config_overrides.is_empty())
    {
        let live: Vec<&Revision> = env
            .revisions
            .iter()
            .filter(|r| {
                r.deployment_id == bundle.deployment_id
                    && r.lifecycle != RevisionLifecycle::Archived
            })
            .collect();
        let mut covered: BTreeSet<&str> = live
            .iter()
            .filter(|r| !drop.contains(&r.revision_id))
            .flat_map(|r| r.pack_list.iter().map(|e| e.pack_id.as_str()))
            .collect();
        for pack in bundle.config_overrides.keys() {
            if covered.contains(pack.as_str()) {
                continue;
            }
            let newest = live
                .iter()
                .filter(|r| r.pack_list.iter().any(|e| e.pack_id.as_str() == pack))
                .max_by_key(|r| r.sequence);
            if let Some(rev) = newest {
                drop.remove(&rev.revision_id);
                covered.extend(rev.pack_list.iter().map(|e| e.pack_id.as_str()));
            }
        }
    }
}

/// The serialized seed `environment.json` (compact JSON, as the full document
/// always was). See [`prune_for_seed`].
pub fn seed_environment_bytes(
    env: &Environment,
    keep: &[RevisionId],
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(prune_for_seed(env, keep).as_ref())
}

#[cfg(test)]
mod tests;
