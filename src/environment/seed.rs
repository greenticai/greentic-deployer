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
//! that are `Archived` and referenced by nothing — and leaves the on-disk store
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
//! Nothing reads an unrouted revision, whatever its lifecycle. Only `Archived`
//! ones are dropped anyway: see [`droppable`].

use std::borrow::Cow;
use std::collections::HashSet;

use greentic_deploy_spec::{Environment, RevisionId, RevisionLifecycle};

/// Whether a revision may be left out of the seed.
///
/// Deliberately narrower than "the runtime does not read it". `Environment::
/// validate` — which the worker's store runs on every load — checks a bundle's
/// `config_overrides` against the pack lists of its **non-archived** revisions,
/// so dropping a non-archived revision could make a valid environment fail
/// validation at boot. An archived revision is excluded from that check, so
/// dropping one cannot. Unrouted revisions in other states (`Ready` and the
/// like) are unread by the runtime too, but are kept until that rule is
/// reconciled — see `docs/cloudrun-internals.md`.
fn droppable(lifecycle: RevisionLifecycle) -> bool {
    lifecycle == RevisionLifecycle::Archived
}

/// The environment as the seed should carry it.
///
/// Drops every `Archived` revision that no traffic split entry, no bundle's
/// `current_revisions` and no entry of `keep` names. Borrows `env` unchanged
/// when there is nothing to drop, so the serialized bytes are identical to the
/// full document's. Also borrows it unchanged if the pruned document would not
/// validate — a seed the worker would refuse is worse than an oversize one, and
/// the oversize one fails loudly at the secret write.
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

    let prunable = |r: &greentic_deploy_spec::Revision| {
        droppable(r.lifecycle) && !referenced.contains(&r.revision_id)
    };
    if !env.revisions.iter().any(prunable) {
        return Cow::Borrowed(env);
    }

    let mut pruned = env.clone();
    pruned.revisions.retain(|r| !prunable(r));
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
