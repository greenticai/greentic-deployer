//! Revision reuse for a multi-revision (traffic-split) deploy.
//!
//! A split step used to stage and warm a FRESH revision for every entry
//! whenever the live split differed from the manifest in any way — weights
//! included. Stepping a canary 10 → 50 → 100 % through the manifest therefore
//! minted a new `RevisionId` for the unchanged baseline on every step, and on
//! Cloud Run a new store revision is a new cloud revision (the deployer only
//! skips creating one when the store `RevisionId` already exists).
//!
//! [`reusable_revisions`] finds, per desired entry, an already-staged revision
//! of the same deployment that serves the same artifact, so the executor can
//! route traffic to it instead of re-staging. A weight-only change then
//! becomes a pure `traffic set`.

use std::collections::BTreeSet;
use std::path::Path;

use greentic_deploy_spec::{DeploymentId, Environment, RevisionId, RevisionLifecycle};

/// What one desired split entry must match to reuse an existing revision.
#[derive(Debug, Clone, Copy)]
pub(super) struct WantedRevision<'a> {
    pub digest: &'a str,
    pub source_uri: Option<&'a str>,
}

/// For each `wanted` entry (in order), the id of an existing revision that can
/// serve it unchanged, or `None` when it must be staged fresh.
///
/// A revision is reusable when ALL of these hold:
/// - it belongs to `deployment_id`;
/// - its lifecycle is `Ready` (staged AND warmed — `traffic set` admits only
///   `Ready` revisions, so anything else could not be routed to anyway);
/// - its `bundle_digest` is real (not the `sha256:00` placeholder) and equals
///   the wanted digest;
/// - its `bundle_source_uri` equals the wanted one (`None` only matches
///   `None`: a K8s worker needs the pull ref to boot);
/// - its pack list is complete when that can be judged locally — reusing a
///   short-locked revision would make the heal re-stage a no-op forever;
/// - no earlier entry in `wanted` already claimed it (two entries naming the
///   same artifact need two revisions, mirroring `split_converged`'s multiset).
///
/// Among several candidates the one currently carrying traffic wins, then the
/// newest (highest per-deployment `sequence`), so a retained 0 % baseline is
/// preferred over an older idle copy of the same artifact.
pub(super) fn reusable_revisions(
    env: &Environment,
    deployment_id: DeploymentId,
    wanted: &[WantedRevision<'_>],
    env_dir: Option<&Path>,
) -> Vec<Option<RevisionId>> {
    let live_weight = |revision_id: RevisionId| -> u32 {
        env.traffic_splits
            .iter()
            .find(|s| s.deployment_id == deployment_id)
            .and_then(|s| s.entries.iter().find(|e| e.revision_id == revision_id))
            .map_or(0, |e| e.weight_bps)
    };
    let mut claimed: BTreeSet<RevisionId> = BTreeSet::new();
    wanted
        .iter()
        .map(|w| {
            let best = env
                .revisions
                .iter()
                .filter(|r| {
                    r.deployment_id == deployment_id
                        && r.lifecycle == RevisionLifecycle::Ready
                        && super::digest_is_real(&r.bundle_digest)
                        && r.bundle_digest == w.digest
                        && r.bundle_source_uri.as_deref() == w.source_uri
                        && !claimed.contains(&r.revision_id)
                        && env_dir.is_none_or(|dir| {
                            super::super::bundle_stage::pack_list_is_complete(
                                dir,
                                r.revision_id,
                                &r.pack_list_lock_ref,
                            )
                        })
                })
                .max_by_key(|r| (live_weight(r.revision_id) > 0, r.sequence))
                .map(|r| r.revision_id);
            if let Some(id) = best {
                claimed.insert(id);
            }
            best
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{
        make_bundle_deployment, make_env, make_revision, make_traffic_split,
    };
    use greentic_deploy_spec::TrafficSplitEntry;

    fn wanted(digest: &str) -> WantedRevision<'_> {
        WantedRevision {
            digest,
            source_uri: None,
        }
    }

    /// Env with one deployment and three revisions: two `Ready` copies of
    /// `sha256:aa` (seq 1 carrying traffic, seq 3 idle) and one of `sha256:bb`.
    fn env_with_revisions() -> (Environment, DeploymentId, [RevisionId; 3]) {
        let mut env = make_env("local");
        let dep = make_bundle_deployment("local", "b");
        let dep_id = dep.deployment_id;
        let mut r1 = make_revision("local", "b", &dep_id, 1, RevisionLifecycle::Ready);
        r1.bundle_digest = "sha256:aa".into();
        let mut r2 = make_revision("local", "b", &dep_id, 2, RevisionLifecycle::Ready);
        r2.bundle_digest = "sha256:bb".into();
        let mut r3 = make_revision("local", "b", &dep_id, 3, RevisionLifecycle::Ready);
        r3.bundle_digest = "sha256:aa".into();
        let mut split = make_traffic_split("local", "b", &dep_id, &r1.revision_id, "seed");
        split.entries[0].weight_bps = 9_000;
        split.entries.push(TrafficSplitEntry {
            revision_id: r2.revision_id,
            weight_bps: 1_000,
        });
        let ids = [r1.revision_id, r2.revision_id, r3.revision_id];
        env.bundles.push(dep);
        env.revisions.extend([r1, r2, r3]);
        env.traffic_splits.push(split);
        (env, dep_id, ids)
    }

    #[test]
    fn prefers_the_revision_carrying_traffic_then_the_newest() {
        let (env, dep_id, [r1, r2, r3]) = env_with_revisions();
        let got = reusable_revisions(
            &env,
            dep_id,
            &[
                wanted("sha256:aa"),
                wanted("sha256:bb"),
                wanted("sha256:aa"),
            ],
            None,
        );
        // First `aa` takes the live one; the duplicate falls back to the idle
        // copy rather than sharing an id.
        assert_eq!(got, vec![Some(r1), Some(r2), Some(r3)]);
    }

    #[test]
    fn unmatched_digest_source_or_lifecycle_is_staged_fresh() {
        let (mut env, dep_id, _) = env_with_revisions();
        for r in &mut env.revisions {
            if r.bundle_digest == "sha256:bb" {
                r.lifecycle = RevisionLifecycle::Draining;
            }
        }
        let got = reusable_revisions(
            &env,
            dep_id,
            &[
                wanted("sha256:cc"),
                wanted("sha256:bb"),
                WantedRevision {
                    digest: "sha256:aa",
                    source_uri: Some("oci://x/b:1"),
                },
            ],
            None,
        );
        assert_eq!(got, vec![None, None, None]);
    }

    #[test]
    fn placeholder_digest_is_never_reused() {
        let (mut env, dep_id, _) = env_with_revisions();
        for r in &mut env.revisions {
            r.bundle_digest = "sha256:00".into();
        }
        let got = reusable_revisions(&env, dep_id, &[wanted("sha256:00")], None);
        assert_eq!(got, vec![None]);
    }
}
