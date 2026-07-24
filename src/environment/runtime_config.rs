//! Runtime-config producer (B4 of `plans/next-gen-deployment.md`).
//!
//! Projects an [`Environment`]'s validated [`TrafficSplit`](greentic_deploy_spec::TrafficSplit)s into the
//! [`greentic.runtime-config.v1`](RuntimeConfig) document that `greentic-start`
//! loads at boot (B0) and the in-process `RevisionDispatcher` routes on (B3).
//!
//! ## Why the projection reads `traffic_splits`, not `revisions`
//!
//! The loader (`greentic-start` B0) enforces, per deployment, that the emitted
//! revision blocks' `weight_bps` sum to exactly 10,000 — and rejects the
//! *entire* env's config if any deployment violates it. A
//! [`TrafficSplit`](greentic_deploy_spec::TrafficSplit) is
//! already validated to sum to 10,000 bps, so emitting **one block per split
//! entry** is the only projection that provably satisfies that invariant. A
//! deployment with no split contributes nothing (it has no live routing).
//!
//! Filtering split entries by `Revision.lifecycle == Ready` would be unsafe: a
//! split that still references a draining revision (e.g. `{v1: 5000 Ready,
//! v2: 5000 Draining}`) would drop below 10,000 bps and take down every
//! deployment's routing. The spec keeps splits well-formed elsewhere — §5.3
//! only admits Ready revisions into a split, and the archive guard
//! ([`super::lifecycle`]) refuses to retire a revision that still owns live
//! traffic — so faithful projection is both correct and fail-safe.
//!
//! `pack_list_refs` is sourced by joining each split entry to its
//! [`Revision`](greentic_deploy_spec::Revision) (by `(deployment_id,
//! revision_id)`) and emitting that revision's `pack_list_lock_ref` — the
//! `pack-list.lock` written at stage time. An entry with no matching revision
//! (or a revision with an empty lock ref) emits no ref: B0 only file-checks
//! non-empty refs, so the boot/route seam stays fail-safe.
//!
//! `pack_config_refs` are sourced from the same revision's
//! `pack_config_refs` field — one env-relative path per pack id that carried
//! a `pack-config-input.v1` at stage time (C7). Bundles with no wizard inputs
//! contribute no refs; B0 file-checks only non-empty refs, so the seam stays
//! fail-safe through the legacy path.

use greentic_deploy_spec::{Environment, RevisionRuntimeBlock, RuntimeConfig, SchemaVersion};

/// Materialize the `runtime-config.v1` projection of an environment's traffic
/// splits. Pure and total: one [`RevisionRuntimeBlock`] per split entry, in
/// split-then-entry order, with `pack_list_refs` joined from the matching
/// revision's `pack_list_lock_ref`. An env with no traffic splits yields an
/// empty `revisions` list (callers delete the on-disk file rather than write
/// one B0 would reject).
pub fn materialize_runtime_config(env: &Environment) -> RuntimeConfig {
    let revisions = env
        .traffic_splits
        .iter()
        .flat_map(|split| {
            split.entries.iter().map(move |entry| {
                // Join to the revision once to surface BOTH its pinned
                // pack-list lockfile AND its per-pack pack-config.v1 refs.
                // A missing match (or an empty lock ref) yields no
                // pack_list_refs / pack_config_refs, which B0 treats as
                // "nothing to file-check" rather than an error.
                let revision = env.revisions.iter().find(|r| {
                    r.revision_id == entry.revision_id && r.deployment_id == split.deployment_id
                });
                let pack_list_refs = revision
                    .filter(|r| !r.pack_list_lock_ref.as_os_str().is_empty())
                    .map(|r| vec![r.pack_list_lock_ref.clone()])
                    .unwrap_or_default();
                let pack_config_refs = revision
                    .map(|r| r.pack_config_refs.clone())
                    .unwrap_or_default();
                RevisionRuntimeBlock {
                    deployment_id: split.deployment_id,
                    revision_id: entry.revision_id,
                    bundle_id: split.bundle_id.clone(),
                    pack_list_refs,
                    pack_config_refs,
                    weight_bps: entry.weight_bps,
                }
            })
        })
        .collect();
    RuntimeConfig {
        schema: SchemaVersion::new(SchemaVersion::RUNTIME_CONFIG_V1),
        env_id: env.environment_id.clone(),
        revisions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{
        BundleId, DeploymentId, EnvId, EnvironmentHostConfig, Revision, RevisionId,
        RevisionLifecycle, TrafficSplit, TrafficSplitEntry,
    };
    use std::path::PathBuf;

    // The materializer reads only `environment_id` + `traffic_splits`, so the
    // test envs leave `bundles`/`revisions` empty rather than pulling in the
    // heavier `cli::tests_common` fixtures (private to `cli`).
    fn env(env_id: &str, traffic_splits: Vec<TrafficSplit>) -> Environment {
        let id = EnvId::try_from(env_id).unwrap();
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: id.clone(),
            name: env_id.to_string(),
            host_config: EnvironmentHostConfig::new(id),
            packs: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits,
            messaging_endpoints: Vec::new(),
            extensions: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    fn split(
        env_id: &str,
        bundle: &str,
        deployment_id: DeploymentId,
        entries: Vec<(RevisionId, u32)>,
    ) -> TrafficSplit {
        TrafficSplit {
            schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
            env_id: EnvId::try_from(env_id).unwrap(),
            deployment_id,
            bundle_id: BundleId::new(bundle),
            generation: 0,
            entries: entries
                .into_iter()
                .map(|(revision_id, weight_bps)| TrafficSplitEntry {
                    revision_id,
                    weight_bps,
                })
                .collect(),
            updated_at: chrono::Utc::now(),
            updated_by: "test".to_string(),
            idempotency_key: "k".to_string(),
            authorization_ref: PathBuf::from("auth.json"),
            previous_split_ref: None,
        }
    }

    fn revision(
        env_id: &str,
        bundle: &str,
        deployment_id: DeploymentId,
        revision_id: RevisionId,
        pack_list_lock_ref: PathBuf,
    ) -> Revision {
        Revision {
            schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
            revision_id,
            env_id: EnvId::try_from(env_id).unwrap(),
            bundle_id: BundleId::new(bundle),
            deployment_id,
            sequence: 1,
            created_at: chrono::Utc::now(),
            bundle_digest: "sha256:00".to_string(),
            bundle_source_uri: None,
            pack_list: Vec::new(),
            pack_list_lock_ref,
            pack_config_refs: Vec::new(),
            config_digest: "sha256:00".to_string(),
            signature_sidecar_ref: PathBuf::from("rev.sig"),
            lifecycle: RevisionLifecycle::Ready,
            staged_at: None,
            warmed_at: None,
            drain_seconds: 30,
            abort_metrics: Vec::new(),
        }
    }

    #[test]
    fn empty_env_yields_no_blocks() {
        let cfg = materialize_runtime_config(&env("local", Vec::new()));
        assert_eq!(cfg.schema.as_str(), SchemaVersion::RUNTIME_CONFIG_V1);
        assert_eq!(cfg.env_id.as_str(), "local");
        assert!(cfg.revisions.is_empty());
    }

    #[test]
    fn single_split_projects_one_block_per_entry_preserving_weights() {
        let did = DeploymentId::new();
        let (rid1, rid2) = (RevisionId::new(), RevisionId::new());
        let env = env(
            "local",
            vec![split(
                "local",
                "fast2flow",
                did,
                vec![(rid1, 9_000), (rid2, 1_000)],
            )],
        );

        let cfg = materialize_runtime_config(&env);
        assert_eq!(cfg.revisions.len(), 2);
        assert_eq!(cfg.revisions[0].revision_id, rid1);
        assert_eq!(cfg.revisions[0].deployment_id, did);
        assert_eq!(cfg.revisions[0].bundle_id, BundleId::new("fast2flow"));
        assert_eq!(cfg.revisions[0].weight_bps, 9_000);
        assert_eq!(cfg.revisions[1].weight_bps, 1_000);
        // Refs are deferred (Phase C/D); empty so B0 skips the file-existence check.
        assert!(cfg.revisions[0].pack_list_refs.is_empty());
        assert!(cfg.revisions[0].pack_config_refs.is_empty());
        // Per-deployment weights sum to 10,000 bps — B0's hard invariant.
        let sum: u32 = cfg.revisions.iter().map(|b| b.weight_bps).sum();
        assert_eq!(sum, 10_000);
    }

    #[test]
    fn multiple_deployments_each_contribute_their_split() {
        let (did1, did2) = (DeploymentId::new(), DeploymentId::new());
        let (rid1, rid2) = (RevisionId::new(), RevisionId::new());
        let env = env(
            "local",
            vec![
                split("local", "fast2flow", did1, vec![(rid1, 10_000)]),
                split("local", "llm-router", did2, vec![(rid2, 10_000)]),
            ],
        );

        let cfg = materialize_runtime_config(&env);
        assert_eq!(cfg.revisions.len(), 2);
        let deployments: Vec<DeploymentId> =
            cfg.revisions.iter().map(|b| b.deployment_id).collect();
        assert!(deployments.contains(&did1));
        assert!(deployments.contains(&did2));
    }

    #[test]
    fn zero_weight_entry_is_preserved_for_cookie_stickiness() {
        // A canary downsized to 0% stays in the split (P3: zero-weight entries
        // are valid for display/stickiness, skipped only for new selection),
        // so it must survive into the runtime-config block list.
        let did = DeploymentId::new();
        let (rid1, rid2) = (RevisionId::new(), RevisionId::new());
        let env = env(
            "local",
            vec![split(
                "local",
                "fast2flow",
                did,
                vec![(rid1, 10_000), (rid2, 0)],
            )],
        );

        let cfg = materialize_runtime_config(&env);
        assert_eq!(cfg.revisions.len(), 2);
        assert_eq!(cfg.revisions[1].revision_id, rid2);
        assert_eq!(cfg.revisions[1].weight_bps, 0);
    }

    #[test]
    fn split_entry_emits_matching_revisions_pack_list_lock_ref() {
        // A split entry whose revision carries a pinned pack-list lockfile must
        // surface that ref so greentic-start can file-check + load it.
        let did = DeploymentId::new();
        let rid = RevisionId::new();
        let lock_ref = PathBuf::from(format!("revisions/{rid}/pack-list.lock"));
        let mut env = env(
            "local",
            vec![split("local", "fast2flow", did, vec![(rid, 10_000)])],
        );
        env.revisions
            .push(revision("local", "fast2flow", did, rid, lock_ref.clone()));

        let cfg = materialize_runtime_config(&env);
        assert_eq!(cfg.revisions.len(), 1);
        assert_eq!(cfg.revisions[0].pack_list_refs, vec![lock_ref]);
        // pack-config refs stay empty when the revision carried no inputs.
        assert!(cfg.revisions[0].pack_config_refs.is_empty());
    }

    #[test]
    fn split_entry_surfaces_revision_pack_config_refs() {
        // A revision staged from a bundle that carried `pack-config-input.v1`
        // files (C7) records env-relative paths on `pack_config_refs`. The
        // materializer must surface them in the runtime-config block so
        // `greentic-start` can resolve them through the C4 channel.
        let did = DeploymentId::new();
        let rid = RevisionId::new();
        let lock_ref = PathBuf::from(format!("revisions/{rid}/pack-list.lock"));
        let cfg_refs = vec![
            PathBuf::from(format!("revisions/{rid}/pack-configs/alpha.pack.json")),
            PathBuf::from(format!("revisions/{rid}/pack-configs/beta.pack.json")),
        ];
        let mut env = env(
            "local",
            vec![split("local", "fast2flow", did, vec![(rid, 10_000)])],
        );
        let mut rev = revision("local", "fast2flow", did, rid, lock_ref.clone());
        rev.pack_config_refs = cfg_refs.clone();
        env.revisions.push(rev);

        let cfg = materialize_runtime_config(&env);
        assert_eq!(cfg.revisions.len(), 1);
        assert_eq!(cfg.revisions[0].pack_list_refs, vec![lock_ref]);
        assert_eq!(cfg.revisions[0].pack_config_refs, cfg_refs);
    }

    #[test]
    fn split_entry_without_matching_revision_emits_no_refs() {
        // The split routes a revision id with no matching `Revision` (e.g. one
        // not yet staged on this host). The block is still projected — weights
        // must stay intact for B0's 10,000-bps invariant — but with no
        // pack_list_refs, which B0 treats as nothing-to-file-check.
        let did = DeploymentId::new();
        let rid = RevisionId::new();
        let env = env(
            "local",
            vec![split("local", "fast2flow", did, vec![(rid, 10_000)])],
        );

        let cfg = materialize_runtime_config(&env);
        assert_eq!(cfg.revisions.len(), 1);
        assert_eq!(cfg.revisions[0].weight_bps, 10_000);
        assert!(cfg.revisions[0].pack_list_refs.is_empty());
    }

    #[test]
    fn revision_with_empty_lock_ref_emits_no_refs() {
        // A legacy/empty `pack_list_lock_ref` must not surface as a ref — B0
        // would reject (or fail to resolve) an empty path. The join filters it.
        let did = DeploymentId::new();
        let rid = RevisionId::new();
        let mut env = env(
            "local",
            vec![split("local", "fast2flow", did, vec![(rid, 10_000)])],
        );
        env.revisions
            .push(revision("local", "fast2flow", did, rid, PathBuf::new()));

        let cfg = materialize_runtime_config(&env);
        assert_eq!(cfg.revisions.len(), 1);
        assert!(cfg.revisions[0].pack_list_refs.is_empty());
    }
}
