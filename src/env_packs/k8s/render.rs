//! [`ManifestRenderer`] impl — the declarative half of `gtc op env render`.
//!
//! Composes the pure renderers in [`manifests`]: the environment-level set
//! (Namespace, runtime ConfigMap, router, NetworkPolicies) followed by the
//! worker pair for every revision with cluster presence. The output matches
//! what the [`Deployer`](crate::env_packs::deployer::Deployer) verbs apply
//! — same functions, same params — so a rendered-manifest or GitOps
//! handoff converges to the same state as direct apply (plan §6 step 10).

use greentic_deploy_spec::{Environment, RevisionLifecycle};
use serde_json::Value;

use super::K8sDeployerHandler;
use super::manifests::{self, K8sParams};
use crate::env_packs::render::ManifestRenderer;

/// Whether a revision's persisted lifecycle puts its worker objects in the
/// cluster's desired state.
///
/// `warm_revision` applies the worker pair (`Staged → Warming → Ready`)
/// and the objects stay up through `Draining` — drain is routing-side,
/// teardown happens at `archive_revision` (the B7 two-state model). So:
///
/// - `Warming` / `Ready` / `Draining` → present.
/// - `Inactive` → absent. A post-drain revision's objects may still exist
///   transiently until the operator archives it, but it is pending
///   teardown, not desired.
/// - `Staged` / `Failed` / `Archived` → absent (never applied, or torn
///   down).
fn has_cluster_presence(lifecycle: RevisionLifecycle) -> bool {
    matches!(
        lifecycle,
        RevisionLifecycle::Warming | RevisionLifecycle::Ready | RevisionLifecycle::Draining
    )
}

impl ManifestRenderer for K8sDeployerHandler {
    fn render_environment(&self, env: &Environment) -> Vec<Value> {
        let params = K8sParams::for_env(env);
        let mut objects = manifests::render_environment_manifests(env, &params);
        for revision in &env.revisions {
            if has_cluster_presence(revision.lifecycle) {
                objects.extend(manifests::render_worker_manifests(env, revision, &params));
            }
        }
        objects
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::EnvPackHandler;
    use crate::env_packs::deployer::conformance::build_fixture_env;

    fn rendered_names(objects: &[Value]) -> Vec<String> {
        objects
            .iter()
            .map(|o| {
                o.pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .expect("every rendered object has metadata.name")
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn handler_exposes_manifest_renderer() {
        let h = K8sDeployerHandler::default();
        assert!(
            (&h as &dyn EnvPackHandler).as_manifest_renderer().is_some(),
            "EnvPackHandler::as_manifest_renderer must surface the K8s renderer"
        );
    }

    #[test]
    fn renders_env_level_set_then_present_revision_workers() {
        // Fixture: two Ready revisions + one Inactive (conformance env).
        let env = build_fixture_env();
        let params = K8sParams::for_env(&env);
        let env_level = manifests::render_environment_manifests(&env, &params);

        let handler = K8sDeployerHandler::default();
        let objects = handler.render_environment(&env);

        assert_eq!(
            &objects[..env_level.len()],
            &env_level[..],
            "env-level objects come first, unchanged from the apply path"
        );
        // Worker pair (Deployment + Service) per present revision only.
        assert_eq!(objects.len(), env_level.len() + 2 * 2);
        let names = rendered_names(&objects);
        for revision in &env.revisions {
            let worker = manifests::worker_name(revision);
            let expected = has_cluster_presence(revision.lifecycle);
            assert_eq!(
                names.iter().filter(|n| **n == worker).count() == 2,
                expected,
                "revision `{}` ({:?}) presence mismatch",
                revision.revision_id,
                revision.lifecycle
            );
        }
    }

    #[test]
    fn presence_policy_matches_the_b7_two_state_model() {
        use RevisionLifecycle::*;
        for (lifecycle, present) in [
            (Inactive, false),
            (Staged, false),
            (Warming, true),
            (Ready, true),
            (Draining, true),
            (Failed, false),
            (Archived, false),
        ] {
            assert_eq!(
                has_cluster_presence(lifecycle),
                present,
                "{lifecycle:?} presence policy drifted"
            );
        }
    }

    #[test]
    fn render_environment_is_deterministic() {
        let env = build_fixture_env();
        let handler = K8sDeployerHandler::default();
        assert_eq!(
            handler.render_environment(&env),
            handler.render_environment(&env)
        );
    }
}
