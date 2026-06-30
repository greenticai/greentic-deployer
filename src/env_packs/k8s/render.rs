//! [`ManifestRenderer`] impl — the declarative half of `gtc op env render`.
//!
//! Composes the pure renderers in [`manifests`]: the environment-level set
//! (Namespace, runtime ConfigMap, router, NetworkPolicies) followed by the
//! worker pair for every revision with cluster presence. The output matches
//! what the [`Deployer`](crate::env_packs::deployer::Deployer) verbs apply
//! — same functions, same params — so a rendered-manifest or GitOps
//! handoff converges to the same state as direct apply (plan §6 step 10).
//!
//! When the binding records wizard answers (`answers_ref`), the renderer
//! feeds them to [`K8sParams::from_answers`] so operator overrides (custom
//! namespace, digest-pinned image, replica count) propagate into the
//! rendered manifests. When no answers are recorded, sandbox defaults
//! apply (`K8sParams::for_env`).

use greentic_deploy_spec::Environment;
use serde_json::Value;

use super::K8sDeployerHandler;
use super::manifests::{self, K8sParams, has_cluster_presence};
use crate::env_packs::render::{ManifestRenderer, RenderError};

impl ManifestRenderer for K8sDeployerHandler {
    fn render_environment(
        &self,
        env: &Environment,
        answers: Option<&serde_json::Value>,
    ) -> Result<Vec<Value>, RenderError> {
        let mut params =
            K8sParams::from_answers(env, answers).map_err(RenderError::InvalidAnswers)?;
        // The reconcile call site owns the filesystem read; inject the dev-store
        // bytes it captured so the env-level Secret carries the operator's
        // secrets. `None` on the preview path → an empty Secret.
        params.dev_secrets_data = self.dev_secrets_data.clone();
        // The CLI resolves the env's `Secrets`-slot binding into a backend and
        // injects it; render/reconcile both set it, so the rendered worker
        // identity (dev-store Secret vs. Vault SA) matches the env's binding.
        params.secrets_backend = self.secrets_backend.clone();
        let mut objects = manifests::render_environment_manifests(env, &params);
        for revision in &env.revisions {
            if has_cluster_presence(revision.lifecycle) {
                objects.extend(manifests::render_worker_manifests(env, revision, &params));
            }
        }
        Ok(objects)
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
        let objects = handler.render_environment(&env, None).unwrap();

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
    fn render_environment_is_deterministic() {
        let env = build_fixture_env();
        let handler = K8sDeployerHandler::default();
        assert_eq!(
            handler.render_environment(&env, None).unwrap(),
            handler.render_environment(&env, None).unwrap()
        );
    }

    #[test]
    fn invalid_answers_surface_render_error() {
        let env = build_fixture_env();
        let handler = K8sDeployerHandler::default();
        // Non-object answers must be rejected.
        let bad = serde_json::json!("not an object");
        let err = handler.render_environment(&env, Some(&bad)).unwrap_err();
        assert!(
            matches!(err, RenderError::InvalidAnswers(_)),
            "expected InvalidAnswers, got {err:?}"
        );
    }
}
