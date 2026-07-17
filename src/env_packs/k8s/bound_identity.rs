//! Resolve the deployer's bound ServiceAccount bearer for live K8s verbs,
//! with the in-cluster identity Secret as a last-resort source.
//!
//! [`crate::cli::secrets::resolve_credentials_token`] is the backend-agnostic
//! base: env-var → dev-store → fail-closed. This wrapper layers the
//! K8s-Secret source ON TOP, consulted ONLY when the base resolver fails
//! closed (a `credentials_ref` is bound but no local material is present) —
//! e.g. on a fresh operator machine that did not run `--bind` but has ambient
//! cluster read access. Keeping the cluster read here leaves `cli::secrets`
//! free of any Kubernetes coupling.
//!
//! Resolution precedence end-to-end: env-var → dev-store (the bootstrapping
//! machine's cache) → in-cluster Secret (ambient read) → fail closed.

use greentic_deploy_spec::{EnvId, Environment};
use serde_json::Value;

use crate::cli::OpError;
use crate::environment::LocalFsStore;

/// Resolve `env.credentials_ref` to a bearer for a live K8s verb. On a local
/// miss (the base resolver's fail-closed `Conflict`), connect ambiently and
/// read the bound identity's durable in-cluster Secret before giving up.
#[cfg(feature = "k8s-client")]
pub fn resolve_bound_identity(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    answers: Option<&Value>,
) -> Result<Option<String>, OpError> {
    match crate::cli::secrets::resolve_credentials_token(store, env, env_id) {
        // Resolved locally (env-var / dev-store) or no ref bound → done.
        Ok(found) => Ok(found),
        // A ref is bound but no local material was found. Try the durable
        // in-cluster Secret (ambient read) before failing closed.
        Err(OpError::Conflict(local_err)) => match read_from_cluster(env, env_id, answers) {
            Ok(Some(bearer)) => Ok(Some(bearer)),
            // Not in the cluster either → keep the base error (it lists every
            // local source checked) so the operator's fix path is unchanged.
            Ok(None) => Err(OpError::Conflict(local_err)),
            // A real cluster-access failure → surface it. Do NOT silently fall
            // back to the ambient identity, same fail-closed stance as the base
            // resolver: an env that declares a bound credential must never run
            // as the (often broader) ambient identity by accident.
            Err(cluster_err) => Err(OpError::Conflict(format!(
                "{local_err}; and the bound identity could not be read from the \
                 cluster Secret: {cluster_err}"
            ))),
        },
        // Any other error (e.g. a malformed ref) is not a missing-material
        // case — propagate unchanged.
        Err(other) => Err(other),
    }
}

/// Connect ambiently and read the bound bearer from its in-cluster Secret.
/// `Ok(None)` ⇒ the Secret/key is absent; `Err` ⇒ a cluster-access failure.
#[cfg(feature = "k8s-client")]
fn read_from_cluster(
    env: &Environment,
    env_id: &EnvId,
    answers: Option<&Value>,
) -> Result<Option<String>, String> {
    use super::async_bridge::run_k8s_async;
    use super::bootstrap::DEPLOYER_IDENTITY_SECRET_NAME;
    use super::kube_client::read_deployer_identity_bearer;
    use super::manifests::{K8sParams, kubeconfig_context_from_answers, namespace_for_env};

    // Read the SAME namespace `bootstrap --bind` wrote into: the binding's
    // resolved `K8sParams::namespace`, else the env-derived default. Broken
    // answers fall back to the env-derived namespace rather than abort — this
    // read is a best-effort last resort, not the place to surface answer rot.
    let namespace = match K8sParams::from_answers(env, answers) {
        Ok(params) => params.namespace,
        Err(_) => namespace_for_env(env_id),
    };
    let context = kubeconfig_context_from_answers(answers);
    run_k8s_async(read_deployer_identity_bearer(
        context.as_deref(),
        &namespace,
        DEPLOYER_IDENTITY_SECRET_NAME,
        env_id.as_str(),
    ))
    .map_err(|e| e.to_string())
}

/// `k8s-client`-less builds resolve only from the local sources.
#[cfg(not(feature = "k8s-client"))]
pub fn resolve_bound_identity(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    _answers: Option<&Value>,
) -> Result<Option<String>, OpError> {
    crate::cli::secrets::resolve_credentials_token(store, env, env_id)
}

#[cfg(all(test, feature = "k8s-client"))]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use crate::environment::EnvironmentStore;
    use greentic_deploy_spec::SecretRef;
    use tempfile::tempdir;

    #[test]
    fn no_bound_ref_resolves_to_none_without_a_cluster_read() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local"); // no credentials_ref
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        // No ref bound → the base resolver returns `Ok(None)` and the wrapper
        // must short-circuit there: it MUST NOT fall through to a cluster read
        // (an ambient reconcile would otherwise connect twice / error with no
        // kubeconfig). A panic-free `None` here is exactly that contract.
        assert_eq!(
            resolve_bound_identity(&store, &env, &env_id, None).unwrap(),
            None
        );
    }

    #[test]
    fn bound_ref_without_local_material_falls_through_to_cluster() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        // Set a credentials_ref so the base resolver will fail closed with
        // Conflict (ref bound, no material in env-var or dev-store).
        env.credentials_ref =
            Some(SecretRef::try_new("secret://local/credentials/deployer").unwrap());
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        // With no kubeconfig, the cluster read will fail, which surfaces as
        // an error (Conflict with the cluster-access message appended). The
        // important thing is that code ENTERS the Conflict branch, covering
        // the cluster-fallback path.
        let result = resolve_bound_identity(&store, &env, &env_id, None);
        assert!(
            result.is_err(),
            "expected error when ref is bound but no material exists anywhere"
        );
    }

    #[test]
    fn bound_ref_with_explicit_answers_exercises_namespace_resolution() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.credentials_ref =
            Some(SecretRef::try_new("secret://local/credentials/deployer").unwrap());
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        // Pass explicit answers with a custom namespace — exercises the
        // `K8sParams::from_answers` → `Ok(params)` branch and the
        // `kubeconfig_context_from_answers` helper inside `read_from_cluster`.
        let answers = serde_json::json!({ "namespace": "custom-ns" });
        let result = resolve_bound_identity(&store, &env, &env_id, Some(&answers));
        assert!(
            result.is_err(),
            "expected error (no cluster), but the answers path was exercised"
        );
    }

    #[test]
    fn bound_ref_with_invalid_answers_falls_back_to_env_namespace() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.credentials_ref =
            Some(SecretRef::try_new("secret://local/credentials/deployer").unwrap());
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        // A non-object Value makes K8sParams::from_answers return Err(_),
        // so read_from_cluster falls back to namespace_for_env — exercises
        // the `Err(_) => namespace_for_env(env_id)` branch.
        let bad_answers = serde_json::json!("not-an-object");
        let result = resolve_bound_identity(&store, &env, &env_id, Some(&bad_answers));
        assert!(result.is_err());
    }
}
