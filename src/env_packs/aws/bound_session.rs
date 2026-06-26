//! Resolve the AWS deployer's bound STS session for live ECS verbs.
//!
//! The AWS analogue of [`crate::env_packs::k8s::resolve_bound_identity`]:
//! [`crate::cli::secrets::resolve_credentials_token`] is the backend-agnostic
//! base (env-var → dev-store → fail-closed). Where K8s layers an in-cluster
//! Secret read on top, AWS has no such ambient source — the session only ever
//! lives in the local material the `--bind` bootstrap / `rotate` wrote — so this
//! wrapper only adds the decode step: the bound material is a serialized
//! [`AssumedSession`] blob, parsed here into the struct
//! [`RealEcsTarget::resolve`](super::real_target::RealEcsTarget::resolve)
//! injects as a static credentials provider.
//!
//! Precedence: env-var → dev-store → fail closed. A bound ref with no readable
//! (or unparseable) material is an error, never a silent fall-back to the
//! ambient identity — an env that declares a bound credential must not run as
//! the (often broader) ambient identity by accident.

use greentic_deploy_spec::{EnvId, Environment};

use super::credentials::AssumedSession;
use crate::cli::OpError;
use crate::environment::LocalFsStore;

/// Resolve `env.credentials_ref` to the bound STS session for a live AWS-ECS
/// verb.
///
/// - `Ok(None)` — no `credentials_ref` is bound; the caller uses the ambient
///   credential chain (`AWS_PROFILE` / env keys / instance role).
/// - `Ok(Some(session))` — the ref resolved to a parseable session.
/// - `Err(Conflict)` — a ref is bound but the material is missing (from the base
///   resolver) or not a valid session blob.
pub(crate) fn resolve_bound_session(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
) -> Result<Option<AssumedSession>, OpError> {
    match crate::cli::secrets::resolve_credentials_token(store, env, env_id)? {
        None => Ok(None),
        Some(material) => Ok(Some(parse_session_material(env_id, &material)?)),
    }
}

/// Decode the bound credential material into an [`AssumedSession`]. A bound ref
/// whose material is not a session blob is fail-closed (re-bind / rotate), not a
/// silent ambient fall-back.
fn parse_session_material(env_id: &EnvId, material: &str) -> Result<AssumedSession, OpError> {
    serde_json::from_str(material).map_err(|e| {
        OpError::Conflict(format!(
            "environment `{}` has a bound deployer credential, but its material is not a valid \
             AWS assumed-session blob: {e}; re-bind the deployer role \
             (`op env bootstrap --bind`) or refresh it (`op credentials rotate`)",
            env_id.as_str()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use crate::environment::EnvironmentStore;
    use tempfile::tempdir;

    #[test]
    fn no_bound_ref_resolves_to_none() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local"); // no credentials_ref
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        // No ref bound → ambient. MUST be `None`, never a fabricated session.
        assert!(
            resolve_bound_session(&store, &env, &env_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unparseable_material_is_fail_closed() {
        let env_id = EnvId::try_from("local").unwrap();
        let err = parse_session_material(&env_id, "not a session blob").unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(msg.contains("assumed-session blob"), "{msg}"),
            other => panic!("expected Conflict, got {other}"),
        }
    }

    #[test]
    fn valid_material_parses_to_the_session() {
        let env_id = EnvId::try_from("local").unwrap();
        let material = serde_json::json!({
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "shh",
            "session_token": "blob",
            "expiration": "2030-01-01T00:00:00Z",
            "issued_at": "2029-12-31T00:00:00Z",
        })
        .to_string();
        let session = parse_session_material(&env_id, &material).unwrap();
        assert_eq!(session.access_key_id, "AKIAEXAMPLE");
        assert_eq!(session.session_token, "blob");
    }
}
