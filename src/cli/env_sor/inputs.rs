//! Reading a SoR unit's inputs out of the env's dev store at reconcile time,
//! and the preflight refusals that must happen before any cluster call.

use greentic_deploy_spec::Environment;
use serde_json::Value;

use crate::cli::OpError;
use crate::cli::secrets::{DEV_SECRETS_PATH_ENV, DEV_STORE_KIND_PATH, get_env_secret};
use crate::env_packs::k8s::manifests::SecretsBackend;
use crate::env_packs::k8s::manifests::sor::SorUnitInputs;
use crate::env_packs::k8s::sor_reconcile::SorUnitRender;
use crate::environment::LocalFsStore;
use crate::environment::sor_units::SorUnit;
use crate::runtime_secrets::SecretValue;

/// Amendment 6: the route documents and the SoR inputs live in the dev store.
pub(crate) fn require_dev_store_backend(backend: &SecretsBackend) -> Result<(), OpError> {
    match backend {
        SecretsBackend::DevStore => Ok(()),
        SecretsBackend::Vault(_) => Err(OpError::Conflict(
            "this environment declares SoR units, which need the dev-store secrets backend in \
             this release; its secrets pack is Vault"
                .to_string(),
        )),
    }
}

/// `read_dev_secrets_bytes` ships the env-dir store and ignores
/// `GREENTIC_DEV_SECRETS_PATH`, while the store writer honours it — a route
/// document written under the override would never reach a worker.
pub(crate) fn refuse_dev_secrets_path_override(
    value: Option<std::ffi::OsString>,
) -> Result<(), OpError> {
    match value {
        Some(v) if !v.is_empty() => Err(OpError::Conflict(format!(
            "{DEV_SECRETS_PATH_ENV} is set; SoR route documents must be written to the env \
             dir's own dev store, which is the one reconcile ships — unset it and re-run"
        ))),
        _ => Ok(()),
    }
}

/// Read every declared unit's inputs from the env's dev store, refusing a
/// missing input or answers whose tenant is not the unit's. No error names a
/// value: only the unit, the ref field and its store path.
pub(crate) fn resolve_sor_inputs(
    store: &LocalFsStore,
    env: &Environment,
    units: &[SorUnit],
) -> Result<Vec<SorUnitRender>, OpError> {
    units
        .iter()
        .map(|unit| {
            let read = |field: &str, rel: &str| read_required(store, env, unit, field, rel);
            let answers = read("answers_ref", &unit.answers_ref)?;
            check_answers_tenant(unit, &answers)?;
            let inputs = SorUnitInputs {
                answers,
                postgres_url: read("postgres_url_ref", &unit.postgres_url_ref)?,
                postgres_ca: unit
                    .postgres_ca_ref
                    .as_deref()
                    .map(|rel| read("postgres_ca_ref", rel))
                    .transpose()?,
                shared_secret: read("shared_secret_ref", &unit.shared_secret_ref)?,
            };
            Ok(SorUnitRender {
                unit: unit.clone(),
                inputs,
            })
        })
        .collect()
}

fn read_required(
    store: &LocalFsStore,
    env: &Environment,
    unit: &SorUnit,
    field: &str,
    rel: &str,
) -> Result<SecretValue, OpError> {
    let (value, _uri, _extra) =
        get_env_secret(store, env, &env.environment_id, DEV_STORE_KIND_PATH, rel)?;
    match value {
        Some(v) if !v.is_empty() => Ok(SecretValue::from(v)),
        _ => Err(OpError::Conflict(format!(
            "SoR unit `{}`: {field} names `{rel}`, which holds no value in environment `{}`; \
             stage it with `op secrets put` before reconciling",
            unit.unit_id,
            env.environment_id.as_str()
        ))),
    }
}

/// Amendment 2: sorx labels every event with the answers' tenant and never
/// compares it with the route document's, so a mismatch must stop here.
/// Accepts the raw answers object or a `{"answers": {…}}` envelope.
fn check_answers_tenant(unit: &SorUnit, answers: &SecretValue) -> Result<(), OpError> {
    let refuse = |what: String| {
        OpError::Conflict(format!(
            "SoR unit `{}`: its answers ({}) {what}; they must set `tenant.tenant_id` to \
             `{}`, the unit's tenant_id",
            unit.unit_id, unit.answers_ref, unit.tenant_id
        ))
    };
    let parsed: Value = serde_json::from_str(answers.expose())
        .ok()
        .filter(Value::is_object)
        .ok_or_else(|| refuse("is not a JSON object".to_string()))?;
    let root = parsed
        .get("answers")
        .filter(|a| a.is_object())
        .unwrap_or(&parsed);
    match root.pointer("/tenant/tenant_id").and_then(Value::as_str) {
        Some(t) if t == unit.tenant_id => Ok(()),
        Some(other) => Err(refuse(format!("set tenant `{other}`"))),
        None => Err(refuse("carry no `tenant.tenant_id`".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::secrets::put_env_secret;
    use crate::cli::tests_common::{make_binding, make_env};
    use crate::environment::{EnvironmentStore as _, LocalFsStore};
    use greentic_deploy_spec::CapabilitySlot;

    fn unit() -> SorUnit {
        crate::env_packs::k8s::manifests::sor::tests::unit()
    }

    fn seeded(values: &[(&str, &str)]) -> (tempfile::TempDir, LocalFsStore, Environment) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        store.save(&env).unwrap();
        for (rel, value) in values {
            put_env_secret(
                &store,
                &env,
                &env.environment_id,
                DEV_STORE_KIND_PATH,
                rel,
                value,
            )
            .unwrap();
        }
        (dir, store, env)
    }

    const ANSWERS: &str = r#"{"server":{"bind":"0.0.0.0:8787"},"tenant":{"tenant_id":"acme"}}"#;

    fn all_inputs() -> Vec<(&'static str, &'static str)> {
        vec![
            ("default/_/sor-landlord/answers", ANSWERS),
            (
                "default/_/sor-landlord/postgres_url",
                "postgres://u:pw-SECRET@db/sor",
            ),
            (
                "default/_/sor-landlord/shared_secret",
                "shared-SECRET-token",
            ),
        ]
    }

    #[test]
    fn every_input_is_read_from_the_env_store() {
        let (_d, store, env) = seeded(&all_inputs());
        let renders = resolve_sor_inputs(&store, &env, &[unit()]).unwrap();
        assert_eq!(renders[0].inputs.answers.expose(), ANSWERS);
        assert_eq!(
            renders[0].inputs.postgres_url.expose(),
            "postgres://u:pw-SECRET@db/sor"
        );
        assert_eq!(
            renders[0].inputs.shared_secret.expose(),
            "shared-SECRET-token"
        );
        assert!(renders[0].inputs.postgres_ca.is_none());
    }

    #[test]
    fn a_declared_postgres_ca_is_read_and_a_missing_one_is_refused_by_its_ref() {
        let mut with_ca = unit();
        with_ca.postgres_ca_ref = Some("default/_/sor-landlord/postgres_ca".into());

        let mut values = all_inputs();
        values.push((
            "default/_/sor-landlord/postgres_ca",
            "-----BEGIN CA-SECRET-----",
        ));
        let (_d, store, env) = seeded(&values);
        let renders = resolve_sor_inputs(&store, &env, std::slice::from_ref(&with_ca)).unwrap();
        assert_eq!(
            renders[0]
                .inputs
                .postgres_ca
                .as_ref()
                .map(SecretValue::expose),
            Some("-----BEGIN CA-SECRET-----")
        );

        let (_d2, store, env) = seeded(&all_inputs());
        let msg = resolve_sor_inputs(&store, &env, std::slice::from_ref(&with_ca))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("postgres_ca_ref"), "{msg}");
        assert!(msg.contains("default/_/sor-landlord/postgres_ca"), "{msg}");
        assert!(
            !msg.contains("CA-SECRET") && !msg.contains("pw-SECRET"),
            "{msg}"
        );
    }

    #[test]
    fn a_missing_input_names_the_unit_and_the_ref_never_a_value() {
        let (_d, store, env) = seeded(&all_inputs()[..2]);
        let msg = resolve_sor_inputs(&store, &env, &[unit()])
            .unwrap_err()
            .to_string();
        assert!(msg.contains("SoR unit `landlord`"), "{msg}");
        assert!(msg.contains("shared_secret_ref"), "{msg}");
        assert!(
            msg.contains("default/_/sor-landlord/shared_secret"),
            "{msg}"
        );
        assert!(msg.contains("op secrets put"), "{msg}");
        assert!(!msg.contains("pw-SECRET"));
    }

    #[test]
    fn answers_without_the_unit_tenant_are_refused() {
        for (answers, shown) in [
            (
                r#"{"server":{"bind":"0.0.0.0:8787"}}"#,
                "no `tenant.tenant_id`",
            ),
            (r#"{"tenant":{"tenant_id":"other"}}"#, "`other`"),
            ("not json at all SECRET-ish", "is not a JSON object"),
        ] {
            let mut values = all_inputs();
            values[0].1 = answers;
            let (_d, store, env) = seeded(&values);
            let msg = resolve_sor_inputs(&store, &env, &[unit()])
                .unwrap_err()
                .to_string();
            assert!(
                msg.contains("SoR unit `landlord`") && msg.contains("`acme`"),
                "{msg}"
            );
            assert!(msg.contains(shown), "{msg}");
            assert!(
                !msg.contains("SECRET-ish") && !msg.contains("0.0.0.0:8787"),
                "never echo the answers: {msg}"
            );
        }
    }

    #[test]
    fn answers_in_a_qa_envelope_are_accepted() {
        let mut values = all_inputs();
        values[0].1 =
            r#"{"form_id":"greentic.sorx.start","answers":{"tenant":{"tenant_id":"acme"}}}"#;
        let (_d, store, env) = seeded(&values);
        resolve_sor_inputs(&store, &env, &[unit()]).expect("envelope form");
    }

    #[test]
    fn a_vault_backend_and_a_dev_secrets_path_override_are_refused() {
        use crate::env_packs::k8s::manifests::SecretsBackend;
        require_dev_store_backend(&SecretsBackend::DevStore).unwrap();
        let vault = SecretsBackend::Vault(crate::env_packs::k8s::manifests::VaultBackend {
            addr: "http://vault.vault.svc:8200".to_string(),
            k8s_role: "greentic-worker".to_string(),
            kv_mount: "secret".to_string(),
            kv_prefix: "greentic".to_string(),
            auth_mount: "kubernetes".to_string(),
            transit_mount: "transit".to_string(),
            transit_key: "greentic".to_string(),
            namespace: None,
        });
        assert!(
            require_dev_store_backend(&vault)
                .unwrap_err()
                .to_string()
                .contains("dev-store")
        );
        refuse_dev_secrets_path_override(None).unwrap();
        let msg = refuse_dev_secrets_path_override(Some("/elsewhere".into()))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("GREENTIC_DEV_SECRETS_PATH"), "{msg}");
    }
}
