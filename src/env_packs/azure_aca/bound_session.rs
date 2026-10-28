//! Service-principal material for the live verbs.
//!
//! Precedence: a bound `credentials_ref` (JSON with `tenant_id`, `client_id`,
//! `client_secret`, `subscription_id`) via the shared resolver, else the
//! `AZURE_*` variables, else a hard error. A bound ref that cannot be read or
//! parsed NEVER falls back to the ambient variables.

use greentic_deploy_spec::{EnvId, Environment};
use serde_json::Value;

use super::token::ClientCredentials;
use crate::cli::OpError;
use crate::environment::LocalFsStore;

pub(crate) const ENV_TENANT: &str = "AZURE_TENANT_ID";
pub(crate) const ENV_CLIENT: &str = "AZURE_CLIENT_ID";
pub(crate) const ENV_SECRET: &str = "AZURE_CLIENT_SECRET";
pub(crate) const ENV_SUBSCRIPTION: &str = "AZURE_SUBSCRIPTION_ID";

pub(crate) fn parse_material(env_id: &EnvId, material: &str) -> Result<ClientCredentials, OpError> {
    let bad = |what: &str| {
        OpError::Conflict(format!(
            "environment `{}` has a bound deployer credential, but {what}; expected JSON with \
             `tenant_id`, `client_id`, `client_secret`; re-bind it with `op credentials rotate`",
            env_id.as_str()
        ))
    };
    let v: Value = serde_json::from_str(material).map_err(|_| bad("it is not valid JSON"))?;
    let field = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| bad(&format!("`{k}` is missing")))
    };
    Ok(ClientCredentials::new(
        field("tenant_id")?,
        field("client_id")?,
        field("client_secret")?,
        v.get("subscription_id")
            .and_then(Value::as_str)
            .map(str::to_string),
    ))
}

/// Read the credentials from an environment-variable lookup (injectable for tests).
pub(crate) fn from_lookup(
    get: impl Fn(&str) -> Option<String>,
) -> Result<ClientCredentials, String> {
    let need = |k: &str| {
        get(k)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| format!("`{k}` is not set"))
    };
    Ok(ClientCredentials::new(
        need(ENV_TENANT)?,
        need(ENV_CLIENT)?,
        need(ENV_SECRET)?,
        get(ENV_SUBSCRIPTION),
    ))
}

pub(crate) fn from_process_env() -> Result<ClientCredentials, String> {
    from_lookup(|k| std::env::var(k).ok())
}

/// `Ok(creds)` from the bound ref, else from the process environment.
pub(crate) fn resolve(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
) -> Result<(&'static str, ClientCredentials), OpError> {
    match crate::cli::secrets::resolve_credentials_token(store, env, env_id)? {
        Some(material) => Ok(("bound", parse_material(env_id, &material)?)),
        None => from_process_env()
            .map(|c| ("ambient", c))
            .map_err(|e| {
                OpError::Conflict(format!(
                    "no Azure credential: the environment has no bound deployer credential and {e}. \
                     Bind the service principal with `op credentials rotate` or set AZURE_TENANT_ID, \
                     AZURE_CLIENT_ID and AZURE_CLIENT_SECRET"
                ))
            }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    #[test]
    fn material_parses_and_fails_closed_without_echoing_the_secret() {
        let ok =
            r#"{"tenant_id":"t","client_id":"c","client_secret":"hunter2","subscription_id":"s"}"#;
        assert_eq!(parse_material(&id(), ok).unwrap().client_id, "c");
        for bad in [
            "nope",
            r#"{"tenant_id":"t","client_id":"c"}"#,
            r#"{"tenant_id":"t","client_id":"c","client_secret":" "}"#,
        ] {
            let e = parse_material(&id(), bad).unwrap_err().to_string();
            assert!(e.contains("rotate") && !e.contains("hunter2"), "{e}");
        }
    }

    #[test]
    fn the_environment_lookup_requires_all_three_variables() {
        let mut m: HashMap<&str, String> = HashMap::new();
        let get = |m: &HashMap<&str, String>| from_lookup(|k| m.get(k).cloned());
        assert!(get(&m).unwrap_err().contains("AZURE_TENANT_ID"));
        m.insert(ENV_TENANT, "t".into());
        m.insert(ENV_CLIENT, "c".into());
        assert!(get(&m).unwrap_err().contains("AZURE_CLIENT_SECRET"));
        m.insert(ENV_SECRET, "s".into());
        assert!(get(&m).is_ok());
    }
}
