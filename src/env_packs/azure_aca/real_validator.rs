//! ARM-backed [`AzureValidatorClient`]: read the managed environment and the
//! identity's effective permissions at the resource-group scope.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::arm_http::{ArmRequest, AzureHttp, Method};
use super::arm_paths::AzureScope;
use super::bound_session::from_process_env;
use super::credentials::AzureValidatorClient;
use super::rbac::Permission;
use super::reqwest_http::ReqwestHttp;

pub(crate) const ENV_RESOURCE_GROUP: &str = "AZURE_RESOURCE_GROUP";
pub(crate) const ENV_ACA_ENVIRONMENT: &str = "AZURE_ACA_ENVIRONMENT";

#[derive(Debug)]
pub(crate) struct RealAzureValidator {
    http: Arc<dyn AzureHttp>,
    scope: AzureScope,
}

impl RealAzureValidator {
    pub(crate) fn new(http: Arc<dyn AzureHttp>, scope: AzureScope) -> Self {
        Self { http, scope }
    }
}

pub(crate) fn from_env() -> Result<RealAzureValidator, String> {
    let creds = from_process_env()?;
    let get = |k: &str| {
        std::env::var(k)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| format!("`{k}` is not set"))
    };
    let subscription = match &creds.subscription_id {
        Some(s) => s.clone(),
        None => get(super::bound_session::ENV_SUBSCRIPTION)?,
    };
    let scope = AzureScope {
        subscription,
        resource_group: get(ENV_RESOURCE_GROUP)?,
        environment: get(ENV_ACA_ENVIRONMENT)?,
    };
    let http = ReqwestHttp::new(creds).map_err(|e| e.to_string())?;
    Ok(RealAzureValidator::new(Arc::new(http), scope))
}

pub(crate) fn parse_permissions(body: &Value) -> Vec<Permission> {
    let list = |p: &Value, k: &str| {
        p.get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    body.get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|p| Permission {
            actions: list(p, "actions"),
            not_actions: list(p, "notActions"),
        })
        .collect()
}

#[async_trait]
impl AzureValidatorClient for RealAzureValidator {
    async fn check_environment(&self) -> Result<(), String> {
        let resp = self
            .http
            .send(ArmRequest::new(Method::Get, self.scope.environment()))
            .await
            .map_err(|e| e.to_string())?;
        match resp.status {
            200 => Ok(()),
            404 => Err("the managed environment does not exist in that resource group".to_string()),
            s => Err(format!("reading the managed environment answered {s}")),
        }
    }

    async fn effective_permissions(&self) -> Result<Vec<Permission>, String> {
        let resp = self
            .http
            .send(ArmRequest::new(Method::Get, self.scope.permissions()))
            .await
            .map_err(|e| e.to_string())?;
        if resp.status != 200 {
            return Err(format!("reading permissions answered {}", resp.status));
        }
        resp.json()
            .map(|b| parse_permissions(&b))
            .ok_or_else(|| "permissions answer was unreadable".to_string())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::env_packs::azure_aca::arm_http::{ArmResponse, fake::FakeHttp};

    fn scope() -> AzureScope {
        AzureScope {
            subscription: "s".into(),
            resource_group: "rg".into(),
            environment: "e".into(),
        }
    }

    #[tokio::test]
    async fn permissions_are_parsed_from_the_authorization_answer() {
        let body = json!({"value": [{"actions": ["Microsoft.App/*"], "notActions": ["Microsoft.App/containerApps/delete"]}]});
        let http = Arc::new(FakeHttp::with(vec![ArmResponse::new(
            200,
            &body.to_string(),
        )]));
        let p = RealAzureValidator::new(http.clone(), scope())
            .effective_permissions()
            .await
            .unwrap();
        assert_eq!(p[0].actions, ["Microsoft.App/*"]);
        assert_eq!(p[0].not_actions.len(), 1);
        assert!(
            http.seen()[0]
                .url
                .contains("Microsoft.Authorization/permissions")
        );
    }

    #[tokio::test]
    async fn the_environment_probe_names_a_missing_environment() {
        let http = Arc::new(FakeHttp::with(vec![ArmResponse::new(404, "{}")]));
        let e = RealAzureValidator::new(http, scope())
            .check_environment()
            .await
            .unwrap_err();
        assert!(e.contains("does not exist"), "{e}");
    }
}
