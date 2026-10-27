//! Wizard answers for the Azure Container Apps binding (pure).

use serde_json::Value;

use super::registry_credential::{self, RegistryCredential};
use crate::env_packs::RUNTIME_IMAGE_REPO;
use crate::env_packs::telemetry::{
    self as telemetry_answers, TelemetryAnswerError, TelemetryAnswers,
};

pub(crate) const DEFAULT_LOCATION: &str = "southeastasia";
const DEFAULT_RUNTIME_IMAGE_TAG: &str = "develop";

#[derive(Debug, thiserror::Error)]
pub enum AcaParamsError {
    #[error("answers must be a JSON object")]
    NotAnObject,
    #[error("answer `{0}` must be a string")]
    NotAString(String),
    #[error("unknown answer key `{0}`")]
    UnknownKey(String),
    #[error("answer `{0}` is required")]
    Missing(&'static str),
    #[error("answer `{key}` is invalid: {detail}")]
    Invalid { key: String, detail: String },
    #[error(transparent)]
    Telemetry(#[from] TelemetryAnswerError),
}

/// Resolved scope for the Azure Container Apps verbs. Credential MATERIAL is never
/// here: the service principal rides the bound credential / environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcaParams {
    pub subscription_id: String,
    pub tenant_id: String,
    pub resource_group: String,
    /// Name of the operator-provided managed environment.
    pub environment_name: String,
    pub location: String,
    pub acr_login_server: Option<String>,
    pub log_analytics_workspace_id: Option<String>,
    /// 0 (scale to zero, default) or 1 (keep warm).
    pub min_instances: u32,
    /// Fixed at 1 (single writer of the per-replica seed).
    pub max_instances: u32,
    pub cpu: Option<String>,
    pub memory: Option<String>,
    pub runtime_image_tag: String,
    pub runtime_image_digest: Option<String>,
    pub runtime_tenant: Option<String>,
    pub runtime_team: Option<String>,
    pub telemetry: TelemetryAnswers,
    pub(crate) registry: Option<RegistryCredential>,
}

fn string(key: &str, v: &Value) -> Result<String, AcaParamsError> {
    v.as_str()
        .map(str::to_string)
        .ok_or_else(|| AcaParamsError::NotAString(key.to_string()))
}

fn optional(key: &str, v: &Value) -> Result<Option<String>, AcaParamsError> {
    let s = string(key, v)?;
    Ok(if s.trim().is_empty() {
        None
    } else {
        Some(s.trim().to_string())
    })
}

fn invalid(key: &str, detail: impl Into<String>) -> AcaParamsError {
    AcaParamsError::Invalid {
        key: key.to_string(),
        detail: detail.into(),
    }
}

fn parse_u32(key: &str, v: &Value) -> Result<u32, AcaParamsError> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).map_err(|_| invalid(key, "out of range"));
    }
    let s = string(key, v)?;
    s.trim()
        .parse()
        .map_err(|_| invalid(key, format!("`{s}` is not a non-negative integer")))
}

fn is_guid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn guid(key: &str, v: &Value) -> Result<String, AcaParamsError> {
    let s = string(key, v)?.trim().to_ascii_lowercase();
    if is_guid(&s) {
        Ok(s)
    } else {
        Err(invalid(key, "must be a GUID"))
    }
}

/// Azure resource names: letters, digits, `-`, `_`, 1..=90 (resource groups also
/// allow `.` and `()` which the deployer deliberately does not).
fn resource_name(key: &str, v: &Value) -> Result<String, AcaParamsError> {
    let s = string(key, v)?.trim().to_string();
    let ok = !s.is_empty()
        && s.len() <= 90
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(s)
    } else {
        Err(invalid(key, "must be 1-90 characters of [A-Za-z0-9_-]"))
    }
}

fn digest(key: &str, v: &Value) -> Result<Option<String>, AcaParamsError> {
    let Some(d) = optional(key, v)? else {
        return Ok(None);
    };
    let ok = d.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    });
    if ok {
        Ok(Some(d))
    } else {
        Err(invalid(key, "is not a `sha256:<64 hex>` digest"))
    }
}

fn host(key: &str, v: &Value) -> Result<Option<String>, AcaParamsError> {
    let Some(h) = optional(key, v)? else {
        return Ok(None);
    };
    let ok = h.len() <= 253
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && h.contains('.');
    if ok {
        Ok(Some(h.to_ascii_lowercase()))
    } else {
        Err(invalid(
            key,
            "must be a registry host name, e.g. `myacr.azurecr.io`",
        ))
    }
}

impl AcaParams {
    /// Parse the binding answers. Fail closed: the four scope answers are
    /// required, unknown keys (including AWS / GCP ones) are refused.
    pub fn from_answers(answers: Option<&Value>) -> Result<Self, AcaParamsError> {
        let obj = answers
            .ok_or(AcaParamsError::Missing("subscription_id"))?
            .as_object()
            .ok_or(AcaParamsError::NotAnObject)?;
        let (mut sub, mut tenant, mut rg, mut envn) = (None, None, None, None);
        let mut p = Self {
            subscription_id: String::new(),
            tenant_id: String::new(),
            resource_group: String::new(),
            environment_name: String::new(),
            location: DEFAULT_LOCATION.to_string(),
            acr_login_server: None,
            log_analytics_workspace_id: None,
            min_instances: 0,
            max_instances: 1,
            cpu: None,
            memory: None,
            runtime_image_tag: DEFAULT_RUNTIME_IMAGE_TAG.to_string(),
            runtime_image_digest: None,
            runtime_tenant: None,
            runtime_team: None,
            telemetry: TelemetryAnswers::default(),
            registry: None,
        };
        let (mut t_env, mut t_headers, mut user, mut pass) = (None, None, None, None);
        for (key, value) in obj {
            match key.as_str() {
                "subscription_id" => sub = Some(guid(key, value)?),
                "tenant_id" => tenant = Some(guid(key, value)?),
                "resource_group" => rg = Some(resource_name(key, value)?),
                "environment_name" => envn = Some(resource_name(key, value)?),
                "location" => {
                    if let Some(l) = optional(key, value)? {
                        let ok = l
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
                        if !ok {
                            return Err(invalid(
                                key,
                                "must be an Azure location name like `southeastasia`",
                            ));
                        }
                        p.location = l;
                    }
                }
                "acr_login_server" => p.acr_login_server = host(key, value)?,
                "log_analytics_workspace_id" => {
                    p.log_analytics_workspace_id = optional(key, value)?
                }
                "min_instances" => {
                    p.min_instances = parse_u32(key, value)?;
                    if p.min_instances > 1 {
                        return Err(invalid(key, "must be 0 (scale to zero) or 1 (keep warm)"));
                    }
                }
                "max_instances" => {
                    p.max_instances = parse_u32(key, value)?;
                    if p.max_instances != 1 {
                        return Err(invalid(
                            key,
                            "must be 1 (the per-replica seed has a single writer)",
                        ));
                    }
                }
                "cpu" => p.cpu = optional(key, value)?,
                "memory" => p.memory = optional(key, value)?,
                "runtime_image_tag" => p.runtime_image_tag = string(key, value)?,
                "runtime_image_digest" => p.runtime_image_digest = digest(key, value)?,
                "runtime_tenant" => p.runtime_tenant = optional(key, value)?,
                "runtime_team" => p.runtime_team = optional(key, value)?,
                registry_credential::USERNAME_KEY => user = Some(value),
                registry_credential::PASSWORD_KEY => pass = Some(value),
                telemetry_answers::TELEMETRY_ENV_KEY => t_env = Some(value),
                telemetry_answers::TELEMETRY_HEADERS_KEY => t_headers = Some(value),
                other => return Err(AcaParamsError::UnknownKey(other.to_string())),
            }
        }
        p.subscription_id = sub.ok_or(AcaParamsError::Missing("subscription_id"))?;
        p.tenant_id = tenant.ok_or(AcaParamsError::Missing("tenant_id"))?;
        p.resource_group = rg.ok_or(AcaParamsError::Missing("resource_group"))?;
        p.environment_name = envn.ok_or(AcaParamsError::Missing("environment_name"))?;
        p.telemetry = telemetry_answers::parse(t_env, t_headers)?;
        p.registry = registry_credential::parse(user, pass)?;
        Ok(p)
    }

    /// Public runtime image: a revision's own `pin` wins over the binding digest,
    /// which wins over the tag.
    pub fn runtime_image_for(&self, pin: Option<&str>) -> String {
        match pin.or(self.runtime_image_digest.as_deref()) {
            Some(d) => format!("{RUNTIME_IMAGE_REPO}@{d}"),
            None => format!("{RUNTIME_IMAGE_REPO}:{}", self.runtime_image_tag),
        }
    }

    /// ARM resource id of the operator's managed environment.
    pub fn managed_environment_id(&self) -> String {
        format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.App/managedEnvironments/{}",
            self.subscription_id, self.resource_group, self.environment_name
        )
    }
}

#[cfg(test)]
#[path = "params_tests.rs"]
mod tests;
