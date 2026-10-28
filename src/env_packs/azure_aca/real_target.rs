//! [`AcaDeployTarget`] over ARM REST. Every call goes through the [`AzureHttp`]
//! seam, so tests replay JSON; nothing here was run against Azure.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::arm_body::{container_app_body, traffic_patch_body};
use super::arm_http::{ArmRequest, ArmResponse, AzureHttp, Method};
use super::arm_paths::AzureScope;
use super::arm_types::{AppSecret, AppSpec, TrafficEntry};
use super::deploy_target::{
    AcaDeployTarget, AcaTargetError, AppRef, AppState, RevisionRef, RevisionStatus,
};
use super::lro::{self, LroError, Policy};
use super::naming::revision_name;
use super::revision_intent::LiveIntent;
use super::status;

#[derive(Debug)]
pub(crate) struct RealAcaTarget {
    http: Arc<dyn AzureHttp>,
    scope: AzureScope,
    policy: Policy,
}

fn api_error(resp: &ArmResponse) -> AcaTargetError {
    let body = resp.json();
    let code = body
        .as_ref()
        .and_then(|b| b.pointer("/error/code"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let msg = body
        .as_ref()
        .and_then(|b| b.pointer("/error/message"))
        .and_then(Value::as_str)
        .unwrap_or("no message");
    let msg: String = msg.chars().take(400).collect();
    let text = format!("ARM answered {} ({code}): {msg}", resp.status);
    if resp.status == 409 {
        AcaTargetError::Conflict(text)
    } else {
        AcaTargetError::Api(text)
    }
}

fn lro_error(e: LroError) -> AcaTargetError {
    AcaTargetError::Api(e.to_string())
}

impl RealAcaTarget {
    pub(crate) fn new(http: Arc<dyn AzureHttp>, scope: AzureScope) -> Self {
        Self {
            http,
            scope,
            policy: Policy::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    async fn send(&self, req: ArmRequest) -> Result<ArmResponse, AcaTargetError> {
        lro::send_with_retry(self.http.as_ref(), req, &self.policy)
            .await
            .map_err(|e| AcaTargetError::Api(e.to_string()))
    }

    /// Send a write and follow its long-running operation to the end.
    async fn write(&self, req: ArmRequest) -> Result<ArmResponse, AcaTargetError> {
        let first = self.send(req).await?;
        if !(200..300).contains(&first.status) {
            return Err(api_error(&first));
        }
        lro::complete(self.http.as_ref(), first, &self.policy)
            .await
            .map_err(lro_error)
    }

    async fn get_json(&self, url: String) -> Result<Option<Value>, AcaTargetError> {
        let resp = self.send(ArmRequest::new(Method::Get, url)).await?;
        match resp.status {
            404 => Ok(None),
            200 => resp.json().map(Some).ok_or_else(|| {
                AcaTargetError::Api("ARM answered 200 with an unreadable body".into())
            }),
            _ => Err(api_error(&resp)),
        }
    }
}

#[async_trait]
impl AcaDeployTarget for RealAcaTarget {
    async fn inspect_app(&self, app: &AppRef) -> Result<AppState, AcaTargetError> {
        let Some(json) = self.get_json(self.scope.app(&app.name)).await? else {
            return Ok(AppState::Absent);
        };
        let traffic = status::traffic_of(&json).map_err(AcaTargetError::Conflict)?;
        Ok(AppState::Present {
            owner: status::owner_of(&json),
            traffic,
        })
    }

    async fn list_secrets(&self, app: &AppRef) -> Result<Vec<AppSecret>, AcaTargetError> {
        let resp = self
            .send(ArmRequest::new(
                Method::Post,
                self.scope.list_secrets(&app.name),
            ))
            .await?;
        match resp.status {
            404 => Ok(Vec::new()),
            200 => {
                let body = resp.json().ok_or_else(|| {
                    AcaTargetError::Api("listSecrets answered an unreadable body".into())
                })?;
                Ok(body
                    .get("value")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|s| {
                        let name = s.get("name")?.as_str()?;
                        let value = s.get("value")?.as_str()?;
                        Some(AppSecret::new(name, value))
                    })
                    .collect())
            }
            _ => Err(api_error(&resp)),
        }
    }

    async fn put_revision(&self, spec: &AppSpec) -> Result<RevisionRef, AcaTargetError> {
        let body = container_app_body(spec);
        let req = ArmRequest::new(Method::Put, self.scope.app(spec.name.as_str())).json(&body);
        self.write(req).await?;
        Ok(RevisionRef {
            app: AppRef {
                name: spec.name.as_str().to_string(),
            },
            name: revision_name(&spec.name, &spec.revision.suffix),
        })
    }

    async fn live_revision_intent(&self, rev: &RevisionRef) -> Result<LiveIntent, AcaTargetError> {
        Ok(
            match self
                .get_json(self.scope.revision(&rev.app.name, &rev.name))
                .await?
            {
                None => LiveIntent::Absent,
                Some(json) => status::intent_from_revision(&json),
            },
        )
    }

    async fn revision_status(&self, rev: &RevisionRef) -> Result<RevisionStatus, AcaTargetError> {
        Ok(
            match self
                .get_json(self.scope.revision(&rev.app.name, &rev.name))
                .await?
            {
                None => RevisionStatus::Absent,
                Some(json) => status::revision_status(&json),
            },
        )
    }

    async fn set_traffic(
        &self,
        app: &AppRef,
        weights: &[TrafficEntry],
    ) -> Result<(), AcaTargetError> {
        let total: u32 = weights.iter().map(|w| w.weight).sum();
        if total != 100 {
            return Err(AcaTargetError::Api(format!(
                "traffic weights sum to {total}, not 100"
            )));
        }
        let req = ArmRequest::new(Method::Patch, self.scope.app(&app.name))
            .json(&traffic_patch_body(weights));
        self.write(req).await.map(|_| ())
    }

    async fn deactivate_revision(&self, rev: &RevisionRef) -> Result<(), AcaTargetError> {
        let resp = self
            .send(ArmRequest::new(
                Method::Post,
                self.scope.deactivate(&rev.app.name, &rev.name),
            ))
            .await?;
        match resp.status {
            200..=299 | 404 => Ok(()),
            _ => Err(api_error(&resp)),
        }
    }

    async fn delete_app(&self, app: &AppRef) -> Result<bool, AcaTargetError> {
        let resp = self
            .send(ArmRequest::new(Method::Delete, self.scope.app(&app.name)))
            .await?;
        match resp.status {
            404 => Ok(false),
            200..=299 => {
                lro::complete(self.http.as_ref(), resp, &self.policy)
                    .await
                    .map_err(lro_error)?;
                Ok(true)
            }
            _ => Err(api_error(&resp)),
        }
    }

    async fn discover_endpoint(&self, app: &AppRef) -> Result<Option<String>, AcaTargetError> {
        Ok(self
            .get_json(self.scope.app(&app.name))
            .await?
            .and_then(|j| status::endpoint_of(&j)))
    }
}

#[cfg(test)]
#[path = "real_target_tests.rs"]
mod tests;
