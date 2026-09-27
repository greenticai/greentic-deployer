//! Production [`SorServiceTarget`] on the same Cloud Run clients the worker
//! path uses (`RealCloudRunTarget`), plus one Artifact Registry IAM
//! read-modify-write over plain REST — no generated AR client is linked, the
//! same choice `credentials.rs` makes for `testIamPermissions`. Holds no
//! policy: request building and response parsing are pure and unit-tested.

use std::collections::BTreeMap;

use async_trait::async_trait;
use google_cloud_iam_v1::model as iam;
use google_cloud_lro::Poller;
use google_cloud_run_v2::model as run;
use serde_json::{Value, json};

use super::spec::AR_READER_ROLE;
use super::target::{
    ArRepository, SorServiceLabels, SorServiceRef, SorServiceSpec, SorServiceStatus,
    SorServiceTarget,
};
use crate::env_packs::gcp_cloudrun::bound_session::{
    GcpCredentialMaterial, ambient_adc_credentials,
};
use crate::env_packs::gcp_cloudrun::deploy_target::{AccessMode, CloudRunTargetError};
use crate::env_packs::gcp_cloudrun::real_target::{
    ENV_LABEL_KEY, MANAGED_LABEL_KEY, RealCloudRunTarget, apply_invoker_binding, clamp_i32,
    classify, is_not_found, non_empty, revision_status_from, service_ready,
};

const SOR_UNIT_LABEL_KEY: &str = "greentic-sor-unit";
const SOR_INTENT_LABEL_KEY: &str = "greentic-sor-intent";
const AR_API: &str = "https://artifactregistry.googleapis.com/v1";
/// 36 × 5 s = 180 s for pack pull + Postgres connect, inside Cloud Run's
/// 240 s startup-probe ceiling.
const PROBE_PERIOD_SECONDS: i32 = 5;
const PROBE_TIMEOUT_SECONDS: i32 = 3;
const PROBE_FAILURE_THRESHOLD: i32 = 36;

/// Every permission the SoR path's REQUIRED calls exercise. Pinned ⊆
/// `REAL_CLOUDRUN_TARGET_IAM_PERMISSIONS` so a SoR deploy needs nothing the
/// preflight does not already validate.
pub const SOR_REQUIRED_IAM_PERMISSIONS: &[&str] = &[
    "run.services.get",
    "run.services.create",
    "run.services.update",
    "run.services.delete",
    "run.services.getIamPolicy",
    "run.services.setIamPolicy",
    "run.revisions.get",
    "iam.serviceAccounts.actAs",
    "secretmanager.secrets.get",
    "secretmanager.secrets.create",
    "secretmanager.versions.add",
    "secretmanager.secrets.getIamPolicy",
    "secretmanager.secrets.setIamPolicy",
    "secretmanager.secrets.delete",
];

/// The reader grant is best effort; these stay OUT of `VALIDATED_GCP_PERMISSIONS`
/// on purpose (a deployer without them deploys and gets the `gcloud` note).
pub const SOR_BEST_EFFORT_IAM_PERMISSIONS: &[&str] = &[
    "artifactregistry.repositories.getIamPolicy",
    "artifactregistry.repositories.setIamPolicy",
];

#[derive(Debug, Clone)]
pub struct RealSorTarget {
    run: RealCloudRunTarget,
    auth: google_cloud_auth::credentials::Credentials,
    http: reqwest::Client,
}

impl RealSorTarget {
    /// Same identity as the worker path: the bound deployer credential, else
    /// ambient ADC. Fails closed exactly as `RealCloudRunTarget::resolve` does.
    pub async fn resolve(
        project: &str,
        region: &str,
        credentials: Option<GcpCredentialMaterial>,
    ) -> Result<Self, CloudRunTargetError> {
        let auth = match &credentials {
            Some(material) => material.build_credentials(),
            None => ambient_adc_credentials(),
        }
        .map_err(CloudRunTargetError::Api)?;
        let run = RealCloudRunTarget::resolve(project, region, credentials).await?;
        Ok(Self {
            run,
            auth,
            http: reqwest::Client::new(),
        })
    }

    /// The same clients as a `CloudRunTarget`, for staging the unit's secret.
    pub fn run_target(&self) -> RealCloudRunTarget {
        self.run.clone()
    }

    async fn auth_headers(&self) -> Result<http::HeaderMap, CloudRunTargetError> {
        use google_cloud_auth::credentials::CacheableResource;
        match self
            .auth
            .headers(http::Extensions::new())
            .await
            .map_err(|e| CloudRunTargetError::Api(format!("Artifact Registry auth: {e}")))?
        {
            CacheableResource::New { data, .. } => Ok(data),
            CacheableResource::NotModified => Err(CloudRunTargetError::Api(
                "Artifact Registry auth returned NotModified for a fresh header request"
                    .to_string(),
            )),
        }
    }
}

#[async_trait]
impl SorServiceTarget for RealSorTarget {
    async fn get_sor_service(
        &self,
        service: &SorServiceRef,
    ) -> Result<Option<SorServiceStatus>, CloudRunTargetError> {
        let svc = match self
            .run
            .services
            .get_service()
            .set_name(sor_service_fqn(service))
            .send()
            .await
        {
            Ok(svc) => svc,
            Err(e) if is_not_found(&e) => return Ok(None),
            Err(e) => return Err(classify("get_service", &e)),
        };
        let mut status = sor_status_from(&svc);
        // The reason lives on the revision; best effort (never alters status).
        if status.failed()
            && !svc.latest_created_revision.is_empty()
            && let Ok(rev) = self
                .run
                .revisions
                .get_revision()
                .set_name(revision_fqn(service, &svc.latest_created_revision))
                .send()
                .await
        {
            let rev = revision_status_from(&rev);
            status.not_ready_reason = rev.not_ready_reason;
            status.log_uri = rev.log_uri;
        }
        Ok(Some(status))
    }

    /// Returns once Cloud Run ACCEPTS the create/update; never waits for the
    /// rollout. Only a request-level refusal errors (a stale etag stays
    /// `PreconditionFailed`); a revision that then fails to boot is observed by
    /// `up::wait_ready` via `get_sor_service`, within `SorReadyTiming` and with
    /// Cloud Run's reason. Awaiting the operation would turn that into an
    /// operation error (maybe `FAILED_PRECONDITION`, retried as an etag race).
    async fn upsert_sor_service(
        &self,
        spec: &SorServiceSpec,
        etag: Option<&str>,
    ) -> Result<SorServiceStatus, CloudRunTargetError> {
        let message = build_sor_service_message(spec, etag);
        let _operation = match etag {
            Some(_) => self
                .run
                .services
                .update_service()
                .set_service(message)
                .send()
                .await
                .map_err(|e| classify("update_service", &e))?,
            None => self
                .run
                .services
                .create_service()
                .set_parent(format!(
                    "projects/{}/locations/{}",
                    spec.service.project, spec.service.region
                ))
                .set_service_id(spec.service.name.clone())
                .set_service(message)
                .send()
                .await
                .map_err(|e| classify("create_service", &e))?,
        };
        Ok(accepted_status(spec))
    }

    async fn set_sor_invoker_public(
        &self,
        service: &SorServiceRef,
    ) -> Result<(), CloudRunTargetError> {
        let resource = sor_service_fqn(service);
        let policy = self
            .run
            .services
            .get_iam_policy()
            .set_resource(resource.clone())
            .set_options(iam::GetPolicyOptions::new().set_requested_policy_version(3))
            .send()
            .await
            .map_err(|e| classify("get_iam_policy", &e))?;
        self.run
            .services
            .set_iam_policy()
            .set_resource(resource)
            .set_policy(apply_invoker_binding(policy, AccessMode::Public))
            .send()
            .await
            .map_err(|e| classify("set_iam_policy", &e))?;
        Ok(())
    }

    async fn delete_sor_service(&self, service: &SorServiceRef) -> Result<(), CloudRunTargetError> {
        match self
            .run
            .services
            .delete_service()
            .set_name(sor_service_fqn(service))
            .poller()
            .until_done()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(classify("delete_service", &e)),
        }
    }

    async fn grant_artifact_registry_reader(
        &self,
        repo: &ArRepository,
        service_account: &str,
    ) -> Result<(), CloudRunTargetError> {
        let url = format!("{AR_API}/{}", repo.resource());
        let headers = self.auth_headers().await?;
        // Policy version 3 keeps conditional bindings' conditions on write-back.
        let response = self
            .http
            .get(format!(
                "{url}:getIamPolicy?options.requestedPolicyVersion=3"
            ))
            .headers(headers.clone())
            .send()
            .await
            .map_err(|e| {
                CloudRunTargetError::Api(format!("Artifact Registry getIamPolicy: {e}"))
            })?;
        let status = response.status();
        let body = response.text().await.map_err(|e| {
            CloudRunTargetError::Api(format!("Artifact Registry getIamPolicy: {e}"))
        })?;
        if !status.is_success() {
            return Err(CloudRunTargetError::Api(format!(
                "Artifact Registry getIamPolicy on `{}` answered HTTP {status}",
                repo.resource()
            )));
        }
        let policy: Value = serde_json::from_str(&body).map_err(|e| {
            CloudRunTargetError::Api(format!("unreadable Artifact Registry IAM policy: {e}"))
        })?;
        let member = format!("serviceAccount:{service_account}");
        let Some(updated) = apply_ar_reader_binding(policy, &member) else {
            return Ok(());
        };
        let response = self
            .http
            .post(format!("{url}:setIamPolicy"))
            .headers(headers)
            .json(&json!({ "policy": updated }))
            .send()
            .await
            .map_err(|e| {
                CloudRunTargetError::Api(format!("Artifact Registry setIamPolicy: {e}"))
            })?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(CloudRunTargetError::Api(format!(
                "Artifact Registry setIamPolicy on `{}` answered HTTP {}",
                repo.resource(),
                response.status()
            )))
        }
    }
}

// ---- Pure request builders / response parsers (unit-tested) ----

fn sor_service_fqn(service: &SorServiceRef) -> String {
    format!(
        "projects/{}/locations/{}/services/{}",
        service.project, service.region, service.name
    )
}

/// `latest_created_revision` is a full resource name; qualify a bare id.
fn revision_fqn(service: &SorServiceRef, revision: &str) -> String {
    if revision.contains('/') {
        revision.to_string()
    } else {
        format!("{}/revisions/{revision}", sor_service_fqn(service))
    }
}

fn sor_labels(labels: &SorServiceLabels) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL_KEY.to_string(), "true".to_string()),
        (ENV_LABEL_KEY.to_string(), labels.owner.clone()),
        (SOR_UNIT_LABEL_KEY.to_string(), labels.unit_id.clone()),
        (SOR_INTENT_LABEL_KEY.to_string(), labels.intent.clone()),
    ])
}

fn sor_env_vars(spec: &SorServiceSpec) -> Vec<run::EnvVar> {
    let plain = spec.env.iter().map(|(name, value)| {
        run::EnvVar::new()
            .set_name(name.clone())
            .set_value(value.clone())
    });
    let from_secret = spec.secret_env.iter().map(|s| {
        run::EnvVar::new()
            .set_name(s.name.clone())
            .set_value_source(
                run::EnvVarSource::new().set_secret_key_ref(
                    run::SecretKeySelector::new()
                        .set_secret(s.secret_name.clone())
                        .set_version(s.version.clone()),
                ),
            )
    });
    plain.chain(from_secret).collect()
}

fn sor_volume_name(index: usize) -> String {
    format!("sor-secret-{index}")
}

pub(super) fn build_sor_service_message(spec: &SorServiceSpec, etag: Option<&str>) -> run::Service {
    let port = i32::from(spec.port);
    let volumes: Vec<run::Volume> = spec
        .secret_mounts
        .iter()
        .enumerate()
        .map(|(index, mount)| {
            run::Volume::new()
                .set_name(sor_volume_name(index))
                .set_secret(
                    run::SecretVolumeSource::new()
                        .set_secret(mount.secret_name.clone())
                        .set_items(mount.items.iter().map(|it| {
                            run::VersionToPath::new()
                                .set_version(it.version.clone())
                                .set_path(it.rel_path.clone())
                        })),
                )
        })
        .collect();
    let mounts: Vec<run::VolumeMount> = spec
        .secret_mounts
        .iter()
        .enumerate()
        .map(|(index, mount)| {
            run::VolumeMount::new()
                .set_name(sor_volume_name(index))
                .set_mount_path(mount.mount_dir.clone())
        })
        .collect();
    let container = run::Container::new()
        .set_image(spec.image.clone())
        .set_args(spec.args.clone())
        .set_ports([run::ContainerPort::new().set_container_port(port)])
        .set_resources(
            run::ResourceRequirements::new()
                .set_limits([
                    ("cpu".to_string(), spec.scaling.cpu.clone()),
                    ("memory".to_string(), spec.scaling.memory.clone()),
                ])
                .set_cpu_idle(true)
                .set_startup_cpu_boost(true),
        )
        .set_env(sor_env_vars(spec))
        .set_volume_mounts(mounts)
        .set_startup_probe(
            run::Probe::new()
                .set_http_get(
                    run::HTTPGetAction::new()
                        .set_path(spec.health_path.clone())
                        .set_port(port),
                )
                .set_period_seconds(PROBE_PERIOD_SECONDS)
                .set_timeout_seconds(PROBE_TIMEOUT_SECONDS)
                .set_failure_threshold(PROBE_FAILURE_THRESHOLD),
        );
    let template = run::RevisionTemplate::new()
        .set_service_account(spec.runtime_service_account.clone())
        .set_max_instance_request_concurrency(clamp_i32(spec.scaling.concurrency))
        .set_scaling(
            run::RevisionScaling::new()
                .set_min_instance_count(clamp_i32(spec.scaling.min_instances))
                .set_max_instance_count(clamp_i32(spec.scaling.max_instances)),
        )
        .set_labels(sor_labels(&spec.labels))
        .set_volumes(volumes)
        .set_containers([container]);
    let mut service = run::Service::new()
        .set_template(template)
        .set_traffic([run::TrafficTarget::new()
            .set_type(run::TrafficTargetAllocationType::Latest)
            .set_percent(100)])
        // E5: the shared secret, not IAM or ingress, is the boundary.
        .set_ingress(run::IngressTraffic::All)
        .set_labels(sor_labels(&spec.labels));
    if let Some(etag) = etag {
        service.name = sor_service_fqn(&spec.service);
        service.etag = etag.to_string();
    }
    service
}

/// `ready` is NOT the Ready condition alone (right after an upsert it can still
/// describe the PREVIOUS revision): the observed generation must have caught up
/// AND the latest CREATED revision must be the latest ready one. A lagging
/// generation is a rollout (`reconciling`), never a failure.
pub(super) fn sor_status_from(svc: &run::Service) -> SorServiceStatus {
    let reconciling = svc.reconciling || svc.observed_generation != svc.generation;
    let latest_created_ready = !svc.latest_created_revision.is_empty()
        && svc.latest_created_revision == svc.latest_ready_revision;
    SorServiceStatus {
        etag: svc.etag.clone(),
        owner: svc.labels.get(ENV_LABEL_KEY).cloned(),
        intent: svc.labels.get(SOR_INTENT_LABEL_KEY).cloned(),
        ready: !reconciling && latest_created_ready && service_ready(svc),
        reconciling,
        url: non_empty(svc.uri.clone()),
        not_ready_reason: None,
        log_uri: None,
    }
}

/// An accepted upsert: reconciling (neither ready nor failed); the caller
/// polls the live service for the outcome.
pub(super) fn accepted_status(spec: &SorServiceSpec) -> SorServiceStatus {
    SorServiceStatus {
        etag: String::new(),
        owner: Some(spec.labels.owner.clone()),
        intent: Some(spec.labels.intent.clone()),
        ready: false,
        reconciling: true,
        url: None,
        not_ready_reason: None,
        log_uri: None,
    }
}

/// Add `member` to the UNCONDITIONAL reader binding, preserving every other
/// field (etag, audit configs, conditional bindings) by working on the raw
/// JSON. `None` when the member already holds it (no write).
pub(super) fn apply_ar_reader_binding(mut policy: Value, member: &str) -> Option<Value> {
    let unconditional = |b: &Value| {
        b.get("role").and_then(Value::as_str) == Some(AR_READER_ROLE)
            && b.get("condition").is_none()
    };
    if !policy.is_object() {
        policy = json!({});
    }
    let already = policy
        .get("bindings")
        .and_then(Value::as_array)
        .is_some_and(|list| {
            list.iter().any(|b| {
                unconditional(b)
                    && b.get("members")
                        .and_then(Value::as_array)
                        .is_some_and(|m| m.iter().any(|x| x.as_str() == Some(member)))
            })
        });
    if already {
        return None;
    }
    let list = policy
        .as_object_mut()?
        .entry("bindings")
        .or_insert_with(|| json!([]))
        .as_array_mut()?;
    match list.iter_mut().find(|b| unconditional(b)) {
        Some(binding) => match binding.get_mut("members").and_then(Value::as_array_mut) {
            Some(members) => members.push(json!(member)),
            None => binding["members"] = json!([member]),
        },
        None => list.push(json!({ "role": AR_READER_ROLE, "members": [member] })),
    }
    Some(policy)
}

#[cfg(test)]
#[path = "real_tests.rs"]
mod tests;
