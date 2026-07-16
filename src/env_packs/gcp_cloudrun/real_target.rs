//! [`RealCloudRunTarget`]: the `google-cloud-*`-backed [`CloudRunTarget`] impl.
//!
//! The scaffold (PR-1) shipped the [`CloudRunTarget`] seam + the
//! [`InMemoryCloudRun`](super::deploy_target::InMemoryCloudRun) fake + the
//! [`UnconfiguredCloudRunTarget`](super::deploy_target::UnconfiguredCloudRunTarget)
//! default; the [`Deployer`](super::deployer) verbs drive that seam. This module
//! supplies the production implementation of the same methods, backed by
//! `google-cloud-run-v2` (Services + Revisions) and `google-cloud-secretmanager-v1`
//! (version-pinned secret staging). Behind the default-on `deploy-gcp-cloudrun`
//! feature.
//!
//! ## Single-resource model + ETag read-modify-write
//!
//! Cloud Run collapses ECS's service + task-set + listener into one `Service`
//! whose `traffic[]` array is a field under optimistic-concurrency `etag`
//! control (plan D4). So [`get_service`](CloudRunTarget::get_service) returns the
//! live `traffic[]` + readiness + `etag`, and [`upsert_service`] /
//! [`set_traffic`] carry that `etag` as a precondition. A stale write surfaces as
//! [`CloudRunTargetError::PreconditionFailed`] (mapped from the gRPC
//! `ABORTED` / `FAILED_PRECONDITION` code, or HTTP 409/412) so the deployer
//! re-reads and recomputes rather than clobbering a concurrent change.
//!
//! ## Identity bridge
//!
//! The seam addresses a Service by `deployment_id` and a revision by
//! `(deployment_id, revision_id)`. Both map to deterministic Cloud Run resource
//! names ([`super::deployer::service_name`] / [`revision_name`]), so a fresh
//! process re-derives every name without persisting Cloud Run ids. Reading the
//! live `traffic[]` back into seam [`TrafficTarget`]s means recovering each
//! entry's `RevisionId` from its revision name — [`parse_revision_id_from_name`],
//! the inverse of [`revision_name`].
//!
//! ## Testing
//!
//! No real GCP in CI. Every request-build + response-parse step is a pure free
//! function (`build_*` / `*_from` / `classify_*`) unit-tested with SDK types
//! built via their builders. The thin async glue that `.await`s the client is
//! exercised only by the gated live E2E (follow-up PR).

use std::collections::BTreeMap;

use async_trait::async_trait;
use google_cloud_gax::error::Error as GaxError;
use google_cloud_gax::error::rpc::Code;
use google_cloud_iam_v1::model as iam;
use google_cloud_lro::Poller;
use google_cloud_run_v2::client::{Revisions, Services};
use google_cloud_run_v2::model as run;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use google_cloud_secretmanager_v1::model as sm;
use greentic_deploy_spec::{DeploymentId, RevisionId};
use ulid::Ulid;

use super::bound_session::{GcpCredentialMaterial, ambient_adc_credentials};
use super::deploy_target::{
    AccessMode, CloudRunTarget, CloudRunTargetError, RevisionRef, RevisionStatus, SecretVersion,
    ServiceRef, ServiceSpec, ServiceStatus, TrafficTarget,
};
use super::deployer::{revision_name, service_name};

/// The IAM permissions [`RealCloudRunTarget`]'s methods exercise at deploy time —
/// the authoritative Cloud Run / Secret Manager runtime surface. A test pins this
/// ⊆ [`VALIDATED_GCP_PERMISSIONS`](super::credentials::VALIDATED_GCP_PERMISSIONS)
/// so the credentials preflight can never under-declare what a live deploy needs:
/// adding an SDK call here without the matching validated permission fails CI
/// rather than the customer's first `op env up` / traffic-shift / archive.
pub const REAL_CLOUDRUN_TARGET_IAM_PERMISSIONS: &[&str] = &[
    // Service lifecycle (get / create / update / delete) + invoker IAM (D12).
    "run.services.get",
    "run.services.create",
    "run.services.update",
    "run.services.delete",
    "run.services.setIamPolicy",
    // Revision readiness poll + archive.
    "run.revisions.get",
    "run.revisions.delete",
    // Pass the least-privilege runtime SA to the created revision (D7).
    "iam.serviceAccounts.actAs",
    // Version-pinned secret staging (D6).
    "secretmanager.secrets.get",
    "secretmanager.secrets.create",
    "secretmanager.versions.add",
];

/// Ownership labels stamped on every managed Service (plan D1). Cloud Run
/// resource-label keys/values follow GCP rules (lowercase alnum + `-`/`_`, no
/// `/` or `.`), so these are the GCP-valid analogue of the k8s `greentic.ai/*`
/// labels — the deployment ULID (lowercased base32) is a valid value.
const MANAGED_LABEL_KEY: &str = "greentic-managed";
const DEPLOYMENT_LABEL_KEY: &str = "greentic-deployment";

/// Production [`CloudRunTarget`]: Cloud Run Services + Revisions + Secret Manager,
/// pinned to one `(project, region)` at construction (the env-pack binding is
/// single-project/region, so every seam ref's `project`/`region` equal these).
#[derive(Debug, Clone)]
pub struct RealCloudRunTarget {
    services: Services,
    revisions: Revisions,
    secrets: SecretManagerService,
    project: String,
    region: String,
}

impl RealCloudRunTarget {
    /// Build the regional Cloud Run clients + the global Secret Manager client
    /// for `(project, region)`.
    ///
    /// `credentials` is the env's bound deployer identity (the
    /// [`GcpCredentialMaterial`] resolved from `credentials_ref`): `Some` injects
    /// it so every call runs as the scoped deployer SA; `None` falls back to the
    /// ambient ADC chain. Fail-closed resolution happens upstream
    /// (`resolve_bound_credentials`), so `None` here means "no ref bound", not
    /// "ref bound but unreadable".
    pub async fn resolve(
        project: &str,
        region: &str,
        credentials: Option<GcpCredentialMaterial>,
    ) -> Result<Self, CloudRunTargetError> {
        let creds = match credentials {
            Some(material) => material.build_credentials(),
            None => ambient_adc_credentials(),
        }
        .map_err(CloudRunTargetError::Api)?;

        // Cloud Run is regional: talk to the regional endpoint so long-running
        // operations poll against the region that owns them. Secret Manager is
        // global — its default endpoint is correct.
        let run_endpoint = format!("https://{region}-run.googleapis.com");
        let services = Services::builder()
            .with_endpoint(run_endpoint.clone())
            .with_credentials(creds.clone())
            .build()
            .await
            .map_err(|e| {
                CloudRunTargetError::Api(format!("build Cloud Run Services client: {e}"))
            })?;
        let revisions = Revisions::builder()
            .with_endpoint(run_endpoint)
            .with_credentials(creds.clone())
            .build()
            .await
            .map_err(|e| {
                CloudRunTargetError::Api(format!("build Cloud Run Revisions client: {e}"))
            })?;
        let secrets = SecretManagerService::builder()
            .with_credentials(creds)
            .build()
            .await
            .map_err(|e| CloudRunTargetError::Api(format!("build Secret Manager client: {e}")))?;

        Ok(Self {
            services,
            revisions,
            secrets,
            project: project.to_string(),
            region: region.to_string(),
        })
    }

    // ---- Resource-name builders (project/region pinned to this target) ----

    fn services_parent(&self) -> String {
        format!("projects/{}/locations/{}", self.project, self.region)
    }

    fn service_resource(&self, deployment_id: DeploymentId) -> String {
        format!(
            "{}/services/{}",
            self.services_parent(),
            service_name(deployment_id)
        )
    }

    fn revision_resource(&self, deployment_id: DeploymentId, revision_id: RevisionId) -> String {
        format!(
            "{}/services/{}/revisions/{}",
            self.services_parent(),
            service_name(deployment_id),
            revision_name(deployment_id, revision_id),
        )
    }

    fn secret_resource(&self, name: &str) -> String {
        format!("projects/{}/secrets/{}", self.project, name)
    }
}

#[async_trait]
impl CloudRunTarget for RealCloudRunTarget {
    async fn get_service(
        &self,
        service: &ServiceRef,
    ) -> Result<Option<ServiceStatus>, CloudRunTargetError> {
        let name = self.service_resource(service.deployment_id);
        match self.services.get_service().set_name(name).send().await {
            Ok(svc) => Ok(Some(service_status_from(&svc))),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(classify("get_service", &e)),
        }
    }

    async fn upsert_service(
        &self,
        spec: &ServiceSpec,
        etag: Option<&str>,
    ) -> Result<ServiceStatus, CloudRunTargetError> {
        let service = build_service_message(spec, etag);
        let svc = match etag {
            // Conditional update: etag rides on the Service message itself
            // (update_service has no separate precondition setter).
            Some(_) => self
                .services
                .update_service()
                .set_service(service)
                .poller()
                .until_done()
                .await
                .map_err(|e| classify("update_service", &e))?,
            // First create: parent + service_id + the desired Service.
            None => self
                .services
                .create_service()
                .set_parent(self.services_parent())
                .set_service_id(service_name(spec.deployment_id))
                .set_service(service)
                .poller()
                .until_done()
                .await
                .map_err(|e| classify("create_service", &e))?,
        };
        Ok(service_status_from(&svc))
    }

    async fn get_revision_status(
        &self,
        revision: &RevisionRef,
    ) -> Result<RevisionStatus, CloudRunTargetError> {
        let name = self.revision_resource(revision.deployment_id, revision.revision_id);
        match self.revisions.get_revision().set_name(name).send().await {
            Ok(rev) => Ok(revision_status_from(&rev)),
            Err(e) if is_not_found(&e) => Err(CloudRunTargetError::NotFound(format!(
                "revision {} not found",
                revision.revision_id
            ))),
            Err(e) => Err(classify("get_revision", &e)),
        }
    }

    async fn set_traffic(
        &self,
        service: &ServiceRef,
        traffic: &[TrafficTarget],
        etag: &str,
    ) -> Result<ServiceStatus, CloudRunTargetError> {
        // Read-modify-write: fetch the live Service, replace its traffic under
        // the caller's etag, and update. The caller passes the etag it read, so a
        // stale token is rejected as PreconditionFailed rather than clobbering.
        let name = self.service_resource(service.deployment_id);
        let mut svc = match self.services.get_service().set_name(name).send().await {
            Ok(svc) => svc,
            Err(e) if is_not_found(&e) => {
                return Err(CloudRunTargetError::NotFound(
                    "service not found".to_string(),
                ));
            }
            Err(e) => return Err(classify("get_service", &e)),
        };
        svc.etag = etag.to_string();
        svc.traffic = build_traffic(service.deployment_id, traffic);
        let updated = self
            .services
            .update_service()
            .set_service(svc)
            .poller()
            .until_done()
            .await
            .map_err(|e| classify("update_service", &e))?;
        Ok(service_status_from(&updated))
    }

    async fn set_invoker_policy(
        &self,
        service: &ServiceRef,
        access_mode: AccessMode,
    ) -> Result<(), CloudRunTargetError> {
        let resource = self.service_resource(service.deployment_id);
        // Read-modify-write the IAM policy so we never drop unrelated bindings.
        let policy = self
            .services
            .get_iam_policy()
            .set_resource(resource.clone())
            .set_options(iam::GetPolicyOptions::new().set_requested_policy_version(3))
            .send()
            .await
            .map_err(|e| classify("get_iam_policy", &e))?;
        let policy = apply_invoker_binding(policy, access_mode);
        self.services
            .set_iam_policy()
            .set_resource(resource)
            .set_policy(policy)
            .send()
            .await
            .map_err(|e| classify("set_iam_policy", &e))?;
        Ok(())
    }

    async fn delete_revision(&self, revision: &RevisionRef) -> Result<(), CloudRunTargetError> {
        let name = self.revision_resource(revision.deployment_id, revision.revision_id);
        match self
            .revisions
            .delete_revision()
            .set_name(name)
            .poller()
            .until_done()
            .await
        {
            Ok(_) => Ok(()),
            // Idempotent against an already-gone revision.
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(classify("delete_revision", &e)),
        }
    }

    async fn delete_service(&self, service: &ServiceRef) -> Result<(), CloudRunTargetError> {
        let name = self.service_resource(service.deployment_id);
        match self
            .services
            .delete_service()
            .set_name(name)
            .poller()
            .until_done()
            .await
        {
            Ok(_) => Ok(()),
            // Idempotent against an already-gone service.
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(classify("delete_service", &e)),
        }
    }

    async fn get_service_url(
        &self,
        service: &ServiceRef,
    ) -> Result<Option<String>, CloudRunTargetError> {
        let name = self.service_resource(service.deployment_id);
        match self.services.get_service().set_name(name).send().await {
            Ok(svc) => Ok(non_empty(svc.uri)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(classify("get_service", &e)),
        }
    }

    async fn upsert_secret(
        &self,
        name: &str,
        payload: &[u8],
    ) -> Result<SecretVersion, CloudRunTargetError> {
        let secret_resource = self.secret_resource(name);
        // Create-or-get: a missing secret is created with automatic replication;
        // an existing one is left as-is (its versions are what we add to).
        if let Err(e) = self
            .secrets
            .get_secret()
            .set_name(secret_resource.clone())
            .send()
            .await
        {
            if is_not_found(&e) {
                self.secrets
                    .create_secret()
                    .set_parent(format!("projects/{}", self.project))
                    .set_secret_id(name)
                    .set_secret(new_automatic_secret())
                    .send()
                    .await
                    .map_err(|e| classify("create_secret", &e))?;
            } else {
                return Err(classify("get_secret", &e));
            }
        }
        let version = self
            .secrets
            .add_secret_version()
            .set_parent(secret_resource)
            .set_payload(sm::SecretPayload::new().set_data(bytes_from(payload)))
            .send()
            .await
            .map_err(|e| classify("add_secret_version", &e))?;
        Ok(SecretVersion {
            version: numeric_version_from(&version.name),
        })
    }
}

// ---- Pure request builders (unit-tested; no HTTP) ----

/// Build the desired Cloud Run [`run::Service`] from a seam [`ServiceSpec`].
/// `etag` (present on an update) is stamped on the message — `update_service`
/// carries the precondition on the Service, not a separate builder call.
fn build_service_message(spec: &ServiceSpec, etag: Option<&str>) -> run::Service {
    let mut service = run::Service::new()
        .set_template(build_revision_template(spec))
        .set_traffic(build_traffic(spec.deployment_id, &spec.traffic))
        // Ingress::All so the returned run.app URL + webhook callbacks reach the
        // service; the invoker IAM binding (D12) is the actual auth boundary.
        .set_ingress(run::IngressTraffic::All)
        .set_labels(ownership_labels(spec.deployment_id));
    if let Some(etag) = etag {
        service.etag = etag.to_string();
    }
    service
}

/// Build the revision template: single container, scale-to-zero, the resolved
/// runtime SA (D7), session affinity (D11), and any secret env sources (D6).
fn build_revision_template(spec: &ServiceSpec) -> run::RevisionTemplate {
    run::RevisionTemplate::new()
        .set_revision(revision_name(spec.deployment_id, spec.revision_id))
        .set_service_account(spec.runtime_service_account.clone())
        .set_session_affinity(spec.session_affinity)
        .set_max_instance_request_concurrency(clamp_i32(spec.scaling.concurrency))
        .set_scaling(build_scaling(spec))
        .set_labels(ownership_labels(spec.deployment_id))
        .set_containers([build_container(spec)])
}

fn build_container(spec: &ServiceSpec) -> run::Container {
    let mut env: Vec<run::EnvVar> = Vec::with_capacity(spec.secrets.len());
    for mount in &spec.secrets {
        env.push(
            run::EnvVar::new()
                .set_name(mount.env_var.clone())
                .set_value_source(
                    run::EnvVarSource::new().set_secret_key_ref(
                        run::SecretKeySelector::new()
                            .set_secret(mount.secret_name.clone())
                            // The immutable numeric version — never `latest` (D6).
                            .set_version(mount.version.clone()),
                    ),
                ),
        );
    }
    run::Container::new()
        .set_image(spec.image.clone())
        .set_resources(build_resources(spec))
        .set_env(env)
}

/// Scale-to-zero rendered explicitly (plan D5): `min_instance_count = 0`,
/// `cpu_idle = true` (request-based billing), `startup_cpu_boost = true`.
fn build_resources(spec: &ServiceSpec) -> run::ResourceRequirements {
    run::ResourceRequirements::new()
        .set_limits([
            ("cpu".to_string(), spec.scaling.cpu.clone()),
            ("memory".to_string(), spec.scaling.memory.clone()),
        ])
        .set_cpu_idle(true)
        .set_startup_cpu_boost(true)
}

fn build_scaling(spec: &ServiceSpec) -> run::RevisionScaling {
    run::RevisionScaling::new()
        .set_min_instance_count(clamp_i32(spec.scaling.min_instances))
        .set_max_instance_count(clamp_i32(spec.scaling.max_instances))
}

/// Map seam [`TrafficTarget`]s (revision_id + integer percent) onto Cloud Run
/// `traffic[]`, each pinned to the *named* revision (never `LATEST`, plan D4).
fn build_traffic(
    deployment_id: DeploymentId,
    targets: &[TrafficTarget],
) -> Vec<run::TrafficTarget> {
    targets
        .iter()
        .map(|t| {
            run::TrafficTarget::new()
                .set_type(run::TrafficTargetAllocationType::Revision)
                .set_revision(revision_name(deployment_id, t.revision_id))
                .set_percent(clamp_i32(t.percent))
        })
        .collect()
}

/// Add or remove the `allUsers` → `roles/run.invoker` binding for the access mode
/// (plan D12), preserving every other binding. `Public` grants unauthenticated
/// access; `Authenticated` revokes it (idempotent either way).
fn apply_invoker_binding(mut policy: iam::Policy, access_mode: AccessMode) -> iam::Policy {
    const INVOKER_ROLE: &str = "roles/run.invoker";
    const ALL_USERS: &str = "allUsers";

    // Drop any existing allUsers member from the invoker binding first, so both
    // arms start from a known state.
    for binding in &mut policy.bindings {
        if binding.role == INVOKER_ROLE {
            binding.members.retain(|m| m != ALL_USERS);
        }
    }
    policy
        .bindings
        .retain(|b| b.role != INVOKER_ROLE || !b.members.is_empty());

    if access_mode == AccessMode::Public {
        if let Some(binding) = policy.bindings.iter_mut().find(|b| b.role == INVOKER_ROLE) {
            binding.members.push(ALL_USERS.to_string());
        } else {
            policy.bindings.push(
                iam::Binding::new()
                    .set_role(INVOKER_ROLE)
                    .set_members([ALL_USERS.to_string()]),
            );
        }
    }
    policy
}

fn new_automatic_secret() -> sm::Secret {
    sm::Secret::new()
        .set_replication(sm::Replication::new().set_automatic(sm::replication::Automatic::new()))
}

fn ownership_labels(deployment_id: DeploymentId) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL_KEY.to_string(), "true".to_string()),
        (
            DEPLOYMENT_LABEL_KEY.to_string(),
            deployment_id.0.to_string().to_lowercase(),
        ),
    ])
}

// ---- Pure response parsers (unit-tested; no HTTP) ----

/// Project a live [`run::Service`] onto the seam [`ServiceStatus`].
fn service_status_from(svc: &run::Service) -> ServiceStatus {
    ServiceStatus {
        ready: service_ready(svc),
        url: non_empty(svc.uri.clone()),
        traffic: traffic_targets_from(&svc.traffic),
        etag: svc.etag.clone(),
    }
}

/// Recover seam [`TrafficTarget`]s from Cloud Run's `traffic[]`. Only entries
/// pinned to a *named* revision whose name parses back to a `RevisionId` are
/// kept — `LATEST`-type or foreign entries are dropped (they are not ours to
/// preserve across a warm).
fn traffic_targets_from(traffic: &[run::TrafficTarget]) -> Vec<TrafficTarget> {
    traffic
        .iter()
        .filter_map(|t| {
            parse_revision_id_from_name(&t.revision).map(|revision_id| TrafficTarget {
                revision_id,
                percent: t.percent.max(0) as u32,
            })
        })
        .collect()
}

fn revision_status_from(rev: &run::Revision) -> RevisionStatus {
    let ready = condition_ready(&rev.conditions);
    RevisionStatus {
        ready,
        // A revision that reports Ready is serving; nothing downstream reads
        // `active` independently, so mirror readiness.
        active: ready,
    }
}

/// A Service is ready when its terminal condition (or a `Ready` condition) has
/// reached `ConditionSucceeded`.
fn service_ready(svc: &run::Service) -> bool {
    if let Some(term) = &svc.terminal_condition
        && term.state == run::condition::State::ConditionSucceeded
    {
        return true;
    }
    condition_ready(&svc.conditions)
}

fn condition_ready(conditions: &[run::Condition]) -> bool {
    conditions
        .iter()
        .any(|c| c.r#type == "Ready" && c.state == run::condition::State::ConditionSucceeded)
}

/// Extract the numeric version id from a Secret Manager version resource name
/// (`projects/P/secrets/S/versions/5` → `5`). The whole name is kept when it has
/// no `/` (defensive; the SDK always returns the full path).
fn numeric_version_from(name: &str) -> String {
    name.rsplit('/').next().unwrap_or(name).to_string()
}

/// Recover a [`RevisionId`] from a Cloud Run revision name produced by
/// [`revision_name`] (`gtc-svc-{dep}-{rev}` → `{rev}`). Case-insensitive: the
/// deployer lowercases ULIDs for DNS-safety, so re-upper before decoding. Returns
/// `None` for any name that does not end in a valid ULID segment.
fn parse_revision_id_from_name(name: &str) -> Option<RevisionId> {
    let tail = name.rsplit('-').next()?;
    Ulid::from_string(&tail.to_uppercase()).ok().map(RevisionId)
}

// ---- Error classification (unit-tested) ----

/// Map a Cloud Run / Secret Manager SDK error onto the seam error. A stale-etag
/// conflict (`ABORTED` / `FAILED_PRECONDITION`, or HTTP 409/412) becomes
/// [`CloudRunTargetError::PreconditionFailed`] so the deployer re-reads; a
/// missing resource becomes [`CloudRunTargetError::NotFound`]; everything else is
/// an opaque [`CloudRunTargetError::Api`].
fn classify(op: &str, err: &GaxError) -> CloudRunTargetError {
    if is_precondition(err) {
        return CloudRunTargetError::PreconditionFailed;
    }
    if is_not_found(err) {
        return CloudRunTargetError::NotFound(format!("{op}: {err}"));
    }
    CloudRunTargetError::Api(format!("{op}: {err}"))
}

fn is_not_found(err: &GaxError) -> bool {
    if let Some(status) = err.status()
        && status.code == Code::NotFound
    {
        return true;
    }
    err.http_status_code() == Some(404)
}

fn is_precondition(err: &GaxError) -> bool {
    if let Some(status) = err.status()
        && matches!(status.code, Code::Aborted | Code::FailedPrecondition)
    {
        return true;
    }
    matches!(err.http_status_code(), Some(409) | Some(412))
}

// ---- Small conversions ----

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

/// Cloud Run scaling/percent fields are `i32`; the seam carries `u32`. Values are
/// small (0..=100 percent, single-digit instance counts), so clamp defensively
/// rather than risk a wrap.
fn clamp_i32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

fn bytes_from(payload: &[u8]) -> bytes::Bytes {
    bytes::Bytes::copy_from_slice(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::gcp_cloudrun::deploy_target::{ScalingSpec, SecretMount};

    fn dep(seed: u128) -> DeploymentId {
        DeploymentId(Ulid::from(seed))
    }
    fn rev(seed: u128) -> RevisionId {
        RevisionId(Ulid::from(seed))
    }

    fn spec(traffic: Vec<TrafficTarget>, secrets: Vec<SecretMount>) -> ServiceSpec {
        ServiceSpec {
            deployment_id: dep(1),
            project: "greentic-local".to_string(),
            region: "us-central1".to_string(),
            image: "ghcr.io/greenticai/greentic-start-distroless:develop".to_string(),
            revision_id: rev(1),
            runtime_service_account: "gtc-local-runtime@greentic-local.iam.gserviceaccount.com"
                .to_string(),
            traffic,
            scaling: ScalingSpec {
                cpu: "1".to_string(),
                memory: "512Mi".to_string(),
                min_instances: 0,
                max_instances: 1,
                concurrency: 80,
            },
            access_mode: AccessMode::Public,
            session_affinity: true,
            secrets,
        }
    }

    #[test]
    fn build_service_maps_template_traffic_scaling_and_sa() {
        let s = spec(
            vec![TrafficTarget {
                revision_id: rev(1),
                percent: 100,
            }],
            vec![],
        );
        let msg = build_service_message(&s, None);
        assert_eq!(msg.ingress, run::IngressTraffic::All);
        assert_eq!(msg.etag, "", "create carries no etag");

        let template = msg.template.expect("template set");
        assert_eq!(
            template.revision,
            revision_name(dep(1), rev(1)),
            "custom revision name pins the revision identity",
        );
        assert_eq!(
            template.service_account, "gtc-local-runtime@greentic-local.iam.gserviceaccount.com",
            "the resolved runtime SA is threaded to the revision (D7)",
        );
        assert!(template.session_affinity, "session affinity on (D11)");
        assert_eq!(template.max_instance_request_concurrency, 80);

        let scaling = template.scaling.expect("scaling set");
        assert_eq!(scaling.min_instance_count, 0, "scale-to-zero (D5)");
        assert_eq!(scaling.max_instance_count, 1, "single writer (D6)");

        let container = &template.containers[0];
        assert_eq!(
            container.image,
            "ghcr.io/greenticai/greentic-start-distroless:develop"
        );
        let resources = container.resources.as_ref().expect("resources set");
        assert!(resources.cpu_idle, "request-based billing (D5)");
        assert!(resources.startup_cpu_boost);
        assert_eq!(resources.limits.get("cpu").map(String::as_str), Some("1"));
        assert_eq!(
            resources.limits.get("memory").map(String::as_str),
            Some("512Mi")
        );

        assert_eq!(msg.traffic.len(), 1);
        assert_eq!(
            msg.traffic[0].r#type,
            run::TrafficTargetAllocationType::Revision
        );
        assert_eq!(msg.traffic[0].revision, revision_name(dep(1), rev(1)));
        assert_eq!(msg.traffic[0].percent, 100);
        assert!(msg.traffic[0].revision != "LATEST", "never LATEST (D4)");

        assert_eq!(
            msg.labels.get(MANAGED_LABEL_KEY).map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn build_service_stamps_etag_on_update() {
        let s = spec(vec![], vec![]);
        let msg = build_service_message(&s, Some("etag-7"));
        assert_eq!(msg.etag, "etag-7", "update carries the precondition etag");
    }

    #[test]
    fn build_container_maps_secret_mounts_to_env_sources() {
        let s = spec(
            vec![],
            vec![SecretMount {
                env_var: "GTC_DB_PASSWORD".to_string(),
                secret_name: "gtc-local-dev-secrets".to_string(),
                version: "5".to_string(),
            }],
        );
        let c = build_container(&s);
        let env = c
            .env
            .iter()
            .find(|e| e.name == "GTC_DB_PASSWORD")
            .expect("env var");
        let source = env.value_source().expect("secret source");
        let selector = source.secret_key_ref.as_ref().expect("secret key ref");
        assert_eq!(selector.secret, "gtc-local-dev-secrets");
        assert_eq!(
            selector.version, "5",
            "pinned to the numeric version, never latest"
        );
    }

    #[test]
    fn build_traffic_pins_named_revisions() {
        let targets = vec![
            TrafficTarget {
                revision_id: rev(1),
                percent: 60,
            },
            TrafficTarget {
                revision_id: rev(2),
                percent: 40,
            },
        ];
        let built = build_traffic(dep(1), &targets);
        assert_eq!(built.len(), 2);
        for t in &built {
            assert_eq!(t.r#type, run::TrafficTargetAllocationType::Revision);
            assert!(t.revision.starts_with("gtc-svc-"));
        }
        assert_eq!(built[0].percent, 60);
        assert_eq!(built[1].percent, 40);
    }

    #[test]
    fn traffic_round_trips_through_revision_names() {
        // The deployer preserves existing traffic by revision_id across a warm,
        // so build_traffic and traffic_targets_from must be inverses.
        let original = vec![
            TrafficTarget {
                revision_id: rev(1),
                percent: 70,
            },
            TrafficTarget {
                revision_id: rev(2),
                percent: 30,
            },
        ];
        let run_traffic = build_traffic(dep(1), &original);
        let recovered = traffic_targets_from(&run_traffic);
        assert_eq!(
            recovered, original,
            "revision_id survives the name round-trip"
        );
    }

    #[test]
    fn traffic_targets_from_drops_latest_and_foreign_entries() {
        let traffic = vec![
            run::TrafficTarget::new()
                .set_type(run::TrafficTargetAllocationType::Latest)
                .set_percent(100),
            run::TrafficTarget::new()
                .set_type(run::TrafficTargetAllocationType::Revision)
                .set_revision("not-a-gtc-name")
                .set_percent(50),
        ];
        assert!(
            traffic_targets_from(&traffic).is_empty(),
            "LATEST + unparseable revisions are not ours to preserve"
        );
    }

    #[test]
    fn parse_revision_id_is_inverse_of_revision_name() {
        let name = revision_name(dep(1), rev(42));
        assert_eq!(parse_revision_id_from_name(&name), Some(rev(42)));
        assert_eq!(parse_revision_id_from_name("garbage"), None);
    }

    #[test]
    fn numeric_version_extracts_trailing_segment() {
        assert_eq!(
            numeric_version_from("projects/p/secrets/s/versions/12"),
            "12"
        );
        assert_eq!(numeric_version_from("7"), "7");
    }

    #[test]
    fn invoker_binding_public_adds_all_users_once() {
        let policy = apply_invoker_binding(iam::Policy::new(), AccessMode::Public);
        let invoker = policy
            .bindings
            .iter()
            .find(|b| b.role == "roles/run.invoker")
            .expect("invoker binding");
        assert_eq!(invoker.members, vec!["allUsers".to_string()]);

        // Idempotent: applying Public again does not duplicate the member.
        let again = apply_invoker_binding(policy, AccessMode::Public);
        let invoker = again
            .bindings
            .iter()
            .find(|b| b.role == "roles/run.invoker")
            .expect("invoker binding");
        assert_eq!(invoker.members, vec!["allUsers".to_string()]);
    }

    #[test]
    fn invoker_binding_authenticated_revokes_all_users_and_keeps_others() {
        let seeded = iam::Policy::new().set_bindings([
            iam::Binding::new()
                .set_role("roles/run.invoker")
                .set_members(["allUsers".to_string()]),
            iam::Binding::new()
                .set_role("roles/run.admin")
                .set_members(["user:admin@example.com".to_string()]),
        ]);
        let locked = apply_invoker_binding(seeded, AccessMode::Authenticated);
        assert!(
            !locked
                .bindings
                .iter()
                .any(|b| b.role == "roles/run.invoker"),
            "empty invoker binding is dropped, not left dangling"
        );
        assert!(
            locked.bindings.iter().any(|b| b.role == "roles/run.admin"),
            "unrelated bindings are preserved"
        );
    }

    #[test]
    fn service_ready_reads_terminal_and_ready_conditions() {
        let mut svc = run::Service::new();
        assert!(!service_ready(&svc), "no conditions → not ready");
        svc.terminal_condition = Some(
            run::Condition::new()
                .set_type("Ready")
                .set_state(run::condition::State::ConditionSucceeded),
        );
        assert!(service_ready(&svc), "terminal Ready=Succeeded → ready");
    }

    #[test]
    fn real_target_iam_permissions_are_a_subset_of_validated() {
        use crate::env_packs::gcp_cloudrun::credentials::VALIDATED_GCP_PERMISSIONS;
        for perm in REAL_CLOUDRUN_TARGET_IAM_PERMISSIONS {
            assert!(
                VALIDATED_GCP_PERMISSIONS.contains(perm),
                "real target uses `{perm}` but the credentials preflight does not validate it",
            );
        }
    }
}
