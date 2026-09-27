//! In-memory [`SorServiceTarget`] for unit tests. Readiness is decided when a
//! service is upserted: ready, failed with a reason, or still reconciling.
//!
//! Services are keyed by `(project, region, name)`, as Cloud Run keys them: a
//! unit that moved region leaves a same-named service behind in the old one.
//! The name-only helpers address the place every test fixture deploys to,
//! [`FAKE_PROJECT`] / [`FAKE_REGION`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;

use super::target::{
    ArRepository, SorServiceRef, SorServiceSpec, SorServiceStatus, SorServiceTarget,
};
use crate::env_packs::gcp_cloudrun::deploy_target::CloudRunTargetError;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Boot {
    Fails(String),
    Stalls,
}

/// The project the name-only helpers address.
pub const FAKE_PROJECT: &str = "proj";
/// The region the name-only helpers address.
pub const FAKE_REGION: &str = "europe-west1";

/// `(project, region, name)`.
type Place = (String, String, String);

fn place_of(service: &SorServiceRef) -> Place {
    (
        service.project.clone(),
        service.region.clone(),
        service.name.clone(),
    )
}

fn place(project: &str, region: &str, name: &str) -> Place {
    (project.to_string(), region.to_string(), name.to_string())
}

fn default_place(name: &str) -> Place {
    place(FAKE_PROJECT, FAKE_REGION, name)
}

#[derive(Debug, Default)]
pub struct InMemorySorServices {
    services: Mutex<BTreeMap<Place, SorServiceStatus>>,
    specs: Mutex<BTreeMap<Place, SorServiceSpec>>,
    /// By name, in every place.
    boot: Mutex<BTreeMap<String, Boot>>,
    public: Mutex<BTreeSet<Place>>,
    delete_refusal: Mutex<Option<String>>,
    ar_grants: Mutex<Vec<(String, String)>>,
    ar_refusal: Mutex<Option<String>>,
    upserts: Mutex<u32>,
    etag_counter: Mutex<u64>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl InMemorySorServices {
    /// The URL the fake assigns — the shape Cloud Run mints.
    pub fn url_for(name: &str) -> String {
        format!("https://{name}-abc123-ew.a.run.app")
    }
    /// Every upsert of `name` settles as failed with `reason`, until [`heal`]
    /// is called for `name`.
    ///
    /// [`heal`]: Self::heal
    pub fn fail_boot(&self, name: &str, reason: &str) {
        lock(&self.boot).insert(name.to_string(), Boot::Fails(reason.to_string()));
    }
    /// Every upsert of `name` never settles, until [`heal`] is called for
    /// `name`.
    ///
    /// [`heal`]: Self::heal
    pub fn stall_boot(&self, name: &str) {
        lock(&self.boot).insert(name.to_string(), Boot::Stalls);
    }
    /// Clears a previously configured [`fail_boot`]/[`stall_boot`] for `name`,
    /// so the next (and every later) upsert of `name` becomes ready.
    ///
    /// [`fail_boot`]: Self::fail_boot
    /// [`stall_boot`]: Self::stall_boot
    pub fn heal(&self, name: &str) {
        lock(&self.boot).remove(name);
    }
    pub fn refuse_ar_grants(&self, reason: &str) {
        *lock(&self.ar_refusal) = Some(reason.to_string());
    }
    /// Every delete fails with `reason` (an API error).
    pub fn refuse_deletes(&self, reason: &str) {
        *lock(&self.delete_refusal) = Some(reason.to_string());
    }
    /// A ready service at the default place, created by `owner` (or by nobody
    /// we know).
    pub fn seed_service(&self, name: &str, owner: Option<&str>) {
        self.seed_service_at(FAKE_PROJECT, FAKE_REGION, name, owner);
    }
    /// [`seed_service`](Self::seed_service) at an explicit place.
    pub fn seed_service_at(&self, project: &str, region: &str, name: &str, owner: Option<&str>) {
        let etag = self.next_etag();
        lock(&self.services).insert(
            place(project, region, name),
            SorServiceStatus {
                etag,
                owner: owner.map(str::to_string),
                intent: None,
                ready: true,
                reconciling: false,
                url: Some(Self::url_for(name)),
                not_ready_reason: None,
                log_uri: None,
            },
        );
    }
    pub fn service(&self, name: &str) -> Option<SorServiceStatus> {
        self.service_at(FAKE_PROJECT, FAKE_REGION, name)
    }
    pub fn service_at(&self, project: &str, region: &str, name: &str) -> Option<SorServiceStatus> {
        lock(&self.services)
            .get(&place(project, region, name))
            .cloned()
    }
    pub fn spec(&self, name: &str) -> Option<SorServiceSpec> {
        lock(&self.specs).get(&default_place(name)).cloned()
    }
    pub fn upserts(&self) -> u32 {
        *lock(&self.upserts)
    }
    pub fn is_public(&self, name: &str) -> bool {
        lock(&self.public).contains(&default_place(name))
    }
    pub fn ar_grants(&self) -> Vec<(String, String)> {
        lock(&self.ar_grants).clone()
    }
    fn next_etag(&self) -> String {
        let mut c = lock(&self.etag_counter);
        *c += 1;
        format!("etag-{c}")
    }
}

#[async_trait]
impl SorServiceTarget for InMemorySorServices {
    async fn get_sor_service(
        &self,
        service: &SorServiceRef,
    ) -> Result<Option<SorServiceStatus>, CloudRunTargetError> {
        Ok(lock(&self.services).get(&place_of(service)).cloned())
    }

    async fn upsert_sor_service(
        &self,
        spec: &SorServiceSpec,
        etag: Option<&str>,
    ) -> Result<SorServiceStatus, CloudRunTargetError> {
        let name = spec.service.name.clone();
        let key = place_of(&spec.service);
        match (lock(&self.services).get(&key), etag) {
            (Some(live), Some(sent)) if live.etag != sent => {
                return Err(CloudRunTargetError::PreconditionFailed);
            }
            (Some(_), None) => return Err(CloudRunTargetError::PreconditionFailed),
            (None, Some(_)) => {
                return Err(CloudRunTargetError::NotFound(format!("service `{name}`")));
            }
            _ => {}
        }
        let (ready, reconciling, not_ready_reason) = match lock(&self.boot).get(&name) {
            None => (true, false, None),
            Some(Boot::Fails(reason)) => (false, false, Some(reason.clone())),
            Some(Boot::Stalls) => (false, true, None),
        };
        let status = SorServiceStatus {
            etag: self.next_etag(),
            owner: Some(spec.labels.owner.clone()),
            intent: Some(spec.labels.intent.clone()),
            ready,
            reconciling,
            url: Some(Self::url_for(&name)),
            not_ready_reason,
            log_uri: None,
        };
        lock(&self.services).insert(key.clone(), status.clone());
        lock(&self.specs).insert(key, spec.clone());
        *lock(&self.upserts) += 1;
        Ok(status)
    }

    async fn set_sor_invoker_public(
        &self,
        service: &SorServiceRef,
    ) -> Result<(), CloudRunTargetError> {
        lock(&self.public).insert(place_of(service));
        Ok(())
    }

    async fn delete_sor_service(&self, service: &SorServiceRef) -> Result<(), CloudRunTargetError> {
        if let Some(reason) = lock(&self.delete_refusal).clone() {
            return Err(CloudRunTargetError::Api(reason));
        }
        let key = place_of(service);
        lock(&self.services).remove(&key);
        lock(&self.specs).remove(&key);
        lock(&self.public).remove(&key);
        Ok(())
    }

    async fn grant_artifact_registry_reader(
        &self,
        repo: &ArRepository,
        service_account: &str,
    ) -> Result<(), CloudRunTargetError> {
        if let Some(reason) = lock(&self.ar_refusal).clone() {
            return Err(CloudRunTargetError::Api(reason));
        }
        lock(&self.ar_grants).push((repo.resource(), service_account.to_string()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::gcp_cloudrun::deploy_target::ScalingSpec;
    use crate::env_packs::gcp_cloudrun::sor::target::{SorServiceLabels, SorServiceSpec};

    fn spec(name: &str) -> SorServiceSpec {
        SorServiceSpec {
            service: SorServiceRef {
                project: "proj".into(),
                region: "europe-west1".into(),
                name: name.into(),
            },
            image: "img".into(),
            args: vec![],
            port: 8787,
            runtime_service_account: "sa@proj.iam.gserviceaccount.com".into(),
            env: vec![],
            secret_env: vec![],
            secret_mounts: vec![],
            scaling: ScalingSpec {
                cpu: "1".into(),
                memory: "512Mi".into(),
                min_instances: 0,
                max_instances: 1,
                concurrency: 80,
            },
            health_path: "/healthz".into(),
            labels: SorServiceLabels {
                owner: "me".into(),
                unit_id: "u".into(),
                intent: "i1".into(),
            },
        }
    }

    #[tokio::test]
    async fn a_create_over_an_existing_service_and_a_stale_etag_are_preconditions() {
        let fake = InMemorySorServices::default();
        let created = fake
            .upsert_sor_service(&spec("gtc-sor-u"), None)
            .await
            .unwrap();
        assert!(matches!(
            fake.upsert_sor_service(&spec("gtc-sor-u"), None).await,
            Err(CloudRunTargetError::PreconditionFailed)
        ));
        assert!(matches!(
            fake.upsert_sor_service(&spec("gtc-sor-u"), Some("stale"))
                .await,
            Err(CloudRunTargetError::PreconditionFailed)
        ));
        fake.upsert_sor_service(&spec("gtc-sor-u"), Some(&created.etag))
            .await
            .unwrap();
        assert_eq!(fake.upserts(), 2);
    }

    #[tokio::test]
    async fn a_failing_boot_reports_its_reason_and_a_stalled_one_keeps_reconciling() {
        let fake = InMemorySorServices::default();
        fake.fail_boot("gtc-sor-a", "Image pull failed");
        let a = fake
            .upsert_sor_service(&spec("gtc-sor-a"), None)
            .await
            .unwrap();
        assert!(a.failed());
        assert_eq!(a.not_ready_reason.as_deref(), Some("Image pull failed"));
        fake.stall_boot("gtc-sor-b");
        let b = fake
            .upsert_sor_service(&spec("gtc-sor-b"), None)
            .await
            .unwrap();
        assert!(!b.ready && b.reconciling && !b.failed());
        let c = fake
            .upsert_sor_service(&spec("gtc-sor-c"), None)
            .await
            .unwrap();
        assert!(c.ready);
        assert_eq!(c.owner.as_deref(), Some("me"));
        assert_eq!(c.intent.as_deref(), Some("i1"));
        assert_eq!(c.url, Some(InMemorySorServices::url_for("gtc-sor-c")));
    }

    #[tokio::test]
    async fn a_refused_ar_grant_is_an_api_error_and_a_granted_one_is_recorded() {
        let fake = InMemorySorServices::default();
        let repo = ArRepository {
            project: "proj".into(),
            location: "europe-west1".into(),
            repository: "greentic".into(),
        };
        fake.grant_artifact_registry_reader(&repo, "sa")
            .await
            .unwrap();
        assert_eq!(
            fake.ar_grants(),
            vec![(
                "projects/proj/locations/europe-west1/repositories/greentic".to_string(),
                "sa".to_string()
            )]
        );
        fake.refuse_ar_grants("HTTP 403");
        assert!(matches!(
            fake.grant_artifact_registry_reader(&repo, "sa").await,
            Err(CloudRunTargetError::Api(_))
        ));
    }
}
