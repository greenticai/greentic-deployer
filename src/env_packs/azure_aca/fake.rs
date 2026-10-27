//! In-memory [`AcaDeployTarget`] enforcing the platform rules the verbs rely on.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;

use super::arm_body::OWNER_TAG;
use super::arm_types::{AppSecret, AppSpec, EnvEntry, TrafficEntry};
use super::deploy_target::{
    AcaDeployTarget, AcaTargetError, AppRef, AppState, RevisionRef, RevisionStatus,
};
use super::naming::revision_name;
use super::revision_intent::{INTENT_ENV, LiveIntent};

#[derive(Debug, Clone)]
struct FakeRevision {
    intent: Option<String>,
    status: RevisionStatus,
    /// Secret names the revision's env refers to.
    secret_refs: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct FakeApp {
    owner: Option<String>,
    secrets: Vec<AppSecret>,
    traffic: Vec<TrafficEntry>,
    revisions: BTreeMap<String, FakeRevision>,
}

/// Test double. Revisions become `Running` immediately unless a failure is queued.
#[derive(Debug, Default)]
pub(crate) struct InMemoryAca {
    apps: Mutex<BTreeMap<String, FakeApp>>,
    fail_next_revision: Mutex<Option<String>>,
    calls: Mutex<Vec<String>>,
}

fn poisoned() -> AcaTargetError {
    AcaTargetError::Unavailable("in-memory target lock poisoned".to_string())
}

impl InMemoryAca {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The next revision created reports `Failed { reason }`.
    pub(crate) fn fail_next_revision(&self, reason: &str) {
        if let Ok(mut g) = self.fail_next_revision.lock() {
            *g = Some(reason.to_string());
        }
    }

    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub(crate) fn app_names(&self) -> Vec<String> {
        self.apps.lock().map(|g| g.keys().cloned().collect()).unwrap_or_default()
    }

    pub(crate) fn revisions_of(&self, app: &str) -> Vec<String> {
        self.apps
            .lock()
            .ok()
            .and_then(|g| g.get(app).map(|a| a.revisions.keys().cloned().collect()))
            .unwrap_or_default()
    }

    pub(crate) fn traffic_of(&self, app: &str) -> Vec<TrafficEntry> {
        self.apps
            .lock()
            .ok()
            .and_then(|g| g.get(app).map(|a| a.traffic.clone()))
            .unwrap_or_default()
    }

    pub(crate) fn secret_names_of(&self, app: &str) -> Vec<String> {
        self.apps
            .lock()
            .ok()
            .and_then(|g| g.get(app).map(|a| a.secrets.iter().map(|s| s.name.clone()).collect()))
            .unwrap_or_default()
    }

    /// Seed an app owned by `owner` (to test foreign-owner refusals).
    pub(crate) fn seed_app(&self, name: &str, owner: Option<&str>) {
        if let Ok(mut g) = self.apps.lock() {
            g.insert(
                name.to_string(),
                FakeApp { owner: owner.map(str::to_string), ..FakeApp::default() },
            );
        }
    }

    fn record(&self, call: String) {
        if let Ok(mut g) = self.calls.lock() {
            g.push(call);
        }
    }
}

fn secret_refs(spec: &AppSpec) -> Vec<String> {
    let mut refs = Vec::new();
    let init_env = spec.revision.init.iter().flat_map(|i| i.env.iter());
    for e in spec.revision.env.iter().chain(init_env) {
        if let EnvEntry::SecretRef { secret, .. } = e {
            refs.push(secret.clone());
        }
    }
    refs
}

fn intent_of(spec: &AppSpec) -> Option<String> {
    spec.revision.env.iter().find_map(|e| match e {
        EnvEntry::Plain { name, value } if name == INTENT_ENV => Some(value.clone()),
        _ => None,
    })
}

#[async_trait]
impl AcaDeployTarget for InMemoryAca {
    async fn inspect_app(&self, app: &AppRef) -> Result<AppState, AcaTargetError> {
        self.record(format!("inspect_app:{}", app.name));
        let g = self.apps.lock().map_err(|_| poisoned())?;
        Ok(match g.get(&app.name) {
            None => AppState::Absent,
            Some(a) => AppState::Present { owner: a.owner.clone(), traffic: a.traffic.clone() },
        })
    }

    async fn list_secrets(&self, app: &AppRef) -> Result<Vec<AppSecret>, AcaTargetError> {
        self.record(format!("list_secrets:{}", app.name));
        let g = self.apps.lock().map_err(|_| poisoned())?;
        Ok(g.get(&app.name).map(|a| a.secrets.clone()).unwrap_or_default())
    }

    async fn put_revision(&self, spec: &AppSpec) -> Result<RevisionRef, AcaTargetError> {
        let app = AppRef { name: spec.name.as_str().to_string() };
        let name = revision_name(&spec.name, &spec.revision.suffix);
        self.record(format!("put_revision:{name}"));
        let total: u32 = spec.traffic.iter().map(|t| t.weight).sum();
        if !spec.traffic.is_empty() && total != 100 {
            return Err(AcaTargetError::Api(format!("traffic sums to {total}, not 100")));
        }
        let mut g = self.apps.lock().map_err(|_| poisoned())?;
        let entry = g.entry(app.name.clone()).or_default();
        let incoming_owner = spec.tags.iter().find(|(k, _)| k == OWNER_TAG).map(|(_, v)| v.clone());
        if entry.owner.is_some() && entry.owner != incoming_owner {
            return Err(AcaTargetError::Conflict(format!("app `{}` has another owner", app.name)));
        }
        entry.owner = incoming_owner;
        let new_intent = intent_of(spec);
        if let Some(existing) = entry.revisions.get(&name) {
            if existing.intent == new_intent {
                return Ok(RevisionRef { app, name });
            }
            return Err(AcaTargetError::Conflict(format!(
                "revision `{name}` is immutable and holds another configuration"
            )));
        }
        // A whole-app PUT replaces the secret set: dropping one a non-inactive
        // revision references is refused.
        for (rev_name, rev) in &entry.revisions {
            if rev.status == RevisionStatus::Inactive {
                continue;
            }
            for s in &rev.secret_refs {
                if !spec.secrets.iter().any(|x| &x.name == s) {
                    return Err(AcaTargetError::Conflict(format!(
                        "secret `{s}` is still referenced by revision `{rev_name}`"
                    )));
                }
            }
        }
        let status = match self.fail_next_revision.lock().map_err(|_| poisoned())?.take() {
            Some(reason) => RevisionStatus::Failed { reason },
            None => RevisionStatus::Running { replicas: spec.revision.min_replicas },
        };
        entry.secrets = spec.secrets.clone();
        entry.traffic = spec.traffic.clone();
        entry.revisions.insert(
            name.clone(),
            FakeRevision { intent: new_intent, status, secret_refs: secret_refs(spec) },
        );
        Ok(RevisionRef { app, name })
    }

    async fn live_revision_intent(&self, rev: &RevisionRef) -> Result<LiveIntent, AcaTargetError> {
        self.record(format!("live_revision_intent:{}", rev.name));
        let g = self.apps.lock().map_err(|_| poisoned())?;
        Ok(match g.get(&rev.app.name).and_then(|a| a.revisions.get(&rev.name)) {
            None => LiveIntent::Absent,
            Some(r) => LiveIntent::Present { intent: r.intent.clone() },
        })
    }

    async fn revision_status(&self, rev: &RevisionRef) -> Result<RevisionStatus, AcaTargetError> {
        let g = self.apps.lock().map_err(|_| poisoned())?;
        Ok(g.get(&rev.app.name)
            .and_then(|a| a.revisions.get(&rev.name))
            .map(|r| r.status.clone())
            .unwrap_or(RevisionStatus::Absent))
    }

    async fn set_traffic(
        &self,
        app: &AppRef,
        weights: &[TrafficEntry],
    ) -> Result<(), AcaTargetError> {
        self.record(format!("set_traffic:{}", app.name));
        let total: u32 = weights.iter().map(|t| t.weight).sum();
        if total != 100 {
            return Err(AcaTargetError::Api(format!("traffic sums to {total}, not 100")));
        }
        let mut g = self.apps.lock().map_err(|_| poisoned())?;
        let a = g
            .get_mut(&app.name)
            .ok_or_else(|| AcaTargetError::Api(format!("app `{}` does not exist", app.name)))?;
        for w in weights {
            if !a.revisions.contains_key(&w.revision_name) {
                return Err(AcaTargetError::Api(format!(
                    "traffic names unknown revision `{}`",
                    w.revision_name
                )));
            }
        }
        a.traffic = weights.to_vec();
        Ok(())
    }

    async fn deactivate_revision(&self, rev: &RevisionRef) -> Result<(), AcaTargetError> {
        self.record(format!("deactivate_revision:{}", rev.name));
        let mut g = self.apps.lock().map_err(|_| poisoned())?;
        if let Some(r) = g.get_mut(&rev.app.name).and_then(|a| a.revisions.get_mut(&rev.name)) {
            r.status = RevisionStatus::Inactive;
        }
        Ok(())
    }

    async fn delete_app(&self, app: &AppRef) -> Result<bool, AcaTargetError> {
        self.record(format!("delete_app:{}", app.name));
        let mut g = self.apps.lock().map_err(|_| poisoned())?;
        Ok(g.remove(&app.name).is_some())
    }

    async fn discover_endpoint(&self, app: &AppRef) -> Result<Option<String>, AcaTargetError> {
        let g = self.apps.lock().map_err(|_| poisoned())?;
        Ok(g.contains_key(&app.name)
            .then(|| format!("https://{}.example.southeastasia.azurecontainerapps.io", app.name)))
    }
}

#[cfg(test)]
#[path = "fake_tests.rs"]
mod tests;
