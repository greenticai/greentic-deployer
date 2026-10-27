//! The warm verb: ensure the app, stage content-addressed secrets, create one
//! immutable revision with an explicit traffic list, wait until it runs.

use std::time::Duration;

use greentic_deploy_spec::{Environment, Revision, RevisionId};
use tokio::time::{Instant, sleep};

use super::AzureAcaDeployerHandler;
use super::arm_body::{OWNER_TAG, secrets_with_values};
use super::arm_types::{AppSecret, AppSpec, EnvEntry, InitSpec, RevisionSpec, TrafficEntry};
use super::boot_env::aca_boot_env;
use super::deploy_target::{
    AcaDeployTarget, AcaTargetError, AppRef, AppState, RevisionRef, RevisionStatus,
};
use super::naming::{app_name, revision_name, revision_suffix};
use super::params::AcaParams;
use super::registry_credential::OCI_PASSWORD_ENV;
use super::revision_intent::{
    INTENT_ENV, IntentInputs, IntentVerdict, classify, revision_conflict, revision_intent,
};
use super::seed::{
    DEV_STORE_FILE, ENVIRONMENT_SEED_FILE, SEED_INIT_IMAGE, SeedFile, check_value, content_var,
    file_secret_name, init_script, seed_secret_name, sha_var, sha256_hex, validate_seed,
};
use super::sizing;
use crate::env_packs::deployer::{DeployerError, WarmOutcome};
use crate::env_packs::owner_stamp::env_owner_stamp;
use crate::env_packs::telemetry::HEADER_ENV_NAMES;
use crate::environment::seed::seed_environment_bytes;

pub(crate) const TARGET_PORT: u16 = 8080;
const WARM_TIMEOUT: Duration = Duration::from_secs(300);
const WARM_TIMEOUT_ENV: &str = "GREENTIC_AZURE_ACA_WARM_READY_TIMEOUT_SECS";

pub(crate) fn provider(e: AcaTargetError) -> DeployerError {
    DeployerError::Provider(e.to_string())
}

pub(crate) fn warm_timeout() -> Duration {
    std::env::var(WARM_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(WARM_TIMEOUT)
}

/// Merge staged secrets into the app's existing ones (the `NEEDS_LIVE` choice:
/// full re-send rather than a partial PATCH).
pub(crate) fn merge_secrets(
    existing: &[AppSecret],
    add: &[AppSecret],
) -> Result<Vec<AppSecret>, DeployerError> {
    secrets_with_values(existing, add).map_err(|e| DeployerError::Provider(e.to_string()))
}

/// Traffic for the revision being created: the first revision takes 100; a later
/// one takes 0 and every earlier revision keeps its weight.
pub(crate) fn traffic_for_new(previous: &[TrafficEntry], new_name: &str) -> Vec<TrafficEntry> {
    let mut out: Vec<TrafficEntry> = previous.to_vec();
    if out.iter().any(|t| t.revision_name == new_name) {
        return out;
    }
    let total: u32 = out.iter().map(|t| t.weight).sum();
    if out.is_empty() || total == 0 {
        for t in &mut out {
            t.weight = 0;
        }
        out.push(TrafficEntry {
            revision_name: new_name.to_string(),
            weight: 100,
        });
    } else {
        out.push(TrafficEntry {
            revision_name: new_name.to_string(),
            weight: 0,
        });
    }
    out
}

pub(crate) async fn wait_running(
    target: &dyn AcaDeployTarget,
    rev: &RevisionRef,
    timeout: Duration,
    poll: Duration,
) -> Result<(), DeployerError> {
    let deadline = Instant::now() + timeout;
    loop {
        match target.revision_status(rev).await.map_err(provider)? {
            RevisionStatus::Running { .. } => return Ok(()),
            RevisionStatus::Failed { reason } => {
                return Err(DeployerError::Provider(format!(
                    "Container Apps revision `{}` failed to start: {reason}",
                    rev.name
                )));
            }
            RevisionStatus::Inactive => {
                return Err(DeployerError::Provider(format!(
                    "Container Apps revision `{}` is inactive",
                    rev.name
                )));
            }
            RevisionStatus::Provisioning | RevisionStatus::Absent => {}
        }
        if Instant::now() >= deadline {
            return Err(DeployerError::Provider(format!(
                "Container Apps revision `{}` did not become ready within {}s",
                rev.name,
                timeout.as_secs()
            )));
        }
        sleep(poll).await;
    }
}

fn seed_files(
    env: &Environment,
    revision_id: RevisionId,
    dev_secrets: Option<&[u8]>,
) -> Result<Vec<SeedFile>, DeployerError> {
    let environment_json = seed_environment_bytes(env, &[revision_id]).map_err(|e| {
        DeployerError::Provider(format!(
            "serializing environment.json for seed staging: {e}"
        ))
    })?;
    let mut files = vec![SeedFile {
        name: ENVIRONMENT_SEED_FILE.to_string(),
        bytes: environment_json,
    }];
    if let Some(dev) = dev_secrets {
        files.push(SeedFile {
            name: DEV_STORE_FILE.to_string(),
            bytes: dev.to_vec(),
        });
    }
    for f in &files {
        validate_seed(f).map_err(|e| DeployerError::Provider(e.to_string()))?;
    }
    Ok(files)
}

/// Everything one warm intends, computed before any ARM write.
struct Plan {
    spec_secrets: Vec<AppSecret>,
    env: Vec<EnvEntry>,
    init: InitSpec,
    intent: String,
}

fn plan(
    env: &Environment,
    revision: &Revision,
    params: &AcaParams,
    files: &[SeedFile],
    image: &str,
    res: &sizing::Resources,
) -> Result<Plan, DeployerError> {
    let refuse = |e: super::seed::SeedError| DeployerError::Provider(e.to_string());
    let boot_env = aca_boot_env(env, revision, params);
    let mut secrets: Vec<AppSecret> = Vec::new();
    let mut seed_names: Vec<String> = Vec::new();
    let mut init_env: Vec<EnvEntry> = Vec::new();
    for f in files {
        let name = file_secret_name(f);
        secrets.push(AppSecret::new(&name, String::from_utf8_lossy(&f.bytes)));
        init_env.push(EnvEntry::secret_ref(content_var(f), &name));
        init_env.push(EnvEntry::plain(sha_var(f), sha256_hex(&f.bytes)));
        seed_names.push(name);
    }
    let script = init_script(files).map_err(refuse)?;
    let mut secret_env: Vec<EnvEntry> = Vec::new();
    if let Some(h) = params.telemetry.headers() {
        check_value("telemetry headers", h.expose().as_bytes()).map_err(refuse)?;
        let name = seed_secret_name("telemetry", h.expose().as_bytes());
        secrets.push(AppSecret::new(&name, h.expose()));
        for n in HEADER_ENV_NAMES {
            secret_env.push(EnvEntry::secret_ref(n, &name));
        }
        seed_names.push(name);
    }
    if let Some(r) = &params.registry {
        check_value("registry password", r.password().expose().as_bytes()).map_err(refuse)?;
        let name = seed_secret_name("oci-pw", r.password().expose().as_bytes());
        secrets.push(AppSecret::new(&name, r.password().expose()));
        secret_env.push(EnvEntry::secret_ref(OCI_PASSWORD_ENV, &name));
        seed_names.push(name);
    }
    let secret_env_names: Vec<&str> = secret_env.iter().map(EnvEntry::name).collect();
    let intent = revision_intent(&IntentInputs {
        image,
        cpu: &res.cpu.to_string(),
        memory: &res.memory,
        min_replicas: params.min_instances,
        max_replicas: params.max_instances,
        seed_secrets: &seed_names,
        boot_env: &boot_env,
        secret_env_names: &secret_env_names,
        seed_init_image: SEED_INIT_IMAGE,
    });
    let mut env_entries: Vec<EnvEntry> = boot_env
        .iter()
        .map(|(k, v)| EnvEntry::plain(k, v))
        .collect();
    env_entries.extend(secret_env);
    env_entries.push(EnvEntry::plain(INTENT_ENV, &intent));
    Ok(Plan {
        spec_secrets: secrets,
        env: env_entries,
        init: InitSpec {
            image: SEED_INIT_IMAGE.to_string(),
            script,
            env: init_env,
        },
        intent,
    })
}

impl AzureAcaDeployerHandler {
    pub(crate) async fn warm(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        params: &AcaParams,
        timeout: Duration,
        poll: Duration,
    ) -> Result<WarmOutcome, DeployerError> {
        let revision = env
            .revisions
            .iter()
            .find(|r| r.revision_id == revision_id)
            .ok_or_else(|| DeployerError::RevisionNotFound {
                env_id: env.environment_id.clone(),
                revision_id,
            })?;
        let files = seed_files(
            env,
            revision_id,
            self.dev_secrets.as_ref().map(super::DevSecrets::as_bytes),
        )?;
        let image = params.runtime_image_for(revision.runtime_image_digest.as_deref());
        let res = sizing::snap(params.cpu.as_deref(), params.memory.as_deref())
            .map_err(|e| DeployerError::Provider(format!("invalid answers: {e}")))?;
        let plan = plan(env, revision, params, &files, &image, &res)?;

        let name = app_name(&revision.deployment_id);
        let suffix = revision_suffix(&revision_id);
        let rev_name = revision_name(&name, &suffix);
        let app = AppRef {
            name: name.as_str().to_string(),
        };
        let rev_ref = RevisionRef {
            app: app.clone(),
            name: rev_name.clone(),
        };
        let ours = env_owner_stamp(env.environment_id.as_str());

        let previous = match self.target.inspect_app(&app).await.map_err(provider)? {
            AppState::Absent => Vec::new(),
            AppState::Present { owner, traffic } => {
                if owner.as_deref() != Some(ours.as_str()) {
                    return Err(DeployerError::Provider(foreign_owner(
                        &app.name,
                        owner.as_deref(),
                    )));
                }
                traffic
            }
        };

        let live = self
            .target
            .live_revision_intent(&rev_ref)
            .await
            .map_err(provider)?;
        match classify(live, &plan.intent) {
            IntentVerdict::Converge => {}
            IntentVerdict::Conflict { live } => {
                return Err(revision_conflict(revision_id, &plan.intent, live));
            }
            IntentVerdict::Create => {
                let existing = self.target.list_secrets(&app).await.map_err(provider)?;
                let secrets = merge_secrets(&existing, &plan.spec_secrets)?;
                let spec = AppSpec {
                    name: name.clone(),
                    location: params.location.clone(),
                    environment_id: params.managed_environment_id(),
                    tags: vec![(OWNER_TAG.to_string(), ours)],
                    target_port: TARGET_PORT,
                    secrets,
                    traffic: traffic_for_new(&previous, &rev_name),
                    revision: RevisionSpec {
                        suffix,
                        image,
                        cpu: res.cpu,
                        memory: res.memory,
                        env: plan.env,
                        init: Some(plan.init),
                        min_replicas: params.min_instances,
                        max_replicas: params.max_instances,
                    },
                };
                self.target.put_revision(&spec).await.map_err(provider)?;
                // A rival warm that created this revision between the probe and
                // the PUT would otherwise be adopted silently.
                let after = self
                    .target
                    .live_revision_intent(&rev_ref)
                    .await
                    .map_err(provider)?;
                if let IntentVerdict::Conflict { live } = classify(after, &plan.intent) {
                    return Err(revision_conflict(revision_id, &plan.intent, live));
                }
            }
        }
        wait_running(self.target.as_ref(), &rev_ref, timeout, poll).await?;
        let endpoint_url = self
            .target
            .discover_endpoint(&app)
            .await
            .map_err(provider)?;
        Ok(WarmOutcome { endpoint_url })
    }
}

pub(crate) fn foreign_owner(app: &str, owner: Option<&str>) -> String {
    let held = match owner {
        Some(o) => format!("belongs to `{o}`"),
        None => format!("carries no `{OWNER_TAG}` tag"),
    };
    format!(
        "Container App `{app}` {held}, not to this environment; the deployer only writes apps it \
         created for this environment"
    )
}
