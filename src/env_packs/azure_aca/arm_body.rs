//! ARM request bodies for `Microsoft.App/containerApps` (pure, golden-tested).

use serde_json::{Value, json};

use super::arm_types::{
    AppSecret, AppSpec, EnvEntry, InitSpec, RevisionSpec, SecretConflict, TrafficEntry,
};
use super::seed::{SEED_INIT_CONTAINER, SEED_MOUNT_DIR, SEED_VOLUME};

pub(crate) const WORKER_CONTAINER: &str = "worker";
pub(crate) const OWNER_TAG: &str = "greentic:owner";

fn env_json(entries: &[EnvEntry]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|e| match e {
                EnvEntry::Plain { name, value } => json!({"name": name, "value": value}),
                EnvEntry::SecretRef { name, secret } => json!({"name": name, "secretRef": secret}),
            })
            .collect(),
    )
}

fn traffic_json(entries: &[TrafficEntry]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|t| json!({"revisionName": t.revision_name, "weight": t.weight, "latestRevision": false}))
            .collect(),
    )
}

fn secrets_json(secrets: &[AppSecret]) -> Value {
    Value::Array(
        secrets
            .iter()
            .map(|s| json!({"name": s.name, "value": s.value.expose()}))
            .collect(),
    )
}

fn init_json(init: &InitSpec) -> Value {
    json!({
        "name": SEED_INIT_CONTAINER,
        "image": init.image,
        "command": ["sh", "-c"],
        "args": [init.script],
        "env": env_json(&init.env),
        "resources": {"cpu": 0.25, "memory": "0.5Gi"},
        "volumeMounts": [{"volumeName": SEED_VOLUME, "mountPath": SEED_MOUNT_DIR}],
    })
}

fn template_json(r: &RevisionSpec) -> Value {
    let mut template = json!({
        "revisionSuffix": r.suffix.as_str(),
        "containers": [{
            "name": WORKER_CONTAINER,
            "image": r.image,
            "env": env_json(&r.env),
            "resources": {"cpu": r.cpu, "memory": r.memory},
            "volumeMounts": [{"volumeName": SEED_VOLUME, "mountPath": SEED_MOUNT_DIR}],
        }],
        "scale": {"minReplicas": r.min_replicas, "maxReplicas": r.max_replicas},
        "volumes": [{"name": SEED_VOLUME, "storageType": "EmptyDir"}],
    });
    if let Some(init) = &r.init {
        template["initContainers"] = json!([init_json(init)]);
    }
    template
}

/// The full `PUT` body. Multiple-revision mode and an explicit traffic list are
/// always sent, so the platform never falls back to `latestRevision` routing.
pub(crate) fn container_app_body(spec: &AppSpec) -> Value {
    let tags: serde_json::Map<String, Value> = spec
        .tags
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    json!({
        "location": spec.location,
        "tags": tags,
        "properties": {
            "managedEnvironmentId": spec.environment_id,
            "configuration": {
                "activeRevisionsMode": "Multiple",
                "ingress": {
                    "external": true,
                    "targetPort": spec.target_port,
                    "transport": "auto",
                    "allowInsecure": false,
                    "traffic": traffic_json(&spec.traffic),
                },
                "secrets": secrets_json(&spec.secrets),
            },
            "template": template_json(&spec.revision),
        }
    })
}

/// `PATCH` body rewriting `ingress.traffic` only (creates no revision).
pub(crate) fn traffic_patch_body(entries: &[TrafficEntry]) -> Value {
    json!({"properties": {"configuration": {"ingress": {"traffic": traffic_json(entries)}}}})
}

/// Merge `add` into `existing` without ever dropping or altering a value: a
/// whole-app PUT that omits a secret deletes it and breaks live revisions.
pub(crate) fn secrets_with_values(
    existing: &[AppSecret],
    add: &[AppSecret],
) -> Result<Vec<AppSecret>, SecretConflict> {
    let mut out = existing.to_vec();
    for a in add {
        match out.iter().find(|s| s.name == a.name) {
            Some(cur) if cur.value != a.value => return Err(SecretConflict(a.name.clone())),
            Some(_) => {}
            None => out.push(a.clone()),
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "arm_body_tests.rs"]
mod tests;
