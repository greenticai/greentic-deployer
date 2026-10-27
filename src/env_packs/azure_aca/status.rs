//! Pure mapping of ARM revision / app JSON into the seam's types.

use serde_json::Value;

use super::arm_body::OWNER_TAG;
use super::arm_types::TrafficEntry;
use super::deploy_target::RevisionStatus;
use super::revision_intent::{INTENT_ENV, LiveIntent};

fn text<'a>(v: &'a Value, pointer: &str) -> Option<&'a str> {
    v.pointer(pointer).and_then(Value::as_str)
}

/// `provisioningState` x `runningState` x `active` -> [`RevisionStatus`].
/// `NEEDS_LIVE`: the exact state vocabulary is read from documentation.
pub(crate) fn revision_status(rev: &Value) -> RevisionStatus {
    let provisioning = text(rev, "/properties/provisioningState").unwrap_or("");
    let running = text(rev, "/properties/runningState").unwrap_or("");
    let detail = text(rev, "/properties/runningStateDetails").unwrap_or("no detail");
    let active = rev
        .pointer("/properties/active")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let replicas = rev
        .pointer("/properties/replicas")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0);
    if !active {
        return RevisionStatus::Inactive;
    }
    match (provisioning, running) {
        ("Failed", _) => RevisionStatus::Failed {
            reason: format!("provisioning failed: {detail}"),
        },
        ("Provisioning" | "Deprovisioning", _) | ("", _) => RevisionStatus::Provisioning,
        ("Deprovisioned", _) => RevisionStatus::Inactive,
        (_, "Failed" | "Degraded") => RevisionStatus::Failed {
            reason: format!("{running}: {detail}"),
        },
        (_, "Stopped") => RevisionStatus::Inactive,
        (_, "Running") => RevisionStatus::Running { replicas },
        _ => RevisionStatus::Provisioning,
    }
}

/// The intent stamp on a revision's containers. `NEEDS_LIVE`: if the revision GET
/// does not expose the template env, the result is `Present { intent: None }`,
/// which the verbs treat as a conflict (never an adoption).
pub(crate) fn intent_from_revision(rev: &Value) -> LiveIntent {
    let intent = rev
        .pointer("/properties/template/containers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|c| c.get("env").and_then(Value::as_array).into_iter().flatten())
        .find(|e| e.get("name").and_then(Value::as_str) == Some(INTENT_ENV))
        .and_then(|e| e.get("value").and_then(Value::as_str))
        .map(str::to_string);
    LiveIntent::Present { intent }
}

/// `greentic:owner` tag of an app.
pub(crate) fn owner_of(app: &Value) -> Option<String> {
    app.pointer("/tags")
        .and_then(|t| t.get(OWNER_TAG))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// `ingress.traffic` as explicit-revision entries. An entry without a
/// `revisionName` (latest-revision / label routing) means the app was not made by
/// this deployer: it is refused rather than guessed.
pub(crate) fn traffic_of(app: &Value) -> Result<Vec<TrafficEntry>, String> {
    let Some(entries) = app
        .pointer("/properties/configuration/ingress/traffic")
        .and_then(Value::as_array)
    else {
        return Ok(Vec::new());
    };
    entries
        .iter()
        .map(|e| {
            let name = e
                .get("revisionName")
                .and_then(Value::as_str)
                .ok_or("the app routes traffic by latest revision or label, which this deployer does not manage")?;
            let weight = e.get("weight").and_then(Value::as_u64).and_then(|w| u32::try_from(w).ok()).unwrap_or(0);
            Ok(TrafficEntry { revision_name: name.to_string(), weight })
        })
        .collect()
}

pub(crate) fn endpoint_of(app: &Value) -> Option<String> {
    text(app, "/properties/configuration/ingress/fqdn")
        .or_else(|| text(app, "/properties/latestRevisionFqdn"))
        .filter(|f| !f.is_empty())
        .map(|f| format!("https://{f}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rev(p: &str, r: &str) -> Value {
        json!({"properties": {"provisioningState": p, "runningState": r, "replicas": 1, "active": true}})
    }

    #[test]
    fn the_state_table() {
        assert_eq!(
            revision_status(&rev("Provisioned", "Running")),
            RevisionStatus::Running { replicas: 1 }
        );
        assert_eq!(
            revision_status(&rev("Provisioning", "Processing")),
            RevisionStatus::Provisioning
        );
        assert!(matches!(
            revision_status(&rev("Failed", "")),
            RevisionStatus::Failed { .. }
        ));
        assert!(matches!(
            revision_status(&rev("Provisioned", "Degraded")),
            RevisionStatus::Failed { .. }
        ));
        assert_eq!(
            revision_status(&rev("Provisioned", "Stopped")),
            RevisionStatus::Inactive
        );
        let mut inactive = rev("Provisioned", "Running");
        inactive["properties"]["active"] = json!(false);
        assert_eq!(revision_status(&inactive), RevisionStatus::Inactive);
    }

    #[test]
    fn provisioning_failed_carries_the_reason() {
        let mut r = rev("Failed", "");
        r["properties"]["runningStateDetails"] = json!("ImagePullBackOff");
        match revision_status(&r) {
            RevisionStatus::Failed { reason } => assert!(reason.contains("ImagePullBackOff")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn intent_is_read_from_the_container_env_or_reads_unstamped() {
        let with = json!({"properties": {"template": {"containers": [{"env": [{"name": "A", "value": "1"}, {"name": INTENT_ENV, "value": "abc"}]}]}}});
        assert_eq!(
            intent_from_revision(&with),
            LiveIntent::Present {
                intent: Some("abc".into())
            }
        );
        assert_eq!(
            intent_from_revision(&json!({"properties": {}})),
            LiveIntent::Present { intent: None }
        );
    }

    #[test]
    fn app_json_is_read_for_owner_traffic_and_endpoint() {
        let app = json!({
            "tags": {"greentic:owner": "me"},
            "properties": {"configuration": {"ingress": {"fqdn": "a.b.azurecontainerapps.io",
                "traffic": [{"revisionName": "a--r1", "weight": 100, "latestRevision": false}]}}}
        });
        assert_eq!(owner_of(&app).as_deref(), Some("me"));
        assert_eq!(traffic_of(&app).unwrap()[0].weight, 100);
        assert_eq!(
            endpoint_of(&app).as_deref(),
            Some("https://a.b.azurecontainerapps.io")
        );
        let latest = json!({"properties": {"configuration": {"ingress": {"traffic": [{"latestRevision": true, "weight": 100}]}}}});
        assert!(traffic_of(&latest).is_err());
    }
}
