//! Bootstrap rules pack: the custom role, an `az` setup script and a README.
//!
//! No Terraform, and no secret value anywhere: the script prints the service
//! principal secret and the ACR token password to the operator's terminal and
//! writes them nowhere. Grants are the exact [`REQUIRED_ACTIONS`] at resource-group
//! scope, never a Contributor / Operator wildcard.

use serde_json::json;

use super::rbac::REQUIRED_ACTIONS;
use crate::credentials::{RulesPack, RulesPackEntry};

pub(crate) struct RulesInput<'a> {
    pub env_id: &'a str,
}

fn slug(env_id: &str) -> String {
    env_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect()
}

pub(crate) fn role_definition(env_id: &str) -> String {
    let doc = json!({
        "Name": format!("Greentic ACA deployer ({})", slug(env_id)),
        "IsCustom": true,
        "Description": "Least-privilege role for the Greentic Azure Container Apps deployer.",
        "Actions": REQUIRED_ACTIONS,
        "NotActions": [],
        "DataActions": [],
        "NotDataActions": [],
        "AssignableScopes": ["/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>"],
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

pub(crate) fn setup_script(env_id: &str) -> String {
    let s = slug(env_id);
    format!(
        r#"#!/usr/bin/env bash
# Greentic Azure Container Apps setup for environment `{env_id}`.
# Review before running. Fill the five variables, then run as an Azure admin.
# The service principal secret and the ACR token password are PRINTED to your
# terminal and written nowhere: store them in your secret manager.
set -euo pipefail

SUBSCRIPTION_ID="<SUBSCRIPTION_ID>"
RESOURCE_GROUP="<RESOURCE_GROUP>"
ACR_NAME="<ACR_NAME>"                    # existing registry (bundles are pushed here)
LOG_ANALYTICS_WORKSPACE="<WORKSPACE_NAME>" # existing workspace the environment logs to
BUNDLE_REPOSITORY="<REPOSITORY>"          # repository prefix the worker may pull from

az account set --subscription "$SUBSCRIPTION_ID"
SCOPE="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"

# 1. Least-privilege custom role (see azure-aca-role.json; assignable at the RG only).
sed "s|<SUBSCRIPTION_ID>|$SUBSCRIPTION_ID|; s|<RESOURCE_GROUP>|$RESOURCE_GROUP|" \
  azure-aca-role.json > /tmp/azure-aca-role.resolved.json
az role definition create --role-definition @/tmp/azure-aca-role.resolved.json

# 2. Service principal with that role. The command prints appId / password / tenant.
az ad sp create-for-rbac --name "gtc-{s}-deployer" \
  --role "Greentic ACA deployer ({s})" --scopes "$SCOPE"

APP_ID="$(az ad sp list --display-name "gtc-{s}-deployer" --query '[0].appId' -o tsv)"

# 3. The deployer pushes bundles (AcrPush) and the designer reads logs.
ACR_ID="$(az acr show --name "$ACR_NAME" --query id -o tsv)"
az role assignment create --assignee "$APP_ID" --role AcrPush --scope "$ACR_ID"
WS_ID="$(az monitor log-analytics workspace show -g "$RESOURCE_GROUP" -n "$LOG_ANALYTICS_WORKSPACE" --query id -o tsv)"
az role assignment create --assignee "$APP_ID" --role "Log Analytics Reader" --scope "$WS_ID"

# 4. Repository-scoped pull token for the RUNTIME (answers oci_username / oci_password).
az acr scope-map create --name "gtc-{s}-pull" --registry "$ACR_NAME" \
  --repository "$BUNDLE_REPOSITORY" content/read
az acr token create --name "gtc-{s}-pull" --registry "$ACR_NAME" \
  --scope-map "gtc-{s}-pull" --no-passwords
az acr token credential generate --name "gtc-{s}-pull" --registry "$ACR_NAME" --password1

echo "Bind the service principal: op credentials rotate with material"
echo '{{"tenant_id":"<tenant>","client_id":"<appId>","client_secret":"<password>","subscription_id":"'"$SUBSCRIPTION_ID"'"}}'
"#
    )
}

pub(crate) fn readme(env_id: &str) -> String {
    let mut actions = String::new();
    for a in REQUIRED_ACTIONS {
        actions.push_str(&format!("- `{a}`\n"));
    }
    format!(
        "# Azure Container Apps bootstrap for `{env_id}`\n\n\
Files: `azure-aca-role.json` (custom role), `azure-aca-setup.sh` (az CLI).\n\n\
The operator provides the managed environment, the Log Analytics workspace and the \
ACR. This pack grants the deployer exactly these actions at resource-group scope:\n\n\
{actions}\n\
Additionally the script assigns *AcrPush* on the registry and *Log Analytics Reader* \
on the workspace, and creates a repository-scoped ACR token for the runtime's bundle \
pull. Secrets are printed once and never written to disk by the script.\n\n\
Bind the service principal as the environment credential, a JSON object with \
`tenant_id`, `client_id`, `client_secret`, `subscription_id`.\n"
    )
}

pub(crate) fn render_rules_pack(input: &RulesInput<'_>) -> RulesPack {
    RulesPack {
        entries: vec![
            RulesPackEntry {
                filename: "azure-aca-role.json".into(),
                content: role_definition(input.env_id),
                description: Some("Least-privilege custom role for the ACA deployer.".into()),
            },
            RulesPackEntry {
                filename: "azure-aca-setup.sh".into(),
                content: setup_script(input.env_id),
                description: Some("az CLI: role, service principal, role assignments, ACR pull token.".into()),
            },
            RulesPackEntry {
                filename: "README.md".into(),
                content: readme(input.env_id),
                description: Some("Apply instructions for the Azure Container Apps bootstrap.".into()),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_json_lists_exactly_the_required_actions_and_no_wildcards() {
        let v: serde_json::Value = serde_json::from_str(&role_definition("prod")).unwrap();
        let actions: Vec<&str> =
            v["Actions"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
        assert_eq!(actions, REQUIRED_ACTIONS);
        assert!(!actions.iter().any(|a| a.contains('*')));
        assert!(v["AssignableScopes"][0].as_str().unwrap().contains("resourceGroups"));
    }

    #[test]
    fn every_required_action_appears_in_the_readme() {
        let r = readme("prod");
        for a in REQUIRED_ACTIONS {
            assert!(r.contains(a), "{a}");
        }
    }

    #[test]
    fn the_script_carries_no_secret_values_and_grants_the_built_in_roles() {
        let s = setup_script("prod");
        assert!(s.contains("AcrPush") && s.contains("Log Analytics Reader"));
        assert!(s.contains("content/read") && s.contains("--no-passwords"));
        assert!(!s.contains("client_secret\":\"") || s.contains("<password>"));
        assert!(!s.to_ascii_lowercase().contains("contributor"));
    }

    #[test]
    fn the_pack_has_three_safe_entries() {
        let p = render_rules_pack(&RulesInput { env_id: "prod" });
        let names: Vec<&str> = p.entries.iter().map(|e| e.filename.as_str()).collect();
        assert_eq!(names, ["azure-aca-role.json", "azure-aca-setup.sh", "README.md"]);
    }
}
