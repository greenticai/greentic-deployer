//! `greentic.env-manifest.v1` — the declarative desired-state document
//! consumed by `gtc op env apply` (PR-1 of `plans/env-manifest-apply.md`).
//!
//! The manifest declares the desired *wiring* of one environment: env
//! identity, trust root, secrets (PR-2), bundle deployments with route
//! bindings, and messaging endpoints with their bundle links. It is a
//! durable document keyed by resource natural keys, designed to live in
//! version control and be re-applied — NOT a recorded wizard-answers file
//! and NOT a batch of per-verb payloads (see the design doc §4 for why
//! those shapes were rejected).
//!
//! This module owns the serde types plus the manifest-*shape* validation
//! (everything checkable without touching the store or the filesystem).
//! Environment-dependent validation, artifact digesting, diffing, and
//! execution live in [`super::env_apply`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::OpError;
use super::bundles::RouteBindingPayload;

/// Exact `schema` discriminator the manifest must carry.
pub const ENV_MANIFEST_SCHEMA_V1: &str = "greentic.env-manifest.v1";

/// Top-level manifest document. `deny_unknown_fields` everywhere so a typo
/// fails loudly at parse time instead of silently no-opping.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvManifest {
    /// Must equal [`ENV_MANIFEST_SCHEMA_V1`].
    pub schema: String,
    pub environment: ManifestEnvironment,
    /// `"bootstrap"` seeds the env trust root with the local operator key
    /// (idempotent). Absent = skip the step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_root: Option<TrustRootDirective>,
    /// Dev-store secret entries. Parsed in PR-1 so the schema is stable, but
    /// rejected at validation until PR-2 wires the `secrets[]` execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<ManifestSecret>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bundles: Vec<ManifestBundle>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messaging_endpoints: Vec<ManifestEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEnvironment {
    /// Environment id. v1 apply can bootstrap only the `local` env (the
    /// `env init` path); any other id must already exist.
    pub id: String,
    /// When set, persisted via the `env set-public-url` path. Absent/`null`
    /// means "leave whatever is there" (upsert — apply never clears it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
}

/// v1 accepts only the string `"bootstrap"`. A future
/// `{ "additional_keys": [...] }` shape extends this enum without a schema
/// bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustRootDirective {
    Bootstrap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSecret {
    /// Dev-store path `<tenant>/<team>/<pack>/<name>` — exactly the
    /// `SecretsPutPayload.path` shape.
    pub path: String,
    /// Name of the environment variable holding the value. Secret VALUES
    /// never appear in the manifest.
    pub from_env: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestBundle {
    /// Natural key — unique within the manifest.
    pub bundle_id: String,
    /// Local `.gtbundle`. Relative paths resolve against the manifest
    /// file's directory (not the CWD), so manifests are relocatable.
    pub bundle_path: PathBuf,
    /// Billing principal (P6/B10): required for non-`local` environments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    /// Forwarded verbatim with `op deploy`'s three-valued semantics:
    /// absent = leave untouched, `{}` = explicit clear, non-empty = replace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_overrides: Option<BTreeMap<String, BTreeMap<String, Value>>>,
    /// Absent = same as `op deploy`: empty binding on fresh add, untouched
    /// on re-deploy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_binding: Option<RouteBindingPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEndpoint {
    /// Manifest-local handle AND the endpoint's `display_name` AND (on
    /// create) its `provider_id` instance identity. Upsert natural key:
    /// apply matches an existing endpoint by `(provider_type, name)`.
    pub name: String,
    /// Provider class, e.g. `messaging.telegram.bot`.
    pub provider_type: String,
    /// `bundle_id`s this endpoint admits. Each must be declared in this
    /// manifest's `bundles[]` or already exist in the environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_flow: Option<ManifestWelcomeFlow>,
    /// Forwarded to `EndpointAddPayload.secret_refs` on create. Drift on an
    /// existing endpoint is reported as a warning (no update verb exists).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestWelcomeFlow {
    pub bundle_id: String,
    pub pack_id: String,
    pub flow_id: String,
}

impl EnvManifest {
    /// Manifest-shape validation: everything checkable without the store or
    /// the filesystem. Runs before any artifact digesting or env read so a
    /// malformed manifest fails fast with no side effects.
    pub fn validate_shape(&self) -> Result<(), OpError> {
        if self.schema != ENV_MANIFEST_SCHEMA_V1 {
            return Err(OpError::InvalidArgument(format!(
                "manifest schema `{}` is not the expected `{ENV_MANIFEST_SCHEMA_V1}`",
                self.schema
            )));
        }
        if self.environment.id.trim().is_empty() {
            return Err(OpError::InvalidArgument(
                "environment.id must not be empty".to_string(),
            ));
        }
        if !self.secrets.is_empty() {
            return Err(OpError::NotYetImplemented(
                "manifest `secrets[]` lands in PR-2 of plans/env-manifest-apply.md; \
                 seed secrets with `greentic-secrets apply` or `gtc op secrets put` for now"
                    .to_string(),
            ));
        }

        let mut bundle_ids = BTreeSet::new();
        for b in &self.bundles {
            if b.bundle_id.trim().is_empty() {
                return Err(OpError::InvalidArgument(
                    "bundles[].bundle_id must not be empty".to_string(),
                ));
            }
            if !bundle_ids.insert(b.bundle_id.as_str()) {
                return Err(OpError::InvalidArgument(format!(
                    "duplicate bundle_id `{}` in manifest bundles[]",
                    b.bundle_id
                )));
            }
            if let Some(rb) = &b.route_binding {
                rb.validate()?;
                for prefix in &rb.path_prefixes {
                    if !prefix.starts_with('/') {
                        return Err(OpError::InvalidArgument(format!(
                            "bundle `{}` route_binding.path_prefixes entry `{prefix}` \
                             must start with `/`",
                            b.bundle_id
                        )));
                    }
                }
            }
        }

        let mut endpoint_names = BTreeSet::new();
        for ep in &self.messaging_endpoints {
            if ep.name.trim().is_empty() {
                return Err(OpError::InvalidArgument(
                    "messaging_endpoints[].name must not be empty".to_string(),
                ));
            }
            if ep.provider_type.trim().is_empty() {
                return Err(OpError::InvalidArgument(format!(
                    "endpoint `{}`: provider_type must not be empty",
                    ep.name
                )));
            }
            if !endpoint_names.insert(ep.name.as_str()) {
                return Err(OpError::InvalidArgument(format!(
                    "duplicate endpoint name `{}` in manifest messaging_endpoints[]",
                    ep.name
                )));
            }
            if let Some(wf) = &ep.welcome_flow
                && !ep.links.contains(&wf.bundle_id)
            {
                // The bundle may already be linked on an existing endpoint;
                // that case is validated env-side in env_apply. Manifest-side
                // we require the welcome-flow bundle to at least be a link
                // target somewhere the manifest can see.
                if !bundle_ids.contains(wf.bundle_id.as_str()) {
                    return Err(OpError::InvalidArgument(format!(
                        "endpoint `{}`: welcome_flow.bundle_id `{}` is neither in this \
                         endpoint's links[] nor declared in bundles[]",
                        ep.name, wf.bundle_id
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Hand-written JSON Schema for the manifest (`op env apply --schema`),
/// following the existing convention (A1 schemars wiring is still deferred).
pub fn manifest_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "EnvManifest",
        "description": "greentic.env-manifest.v1 — declarative environment wiring for `gtc op env apply`",
        "type": "object",
        "required": ["schema", "environment"],
        "additionalProperties": false,
        "properties": {
            "schema": {"const": ENV_MANIFEST_SCHEMA_V1},
            "environment": {
                "type": "object",
                "required": ["id"],
                "additionalProperties": false,
                "properties": {
                    "id": {"type": "string", "description": "Environment id; v1 bootstraps only `local`"},
                    "public_base_url": {"type": ["string", "null"], "description": "origin-only URL; absent = leave untouched"}
                }
            },
            "trust_root": {"enum": ["bootstrap", null], "description": "`bootstrap` seeds the operator key (idempotent)"},
            "secrets": {
                "type": "array",
                "description": "PR-2 — rejected with not-yet-implemented in PR-1",
                "items": {
                    "type": "object",
                    "required": ["path", "from_env"],
                    "additionalProperties": false,
                    "properties": {
                        "path": {"type": "string", "description": "<tenant>/<team>/<pack>/<name>"},
                        "from_env": {"type": "string", "description": "env var holding the value; values never appear in the manifest"}
                    }
                }
            },
            "bundles": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["bundle_id", "bundle_path"],
                    "additionalProperties": false,
                    "properties": {
                        "bundle_id": {"type": "string"},
                        "bundle_path": {"type": "string", "description": "local .gtbundle; relative to the manifest file"},
                        "customer_id": {"type": ["string", "null"], "description": "required for non-local envs (B10)"},
                        "config_overrides": {"type": ["object", "null"], "description": "<pack_id> -> <key> -> <json>; absent=untouched, {}=clear, map=replace"},
                        "route_binding": {
                            "type": ["object", "null"],
                            "properties": {
                                "hosts": {"type": "array", "items": {"type": "string"}},
                                "path_prefixes": {"type": "array", "items": {"type": "string"}},
                                "tenant_selector": {
                                    "type": ["object", "null"],
                                    "required": ["tenant", "team"],
                                    "properties": {"tenant": {"type": "string"}, "team": {"type": "string"}}
                                }
                            }
                        }
                    }
                }
            },
            "messaging_endpoints": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "provider_type"],
                    "additionalProperties": false,
                    "properties": {
                        "name": {"type": "string", "description": "natural key: matches existing endpoints by (provider_type, display_name)"},
                        "provider_type": {"type": "string"},
                        "links": {"type": "array", "items": {"type": "string"}},
                        "welcome_flow": {
                            "type": ["object", "null"],
                            "required": ["bundle_id", "pack_id", "flow_id"],
                            "additionalProperties": false,
                            "properties": {
                                "bundle_id": {"type": "string"},
                                "pack_id": {"type": "string"},
                                "flow_id": {"type": "string"}
                            }
                        },
                        "secret_refs": {"type": "array", "items": {"type": "string"}}
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal(schema: &str) -> EnvManifest {
        serde_json::from_value(serde_json::json!({
            "schema": schema,
            "environment": {"id": "local"}
        }))
        .expect("minimal manifest parses")
    }

    #[test]
    fn schema_mismatch_rejected() {
        let err = minimal("greentic.env-manifest.v2")
            .validate_shape()
            .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "{err}");
    }

    #[test]
    fn unknown_top_level_field_rejected_at_parse() {
        let err = serde_json::from_value::<EnvManifest>(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundlez": []
        }))
        .unwrap_err();
        assert!(err.to_string().contains("bundlez"), "{err}");
    }

    #[test]
    fn secrets_rejected_until_pr2() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "secrets": [{"path": "legal/_/p/n", "from_env": "X"}]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(matches!(err, OpError::NotYetImplemented(_)), "{err}");
    }

    #[test]
    fn duplicate_bundle_id_rejected() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [
                {"bundle_id": "a", "bundle_path": "a.gtbundle"},
                {"bundle_id": "a", "bundle_path": "b.gtbundle"}
            ]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("duplicate bundle_id"), "{err}");
    }

    #[test]
    fn duplicate_endpoint_name_rejected() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "messaging_endpoints": [
                {"name": "n", "provider_type": "messaging.telegram.bot"},
                {"name": "n", "provider_type": "messaging.telegram.bot"}
            ]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("duplicate endpoint name"), "{err}");
    }

    #[test]
    fn tenant_selector_without_matcher_rejected() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "a",
                "bundle_path": "a.gtbundle",
                "route_binding": {"tenant_selector": {"tenant": "t", "team": "d"}}
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("tenant_selector"), "{err}");
    }

    #[test]
    fn path_prefix_must_start_with_slash() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "a",
                "bundle_path": "a.gtbundle",
                "route_binding": {"path_prefixes": ["legal"]}
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("must start with `/`"), "{err}");
    }

    #[test]
    fn welcome_flow_bundle_must_be_visible() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "messaging_endpoints": [{
                "name": "n",
                "provider_type": "messaging.telegram.bot",
                "welcome_flow": {"bundle_id": "ghost", "pack_id": "p", "flow_id": "f"}
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("welcome_flow.bundle_id"), "{err}");
    }

    #[test]
    fn trust_root_bootstrap_parses() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "trust_root": "bootstrap"
        }))
        .unwrap();
        assert_eq!(manifest.trust_root, Some(TrustRootDirective::Bootstrap));
        manifest.validate_shape().expect("valid");
    }

    #[test]
    fn two_dept_worked_example_parses() {
        // The §3 worked example from the design doc, minus secrets (PR-2).
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local", "public_base_url": null},
            "trust_root": "bootstrap",
            "bundles": [
                {
                    "bundle_id": "realbot-legal",
                    "bundle_path": "bundle-workspace-legal/realbot-legal.gtbundle",
                    "route_binding": {
                        "hosts": [],
                        "path_prefixes": ["/legal"],
                        "tenant_selector": {"tenant": "legal", "team": "default"}
                    }
                },
                {
                    "bundle_id": "realbot-accounting",
                    "bundle_path": "bundle-workspace-accounting/realbot-accounting.gtbundle",
                    "route_binding": {
                        "hosts": [],
                        "path_prefixes": ["/accounting"],
                        "tenant_selector": {"tenant": "accounting", "team": "default"}
                    }
                }
            ],
            "messaging_endpoints": [
                {
                    "name": "realbot-legal",
                    "provider_type": "messaging.telegram.bot",
                    "links": ["realbot-legal"]
                },
                {
                    "name": "realbot-accounting",
                    "provider_type": "messaging.telegram.bot",
                    "links": ["realbot-accounting"]
                }
            ]
        }))
        .unwrap();
        manifest.validate_shape().expect("worked example is valid");
        assert_eq!(manifest.bundles.len(), 2);
        assert_eq!(manifest.messaging_endpoints.len(), 2);
    }
}
