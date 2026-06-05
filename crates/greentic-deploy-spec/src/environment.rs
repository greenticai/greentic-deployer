//! `greentic.environment.v1` (`§5.1`).
//!
//! Top-level Environment compose-view. Decomposes into three persistence units
//! on disk (`environment.json`, `env-packs/<slot>/answers.json`, `runtime.json`)
//! — the in-memory `Environment` is the union of those, owned by A2's
//! `EnvironmentStore`.

use crate::bundle_deployment::BundleDeployment;
use crate::capability_slot::{CapabilitySlot, PackDescriptor};
use crate::error::SpecError;
use crate::ids::PackId;
use crate::messaging_endpoint::MessagingEndpoint;
use crate::refs::{ExtensionRef, SecretRef};
use crate::retention::{HealthStatus, RetentionPolicy, RevocationConfig};
use crate::revision::Revision;
use crate::traffic_split::TrafficSplit;
use crate::version::SchemaVersion;
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Default bind address for the runtime's local HTTP listener when
/// [`EnvironmentHostConfig::listen_addr`] is unset and no runtime-level
/// override applies. Loopback by design — exposing externally is an explicit
/// opt-in via `op config set listen_addr 0.0.0.0:<port>`.
pub const DEFAULT_LISTEN_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

/// Host-level config moved out of `greentic-config-types::EnvironmentConfig`
/// (`§5.1`). Identity-only — connectivity, region, and deployment ctx; nothing
/// secret, nothing tenant-scoped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentHostConfig {
    pub env_id: EnvId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Tenant organization the env belongs to. `None` for `local`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_org_id: Option<String>,
    /// Bind address for the runtime's local HTTP listener. Set at `op env init`
    /// to [`DEFAULT_LISTEN_ADDR`] so a freshly-initialized env can be started
    /// with no bundles attached. The runtime (`gtc start`) may layer its own
    /// env-var override on top — see the `greentic-start` docs for the
    /// concrete name and precedence; this crate stays implementation-agnostic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<SocketAddr>,
}

impl EnvironmentHostConfig {
    /// Resolves the bind address using `self.listen_addr` falling back to
    /// [`DEFAULT_LISTEN_ADDR`]. Runtime-level env-var precedence (if any) is
    /// the caller's responsibility — this helper is the persisted-state
    /// resolution only.
    pub fn resolved_listen_addr(&self) -> SocketAddr {
        self.listen_addr.unwrap_or(DEFAULT_LISTEN_ADDR)
    }
}

/// Binding from a [`CapabilitySlot`] to a concrete pack (`§5.1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvPackBinding {
    pub slot: CapabilitySlot,
    pub kind: PackDescriptor,
    pub pack_ref: PackId,
    /// `env-packs/<slot>/answers.json` (env-relative path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers_ref: Option<PathBuf>,
    /// Bumped on attach/update/remove/rollback.
    #[serde(default)]
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_binding_ref: Option<PathBuf>,
}

/// An open-namespace capability binding (`§5.1`, Path 3).
///
/// Unlike [`EnvPackBinding`] it carries no `slot` field — its slot is always
/// [`CapabilitySlot::Extension`](crate::CapabilitySlot::Extension). Its identity
/// is `(kind.path(), instance_id)`: the descriptor path plus an optional
/// instance selector distinguishing N instances of the same extension type.
/// Bindings live in [`Environment::extensions`], never in
/// [`Environment::packs`], so the 1-per-slot rule does not apply; a workload
/// resolves one by name via `ext://<path>[/<instance>]`
/// ([`ExtensionRef`](crate::ExtensionRef)) — no typed host interface is wired.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionBinding {
    pub kind: PackDescriptor,
    pub pack_ref: PackId,
    /// Distinguishes N instances of the SAME extension type. `None` ⇒ the
    /// descriptor path is the whole key (the single default instance). A
    /// `None` binding and a `Some(..)` binding on the same path coexist; two
    /// `None` bindings on the same path collide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// `extensions/<path>[-<instance>]/answers.json` (env-relative path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers_ref: Option<PathBuf>,
    /// Bumped on attach/update/remove/rollback.
    #[serde(default)]
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_binding_ref: Option<PathBuf>,
}

impl ExtensionBinding {
    /// Per-document invariants. The `(path, instance_id)` uniqueness check is a
    /// cross-document invariant on [`Environment::validate`] where the sibling
    /// bindings are in scope.
    pub fn validate(&self) -> Result<(), SpecError> {
        if let Some(inst) = &self.instance_id {
            crate::refs::validate_instance_id(inst).map_err(|e| {
                SpecError::InvalidExtensionInstanceId {
                    path: self.kind.path().to_string(),
                    reason: e.to_string(),
                }
            })?;
        }
        Ok(())
    }
}

/// `greentic.environment.v1` compose-view (`§5.1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    pub schema: SchemaVersion,
    pub environment_id: EnvId,
    pub name: String,
    pub host_config: EnvironmentHostConfig,
    /// One entry per [`CapabilitySlot`]. Use [`Environment::validate`] to enforce.
    pub packs: Vec<EnvPackBinding>,
    /// `secret://<env>/credentials/...` reference into `packs[secrets]` (P5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_ref: Option<SecretRef>,
    #[serde(default)]
    pub bundles: Vec<BundleDeployment>,
    #[serde(default)]
    pub revisions: Vec<Revision>,
    #[serde(default)]
    pub traffic_splits: Vec<TrafficSplit>,
    /// Per-environment messaging provider instances (`Phase M1`). N-per-env;
    /// unique on `endpoint_id` and on `(provider_type, provider_id)`.
    #[serde(default)]
    pub messaging_endpoints: Vec<MessagingEndpoint>,
    /// Open-namespace extension bindings (`Path 3`). N-per-env; unique on
    /// `(kind.path(), instance_id)`. Resolved by workloads via
    /// `ext://<path>[/<instance>]`, never linked as a typed host interface and
    /// never reported in `doctor`'s `missing_slots` (the namespace is open).
    #[serde(default)]
    pub extensions: Vec<ExtensionBinding>,
    #[serde(default)]
    pub revocation: RevocationConfig,
    #[serde(default)]
    pub retention: RetentionPolicy,
    #[serde(default)]
    pub health: HealthStatus,
}

impl Environment {
    pub fn schema_str() -> &'static str {
        SchemaVersion::ENVIRONMENT_V1
    }

    /// Returns the binding for a slot, if any.
    pub fn pack_for_slot(&self, slot: CapabilitySlot) -> Option<&EnvPackBinding> {
        self.packs.iter().find(|b| b.slot == slot)
    }

    /// Resolve an [`ExtensionRef`] to its binding by `(path, instance_id)` —
    /// the same key [`Environment::validate`] enforces uniqueness on. Returns
    /// `None` when no extension matches both the path and the (absence of an)
    /// instance selector.
    pub fn extension_for_ref(&self, r: &ExtensionRef) -> Option<&ExtensionBinding> {
        self.extensions
            .iter()
            .find(|b| b.kind.path() == r.path() && b.instance_id.as_deref() == r.instance_id())
    }

    /// Validates spec-level invariants:
    /// - schema discriminator matches `greentic.environment.v1`,
    /// - slot uniqueness across `packs`,
    /// - extension binding uniqueness on `(kind.path(), instance_id)`,
    /// - basis-points sums on contained `TrafficSplit` / `BundleDeployment`,
    /// - `env_id` ownership across `host_config`, `revisions`, `bundles`, and
    ///   `traffic_splits` (every nested doc carries the same env identifier),
    /// - referential integrity: split entries reference a `Revision` in this
    ///   env whose `deployment_id` + `bundle_id` match the split's, and every
    ///   bundle's `current_revisions` references a `Revision` whose
    ///   `deployment_id` matches the bundle's. Lifecycle-state checks (e.g.
    ///   `lifecycle == Ready` for split entries per `§5.3`) stay at apply
    ///   time — pure data invariants only here.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.schema.as_str() != SchemaVersion::ENVIRONMENT_V1 {
            return Err(SpecError::SchemaMismatch {
                expected: SchemaVersion::ENVIRONMENT_V1,
                actual: self.schema.as_str().to_string(),
            });
        }

        if self.host_config.env_id != self.environment_id {
            return Err(SpecError::EnvIdMismatch {
                context: "host_config",
                expected: self.environment_id.clone(),
                actual: self.host_config.env_id.clone(),
            });
        }

        // Sized to the `CapabilitySlot` enum cardinality. Bump in lock-step
        // when the enum grows.
        let mut seen = [false; CapabilitySlot::ALL.len()];
        for binding in &self.packs {
            let idx = binding.slot as usize;
            if seen[idx] {
                return Err(SpecError::DuplicateCapabilitySlot(binding.slot));
            }
            seen[idx] = true;
        }

        // `credentials_ref` is documented as `secret://<env>/credentials/...`.
        // Without this scope check, a saved Environment could persist a
        // pointer into a different env's secrets backend and bypass tenant
        // isolation at resolve time.
        if let Some(cred_ref) = &self.credentials_ref {
            let actual = cred_ref.env_segment();
            if actual != self.environment_id.as_str() {
                return Err(SpecError::CrossEnvRef {
                    context: "credentials_ref",
                    uri: cred_ref.as_str().to_string(),
                    expected_env: self.environment_id.clone(),
                    actual_env: actual.to_string(),
                });
            }
        }

        for revision in &self.revisions {
            revision.validate()?;
            if revision.env_id != self.environment_id {
                return Err(SpecError::EnvIdMismatch {
                    context: "revision",
                    expected: self.environment_id.clone(),
                    actual: revision.env_id.clone(),
                });
            }
        }

        for bundle in &self.bundles {
            if bundle.env_id != self.environment_id {
                return Err(SpecError::EnvIdMismatch {
                    context: "bundle_deployment",
                    expected: self.environment_id.clone(),
                    actual: bundle.env_id.clone(),
                });
            }
            bundle.validate()?;
            let mut revision_pack_ids: HashSet<&str> = HashSet::new();
            for rev_id in &bundle.current_revisions {
                let referenced = self
                    .revisions
                    .iter()
                    .find(|r| r.revision_id == *rev_id)
                    .ok_or(SpecError::UnknownRevision(*rev_id))?;
                if referenced.deployment_id != bundle.deployment_id {
                    return Err(SpecError::BundleRevisionWrongDeployment {
                        deployment: bundle.deployment_id,
                        revision: *rev_id,
                        actual_deployment: referenced.deployment_id,
                    });
                }
                // A `BundleDeployment` is `(deployment_id, bundle_id)`-shaped;
                // a revision whose `bundle_id` does not match the deployment's
                // would let the deployment route or bill a different bundle's
                // revisions. Reject statically.
                if referenced.bundle_id != bundle.bundle_id {
                    return Err(SpecError::BundleRevisionWrongBundle {
                        deployment: bundle.deployment_id,
                        revision: *rev_id,
                        expected_bundle: bundle.bundle_id.clone(),
                        actual_bundle: referenced.bundle_id.clone(),
                    });
                }
                revision_pack_ids.extend(referenced.pack_list.iter().map(|e| e.pack_id.as_str()));
            }

            // Cross-ref: every config_overrides pack_id must appear in a
            // non-archived revision's pack_list for this deployment.
            // Forward-accept when no such revisions yet exist OR when their
            // pack_list is empty (the in-memory data the validator can see —
            // disk lock is the source of truth). The override gets
            // re-validated on the next env.validate() call once a revision
            // lands with populated pack_list.
            if !bundle.config_overrides.is_empty() {
                let mut deployment_pack_ids: HashSet<&str> = HashSet::new();
                for rev in self.revisions.iter().filter(|r| {
                    r.deployment_id == bundle.deployment_id
                        && r.lifecycle != crate::RevisionLifecycle::Archived
                }) {
                    deployment_pack_ids.extend(rev.pack_list.iter().map(|e| e.pack_id.as_str()));
                }
                if !deployment_pack_ids.is_empty() {
                    for override_pack_id in bundle.config_overrides.keys() {
                        if !deployment_pack_ids.contains(override_pack_id.as_str()) {
                            return Err(SpecError::ConfigOverridePackNotInRevisions {
                                deployment: bundle.deployment_id,
                                pack_id: override_pack_id.clone(),
                            });
                        }
                    }
                }
            }
        }

        for split in &self.traffic_splits {
            if split.env_id != self.environment_id {
                return Err(SpecError::EnvIdMismatch {
                    context: "traffic_split",
                    expected: self.environment_id.clone(),
                    actual: split.env_id.clone(),
                });
            }
            split.validate()?;
            // Resolve the referenced BundleDeployment and assert that its
            // bundle_id matches the split's. Without this, a split's
            // (deployment_id, bundle_id) pair can diverge from the
            // deployment's recorded bundle and cross-route traffic.
            let referenced_bundle = self
                .bundles
                .iter()
                .find(|b| b.deployment_id == split.deployment_id)
                .ok_or(SpecError::UnknownDeployment(split.deployment_id))?;
            if referenced_bundle.bundle_id != split.bundle_id {
                return Err(SpecError::SplitDeploymentBundleMismatch {
                    deployment: split.deployment_id,
                    split_bundle: split.bundle_id.clone(),
                    deployment_bundle: referenced_bundle.bundle_id.clone(),
                });
            }
            for entry in &split.entries {
                let referenced = self
                    .revisions
                    .iter()
                    .find(|r| r.revision_id == entry.revision_id)
                    .ok_or(SpecError::UnknownRevision(entry.revision_id))?;
                if referenced.deployment_id != split.deployment_id {
                    return Err(SpecError::SplitRevisionWrongDeployment {
                        revision: entry.revision_id,
                        expected_deployment: split.deployment_id,
                        actual_deployment: referenced.deployment_id,
                    });
                }
                if referenced.bundle_id != split.bundle_id {
                    return Err(SpecError::SplitRevisionWrongBundle {
                        revision: entry.revision_id,
                        expected_bundle: split.bundle_id.clone(),
                        actual_bundle: referenced.bundle_id.clone(),
                    });
                }
            }
        }

        // Phase M1: messaging endpoint cross-document invariants. Per-document
        // checks (schema discriminator, non-empty ids, secret-ref env scope)
        // live on `MessagingEndpoint::validate`.
        let mut seen_endpoint_ids = HashSet::with_capacity(self.messaging_endpoints.len());
        let mut seen_provider_instances = HashSet::with_capacity(self.messaging_endpoints.len());
        for endpoint in &self.messaging_endpoints {
            endpoint.validate()?;
            if endpoint.env_id != self.environment_id {
                return Err(SpecError::EnvIdMismatch {
                    context: "messaging_endpoint",
                    expected: self.environment_id.clone(),
                    actual: endpoint.env_id.clone(),
                });
            }
            if !seen_endpoint_ids.insert(endpoint.endpoint_id) {
                return Err(SpecError::DuplicateMessagingEndpoint(endpoint.endpoint_id));
            }
            let instance_key = (
                endpoint.provider_type.as_str(),
                endpoint.provider_id.as_str(),
            );
            if !seen_provider_instances.insert(instance_key) {
                return Err(SpecError::DuplicateProviderInstance {
                    provider_type: endpoint.provider_type.clone(),
                    provider_id: endpoint.provider_id.clone(),
                });
            }
            for bundle_id in &endpoint.linked_bundles {
                if !self.bundles.iter().any(|b| b.bundle_id == *bundle_id) {
                    return Err(SpecError::MessagingEndpointBundleNotLinked {
                        endpoint: endpoint.endpoint_id,
                        bundle: bundle_id.clone(),
                    });
                }
            }
            if let Some(welcome) = &endpoint.welcome_flow
                && !endpoint.linked_bundles.contains(&welcome.bundle_id)
            {
                return Err(SpecError::WelcomeFlowBundleNotLinked {
                    endpoint: endpoint.endpoint_id,
                    bundle: welcome.bundle_id.clone(),
                });
            }
        }

        // Extension bindings (`Path 3`): open N-per-env namespace, unique on
        // `(kind.path(), instance_id)`. A `None` instance and a `Some(..)`
        // instance on the same path coexist; two identical keys collide.
        let mut seen_extensions = HashSet::with_capacity(self.extensions.len());
        for ext in &self.extensions {
            ext.validate()?;
            let key = (ext.kind.path(), ext.instance_id.as_deref());
            if !seen_extensions.insert(key) {
                return Err(SpecError::DuplicateExtension {
                    path: ext.kind.path().to_string(),
                    instance_id: ext.instance_id.clone(),
                });
            }
        }

        Ok(())
    }
}
