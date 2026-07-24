//! `greentic.environment.v1` (`§5.1`).
//!
//! Top-level Environment compose-view. Decomposes into three persistence units
//! on disk (`environment.json`, `env-packs/<slot>/answers.json`, `runtime.json`)
//! — the in-memory `Environment` is the union of those, owned by A2's
//! `EnvironmentStore`.

use crate::bundle_deployment::{BundleDeployment, BundleDeploymentStatus};
use crate::capability_slot::{CapabilitySlot, PackDescriptor};
use crate::error::SpecError;
use crate::ids::{BundleId, PackId};
use crate::messaging_endpoint::MessagingEndpoint;
use crate::refs::{ExtensionRef, SecretRef};
use crate::retention::{HealthStatus, RetentionPolicy, RevocationConfig};
use crate::revision::Revision;
use crate::traffic_split::TrafficSplit;
use crate::version::SchemaVersion;
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
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
#[non_exhaustive]
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
    /// Persistent public base URL the runtime exposes (e.g. via a static
    /// tunnel or load balancer). Stored as origin only — `https://host[:port]`,
    /// no path, no query, no fragment. Validated by [`Environment::validate`]
    /// (so save AND load both reject invalid values via [`LocalFsStore`]).
    /// Runtime precedence (env var override vs. tunnel-discovered vs. persisted)
    /// is `greentic-start`'s concern; this crate persists the configured value
    /// only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
    /// Whether the runtime serves the built-in webchat GUI for this env.
    /// `None` = unset → resolved by [`EnvironmentHostConfig::resolved_gui_enabled`]
    /// (on for `local`, off elsewhere — the chat path is loopback-only and
    /// unauthenticated, so it stays off public envs unless explicitly enabled).
    /// `Some(b)` is an explicit operator/wizard choice that overrides the
    /// env-id default either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gui_enabled: Option<bool>,
    /// The bundle that the bare webchat URL `/v1/web/webchat/{tenant}/`
    /// resolves to when an environment holds several bundles. `None` = unset
    /// → resolved by [`Environment::resolve_default_bundle`] using a
    /// deterministic fallback ladder (lone Active match, then newest
    /// `created_at` / largest `deployment_id`).
    ///
    /// **Note:** not yet settable through [`UpdateEnvironmentPayload`] /
    /// [`apply_environment_update`](crate::engine::apply_environment_update);
    /// only the first-deploy stamp in `greentic-setup` writes it. For
    /// existing environments the resolution ladder is the sole path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_bundle: Option<BundleId>,
}

/// Env id whose runtime serves the built-in webchat GUI by default. Other
/// envs default off because the chat path is loopback-only and unauthenticated
/// — exposing it on a public env is an explicit opt-in.
pub const GUI_DEFAULT_ENV_ID: &str = "local";

impl EnvironmentHostConfig {
    /// Construct a new config with only the required `env_id`; every optional
    /// field starts as `None`. Chain [`with_region`](Self::with_region),
    /// [`with_listen_addr`](Self::with_listen_addr), etc. to set them.
    pub fn new(env_id: EnvId) -> Self {
        Self {
            env_id,
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
            gui_enabled: None,
            default_bundle: None,
        }
    }

    /// Set the cloud region tag (e.g. `"eu-west-1"`).
    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    /// Set the tenant organization this env belongs to.
    pub fn with_tenant_org_id(mut self, tenant_org_id: String) -> Self {
        self.tenant_org_id = Some(tenant_org_id);
        self
    }

    /// Set the bind address for the runtime's local HTTP listener.
    pub fn with_listen_addr(mut self, listen_addr: SocketAddr) -> Self {
        self.listen_addr = Some(listen_addr);
        self
    }

    /// Set the persistent public base URL (origin only, no path).
    pub fn with_public_base_url(mut self, public_base_url: String) -> Self {
        self.public_base_url = Some(public_base_url);
        self
    }

    /// Explicitly enable or disable the built-in webchat GUI.
    pub fn with_gui_enabled(mut self, gui_enabled: bool) -> Self {
        self.gui_enabled = Some(gui_enabled);
        self
    }

    /// Pin a default bundle for bare-URL webchat resolution.
    pub fn with_default_bundle(mut self, default_bundle: BundleId) -> Self {
        self.default_bundle = Some(default_bundle);
        self
    }

    /// Resolves the bind address using `self.listen_addr` falling back to
    /// [`DEFAULT_LISTEN_ADDR`]. Runtime-level env-var precedence (if any) is
    /// the caller's responsibility — this helper is the persisted-state
    /// resolution only.
    pub fn resolved_listen_addr(&self) -> SocketAddr {
        self.listen_addr.unwrap_or(DEFAULT_LISTEN_ADDR)
    }

    /// Resolves whether the runtime should serve the built-in webchat GUI.
    /// Explicit [`gui_enabled`](Self::gui_enabled) wins; when unset the GUI is
    /// on only for [`GUI_DEFAULT_ENV_ID`] (`local`). Both the deployer's apply
    /// engine and `greentic-start`'s boot path read through this helper so the
    /// default lives in exactly one place.
    pub fn resolved_gui_enabled(&self) -> bool {
        self.gui_enabled
            .unwrap_or(self.env_id.as_str() == GUI_DEFAULT_ENV_ID)
    }
}

/// Normalize and validate a candidate `public_base_url`. Returns the canonical
/// form (trimmed, trailing `/` removed) on success. Rules mirror
/// `greentic-start::startup_contract::normalize_public_base_url` so a value
/// accepted here passes the runtime's gate without reformatting.
///
/// - Scheme MUST be `http://` or `https://`.
/// - MUST include a non-empty host.
/// - MUST NOT contain whitespace.
/// - MUST NOT include userinfo (`user:pass@`).
/// - MUST NOT include a query string (`?...`).
/// - MUST NOT include a fragment (`#...`).
/// - Path MUST be empty or exactly `/`.
pub fn validate_public_base_url(value: &str) -> Result<String, crate::error::SpecError> {
    let trimmed = value.trim();
    let invalid = |reason: &'static str| crate::error::SpecError::InvalidPublicBaseUrl {
        value: trimmed.to_string(),
        reason,
    };
    if trimmed.is_empty() {
        return Err(invalid("must not be empty"));
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(invalid("must not contain whitespace"));
    }
    // Parse via http::Uri for robust authority/port/host validation.
    let uri: http::Uri = trimmed.parse().map_err(|_| invalid("is not a valid URI"))?;
    // Require http or https scheme.
    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        _ => return Err(invalid("must start with http:// or https://")),
    }
    // Require authority (host[:port]).
    let authority = uri
        .authority()
        .ok_or_else(|| invalid("must include a host"))?;
    // Reject userinfo.
    if authority.as_str().contains('@') {
        return Err(invalid("must not include userinfo"));
    }
    // Reject empty host.
    if authority.host().is_empty() {
        return Err(invalid("must include a host"));
    }
    // Reject non-numeric port: http::Uri accepts `host:bad` (port() → None)
    // but we require a valid numeric port if `:` follows the host.
    if authority.as_str().len() > authority.host().len() && authority.port_u16().is_none() {
        // There's text after the host (a `:something`) but it's not a valid port.
        return Err(invalid("port is not a valid number"));
    }
    // Reject query.
    if uri.query().is_some() {
        return Err(invalid("must not include a query string"));
    }
    // Reject fragment (http::Uri does not parse fragments, but guard anyway).
    if trimmed.contains('#') {
        return Err(invalid("must not include a fragment"));
    }
    // Path must be empty or exactly "/".
    let path = uri.path();
    if !path.is_empty() && path != "/" {
        return Err(invalid("must be an origin without a path"));
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

/// Why [`Environment::resolve_default_bundle`] picked a particular deployment.
/// Callers (e.g. `greentic-start`) log the reason when the choice was implicit
/// so operators can tell whether a bundle was served by explicit config or by
/// fallback heuristics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefaultBundleReason {
    /// [`EnvironmentHostConfig::default_bundle`] named this bundle and it has
    /// an Active, tenant-matched deployment.
    ExplicitConfig,
    /// Exactly one Active deployment matched the tenant — unambiguous.
    LoneActive,
    /// Multiple Active deployments matched; the one with the newest
    /// `created_at` (ties broken by largest `deployment_id`) was chosen.
    NewestActive,
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

/// Deterministic total order for picking the "newest" deployment: newest
/// `created_at` first, ties broken by largest `deployment_id` (ULIDs are
/// monotonic). Used by every rung of
/// [`Environment::resolve_default_bundle`] so the comparator cannot drift
/// between the explicit-config and fallback paths.
fn newest_deployment_order(a: &&BundleDeployment, b: &&BundleDeployment) -> Ordering {
    a.created_at
        .cmp(&b.created_at)
        .then_with(|| a.deployment_id.cmp(&b.deployment_id))
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

    /// Resolve the default bundle deployment for a tenant. Returns the chosen
    /// deployment and the reason it was selected, or `None` when no Active
    /// tenant-matched deployment exists.
    ///
    /// Resolution ladder (in order):
    /// 1. [`EnvironmentHostConfig::default_bundle`] — only if that bundle has
    ///    an Active deployment whose `route_binding.tenant_selector.tenant`
    ///    matches `tenant`. If the configured bundle is missing, not Active,
    ///    or bound to a different tenant, falls through. When multiple
    ///    deployments share the configured `(tenant, bundle_id)`, the newest
    ///    `created_at` / largest `deployment_id` wins (same total order as
    ///    step 3).
    /// 2. If exactly one Active deployment matches the tenant, that one.
    /// 3. The Active tenant-matched deployment with the newest `created_at`;
    ///    ties broken by the larger `deployment_id` (ULIDs are monotonic, so
    ///    this is a deterministic total order).
    /// 4. `None` if no Active deployment matches.
    pub fn resolve_default_bundle(
        &self,
        tenant: &str,
    ) -> Option<(&BundleDeployment, DefaultBundleReason)> {
        // Predicate shared by all ladder steps.
        let is_active_tenant = |b: &&BundleDeployment| {
            b.status == BundleDeploymentStatus::Active
                && b.route_binding.tenant_selector.tenant == tenant
        };

        // (a) Explicit config hit — collect all Active tenant-matched
        //     deployments whose bundle_id equals the configured one, then
        //     pick the newest via the shared total order.
        if let Some(configured) = &self.host_config.default_bundle {
            let hit = self
                .bundles
                .iter()
                .filter(|b| is_active_tenant(b) && b.bundle_id == *configured)
                .max_by(newest_deployment_order);
            if let Some(bd) = hit {
                return Some((bd, DefaultBundleReason::ExplicitConfig));
            }
        }
        // Configured bundle is absent / not Active / wrong tenant — fall through.

        // Collect all Active tenant-matched deployments.
        let mut matches: Vec<&BundleDeployment> = self
            .bundles
            .iter()
            .filter(|b| is_active_tenant(b))
            .collect();

        match matches.len() {
            0 => None,
            1 => Some((matches[0], DefaultBundleReason::LoneActive)),
            _ => {
                // (c) Newest created_at, then largest deployment_id.
                matches.sort_by(|a, b| newest_deployment_order(a, b).reverse());
                Some((matches[0], DefaultBundleReason::NewestActive))
            }
        }
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

        if let Some(url) = self.host_config.public_base_url.as_deref() {
            validate_public_base_url(url)?;
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

#[cfg(test)]
mod public_base_url_tests {
    use super::validate_public_base_url;

    #[test]
    fn accepts_https_origin() {
        assert_eq!(
            validate_public_base_url("https://chat.example.com").unwrap(),
            "https://chat.example.com"
        );
    }

    #[test]
    fn accepts_http_origin() {
        assert_eq!(
            validate_public_base_url("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
    }

    #[test]
    fn trims_trailing_slash() {
        // Match `greentic-start::startup_contract::normalize_public_base_url`
        // so a value persisted here passes the runtime's gate unchanged.
        assert_eq!(
            validate_public_base_url("https://chat.example.com/").unwrap(),
            "https://chat.example.com"
        );
    }

    #[test]
    fn rejects_path() {
        let err = validate_public_base_url("https://chat.example.com/api").unwrap_err();
        assert!(matches!(err, crate::SpecError::InvalidPublicBaseUrl { .. }));
    }

    #[test]
    fn rejects_query() {
        let err = validate_public_base_url("https://chat.example.com?x=1").unwrap_err();
        assert!(matches!(err, crate::SpecError::InvalidPublicBaseUrl { .. }));
    }

    #[test]
    fn rejects_fragment() {
        let err = validate_public_base_url("https://chat.example.com#frag").unwrap_err();
        assert!(matches!(err, crate::SpecError::InvalidPublicBaseUrl { .. }));
    }

    #[test]
    fn rejects_non_http_scheme() {
        let err = validate_public_base_url("ftp://chat.example.com").unwrap_err();
        assert!(matches!(err, crate::SpecError::InvalidPublicBaseUrl { .. }));
    }

    #[test]
    fn rejects_missing_scheme() {
        let err = validate_public_base_url("chat.example.com").unwrap_err();
        assert!(matches!(err, crate::SpecError::InvalidPublicBaseUrl { .. }));
    }

    #[test]
    fn rejects_empty_host() {
        let err = validate_public_base_url("https:///path").unwrap_err();
        assert!(matches!(err, crate::SpecError::InvalidPublicBaseUrl { .. }));
    }

    #[test]
    fn rejects_whitespace() {
        let err = validate_public_base_url("https://chat .example.com").unwrap_err();
        assert!(matches!(err, crate::SpecError::InvalidPublicBaseUrl { .. }));
    }

    #[test]
    fn trims_surrounding_whitespace_before_validation() {
        // Mirrors `normalize_public_base_url`: trim outer whitespace, reject
        // inner whitespace.
        assert_eq!(
            validate_public_base_url("  https://chat.example.com  ").unwrap(),
            "https://chat.example.com"
        );
    }

    #[test]
    fn rejects_userinfo() {
        let err = validate_public_base_url("https://user:pass@example.com").unwrap_err();
        assert!(matches!(err, crate::SpecError::InvalidPublicBaseUrl { .. }));
    }

    #[test]
    fn rejects_empty_host_in_authority() {
        // `https://:443` has an empty host but non-empty authority.
        let err = validate_public_base_url("https://:443").unwrap_err();
        assert!(matches!(err, crate::SpecError::InvalidPublicBaseUrl { .. }));
    }

    #[test]
    fn rejects_authority_with_bad_port() {
        // `http::Uri` rejects a non-numeric port at parse time.
        let err = validate_public_base_url("https://example.com:bad").unwrap_err();
        assert!(matches!(err, crate::SpecError::InvalidPublicBaseUrl { .. }));
    }

    #[test]
    fn accepts_ipv6_origin() {
        // Parity with `greentic-start::normalize_public_base_url`.
        assert_eq!(
            validate_public_base_url("https://[::1]:8080").unwrap(),
            "https://[::1]:8080"
        );
    }
}

#[cfg(test)]
mod gui_enabled_tests {
    use super::{EnvironmentHostConfig, GUI_DEFAULT_ENV_ID};
    use greentic_types::EnvId;

    fn host_config(env_id: &str, gui_enabled: Option<bool>) -> EnvironmentHostConfig {
        EnvironmentHostConfig {
            env_id: EnvId::try_from(env_id).unwrap(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
            gui_enabled,
            default_bundle: None,
        }
    }

    #[test]
    fn unset_defaults_on_for_local() {
        assert_eq!(GUI_DEFAULT_ENV_ID, "local");
        assert!(host_config("local", None).resolved_gui_enabled());
    }

    #[test]
    fn unset_defaults_off_for_non_local() {
        assert!(!host_config("staging", None).resolved_gui_enabled());
    }

    #[test]
    fn explicit_value_overrides_env_id_default() {
        // Off on local (the wizard "no" case) ...
        assert!(!host_config("local", Some(false)).resolved_gui_enabled());
        // ... and on for a non-local env (explicit opt-in).
        assert!(host_config("staging", Some(true)).resolved_gui_enabled());
    }
}

#[cfg(test)]
mod default_bundle_tests {
    use super::*;
    use crate::bundle_deployment::{
        BundleDeployment, BundleDeploymentStatus, RevenueShareEntry, RouteBinding, TenantSelector,
    };
    use crate::ids::{BundleId, CustomerId, DeploymentId, PartyId};
    use crate::version::SchemaVersion;
    use chrono::{DateTime, TimeZone, Utc};
    use greentic_types::EnvId;
    use std::path::PathBuf;

    const TENANT: &str = "acme";

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn base_env(default_bundle: Option<BundleId>) -> Environment {
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id(),
            name: "local".into(),
            host_config: EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
                default_bundle,
            },
            packs: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            messaging_endpoints: Vec::new(),
            extensions: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    fn deployment(
        bundle_id: &str,
        tenant: &str,
        status: BundleDeploymentStatus,
        created_at: DateTime<Utc>,
        deployment_id: DeploymentId,
    ) -> BundleDeployment {
        BundleDeployment {
            schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
            deployment_id,
            env_id: env_id(),
            bundle_id: BundleId::new(bundle_id),
            customer_id: CustomerId::new("local-dev"),
            status,
            current_revisions: Vec::new(),
            route_binding: RouteBinding {
                hosts: Vec::new(),
                path_prefixes: Vec::new(),
                tenant_selector: TenantSelector {
                    tenant: tenant.to_string(),
                    team: "default".to_string(),
                },
            },
            revenue_share: vec![RevenueShareEntry {
                party_id: PartyId::new("operator"),
                basis_points: 10_000,
            }],
            revenue_policy_ref: PathBuf::from("revenue-policy.json"),
            usage: None,
            created_at,
            authorization_ref: PathBuf::from("authorization.json"),
            config_overrides: Default::default(),
        }
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn did(val: u128) -> DeploymentId {
        DeploymentId(ulid::Ulid(val))
    }

    // -- explicit config hit --

    #[test]
    fn explicit_config_hits_active_tenant_matched_bundle() {
        let mut env = base_env(Some(BundleId::new("chat-bundle")));
        env.bundles.push(deployment(
            "chat-bundle",
            TENANT,
            BundleDeploymentStatus::Active,
            ts(1000),
            did(1),
        ));
        let (bd, reason) = env.resolve_default_bundle(TENANT).unwrap();
        assert_eq!(bd.bundle_id.as_str(), "chat-bundle");
        assert_eq!(reason, DefaultBundleReason::ExplicitConfig);
    }

    #[test]
    fn explicit_config_picks_newest_among_duplicates() {
        // Two Active deployments share the same (tenant, bundle_id).
        // The explicit path must pick the newest created_at / largest
        // deployment_id — the same total order the fallback rungs use.
        // Insert the *newer* deployment first so a naive `.find()` would
        // return it by accident; the test proves the choice is
        // order-independent by also checking the reversed insertion order.
        let newer_did = did(200);
        let older_did = did(100);

        let mut env = base_env(Some(BundleId::new("dup-bundle")));
        // Newer first in vec — a `.find()` regression would still pass
        // if we only checked this order, so we verify both.
        env.bundles.push(deployment(
            "dup-bundle",
            TENANT,
            BundleDeploymentStatus::Active,
            ts(5000),
            newer_did,
        ));
        env.bundles.push(deployment(
            "dup-bundle",
            TENANT,
            BundleDeploymentStatus::Active,
            ts(3000),
            older_did,
        ));
        let (bd, reason) = env.resolve_default_bundle(TENANT).unwrap();
        assert_eq!(reason, DefaultBundleReason::ExplicitConfig);
        assert_eq!(bd.deployment_id, newer_did);

        // Reverse insertion order — must still pick the newer one.
        let mut env2 = base_env(Some(BundleId::new("dup-bundle")));
        env2.bundles.push(deployment(
            "dup-bundle",
            TENANT,
            BundleDeploymentStatus::Active,
            ts(3000),
            older_did,
        ));
        env2.bundles.push(deployment(
            "dup-bundle",
            TENANT,
            BundleDeploymentStatus::Active,
            ts(5000),
            newer_did,
        ));
        let (bd2, reason2) = env2.resolve_default_bundle(TENANT).unwrap();
        assert_eq!(reason2, DefaultBundleReason::ExplicitConfig);
        assert_eq!(bd2.deployment_id, newer_did);
    }

    // -- explicit config falls through --

    #[test]
    fn explicit_config_falls_through_when_bundle_absent() {
        let env = base_env(Some(BundleId::new("missing")));
        assert!(env.resolve_default_bundle(TENANT).is_none());
    }

    #[test]
    fn explicit_config_falls_through_when_not_active() {
        let mut env = base_env(Some(BundleId::new("paused-bundle")));
        env.bundles.push(deployment(
            "paused-bundle",
            TENANT,
            BundleDeploymentStatus::Paused,
            ts(1000),
            did(1),
        ));
        assert!(env.resolve_default_bundle(TENANT).is_none());
    }

    #[test]
    fn explicit_config_falls_through_when_wrong_tenant() {
        let mut env = base_env(Some(BundleId::new("other-tenant-bundle")));
        env.bundles.push(deployment(
            "other-tenant-bundle",
            "other-corp",
            BundleDeploymentStatus::Active,
            ts(1000),
            did(1),
        ));
        assert!(env.resolve_default_bundle(TENANT).is_none());
    }

    #[test]
    fn explicit_config_wrong_tenant_falls_through_to_lone_active() {
        let mut env = base_env(Some(BundleId::new("wrong-tenant")));
        env.bundles.push(deployment(
            "wrong-tenant",
            "other-corp",
            BundleDeploymentStatus::Active,
            ts(1000),
            did(1),
        ));
        env.bundles.push(deployment(
            "correct-bundle",
            TENANT,
            BundleDeploymentStatus::Active,
            ts(2000),
            did(2),
        ));
        let (bd, reason) = env.resolve_default_bundle(TENANT).unwrap();
        assert_eq!(bd.bundle_id.as_str(), "correct-bundle");
        assert_eq!(reason, DefaultBundleReason::LoneActive);
    }

    // -- lone active --

    #[test]
    fn lone_active_deployment_wins() {
        let mut env = base_env(None);
        env.bundles.push(deployment(
            "solo",
            TENANT,
            BundleDeploymentStatus::Active,
            ts(1000),
            did(1),
        ));
        let (bd, reason) = env.resolve_default_bundle(TENANT).unwrap();
        assert_eq!(bd.bundle_id.as_str(), "solo");
        assert_eq!(reason, DefaultBundleReason::LoneActive);
    }

    // -- newest created_at --

    #[test]
    fn newest_created_at_wins_among_multiple() {
        let mut env = base_env(None);
        env.bundles.push(deployment(
            "old",
            TENANT,
            BundleDeploymentStatus::Active,
            ts(1000),
            did(1),
        ));
        env.bundles.push(deployment(
            "new",
            TENANT,
            BundleDeploymentStatus::Active,
            ts(2000),
            did(2),
        ));
        let (bd, reason) = env.resolve_default_bundle(TENANT).unwrap();
        assert_eq!(bd.bundle_id.as_str(), "new");
        assert_eq!(reason, DefaultBundleReason::NewestActive);
    }

    // -- ULID tiebreak --

    #[test]
    fn ulid_tiebreak_is_deterministic() {
        let same_time = ts(5000);
        let mut env = base_env(None);
        env.bundles.push(deployment(
            "smaller-id",
            TENANT,
            BundleDeploymentStatus::Active,
            same_time,
            did(10),
        ));
        env.bundles.push(deployment(
            "larger-id",
            TENANT,
            BundleDeploymentStatus::Active,
            same_time,
            did(20),
        ));
        let (bd, reason) = env.resolve_default_bundle(TENANT).unwrap();
        assert_eq!(bd.bundle_id.as_str(), "larger-id");
        assert_eq!(reason, DefaultBundleReason::NewestActive);

        // Reversing insertion order must yield the same result.
        let mut env2 = base_env(None);
        env2.bundles.push(deployment(
            "larger-id",
            TENANT,
            BundleDeploymentStatus::Active,
            same_time,
            did(20),
        ));
        env2.bundles.push(deployment(
            "smaller-id",
            TENANT,
            BundleDeploymentStatus::Active,
            same_time,
            did(10),
        ));
        let (bd2, _) = env2.resolve_default_bundle(TENANT).unwrap();
        assert_eq!(bd2.bundle_id.as_str(), "larger-id");
    }

    // -- empty / no match --

    #[test]
    fn empty_bundles_returns_none() {
        let env = base_env(None);
        assert!(env.resolve_default_bundle(TENANT).is_none());
    }

    #[test]
    fn no_active_tenant_match_returns_none() {
        let mut env = base_env(None);
        // Wrong tenant.
        env.bundles.push(deployment(
            "other",
            "other-corp",
            BundleDeploymentStatus::Active,
            ts(1000),
            did(1),
        ));
        // Right tenant, but paused.
        env.bundles.push(deployment(
            "paused",
            TENANT,
            BundleDeploymentStatus::Paused,
            ts(2000),
            did(2),
        ));
        assert!(env.resolve_default_bundle(TENANT).is_none());
    }

    // -- serde round-trip --

    #[test]
    fn absent_default_bundle_deserializes_to_none_and_none_is_not_serialized() {
        let hc = EnvironmentHostConfig {
            env_id: env_id(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
            gui_enabled: None,
            default_bundle: None,
        };
        let json = serde_json::to_string(&hc).unwrap();
        assert!(
            !json.contains("default_bundle"),
            "None field must not appear in serialized JSON"
        );
        let back: EnvironmentHostConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.default_bundle, None);
    }

    #[test]
    fn present_default_bundle_round_trips() {
        let hc = EnvironmentHostConfig {
            env_id: env_id(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
            gui_enabled: None,
            default_bundle: Some(BundleId::new("my-bundle")),
        };
        let json = serde_json::to_string(&hc).unwrap();
        assert!(json.contains("\"default_bundle\":\"my-bundle\""));
        let back: EnvironmentHostConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.default_bundle.as_ref().map(|b| b.as_str()),
            Some("my-bundle")
        );
    }
}
