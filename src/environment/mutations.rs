//! [`EnvironmentMutations`] — typed-verb trait for state mutations on a
//! Greentic environment.
//!
//! Phase D rescope (2026-06-09): this trait replaces the closure-based
//! [`LocalFsStore::transact`](super::LocalFsStore::transact) pattern with one
//! method per logical CLI verb. See `plans/next-gen-deployment.md` §13.5 #2
//! for the architectural rationale; in short: closures can't cross the A8
//! HTTP wire contract (`greentic_deploy_spec::remote`), so the deployer-CLI's
//! seam against a remote store has to be typed verbs, not opaque
//! `FnOnce(&Locked)` closures.
//!
//! This module ships in **PR-3a.1 as signatures only** — there are no impls,
//! and no callers reach the trait yet. PR-3a.2..3a.16 migrate one verb group
//! at a time, each adding the `LocalFsStore` impl + flipping the matching
//! CLI helper from `store.transact(|locked| …)` to a typed call. PR-3b lands
//! `HttpEnvironmentStore` implementing the same trait over the A8 HTTP
//! contract.
//!
//! Signatures here are derived from the existing 33 `LocalFsStore::transact`
//! sites in `src/cli/*` (15 logical verb groups, ~28 methods). They may
//! tweak as PR-3a.2..16 add impls — flag drift in code review.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CapabilitySlot, CustomerId, DeploymentId,
    EnvId, EnvPackBinding, Environment, EnvironmentHostConfig, ExtensionBinding, IdempotencyKey,
    MessagingEndpoint, MessagingEndpointId, PackId, RevenueShareEntry, Revision, RevisionId,
    RevisionLifecycle, RouteBinding, TrafficSplit, TrafficSplitEntry,
};
use serde_json::Value;

use super::StoreError;
use super::lifecycle::HealthGateFailure;

/// `(kind_path, instance_id)` composite key identifying one extension binding
/// in `Environment::extensions`. `kind_path` is the canonical
/// `ExtensionKind::path()` form (e.g. `"capability/memory/long-term"`).
///
/// `instance_id` is `Option<String>`: a `None` binding (the unnamed default)
/// and a `Some("default")` binding on the same `kind_path` are **distinct**
/// and may coexist — two `None` bindings on the same path collide.
/// This mirrors `ExtensionBinding::instance_id` in `greentic-deploy-spec`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtensionKey {
    pub kind_path: String,
    pub instance_id: Option<String>,
}

impl ExtensionKey {
    pub fn new(kind_path: impl Into<String>, instance_id: Option<String>) -> Self {
        Self {
            kind_path: kind_path.into(),
            instance_id,
        }
    }

    /// Derive the key from an existing [`ExtensionBinding`], mirroring the
    /// `(descriptor-path, instance_id)` convention in `cli/extensions.rs`.
    pub fn from_binding(b: &ExtensionBinding) -> Self {
        Self {
            kind_path: b.kind.path().to_string(),
            instance_id: b.instance_id.clone(),
        }
    }
}

/// Outcome of mutating a revision-lifecycle verb (`warm`/`drain`/`archive`).
/// Carries the post-transition revision, the parent env after the save, and
/// the starting lifecycle for idempotent-no-op detection and audit emission.
#[derive(Debug, Clone)]
pub struct RevisionTransitionOutcome {
    pub revision: Revision,
    pub environment: Environment,
    pub starting_lifecycle: RevisionLifecycle,
}

/// Outcome of seeding the bootstrap trust root for an env (the operator
/// signing key for revenue policies and other env-scoped DSSE artifacts).
///
/// `trusted_key_count` is the post-add total — the CLI surfaces it on the
/// wire so operators can see at a glance whether they added a duplicate.
#[derive(Debug, Clone)]
pub struct TrustRootSeed {
    pub key_id: String,
    pub public_key_pem: String,
    pub trusted_key_count: usize,
}

/// Optional-field patch for [`EnvironmentMutations::update_environment`].
/// Replaces the earlier `set_public_url` and `set_config` verbs — both were
/// strict subsets of this patch shape, so collapsing them removes two
/// HTTP endpoints and two impl bodies that would drift over time.
#[derive(Debug, Clone, Default)]
pub struct UpdateEnvironmentPayload {
    pub name: Option<String>,
    pub region: Option<String>,
    pub tenant_org_id: Option<String>,
    pub listen_addr: Option<SocketAddr>,
    pub public_base_url: Option<String>,
}

/// Inputs to [`EnvironmentMutations::stage_revision`]. Bundled so the
/// method signature stays under clippy's `too_many_arguments` threshold;
/// the existing `cli::revisions::RevisionStagePayload` is the CLI-shaped
/// counterpart and maps to this at the call site.
#[derive(Debug, Clone)]
pub struct StageRevisionPayload {
    pub deployment_id: DeploymentId,
    pub bundle_digest: String,
    pub pack_list_lock_ref: String,
    pub pack_config_refs: BTreeMap<String, String>,
    pub config_digest: Option<String>,
    pub signature_sidecar_ref: Option<PathBuf>,
    pub drain_seconds: Option<u32>,
    /// A8 idempotency: same-key replay returns the originally staged
    /// `Revision` without re-minting the ULID or advancing
    /// `deployment.next_sequence`.
    pub idempotency_key: IdempotencyKey,
}

/// Inputs to [`EnvironmentMutations::warm_revision`]. The closure-based gate
/// from [`apply_revision_transition_with_health_gate`](super::apply_revision_transition_with_health_gate)
/// can't cross the HTTP wire, so the deployer CLI evaluates runner health
/// locally and ships the typed outcome. The impl applies `Ok(())` → `Ready`
/// or `Err(failure)` → `Failed` atomically.
#[derive(Debug, Clone)]
pub struct WarmRevisionPayload {
    pub revision_id: RevisionId,
    /// The client-evaluated health-gate outcome. `Ok(())` advances the
    /// revision to `Ready`; `Err(failure)` flips it to `Failed`
    /// atomically inside the impl.
    pub health_gate: Result<(), HealthGateFailure>,
    pub idempotency_key: IdempotencyKey,
}

/// Inputs to [`EnvironmentMutations::add_bundle`].
#[derive(Debug, Clone)]
pub struct AddBundlePayload {
    pub bundle_id: BundleId,
    pub customer_id: CustomerId,
    pub revenue_share: Vec<RevenueShareEntry>,
    pub route_binding: Option<RouteBinding>,
    pub authorization_ref: Option<String>,
    pub config_overrides: BTreeMap<String, BTreeMap<String, Value>>,
}

/// Inputs to [`EnvironmentMutations::add_messaging_endpoint`].
#[derive(Debug, Clone)]
pub struct AddMessagingEndpointPayload {
    pub provider_id: String,
    pub provider_type: String,
    pub display_name: String,
    pub secret_refs: Vec<String>,
    pub updated_by: String,
    pub idempotency_key: IdempotencyKey,
}

/// Inputs to [`EnvironmentMutations::set_messaging_welcome_flow`].
#[derive(Debug, Clone)]
pub struct SetMessagingWelcomeFlowPayload {
    pub endpoint_id: MessagingEndpointId,
    pub bundle_id: BundleId,
    pub pack_id: PackId,
    pub flow_id: String,
    pub updated_by: String,
    pub idempotency_key: IdempotencyKey,
}

/// The typed-verb persistence operations a Greentic environment store
/// performs in response to `op …` CLI verbs.
///
/// Replaces the closure-based `LocalFsStore::transact` pattern with one
/// method per logical verb. All methods take `&self` — concurrency is the
/// impl's responsibility (flock for `LocalFsStore`, optimistic CAS via
/// `If-Match` for `HttpEnvironmentStore` against an A8-compliant server).
///
/// Methods that need idempotency replay (per A8 §2) take an
/// [`IdempotencyKey`]; methods that are intrinsically idempotent (e.g.
/// `seed_trust_root_if_absent`) do not.
///
/// **Errors**: all methods return [`StoreError`]. Impls may map their
/// transport-specific errors into the existing variants; new variants land
/// alongside the impl that needs them.
pub trait EnvironmentMutations: Send + Sync {
    // -------------------------------------------------------------
    // Environment lifecycle
    //   `op env create | update | set-public-url`
    //   `op config set`
    //
    // `op env init` / `gtc setup` is NOT on this trait — it's local-FS
    // only (default-binding heal + runtime stub), so it stays inherent
    // on `LocalFsStore`. The HTTP backend has its own bootstrap path.
    // -------------------------------------------------------------

    /// Create a fresh environment with empty bundles/revisions/packs.
    /// Rejects if the env already exists.
    fn create_environment(
        &self,
        env_id: &EnvId,
        name: String,
        host_config: EnvironmentHostConfig,
    ) -> Result<Environment, StoreError>;

    /// Patch the named scalar fields on an existing environment. `None`
    /// values are skipped. The full updated `Environment` is returned.
    /// Covers what was previously split across `update_environment` (no
    /// `listen_addr`), `set_public_url` (single field), and `set_config`
    /// (host-level fields including `listen_addr`). One verb, one HTTP
    /// endpoint, one impl body per backend.
    fn update_environment(
        &self,
        env_id: &EnvId,
        patch: UpdateEnvironmentPayload,
    ) -> Result<Environment, StoreError>;

    // -------------------------------------------------------------
    // Migration
    //   `op env migrate-dev --apply`
    // -------------------------------------------------------------

    /// Merge pack bindings and extension bindings into `target_env_id`.
    /// Skips slots / extension keys already bound in the target. Returns
    /// the list of newly-merged slots + extension key strings (in the
    /// form `"<kind_path>::<instance_id>"`).
    ///
    /// Takes the bindings directly rather than a full source `Environment`
    /// so the HTTP impl doesn't have to ship an entire env aggregate when
    /// the operation reads only these two vectors.
    fn migrate_merge_bindings(
        &self,
        target_env_id: &EnvId,
        packs: &[EnvPackBinding],
        extensions: &[ExtensionBinding],
    ) -> Result<(Vec<String>, Vec<String>), StoreError>;

    // -------------------------------------------------------------
    // Revision lifecycle
    //   `op revisions stage | warm | drain | archive`
    // -------------------------------------------------------------

    /// Stage a fresh revision under `deployment_id`. The caller supplies
    /// the pinned artifact pointers; `LocalFsStore`'s CLI helper resolves
    /// them from a local `.gtbundle` upstream of this call so the trait
    /// stays storage-only.
    fn stage_revision(
        &self,
        env_id: &EnvId,
        payload: StageRevisionPayload,
    ) -> Result<Revision, StoreError>;

    /// Transition a revision through its `warm` lifecycle chain, applying the
    /// client-evaluated health-gate outcome. The deployer CLI runs the
    /// runner-side health checks locally and ships the result in
    /// [`WarmRevisionPayload::health_gate`]: `Ok(())` advances the revision
    /// to `Ready`; `Err(failure)` flips it to `Failed` atomically. This
    /// replaces the closure-based gate so the operation can cross the A8
    /// HTTP wire contract.
    fn warm_revision(
        &self,
        env_id: &EnvId,
        payload: WarmRevisionPayload,
    ) -> Result<RevisionTransitionOutcome, StoreError>;

    /// Drain a `Ready` revision (graceful step-down → `Drained`).
    /// `idempotency_key` is required for A8 mutation consistency even though
    /// drain is logically idempotent — the key enables audit-event replay.
    fn drain_revision(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError>;

    /// Archive a `Drained` / `Failed` revision (terminal).
    /// `idempotency_key` is required for A8 mutation consistency even though
    /// archive is logically idempotent — the key enables audit-event replay.
    fn archive_revision(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError>;

    // -------------------------------------------------------------
    // Bundle deployment CRUD
    //   `op bundles add | update | remove`
    // -------------------------------------------------------------

    fn add_bundle(
        &self,
        env_id: &EnvId,
        payload: AddBundlePayload,
    ) -> Result<BundleDeployment, StoreError>;

    fn update_bundle(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        status: Option<BundleDeploymentStatus>,
        route_binding: Option<RouteBinding>,
        revenue_share: Option<Vec<RevenueShareEntry>>,
        config_overrides: Option<BTreeMap<String, BTreeMap<String, Value>>>,
    ) -> Result<BundleDeployment, StoreError>;

    fn remove_bundle(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
    ) -> Result<BundleDeployment, StoreError>;

    // -------------------------------------------------------------
    // Env-pack binding CRUD
    //   `op env-packs add | update | remove | rollback`
    // -------------------------------------------------------------

    fn add_pack_binding(
        &self,
        env_id: &EnvId,
        binding: EnvPackBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<EnvPackBinding, StoreError>;

    /// Returns `(new_binding, new_generation)` — the bumped audit generation
    /// is surfaced for downstream observability.
    fn update_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        binding: EnvPackBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError>;

    fn remove_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError>;

    fn rollback_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError>;

    // -------------------------------------------------------------
    // Extension binding CRUD
    //   `op extensions add | update | remove | rollback`
    // -------------------------------------------------------------

    fn add_extension_binding(
        &self,
        env_id: &EnvId,
        binding: ExtensionBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<ExtensionBinding, StoreError>;

    fn update_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        binding: ExtensionBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError>;

    fn remove_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError>;

    fn rollback_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError>;

    // -------------------------------------------------------------
    // Traffic
    //   `op traffic set | rollback`
    // -------------------------------------------------------------

    fn set_traffic_split(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        entries: Vec<TrafficSplitEntry>,
        idempotency_key: IdempotencyKey,
        updated_by: String,
        authorization_ref: Option<String>,
    ) -> Result<TrafficSplit, StoreError>;

    fn rollback_traffic_split(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
    ) -> Result<TrafficSplit, StoreError>;

    // -------------------------------------------------------------
    // Messaging endpoints
    //   `op messaging endpoint add | link-bundle | unlink-bundle
    //                  | set-welcome-flow | remove | rotate-webhook-secret`
    // -------------------------------------------------------------

    fn add_messaging_endpoint(
        &self,
        env_id: &EnvId,
        payload: AddMessagingEndpointPayload,
    ) -> Result<MessagingEndpoint, StoreError>;

    fn link_messaging_bundle(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        bundle_id: BundleId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError>;

    fn unlink_messaging_bundle(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        bundle_id: BundleId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError>;

    fn set_messaging_welcome_flow(
        &self,
        env_id: &EnvId,
        payload: SetMessagingWelcomeFlowPayload,
    ) -> Result<MessagingEndpoint, StoreError>;

    fn remove_messaging_endpoint(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
    ) -> Result<MessagingEndpointId, StoreError>;

    fn rotate_messaging_webhook_secret(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError>;

    // -------------------------------------------------------------
    // Trust root
    //   `op trust-root bootstrap | add | remove`
    //   (`seed_trust_root_if_absent` is called from `op env init`)
    // -------------------------------------------------------------

    /// Generate and persist a fresh operator signing key for the env.
    /// Rejects if a trust root already exists.
    fn bootstrap_trust_root(&self, env_id: &EnvId) -> Result<TrustRootSeed, StoreError>;

    /// Idempotent variant called from `op env init`: returns `Some(seed)`
    /// when a key was minted, `None` when a trust root already existed.
    fn seed_trust_root_if_absent(
        &self,
        env_id: &EnvId,
    ) -> Result<Option<TrustRootSeed>, StoreError>;

    /// `idempotency_key` is required for A8 mutation consistency even though
    /// `add_trusted_key` is intrinsically idempotent on `key_id` collision —
    /// the key enables HTTP-backend audit-event replay. Local-FS impls accept
    /// and ignore it; HTTP impls cache it for replay.
    fn add_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        public_key_pem: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<Value, StoreError>;

    /// `idempotency_key` is required for A8 mutation consistency. `remove`
    /// is logically idempotent on the trust-root state, but the wire-shape
    /// `removed_public_key_pem` field would be `null` on retry (the original
    /// PEM is gone) — so a retry without replay loses recovery material AND
    /// audit fidelity. The key enables HTTP-backend replay of the original
    /// response/audit; local-FS impls accept and ignore it.
    fn remove_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<Value, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time guard: the trait stays object-safe so future code can
    /// hold `&dyn EnvironmentMutations` / `Box<dyn EnvironmentMutations>`
    /// (e.g. for runtime selection between `LocalFsStore` and
    /// `HttpEnvironmentStore` in PR-3c).
    #[allow(dead_code)]
    fn _is_object_safe(_: &dyn EnvironmentMutations) {}

    #[test]
    fn extension_key_roundtrips() {
        let key = ExtensionKey::new("capability/memory/long-term", Some("default".to_string()));
        assert_eq!(key.kind_path, "capability/memory/long-term");
        assert_eq!(key.instance_id, Some("default".to_string()));

        // Hashable + Eq for use in `HashMap` / `HashSet` (the existing
        // `extensions.rs` uses `(kind.path(), instance_id)` as a lookup
        // key).
        let mut set = std::collections::HashSet::new();
        set.insert(key.clone());
        assert!(set.contains(&key));

        // `None` and `Some("default")` on the SAME kind_path are distinct
        // identities: an unnamed binding (None) is the default instance,
        // a named "default" binding is a separate instance — both coexist
        // per `ExtensionBinding`'s doc comment in `greentic-deploy-spec`.
        let unnamed = ExtensionKey::new("capability/memory/long-term", None);
        assert_ne!(unnamed, key, "None and Some(_) must differ");
        assert!(
            !set.contains(&unnamed),
            "None key must not hash-collide with Some(_) key"
        );
        set.insert(unnamed.clone());
        assert_eq!(set.len(), 2);
    }
}
