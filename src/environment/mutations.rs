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

use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CapabilitySlot, CustomerId, DeploymentId,
    EnvId, EnvPackBinding, Environment, EnvironmentHostConfig, ExtensionBinding, IdempotencyKey,
    MessagingEndpoint, MessagingEndpointId, PackId, RevenueShareEntry, Revision, RevisionId,
    RouteBinding,
};
use serde_json::Value;

use super::StoreError;

// PR-4.2a/4.2b/4.2c: the env-lifecycle payload shapes (`ExtensionKey`,
// `FieldUpdate`, `UpdateEnvironmentPayload`, `MigrateSeedPayload`,
// `MigrateMergePayload`), the revision verb group's
// (`StageRevisionPayload`, `WarmRevisionPayload`,
// `RevisionTransitionOutcome`) and the traffic verb group's
// (`SetTrafficSplitPayload`, `ApplyTrafficSplitOutcome`,
// `RollbackTrafficSplitOutcome`) moved to `greentic_deploy_spec::engine` so
// the operator-store-server applies the same verb semantics (and wire
// encoding) as `LocalFsStore`. Re-exported here so every existing
// `environment::mutations::…` path keeps working. The revision payloads no
// longer carry `idempotency_key` — the key rides the trait methods (and the
// A8 `Idempotency-Key` header), matching every other verb group. (The
// traffic outcomes gained an `environment` snapshot: the CLI emits
// `TrafficSplitApplied` telemetry from it, identical local and remote.)
// PR-4.2f: the trust-root group's wire shapes (`AddTrustedKeyPayload`,
// `TrustRootSeed`, `TrustRootAddOutcome`, `TrustRootRemoveOutcome`)
// followed — shapes only; the pure transforms need crypto and live in
// `greentic-operator-trust`.
pub use greentic_deploy_spec::engine::{
    AddTrustedKeyPayload, ApplyTrafficSplitOutcome, ExtensionKey, FieldUpdate, MigrateMergePayload,
    MigrateSeedPayload, RevisionTransitionOutcome, RollbackTrafficSplitOutcome,
    SetTrafficSplitPayload, StageRevisionPayload, TrustRootAddOutcome, TrustRootRemoveOutcome,
    TrustRootSeed, UpdateEnvironmentPayload, WarmRevisionPayload,
};

/// Outcome of [`EnvironmentMutations::remove_bundle`]. Surfaces the
/// archived revisions that were pruned alongside the deployment so the
/// destructive side effect is explicit on the contract — the CLI records
/// the IDs in the audit target, and HTTP backends can apply a separate
/// authorization check against the prune set before committing.
#[derive(Debug, Clone)]
pub struct RemoveBundleOutcome {
    pub deployment: BundleDeployment,
    /// IDs of revisions removed from `Environment.revisions` as part of the
    /// post-removal compaction (always in `Archived` state because the
    /// live-state guard refuses any non-archived revision under the
    /// deployment).
    pub pruned_revision_ids: Vec<RevisionId>,
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
    /// A8 §2 idempotency key. The local-FS impl accepts and ignores;
    /// the HTTP backend caches it for safe-retry replay.
    pub idempotency_key: IdempotencyKey,
}

/// Inputs to [`EnvironmentMutations::update_bundle`].
#[derive(Debug, Clone)]
pub struct UpdateBundlePayload {
    pub deployment_id: DeploymentId,
    pub status: Option<BundleDeploymentStatus>,
    pub route_binding: Option<RouteBinding>,
    pub revenue_share: Option<Vec<RevenueShareEntry>>,
    pub config_overrides: Option<BTreeMap<String, BTreeMap<String, Value>>>,
    /// A8 §2 idempotency key. The local-FS impl accepts and ignores;
    /// the HTTP backend caches it for safe-retry replay.
    pub idempotency_key: IdempotencyKey,
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

    /// Patch the named scalar fields on an existing environment.
    /// [`FieldUpdate::Keep`] fields are skipped, [`FieldUpdate::Set`]
    /// writes the new value, [`FieldUpdate::Clear`] resets optional
    /// fields to `None`. The full updated `Environment` is returned.
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
    /// `payload.seed_if_missing` is the optional seed-on-create-target
    /// branch used by `op env migrate-dev` to migrate a legacy `dev` env
    /// into a fresh `local` target atomically — load, fallback-to-seed,
    /// merge, save all happen under one lock.
    fn migrate_merge_bindings(
        &self,
        target_env_id: &EnvId,
        payload: MigrateMergePayload,
    ) -> Result<(Vec<String>, Vec<String>), StoreError>;

    // -------------------------------------------------------------
    // Revision lifecycle
    //   `op revisions stage | warm | drain | archive`
    // -------------------------------------------------------------

    /// Stage a fresh revision under `deployment_id`. The caller supplies
    /// the pinned artifact pointers; `LocalFsStore`'s CLI helper resolves
    /// them from a local `.gtbundle` upstream of this call so the trait
    /// stays storage-only.
    ///
    /// `idempotency_key`: A8 §2 — same-key replay returns the originally
    /// staged `Revision` without re-minting the ULID or advancing the
    /// sequence. Local impl accepts and ignores; HTTP backends cache it.
    fn stage_revision(
        &self,
        env_id: &EnvId,
        payload: StageRevisionPayload,
        idempotency_key: IdempotencyKey,
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
        idempotency_key: IdempotencyKey,
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
        payload: UpdateBundlePayload,
    ) -> Result<BundleDeployment, StoreError>;

    /// Remove a bundle deployment from the env. Refuses if the deployment
    /// still has live traffic splits or non-archived revisions —
    /// callers must `op traffic clear` and archive revisions first.
    ///
    /// Also drops archived revisions for the same `deployment_id` so the
    /// env stays compact. The pruned IDs are surfaced on the outcome so
    /// the destructive side effect is explicit on the contract —
    /// HTTP backends can apply a separate authorization check against
    /// the prune set, the CLI logs the IDs in the audit target.
    ///
    /// `idempotency_key` is required for A8 §2 mutation replay; the local
    /// impl accepts and ignores, the HTTP backend caches the original
    /// outcome.
    fn remove_bundle(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RemoveBundleOutcome, StoreError>;

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
        payload: SetTrafficSplitPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<ApplyTrafficSplitOutcome, StoreError>;

    fn rollback_traffic_split(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RollbackTrafficSplitOutcome, StoreError>;

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

    /// Load (or generate) the backend's operator signing key and add it to
    /// the env trust root. Idempotent re-grant: a second call with the same
    /// operator key is a no-op on the key set (case-insensitive `key_id`
    /// dedup), and it never rejects on an existing trust root.
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
    ) -> Result<TrustRootAddOutcome, StoreError>;

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
    ) -> Result<TrustRootRemoveOutcome, StoreError>;
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

    // `FieldUpdate` / `UpdateEnvironmentPayload` / `ExtensionKey` unit tests
    // moved to `greentic_deploy_spec::engine` alongside the types (PR-4.2a).
}
