//! `ensure_local_environment` (`A4` of `plans/next-gen-deployment.md`).
//!
//! Idempotent bootstrap of the `local` [`Environment`] with the five default
//! [`greentic_deploy_spec::EnvPackBinding`]s (deployer/secrets/telemetry/sessions/state).
//! Invoked by `gtc setup` and `gtc start` before any operator-state read so
//! first-run installs always have an env to bind against.
//!
//! Heavy resolution of the descriptor strings to concrete handlers is the
//! env-pack registry's job (A9); A4 only persists the binding intent.

use chrono::Utc;
use greentic_deploy_spec::{
    CapabilitySlot, EnvId, Environment, EnvironmentRuntime, PackDescriptor, SchemaVersion,
};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::defaults::{LOCAL_DEPLOYER_PACK, LOCAL_ENV_ID};
use crate::env_packs::LocalProcessDeployerHandler;
// Re-export so `cli::env` can reference `super::bootstrap::LocalEnvOutcome`
// as before (the enum moved from this module to `environment::bootstrap`).
pub use crate::environment::LocalEnvOutcome;
use crate::environment::{EnsureLocalEnvironmentPayload, LocalFsStore, Locked};

use super::{OpError, map_store_err_preserving_noun};

/// Creates the `local` Environment with default env-pack bindings if absent.
///
/// Idempotent: callers may invoke this on every `gtc setup` / `gtc start`
/// without checking first. Returns `(Environment, LocalEnvOutcome)` so
/// consumers can log a one-line note on creation and stay silent otherwise.
///
/// `public_base_url`: when `Some`, persisted on the env's `host_config` ONLY
/// during creation (so a `Created` outcome carries it). For `AlreadyExists`
/// and `Healed` outcomes the existing URL is preserved — use
/// `op env set-public-url` (or `op config set --public-url`) to overwrite it.
/// The value is NOT validated here; callers (the `op env init` dispatcher)
/// must run [`greentic_deploy_spec::validate_public_base_url`] before passing
/// it in.
///
/// Delegates to [`LocalFsStore::ensure_local_environment`] for the atomic
/// read-modify-write, then runs `refresh_local_runtime_stub` at the CLI
/// layer.
pub fn ensure_local_environment(
    store: &LocalFsStore,
    public_base_url: Option<String>,
) -> Result<(Environment, LocalEnvOutcome), OpError> {
    let env_id = EnvId::try_from(LOCAL_ENV_ID).map_err(|e| {
        OpError::InvalidArgument(format!("default env id `{}`: {}", LOCAL_ENV_ID, e))
    })?;
    let payload = EnsureLocalEnvironmentPayload { public_base_url };
    let (env, outcome) = store
        .ensure_local_environment(&env_id, payload)
        .map_err(map_store_err_preserving_noun)?;
    // Runtime stub refresh runs outside the typed verb's flock. The tiny
    // race window is acceptable — the stub is a derived projection that
    // self-heals on every bootstrap call.
    let force_bump = !matches!(outcome, LocalEnvOutcome::AlreadyExists);
    store.transact(&env_id, |locked| -> Result<(), OpError> {
        refresh_local_runtime_stub(locked, &env, force_bump)?;
        Ok(())
    })?;
    Ok((env, outcome))
}

/// Refresh (or create) the local-process deployer's `runtime.json` stub.
/// `force_bump = true` (Create/Heal): always write with a bumped generation.
/// `force_bump = false` (AlreadyExists): write only when `listen_addr` is
/// stale or the file is absent. Existing `discovered` keys are preserved;
/// only `listen_addr` is upserted.
///
/// TODO(phase-d): replace with `EnvPackHandler::report_runtime_config()` on
/// `LocalProcessDeployerHandler` once the trait method lands (see
/// `plans/next-gen-deployment.md` line 1406).
fn refresh_local_runtime_stub(
    locked: &Locked<'_>,
    env: &Environment,
    force_bump: bool,
) -> Result<(), OpError> {
    // Gate 1: env Deployer binding must be local-process — otherwise this
    // helper is not the authoritative producer.
    let is_local = env
        .pack_for_slot(CapabilitySlot::Deployer)
        .is_some_and(|b| b.kind.path() == LocalProcessDeployerHandler::DESCRIPTOR_PATH);
    if !is_local {
        return Ok(());
    }

    let existing = locked.load_runtime()?;

    // Gate 2: a foreign producer's runtime.json is left untouched.
    if let Some(ref rt) = existing
        && rt.generated_by.path() != LocalProcessDeployerHandler::DESCRIPTOR_PATH
    {
        return Ok(());
    }

    // No-op fast path for the dominant AlreadyExists case: check the one key
    // we own BEFORE cloning the discovered map.
    let new_addr_str = env.host_config.resolved_listen_addr().to_string();
    if !force_bump
        && let Some(ref rt) = existing
        && rt.discovered.get("listen_addr") == Some(&Value::String(new_addr_str.clone()))
    {
        return Ok(());
    }

    let prev_generation = existing.as_ref().map(|r| r.generation).unwrap_or(0);
    let mut desired_discovered = existing.map(|r| r.discovered).unwrap_or_default();
    desired_discovered.insert("listen_addr".to_string(), Value::String(new_addr_str));

    locked
        .save_runtime(&build_local_runtime_stub(
            &env.environment_id,
            prev_generation + 1,
            desired_discovered,
        )?)
        .map_err(Into::into)
}

fn build_local_runtime_stub(
    env_id: &EnvId,
    generation: u64,
    discovered: BTreeMap<String, Value>,
) -> Result<EnvironmentRuntime, OpError> {
    let generated_by = PackDescriptor::try_new(LOCAL_DEPLOYER_PACK).map_err(|e| {
        OpError::InvalidArgument(format!(
            "local-process descriptor `{}`: {}",
            LOCAL_DEPLOYER_PACK, e
        ))
    })?;
    Ok(EnvironmentRuntime {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_RUNTIME_V1),
        environment_id: env_id.clone(),
        discovered,
        generated_at: Utc::now(),
        generated_by,
        generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defaults::{
        LOCAL_DEPLOYER_PACK, LOCAL_SECRETS_PACK, LOCAL_SESSIONS_PACK, LOCAL_STATE_PACK,
        LOCAL_TELEMETRY_PACK,
    };
    use greentic_deploy_spec::{CapabilitySlot, DEFAULT_LISTEN_ADDR, EnvironmentHostConfig};
    use tempfile::TempDir;

    fn store() -> (TempDir, LocalFsStore) {
        let tmp = TempDir::new().expect("tempdir");
        let store = LocalFsStore::new(tmp.path().to_path_buf());
        (tmp, store)
    }

    #[test]
    fn creates_local_env_when_missing() {
        let (_tmp, store) = store();
        let (env, outcome) = ensure_local_environment(&store, None).expect("bootstrap");
        assert_eq!(outcome, LocalEnvOutcome::Created);
        assert_eq!(env.environment_id.as_str(), LOCAL_ENV_ID);
        assert_eq!(env.name, LOCAL_ENV_ID);
        assert_eq!(env.packs.len(), 5);
        env.validate().expect("env is spec-valid");
    }

    #[test]
    fn returns_existing_env_on_second_call() {
        let (_tmp, store) = store();
        let (first, first_outcome) =
            ensure_local_environment(&store, None).expect("first bootstrap");
        assert_eq!(first_outcome, LocalEnvOutcome::Created);
        let (second, second_outcome) =
            ensure_local_environment(&store, None).expect("second bootstrap");
        assert_eq!(second_outcome, LocalEnvOutcome::AlreadyExists);
        assert_eq!(first, second);
    }

    #[test]
    fn default_bindings_cover_expected_slots_and_descriptors() {
        let (_tmp, store) = store();
        let (env, _) = ensure_local_environment(&store, None).expect("bootstrap");
        let by_slot: std::collections::BTreeMap<CapabilitySlot, &str> = env
            .packs
            .iter()
            .map(|b| (b.slot, b.kind.as_str()))
            .collect();
        assert_eq!(
            by_slot.get(&CapabilitySlot::Deployer).copied(),
            Some(LOCAL_DEPLOYER_PACK)
        );
        assert_eq!(
            by_slot.get(&CapabilitySlot::Secrets).copied(),
            Some(LOCAL_SECRETS_PACK)
        );
        assert_eq!(
            by_slot.get(&CapabilitySlot::Telemetry).copied(),
            Some(LOCAL_TELEMETRY_PACK)
        );
        assert_eq!(
            by_slot.get(&CapabilitySlot::Sessions).copied(),
            Some(LOCAL_SESSIONS_PACK)
        );
        assert_eq!(
            by_slot.get(&CapabilitySlot::State).copied(),
            Some(LOCAL_STATE_PACK)
        );
        assert!(!by_slot.contains_key(&CapabilitySlot::Revocation));
    }

    #[test]
    fn bootstrap_env_has_no_bundles_or_revisions_or_splits() {
        let (_tmp, store) = store();
        let (env, _) = ensure_local_environment(&store, None).expect("bootstrap");
        assert!(env.bundles.is_empty());
        assert!(env.revisions.is_empty());
        assert!(env.traffic_splits.is_empty());
        assert!(env.credentials_ref.is_none());
    }

    #[test]
    fn bootstrap_env_host_config_has_no_region_or_org() {
        let (_tmp, store) = store();
        let (env, _) = ensure_local_environment(&store, None).expect("bootstrap");
        assert_eq!(env.host_config.env_id, env.environment_id);
        assert!(env.host_config.region.is_none());
        assert!(env.host_config.tenant_org_id.is_none());
    }

    #[test]
    fn bootstrap_env_writes_default_listen_addr_so_start_can_resolve_it() {
        let (_tmp, store) = store();
        let (env, outcome) = ensure_local_environment(&store, None).expect("bootstrap");
        assert_eq!(outcome, LocalEnvOutcome::Created);
        assert_eq!(
            env.host_config.listen_addr,
            Some(DEFAULT_LISTEN_ADDR),
            "fresh env must carry the canonical loopback default so `gtc start` \
             on an empty env has a deterministic bind address",
        );
        assert_eq!(env.host_config.resolved_listen_addr(), DEFAULT_LISTEN_ADDR);
    }

    #[test]
    fn bootstrap_heal_path_preserves_user_set_listen_addr() {
        use crate::environment::EnvironmentStore;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let (_tmp, store) = store();
        let (mut env, _) = ensure_local_environment(&store, None).expect("bootstrap");
        let custom = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9090);
        env.host_config.listen_addr = Some(custom);
        store.save(&env).expect("user save");
        let (reloaded, outcome) = ensure_local_environment(&store, None).expect("second bootstrap");
        assert_eq!(outcome, LocalEnvOutcome::AlreadyExists);
        assert_eq!(
            reloaded.host_config.listen_addr,
            Some(custom),
            "user's custom bind must survive re-bootstrap",
        );
    }

    #[test]
    fn second_call_does_not_overwrite_user_mutations() {
        use crate::environment::EnvironmentStore;
        let (_tmp, store) = store();
        let (mut env, _) = ensure_local_environment(&store, None).expect("bootstrap");
        env.name = "user-renamed".to_string();
        env.host_config.region = Some("eu-west-1".to_string());
        store.save(&env).expect("user save");
        let (reloaded, outcome) = ensure_local_environment(&store, None).expect("second bootstrap");
        assert_eq!(outcome, LocalEnvOutcome::AlreadyExists);
        assert_eq!(reloaded.name, "user-renamed");
        assert_eq!(reloaded.host_config.region.as_deref(), Some("eu-west-1"));
    }

    // Helpers for the heal-path tests below.
    use crate::environment::EnvironmentStore;
    use greentic_deploy_spec::{EnvPackBinding, PackDescriptor, PackId};

    /// Seed an empty `local` env (all 5 slots missing) — mimics the state a
    /// user lands in after running `gtc op env create local` (A3), which
    /// creates an env with `packs = Vec::new()`.
    fn seed_empty_local_env(store: &LocalFsStore) -> Environment {
        let env_id = EnvId::try_from(LOCAL_ENV_ID).unwrap();
        let env = Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id.clone(),
            name: LOCAL_ENV_ID.to_string(),
            host_config: EnvironmentHostConfig {
                env_id,
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
                default_bundle: None,
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
        };
        store.save(&env).expect("seed save");
        env
    }

    fn custom_binding(slot: CapabilitySlot, descriptor: &str) -> EnvPackBinding {
        EnvPackBinding {
            slot,
            kind: PackDescriptor::try_new(descriptor).expect("valid descriptor"),
            pack_ref: PackId::new(descriptor),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        }
    }

    #[test]
    fn heals_existing_env_with_no_packs() {
        let (_tmp, store) = store();
        seed_empty_local_env(&store);
        let (env, outcome) = ensure_local_environment(&store, None).expect("bootstrap heal");
        match outcome {
            LocalEnvOutcome::Healed { added_slots } => {
                assert_eq!(
                    added_slots,
                    vec![
                        CapabilitySlot::Deployer,
                        CapabilitySlot::Secrets,
                        CapabilitySlot::Telemetry,
                        CapabilitySlot::Sessions,
                        CapabilitySlot::State,
                    ],
                    "all 5 default slots should be reported as added"
                );
            }
            other => panic!("expected Healed, got {other:?}"),
        }
        assert_eq!(env.packs.len(), 5);
        env.validate().expect("env is spec-valid after heal");
        // Persisted: second call sees a fully-bound env and reports AlreadyExists.
        let (_again, outcome2) = ensure_local_environment(&store, None).expect("second bootstrap");
        assert_eq!(outcome2, LocalEnvOutcome::AlreadyExists);
    }

    #[test]
    fn heals_existing_env_with_partial_packs() {
        let (_tmp, store) = store();
        let mut env = seed_empty_local_env(&store);
        // Pre-seed only the deployer slot; expect bootstrap to add the other 4.
        env.packs.push(custom_binding(
            CapabilitySlot::Deployer,
            LOCAL_DEPLOYER_PACK,
        ));
        store.save(&env).expect("partial save");

        let (env, outcome) = ensure_local_environment(&store, None).expect("bootstrap heal");
        match outcome {
            LocalEnvOutcome::Healed { added_slots } => {
                assert_eq!(
                    added_slots,
                    vec![
                        CapabilitySlot::Secrets,
                        CapabilitySlot::Telemetry,
                        CapabilitySlot::Sessions,
                        CapabilitySlot::State,
                    ],
                    "only the 4 missing slots should be reported as added"
                );
            }
            other => panic!("expected Healed, got {other:?}"),
        }
        assert_eq!(env.packs.len(), 5);
        env.validate()
            .expect("env is spec-valid after partial heal");
    }

    #[test]
    fn heal_preserves_user_bound_non_default_descriptor() {
        let (_tmp, store) = store();
        let mut env = seed_empty_local_env(&store);
        // User bound `secrets` to a custom backend; bootstrap must NOT overwrite.
        let custom_secrets = "greentic.secrets.aws-secrets-manager@1.0.0";
        env.packs
            .push(custom_binding(CapabilitySlot::Secrets, custom_secrets));
        store.save(&env).expect("custom-secrets save");

        let (env, outcome) = ensure_local_environment(&store, None).expect("bootstrap heal");
        match outcome {
            LocalEnvOutcome::Healed { added_slots } => {
                assert_eq!(
                    added_slots,
                    vec![
                        CapabilitySlot::Deployer,
                        CapabilitySlot::Telemetry,
                        CapabilitySlot::Sessions,
                        CapabilitySlot::State,
                    ],
                    "secrets must NOT be re-added; the 4 other defaults fill the gaps"
                );
            }
            other => panic!("expected Healed, got {other:?}"),
        }
        let secrets_descriptor = env
            .packs
            .iter()
            .find(|b| b.slot == CapabilitySlot::Secrets)
            .map(|b| b.kind.as_str())
            .expect("secrets slot present");
        assert_eq!(
            secrets_descriptor, custom_secrets,
            "user's custom secrets descriptor must survive bootstrap"
        );
        assert_eq!(env.packs.len(), 5);
    }

    #[test]
    fn fully_bound_env_yields_already_exists_with_no_healing() {
        let (_tmp, store) = store();
        // First call creates the env with all 5 defaults; second call must NOT
        // report any healing — env is already in the required shape.
        ensure_local_environment(&store, None).expect("first bootstrap");
        let (_env, outcome) = ensure_local_environment(&store, None).expect("second bootstrap");
        assert_eq!(outcome, LocalEnvOutcome::AlreadyExists);
    }

    #[test]
    fn create_writes_runtime_stub_with_listen_addr() {
        let (_tmp, store) = store();
        let (env, _) = ensure_local_environment(&store, None).expect("bootstrap");
        let runtime = store
            .load_runtime(&env.environment_id)
            .expect("load runtime")
            .expect("runtime.json must exist after first bootstrap");
        assert_eq!(runtime.environment_id, env.environment_id);
        assert_eq!(
            runtime.schema.as_str(),
            SchemaVersion::ENVIRONMENT_RUNTIME_V1
        );
        assert_eq!(runtime.generation, 1);
        assert_eq!(runtime.generated_by.as_str(), LOCAL_DEPLOYER_PACK);
        let listen_addr = runtime
            .discovered
            .get("listen_addr")
            .expect("discovered must seed listen_addr for runtime:// resolution");
        assert_eq!(
            listen_addr.as_str(),
            Some(env.host_config.resolved_listen_addr().to_string().as_str()),
        );
    }

    #[test]
    fn already_exists_preserves_runtime_stub_and_skips_rewrite() {
        let (_tmp, store) = store();
        ensure_local_environment(&store, None).expect("first bootstrap");
        let env_id = EnvId::try_from(LOCAL_ENV_ID).unwrap();
        let first = store
            .load_runtime(&env_id)
            .expect("load runtime")
            .expect("runtime.json exists");
        ensure_local_environment(&store, None).expect("second bootstrap");
        let second = store
            .load_runtime(&env_id)
            .expect("load runtime")
            .expect("runtime.json exists");
        // An idempotent re-bootstrap must NOT churn the runtime stub — the
        // file is identical (same generation + same generated_at). This is
        // what the C5 watcher relies on to avoid spurious reloads on every
        // `gtc start`.
        assert_eq!(
            first.generation, second.generation,
            "generation must not bump on AlreadyExists"
        );
        assert_eq!(
            first.generated_at, second.generated_at,
            "generated_at must not refresh on AlreadyExists"
        );
    }

    #[test]
    fn already_exists_writes_runtime_stub_when_absent() {
        let (_tmp, store) = store();
        let (_env, _) = ensure_local_environment(&store, None).expect("first bootstrap");
        let env_id = EnvId::try_from(LOCAL_ENV_ID).unwrap();
        // Simulate an env that was created before the C5 stub-producer landed
        // (or where an operator manually deleted runtime.json): delete the
        // file under the env-store layout and re-run bootstrap.
        let runtime_path = store
            .env_lock_path(&env_id)
            .map(|p| {
                p.parent()
                    .expect("lock path has parent")
                    .join("runtime.json")
            })
            .expect("runtime path");
        std::fs::remove_file(&runtime_path).expect("remove runtime.json");
        assert!(!runtime_path.exists());

        let (_env, outcome) = ensure_local_environment(&store, None).expect("second bootstrap");
        assert_eq!(outcome, LocalEnvOutcome::AlreadyExists);
        let runtime = store
            .load_runtime(&env_id)
            .expect("load runtime")
            .expect("runtime.json must be re-emitted by the AlreadyExists path");
        assert_eq!(runtime.generation, 1);
    }

    #[test]
    fn heal_writes_runtime_stub() {
        let (_tmp, store) = store();
        seed_empty_local_env(&store);
        let env_id = EnvId::try_from(LOCAL_ENV_ID).unwrap();
        assert!(
            store.load_runtime(&env_id).expect("load runtime").is_none(),
            "seeded env should have no runtime.json yet",
        );
        let (_env, outcome) = ensure_local_environment(&store, None).expect("bootstrap heal");
        assert!(matches!(outcome, LocalEnvOutcome::Healed { .. }));
        let runtime = store
            .load_runtime(&env_id)
            .expect("load runtime")
            .expect("heal arm must emit runtime.json");
        assert_eq!(runtime.generation, 1);
    }

    #[test]
    fn heal_bumps_runtime_stub_generation_when_present() {
        let (_tmp, store) = store();
        // First bootstrap creates env + writes generation=1.
        ensure_local_environment(&store, None).expect("first bootstrap");
        let env_id = EnvId::try_from(LOCAL_ENV_ID).unwrap();
        // Strip one of the default bindings so the next bootstrap call falls
        // into the Heal arm and re-emits the stub.
        let mut env = store.load(&env_id).expect("load");
        env.packs.retain(|b| b.slot != CapabilitySlot::Telemetry);
        store.save(&env).expect("user save");

        let (_env, outcome) = ensure_local_environment(&store, None).expect("heal bootstrap");
        assert!(matches!(outcome, LocalEnvOutcome::Healed { .. }));
        let runtime = store
            .load_runtime(&env_id)
            .expect("load runtime")
            .expect("runtime.json still present");
        assert_eq!(
            runtime.generation, 2,
            "Heal arm must bump generation against the previous stub",
        );
    }

    #[test]
    fn heal_preserves_existing_discovered_keys() {
        let (_tmp, store) = store();
        // First bootstrap to create env + runtime stub (generation=1).
        ensure_local_environment(&store, None).expect("first bootstrap");
        let env_id = EnvId::try_from(LOCAL_ENV_ID).unwrap();

        // Inject extra discovered keys into the existing runtime.json,
        // simulating a Phase-D deployer that added `alb_dns`.
        let mut runtime = store.load_runtime(&env_id).expect("load").expect("exists");
        runtime
            .discovered
            .insert("alb_dns".to_string(), Value::String("ALB".to_string()));
        store.save_runtime(&runtime).expect("save patched runtime");

        // Strip one default binding so the next bootstrap falls into Heal.
        let mut env = store.load(&env_id).expect("load env");
        env.packs.retain(|b| b.slot != CapabilitySlot::Telemetry);
        store.save(&env).expect("user save");

        let (healed_env, outcome) = ensure_local_environment(&store, None).expect("heal bootstrap");
        assert!(matches!(outcome, LocalEnvOutcome::Healed { .. }));

        let refreshed = store.load_runtime(&env_id).expect("load").expect("exists");
        assert_eq!(
            refreshed.discovered.get("alb_dns").and_then(Value::as_str),
            Some("ALB"),
            "pre-existing discovered keys must survive Heal",
        );
        assert_eq!(
            refreshed
                .discovered
                .get("listen_addr")
                .and_then(Value::as_str),
            Some(
                healed_env
                    .host_config
                    .resolved_listen_addr()
                    .to_string()
                    .as_str()
            ),
        );
        assert!(
            refreshed.generation > runtime.generation,
            "generation must bump on Heal",
        );
    }

    #[test]
    fn heal_skips_runtime_stub_when_deployer_binding_is_not_local_process() {
        let (_tmp, store) = store();
        let mut env = seed_empty_local_env(&store);
        // Bind the Deployer slot to a non-local-process descriptor.
        env.packs.push(custom_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        store.save(&env).expect("save env with aws deployer");

        // Pre-seed runtime.json with the AWS deployer as generated_by.
        let aws_descriptor = PackDescriptor::try_new("greentic.deployer.aws-ecs@1.0.0").unwrap();
        let mut aws_discovered = BTreeMap::new();
        aws_discovered.insert("alb_dns".to_string(), Value::String("ALB".to_string()));
        let aws_runtime = EnvironmentRuntime {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_RUNTIME_V1),
            environment_id: env.environment_id.clone(),
            discovered: aws_discovered,
            generated_at: Utc::now(),
            generated_by: aws_descriptor,
            generation: 5,
        };
        store.save_runtime(&aws_runtime).expect("save aws runtime");

        // Bootstrap — should heal missing slots but NOT touch runtime.json.
        let (_env, outcome) = ensure_local_environment(&store, None).expect("heal");
        assert!(matches!(outcome, LocalEnvOutcome::Healed { .. }));

        let after = store
            .load_runtime(&env.environment_id)
            .expect("load")
            .expect("exists");
        assert_eq!(
            after.generation, aws_runtime.generation,
            "generation must not change — foreign producer owns the file",
        );
        assert_eq!(
            after.generated_at, aws_runtime.generated_at,
            "generated_at must not change",
        );
        assert_eq!(
            after.discovered, aws_runtime.discovered,
            "discovered must be untouched",
        );
    }

    #[test]
    fn already_exists_refreshes_stale_listen_addr() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let (_tmp, store) = store();
        // First bootstrap writes env + runtime stub with default listen_addr.
        ensure_local_environment(&store, None).expect("first bootstrap");
        let env_id = EnvId::try_from(LOCAL_ENV_ID).unwrap();
        let before = store.load_runtime(&env_id).expect("load").expect("exists");

        // Mutate listen_addr on the persisted env (simulates `op config set`).
        let mut env = store.load(&env_id).expect("load env");
        let custom = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9090);
        env.host_config.listen_addr = Some(custom);
        store.save(&env).expect("user save");

        // Second bootstrap → AlreadyExists, but listen_addr is now stale.
        let (_env, outcome) = ensure_local_environment(&store, None).expect("second bootstrap");
        assert_eq!(outcome, LocalEnvOutcome::AlreadyExists);

        let after = store.load_runtime(&env_id).expect("load").expect("exists");
        assert_eq!(
            after.discovered.get("listen_addr").and_then(Value::as_str),
            Some(custom.to_string().as_str()),
            "listen_addr must be refreshed to the new address",
        );
        assert_eq!(
            after.generation,
            before.generation + 1,
            "generation must bump by exactly 1",
        );
    }
}
