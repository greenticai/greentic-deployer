//! `ensure_local_environment` (`A4` of `plans/next-gen-deployment.md`).
//!
//! Idempotent bootstrap of the `local` [`Environment`] with the five default
//! [`greentic_deploy_spec::EnvPackBinding`]s (deployer/secrets/telemetry/sessions/state).
//! Invoked by `gtc setup` and `gtc start` before any operator-state read so
//! first-run installs always have an env to bind against.
//!
//! Heavy resolution of the descriptor strings to concrete handlers is the
//! env-pack registry's job (A9); A4 only persists the binding intent.

use greentic_deploy_spec::{
    CapabilitySlot, EnvId, Environment, EnvironmentHostConfig, SchemaVersion,
};

use crate::defaults::{LOCAL_ENV_ID, local_pack_bindings};
use crate::environment::LocalFsStore;

use super::OpError;

/// Whether [`ensure_local_environment`] created the env, found it intact, or
/// repaired missing default bindings on an existing env.
///
/// `Healed` carries the slots that were missing and got the default binding
/// inserted. Slots already bound to a non-default descriptor are NOT
/// overwritten — bootstrap only fills *missing* slots, never replaces user
/// intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalEnvOutcome {
    Created,
    AlreadyExists,
    Healed { added_slots: Vec<CapabilitySlot> },
}

/// Creates the `local` Environment with default env-pack bindings if absent.
///
/// Idempotent: callers may invoke this on every `gtc setup` / `gtc start`
/// without checking first. Returns `(Environment, LocalEnvOutcome)` so
/// consumers can log a one-line note on creation and stay silent otherwise.
///
/// The entire read-modify-write runs inside [`LocalFsStore::transact`], so
/// concurrent first-run invocations on the same host serialize on the per-env
/// flock and produce a single env.
pub fn ensure_local_environment(
    store: &LocalFsStore,
) -> Result<(Environment, LocalEnvOutcome), OpError> {
    let env_id = EnvId::try_from(LOCAL_ENV_ID).map_err(|e| {
        OpError::InvalidArgument(format!("default env id `{}`: {}", LOCAL_ENV_ID, e))
    })?;
    store.transact(
        &env_id,
        |locked| -> Result<(Environment, LocalEnvOutcome), OpError> {
            if let Ok(mut existing) = locked.load() {
                let added = fill_missing_default_bindings(&mut existing)?;
                if added.is_empty() {
                    return Ok((existing, LocalEnvOutcome::AlreadyExists));
                }
                locked.save(&existing)?;
                return Ok((existing, LocalEnvOutcome::Healed { added_slots: added }));
            }
            let packs = local_pack_bindings().map_err(|e| {
                OpError::InvalidArgument(format!("default pack binding parse: {e}"))
            })?;
            let env = Environment {
                schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
                environment_id: locked.env_id().clone(),
                name: LOCAL_ENV_ID.to_string(),
                host_config: EnvironmentHostConfig {
                    env_id: locked.env_id().clone(),
                    region: None,
                    tenant_org_id: None,
                },
                packs,
                credentials_ref: None,
                bundles: Vec::new(),
                revisions: Vec::new(),
                traffic_splits: Vec::new(),
                revocation: Default::default(),
                retention: Default::default(),
                health: Default::default(),
            };
            locked.save(&env)?;
            Ok((env, LocalEnvOutcome::Created))
        },
    )
}

/// Walks the five default capability slots and appends a default
/// [`greentic_deploy_spec::EnvPackBinding`] for any slot not already bound on
/// `env`. Slots already bound — regardless of descriptor — are left untouched
/// so user-customized bindings (e.g. an externally-provisioned secrets backend)
/// survive.
///
/// Returns the slots that were appended, in the canonical default order.
/// Empty return means the env already satisfied the A4 invariant.
fn fill_missing_default_bindings(env: &mut Environment) -> Result<Vec<CapabilitySlot>, OpError> {
    let defaults = local_pack_bindings()
        .map_err(|e| OpError::InvalidArgument(format!("default pack binding parse: {e}")))?;
    let mut added = Vec::new();
    for binding in defaults {
        if env.packs.iter().any(|b| b.slot == binding.slot) {
            continue;
        }
        added.push(binding.slot);
        env.packs.push(binding);
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defaults::{
        LOCAL_DEPLOYER_PACK, LOCAL_ROUTING_HOOK_PACK, LOCAL_SECRETS_PACK, LOCAL_SESSIONS_PACK,
        LOCAL_STATE_PACK, LOCAL_TELEMETRY_PACK,
    };
    use greentic_deploy_spec::CapabilitySlot;
    use tempfile::TempDir;

    fn store() -> (TempDir, LocalFsStore) {
        let tmp = TempDir::new().expect("tempdir");
        let store = LocalFsStore::new(tmp.path().to_path_buf());
        (tmp, store)
    }

    #[test]
    fn creates_local_env_when_missing() {
        let (_tmp, store) = store();
        let (env, outcome) = ensure_local_environment(&store).expect("bootstrap");
        assert_eq!(outcome, LocalEnvOutcome::Created);
        assert_eq!(env.environment_id.as_str(), LOCAL_ENV_ID);
        assert_eq!(env.name, LOCAL_ENV_ID);
        assert_eq!(env.packs.len(), 6);
        env.validate().expect("env is spec-valid");
    }

    #[test]
    fn returns_existing_env_on_second_call() {
        let (_tmp, store) = store();
        let (first, first_outcome) = ensure_local_environment(&store).expect("first bootstrap");
        assert_eq!(first_outcome, LocalEnvOutcome::Created);
        let (second, second_outcome) = ensure_local_environment(&store).expect("second bootstrap");
        assert_eq!(second_outcome, LocalEnvOutcome::AlreadyExists);
        assert_eq!(first, second);
    }

    #[test]
    fn default_bindings_cover_expected_slots_and_descriptors() {
        let (_tmp, store) = store();
        let (env, _) = ensure_local_environment(&store).expect("bootstrap");
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
        assert_eq!(
            by_slot.get(&CapabilitySlot::RoutingHook).copied(),
            Some(LOCAL_ROUTING_HOOK_PACK)
        );
        assert!(!by_slot.contains_key(&CapabilitySlot::Revocation));
    }

    #[test]
    fn bootstrap_env_has_no_bundles_or_revisions_or_splits() {
        let (_tmp, store) = store();
        let (env, _) = ensure_local_environment(&store).expect("bootstrap");
        assert!(env.bundles.is_empty());
        assert!(env.revisions.is_empty());
        assert!(env.traffic_splits.is_empty());
        assert!(env.credentials_ref.is_none());
    }

    #[test]
    fn bootstrap_env_host_config_has_no_region_or_org() {
        let (_tmp, store) = store();
        let (env, _) = ensure_local_environment(&store).expect("bootstrap");
        assert_eq!(env.host_config.env_id, env.environment_id);
        assert!(env.host_config.region.is_none());
        assert!(env.host_config.tenant_org_id.is_none());
    }

    #[test]
    fn second_call_does_not_overwrite_user_mutations() {
        use crate::environment::EnvironmentStore;
        let (_tmp, store) = store();
        let (mut env, _) = ensure_local_environment(&store).expect("bootstrap");
        env.name = "user-renamed".to_string();
        env.host_config.region = Some("eu-west-1".to_string());
        store.save(&env).expect("user save");
        let (reloaded, outcome) = ensure_local_environment(&store).expect("second bootstrap");
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
            },
            packs: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
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
        let (env, outcome) = ensure_local_environment(&store).expect("bootstrap heal");
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
                        CapabilitySlot::RoutingHook,
                    ],
                    "all 6 default slots should be reported as added"
                );
            }
            other => panic!("expected Healed, got {other:?}"),
        }
        assert_eq!(env.packs.len(), 6);
        env.validate().expect("env is spec-valid after heal");
        // Persisted: second call sees a fully-bound env and reports AlreadyExists.
        let (_again, outcome2) = ensure_local_environment(&store).expect("second bootstrap");
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

        let (env, outcome) = ensure_local_environment(&store).expect("bootstrap heal");
        match outcome {
            LocalEnvOutcome::Healed { added_slots } => {
                assert_eq!(
                    added_slots,
                    vec![
                        CapabilitySlot::Secrets,
                        CapabilitySlot::Telemetry,
                        CapabilitySlot::Sessions,
                        CapabilitySlot::State,
                        CapabilitySlot::RoutingHook,
                    ],
                    "only the 5 missing slots should be reported as added"
                );
            }
            other => panic!("expected Healed, got {other:?}"),
        }
        assert_eq!(env.packs.len(), 6);
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

        let (env, outcome) = ensure_local_environment(&store).expect("bootstrap heal");
        match outcome {
            LocalEnvOutcome::Healed { added_slots } => {
                assert_eq!(
                    added_slots,
                    vec![
                        CapabilitySlot::Deployer,
                        CapabilitySlot::Telemetry,
                        CapabilitySlot::Sessions,
                        CapabilitySlot::State,
                        CapabilitySlot::RoutingHook,
                    ],
                    "secrets must NOT be re-added; the 5 other defaults fill the gaps"
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
        assert_eq!(env.packs.len(), 6);
    }

    #[test]
    fn fully_bound_env_yields_already_exists_with_no_healing() {
        let (_tmp, store) = store();
        // First call creates the env with all 5 defaults; second call must NOT
        // report any healing — env is already in the required shape.
        ensure_local_environment(&store).expect("first bootstrap");
        let (_env, outcome) = ensure_local_environment(&store).expect("second bootstrap");
        assert_eq!(outcome, LocalEnvOutcome::AlreadyExists);
    }
}
