//! Regression tests for the env-up apply/retire/bring-up boundary. No cloud calls.
use super::*;
use crate::cli::bundles_retire::{HookResult, RetireHooks};
use crate::cli::env_apply::{ApplyMode, ApplyOptions};
use crate::cli::tests_common::{bootstrap_env_trust_root, make_bundle_deployment, make_env};
use crate::environment::EnvironmentStore;
use greentic_deploy_spec::{EnvId, RevisionId};
use std::cell::Cell;

const WORKERS: &[&str] = &[
    "invoice-reader-and-summary",
    "invoice-review-worker",
    "invoice-review",
    "invoice-review-worker-2",
];

struct FakeRetire {
    fail: Cell<bool>,
    calls: Cell<usize>,
}
impl RetireHooks for FakeRetire {
    fn drain(&self, _: &EnvId, _: RevisionId) -> Result<HookResult, OpError> {
        self.calls.set(self.calls.get() + 1);
        Ok(HookResult::Done)
    }
    fn teardown(&self, _: &EnvId, _: RevisionId) -> Result<HookResult, OpError> {
        if self.fail.get() {
            return Err(OpError::Conflict("fake teardown failed".into()));
        }
        Ok(HookResult::Done)
    }
}

fn args(prune: bool, dry_run: bool) -> EnvUpArgs {
    EnvUpArgs {
        yes: true,
        non_interactive: true,
        dry_run,
        prune,
        confirm_prune: prune,
        skip_cluster: true,
        no_port_forward: true,
        port: 8080,
        allow_missing_seeds: false,
        updated_by: None,
    }
}
fn manifest(path: &std::path::Path, workers: &[&str]) {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/bundles/perf-smoke-bundle.gtbundle");
    std::fs::write(path, serde_json::to_vec(&json!({
        "schema": crate::cli::env_manifest::ENV_MANIFEST_SCHEMA_V1,
        "environment": {"id": "local"},
        "bundles": workers.iter().map(|b| json!({"bundle_id": b, "bundle_path": fixture})).collect::<Vec<_>>()
    })).unwrap()).unwrap();
}
fn apply(
    store: &LocalFsStore,
    flags: &OpFlags,
    opts: ApplyOptions,
    hooks: &FakeRetire,
) -> Result<OpOutcome, OpError> {
    crate::cli::env_apply::apply_with_retire_hooks(store, flags, opts, &|_| None, None, Some(hooks))
}

#[test]
fn unconfirmed_up_refuses_before_reading_answers_or_creating_an_environment() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut a = args(true, false);
    a.confirm_prune = false;
    let err = up(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags {
            schema_only: false,
            answers: None,
        },
        a,
    )
    .unwrap_err();
    assert!(err.to_string().contains("--confirm-prune"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[cfg(feature = "k8s-client")]
#[test]
fn env_up_prunes_owned_omissions_before_warm_and_retries_failed_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalFsStore::new(dir.path().join("store"));
    let id = EnvId::try_from("local").unwrap();
    store.save(&make_env("local")).unwrap();
    bootstrap_env_trust_root(&store.env_dir(&id).unwrap());
    let path = dir.path().join("manifest.json");
    let flags = OpFlags {
        schema_only: false,
        answers: Some(path.clone()),
    };
    let hooks = FakeRetire {
        fail: Cell::new(false),
        calls: Cell::new(0),
    };
    manifest(&path, WORKERS);
    apply(
        &store,
        &flags,
        ApplyOptions {
            mode: ApplyMode::Apply,
            non_interactive: true,
            ..Default::default()
        },
        &hooks,
    )
    .unwrap();
    let before = store.load(&id).unwrap();
    let removed = before
        .bundles
        .iter()
        .find(|b| b.bundle_id.as_str() == WORKERS[3])
        .unwrap()
        .deployment_id;
    let failed_revision = before
        .revisions
        .iter()
        .find(|r| r.deployment_id == removed)
        .unwrap()
        .revision_id;
    // The persisted split still targets the removed worker, as in the incident.
    assert!(
        before
            .traffic_splits
            .iter()
            .any(|s| s.deployment_id == removed)
    );
    manifest(&path, &WORKERS[..3]);
    let registry = EnvPackRegistry::with_builtins();
    let warmed = Cell::new(0);
    let run = |a| {
        up_with_operations(
            &store,
            &registry,
            &flags,
            a,
            |s, f, o| apply(s, f, o, &hooks),
            |s, _, id| {
                let env = s.load(id)?;
                assert!(!env.bundles.iter().any(|b| b.deployment_id == removed));
                assert!(
                    !env.traffic_splits
                        .iter()
                        .any(|s| s.deployment_id == removed)
                );
                assert!(
                    !env.revisions
                        .iter()
                        .any(|r| r.revision_id == failed_revision)
                );
                assert_eq!(env.bundles.len(), 3);
                #[cfg(feature = "creds-gcp")]
                {
                    let selected = crate::cli::env::cloudrun_revisions_to_warm(&env);
                    assert_eq!(selected.len(), 3);
                    assert!(selected.iter().all(|r| r.revision_id != failed_revision));
                }
                warmed.set(warmed.get() + 1);
                Ok(Some(json!({"warmed": 3})))
            },
        )
    };
    let preview = run(args(true, true)).unwrap().0;
    assert_eq!(
        preview.result["prune"]["retire"],
        json!([removed.to_string()])
    );
    assert_eq!(store.load(&id).unwrap(), before);
    assert_eq!(warmed.get(), 0);
    assert_eq!(hooks.calls.get(), 0);
    // Default env up retains omissions and lets the persisted worker reach warm.
    up_with_operations(
        &store,
        &registry,
        &flags,
        args(false, false),
        |s, f, o| apply(s, f, o, &hooks),
        |s, _, id| {
            let env = s.load(id)?;
            assert_eq!(env.bundles.len(), 4);
            #[cfg(feature = "creds-gcp")]
            assert!(
                crate::cli::env::cloudrun_revisions_to_warm(&env)
                    .iter()
                    .any(|r| r.revision_id == failed_revision)
            );
            Err(OpError::Conflict(
                "fake warm: immutable failed revision".into(),
            ))
        },
    )
    .unwrap_err();
    hooks.fail.set(true);
    assert!(
        run(args(true, false))
            .unwrap_err()
            .to_string()
            .contains("fake teardown failed")
    );
    assert_eq!(warmed.get(), 0);
    assert!(
        store
            .load(&id)
            .unwrap()
            .bundles
            .iter()
            .any(|b| b.deployment_id == removed)
    );
    hooks.fail.set(false);
    let result = run(args(true, false)).unwrap().0;
    assert_eq!(
        result.result["prune"]["retired"].as_array().unwrap().len(),
        1
    );
    assert_eq!(warmed.get(), 1);
    assert_eq!(
        run(args(true, false)).unwrap().0.result["prune"]["retired"],
        json!([])
    );
    assert_eq!(warmed.get(), 2);
}

#[cfg(feature = "k8s-client")]
#[test]
fn env_up_keeps_unmanaged_and_other_manifest_workers() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalFsStore::new(dir.path().join("store"));
    let id = EnvId::try_from("local").unwrap();
    store.save(&make_env("local")).unwrap();
    bootstrap_env_trust_root(&store.env_dir(&id).unwrap());
    let hooks = FakeRetire {
        fail: Cell::new(false),
        calls: Cell::new(0),
    };
    let a = dir.path().join("a.json");
    let b = dir.path().join("b.json");
    for (path, workers) in [(&a, WORKERS), (&b, &WORKERS[3..])] {
        manifest(path, workers);
        apply(
            &store,
            &OpFlags {
                schema_only: false,
                answers: Some(path.clone()),
            },
            ApplyOptions {
                non_interactive: true,
                ..Default::default()
            },
            &hooks,
        )
        .unwrap();
    }
    let mut env = store.load(&id).unwrap();
    // Same bundle name in another customer scope remains unmanaged.
    let mut unmanaged = make_bundle_deployment("local", WORKERS[3]);
    unmanaged.customer_id = greentic_deploy_spec::CustomerId::new("other-scope");
    env.bundles.push(unmanaged);
    store.save(&env).unwrap();
    manifest(&a, &WORKERS[..3]);
    up_with_operations(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags {
            schema_only: false,
            answers: Some(a),
        },
        args(true, false),
        |s, f, o| apply(s, f, o, &hooks),
        |s, _, id| {
            assert_eq!(s.load(id)?.bundles.len(), 5);
            Ok(Some(json!({})))
        },
    )
    .unwrap();
    assert_eq!(hooks.calls.get(), 0);
}

#[test]
fn env_up_endpoint_and_welcome_links_refuse_before_mutation_or_bring_up() {
    use greentic_deploy_spec::{
        BundleId, MessagingEndpoint, MessagingEndpointId, PackId, SchemaVersion, WelcomeFlowRef,
    };
    for welcome in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("store"));
        let id = EnvId::try_from("local").unwrap();
        store.save(&make_env("local")).unwrap();
        bootstrap_env_trust_root(&store.env_dir(&id).unwrap());
        let path = dir.path().join("manifest.json");
        let flags = OpFlags {
            schema_only: false,
            answers: Some(path.clone()),
        };
        let hooks = FakeRetire {
            fail: Cell::new(false),
            calls: Cell::new(0),
        };
        manifest(&path, WORKERS);
        apply(
            &store,
            &flags,
            ApplyOptions {
                non_interactive: true,
                ..Default::default()
            },
            &hooks,
        )
        .unwrap();
        let mut env = store.load(&id).unwrap();
        let now = env.bundles[0].created_at;
        env.messaging_endpoints.push(MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: id.clone(),
            endpoint_id: MessagingEndpointId::new(),
            provider_id: "bot".into(),
            provider_type: "messaging.telegram.bot".into(),
            display_name: "bot".into(),
            secret_refs: vec![],
            webhook_secret_ref: None,
            linked_bundles: vec![BundleId::new(WORKERS[3])],
            welcome_flow: welcome.then(|| WelcomeFlowRef {
                bundle_id: BundleId::new(WORKERS[3]),
                pack_id: PackId::new("perf.smoke"),
                flow_id: "start".into(),
            }),
            generation: 0,
            created_at: now,
            updated_at: now,
            updated_by: "test".into(),
        });
        store.save(&env).unwrap();
        manifest(&path, &WORKERS[..3]);
        let err = up_with_operations(
            &store,
            &EnvPackRegistry::with_builtins(),
            &flags,
            args(true, false),
            |s, f, o| apply(s, f, o, &hooks),
            |_, _, _| panic!("unsafe bring-up after retirement refusal"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("bot"), "{err}");
        assert_eq!(store.load(&id).unwrap(), env);
        assert_eq!(hooks.calls.get(), 0);
    }
}

#[test]
fn env_up_cli_accepts_explicit_prune_flags_and_defaults_to_upsert_only() {
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        up: EnvUpArgs,
    }
    let defaults = Cli::try_parse_from(["env-up"]).unwrap().up;
    assert!(!defaults.prune && !defaults.confirm_prune);
    let explicit = Cli::try_parse_from(["env-up", "--prune", "--confirm-prune"])
        .unwrap()
        .up;
    assert!(explicit.prune && explicit.confirm_prune);
}
