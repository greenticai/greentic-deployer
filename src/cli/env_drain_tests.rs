//! Tests for [`super`] (`op env drain-revision` / `sweep` / `capabilities`).
use tempfile::tempdir;

use super::*;
use crate::cli::tests_common::{make_binding, make_env};

fn store_with(kind: &str) -> (tempfile::TempDir, LocalFsStore) {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("zain");
    env.packs.push(make_binding(CapabilitySlot::Deployer, kind));
    store.save(&env).unwrap();
    (dir, store)
}

#[test]
fn capabilities_reports_the_k8s_flags() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    let caps = &out.result["capabilities"];
    assert_eq!(caps["drain"], true);
    assert_eq!(caps["remove"], true);
    assert_eq!(caps["multi_instance_safe"], false);
    assert!(
        out.result["missing"]
            .as_array()
            .unwrap()
            .contains(&json!("ingress_managed"))
    );
}

#[cfg(feature = "creds-gcp")]
#[test]
fn capabilities_is_honest_about_cloud_run_multi_instance() {
    let (_d, store) = store_with("greentic.deployer.gcp-cloudrun@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    assert_eq!(out.result["capabilities"]["multi_instance_safe"], false);
    assert_eq!(out.result["capabilities"]["drain"], true);
    let notes = out.result["notes"].to_string();
    assert!(notes.contains("/tmp"), "{notes}");
}

/// k8s builds without `creds-gcp`, so its half of the runtime_pin claim is
/// asserted ungated (unified update L2b: it declares it, like Cloud Run).
#[test]
fn k8s_declares_runtime_pin() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    assert_eq!(out.result["capabilities"]["runtime_pin"], true);
}

#[cfg(feature = "creds-gcp")]
#[test]
fn cloud_run_declares_runtime_pin() {
    let (_d, store) = store_with("greentic.deployer.gcp-cloudrun@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    assert_eq!(out.result["capabilities"]["runtime_pin"], true);
}

#[test]
fn drain_is_refused_by_capability_name_on_an_adapter_without_drain() {
    let (_d, store) = store_with(crate::defaults::LOCAL_DEPLOYER_PACK);
    let err = drain_revision(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        EnvDrainRevisionArgs {
            env_id: "zain".into(),
            revision_id: "00000000000000000000000000".into(),
            kind: None,
        },
    )
    .unwrap_err();
    assert_eq!(err.kind(), "capability-missing");
    assert!(err.to_string().contains("`drain`"), "{err}");
}

#[test]
fn sweep_is_refused_by_capability_name_on_an_adapter_without_remove() {
    let (_d, store) = store_with(crate::defaults::LOCAL_DEPLOYER_PACK);
    let err = sweep(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        EnvSweepArgs {
            env_id: "zain".into(),
            apply: false,
            kind: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("`remove`"), "{err}");
}

#[test]
fn drain_names_an_unknown_revision() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let err = drain_revision(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        EnvDrainRevisionArgs {
            env_id: "zain".into(),
            revision_id: "00000000000000000000000000".into(),
            kind: None,
        },
    )
    .unwrap_err();
    assert!(matches!(err, OpError::NotFound(_)), "{err}");
}

#[test]
fn not_drained_maps_to_a_typed_cli_error_naming_the_revision() {
    let r = RevisionId::new();
    let err = drain_error(DeployerError::NotDrained {
        revision_id: r,
        reason: "1 pod".into(),
    });
    assert_eq!(err.kind(), "not-drained");
    let msg = err.to_string();
    assert!(
        msg.contains(&r.to_string()) && msg.contains("--force-drain"),
        "{msg}"
    );
}

#[tokio::test]
async fn archive_gate_refuses_then_force_overrides() {
    use crate::env_packs::deployer::DrainPolicy;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::k8s::K8sDeployerHandler;
    use crate::env_packs::k8s::cluster::InMemoryCluster;
    let h = K8sDeployerHandler::with_cluster(std::sync::Arc::new(InMemoryCluster::default()))
        .with_drain_policy(DrainPolicy::immediate());
    let env = build_fixture_env();
    let r = env.revisions[0].revision_id;
    h.warm_revision(&env, r, None).await.unwrap();
    let err = archive_drain_gate(&h, &env, r, None, false)
        .await
        .unwrap_err();
    assert!(matches!(err, OpError::NotDrained { .. }), "{err}");
    archive_drain_gate(&h, &env, r, None, true).await.unwrap();
}

#[test]
fn sweep_preflight_refusal_is_a_typed_permission_error() {
    use crate::env_packs::k8s::sweep::SweepPreflightError;
    let err = preflight_error(SweepPreflightError::MissingPermission {
        env_id: "zain".into(),
        namespace: "gtc-zain".into(),
        permissions: vec!["k8s.rbac.allow:apps/deployments:list".into()],
    });
    assert_eq!(err.kind(), "permission-missing");
    let msg = err.to_string();
    assert!(msg.contains("apps/deployments:list"), "{msg}");
    assert!(msg.contains("gtc op credentials bootstrap zain"), "{msg}");
    let err = preflight_error(SweepPreflightError::ReviewFailed("x".into()));
    assert_eq!(err.kind(), "conflict");
}

fn schema_flags() -> OpFlags {
    OpFlags {
        schema_only: true,
        ..OpFlags::default()
    }
}

#[test]
fn schema_only_answers_without_touching_the_store() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let registry = EnvPackRegistry::with_builtins();

    let cap = capabilities(&store, &registry, &schema_flags(), "absent", None).unwrap();
    assert_eq!(cap.op, "capabilities");
    assert!(cap.result["input_schema"].is_string());

    let drain = drain_revision(
        &store,
        &registry,
        &schema_flags(),
        EnvDrainRevisionArgs {
            env_id: "absent".into(),
            revision_id: "x".into(),
            kind: None,
        },
    )
    .unwrap();
    assert_eq!(drain.op, "drain-revision");
    assert!(drain.result["input_schema"].is_string());

    let swept = sweep(
        &store,
        &registry,
        &schema_flags(),
        EnvSweepArgs {
            env_id: "absent".into(),
            apply: false,
            kind: None,
        },
    )
    .unwrap();
    assert_eq!(swept.op, "sweep");
    assert!(swept.result["input_schema"].is_string());
}

#[test]
fn an_unknown_or_malformed_env_is_refused_before_anything_else() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let registry = EnvPackRegistry::with_builtins();

    let missing = capabilities(&store, &registry, &OpFlags::default(), "absent", None).unwrap_err();
    assert!(matches!(missing, OpError::NotFound(_)), "{missing}");

    let malformed =
        capabilities(&store, &registry, &OpFlags::default(), "Not An Id!", None).unwrap_err();
    assert!(
        matches!(malformed, OpError::InvalidArgument(_)),
        "{malformed}"
    );
}

#[test]
fn an_env_without_a_deployer_binding_cannot_report_capabilities() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    store.save(&make_env("zain")).unwrap();
    let err = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    );
    assert!(err.is_err());
}

#[test]
fn capabilities_carries_the_environment_id() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    assert_eq!(out.result["environment_id"], "zain");
}

#[test]
fn drain_rejects_a_malformed_revision_id() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let err = drain_revision(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        EnvDrainRevisionArgs {
            env_id: "zain".into(),
            revision_id: "not-a-ulid".into(),
            kind: None,
        },
    )
    .unwrap_err();
    assert!(matches!(err, OpError::InvalidArgument(_)), "{err}");
}

#[test]
fn sweep_refuses_a_deployer_that_is_not_k8s() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    // Same pack path is k8s: the refusal below is for the other adapters, so
    // assert the positive classifier instead.
    let env = store.load(&EnvId::try_from("zain").unwrap()).unwrap();
    let k8s = resolve_live_deployer_kind(&env, None).unwrap();
    assert!(is_k8s(&k8s));
    let local = PackDescriptor::try_new(crate::defaults::LOCAL_DEPLOYER_PACK).unwrap();
    assert!(!is_k8s(&local));
}

#[test]
fn deployer_of_names_the_pack_when_nothing_resolves() {
    let registry = EnvPackRegistry::with_builtins();
    let unknown = PackDescriptor::try_new("greentic.deployer.nonexistent@1.0.0").unwrap();
    match deployer_of(&registry, &unknown) {
        Err(OpError::Conflict(_)) => {}
        Err(other) => panic!("expected a conflict, got {other}"),
        Ok(_) => panic!("an unknown pack must not resolve"),
    }
}

#[test]
fn doctor_capabilities_is_null_without_a_binding_and_a_report_with_one() {
    let registry = EnvPackRegistry::with_builtins();
    assert_eq!(
        doctor_capabilities(&registry, &make_env("zain")),
        Value::Null
    );

    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let env = store.load(&EnvId::try_from("zain").unwrap()).unwrap();
    let report = doctor_capabilities(&registry, &env);
    assert_eq!(report["capabilities"]["drain"], true);
}

#[test]
fn doctor_capabilities_is_null_for_a_binding_no_pack_handles() {
    let mut env = make_env("zain");
    env.packs.push(make_binding(
        CapabilitySlot::Deployer,
        "greentic.deployer.nonexistent@1.0.0",
    ));
    assert_eq!(
        doctor_capabilities(&EnvPackRegistry::with_builtins(), &env),
        Value::Null
    );
}

#[test]
fn a_non_drain_deployer_error_maps_to_conflict() {
    let err = drain_error(DeployerError::RevisionNotFound {
        env_id: EnvId::try_from("zain").unwrap(),
        revision_id: RevisionId::new(),
    });
    assert_eq!(err.kind(), "conflict");
}

#[test]
fn k8s_store_label_is_derived_from_the_env_directory() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let id = EnvId::try_from("zain").unwrap();
    let label = k8s_store_label(&store, &id).expect("label for a valid env id");
    assert!(!label.is_empty());
    assert_eq!(Some(label), k8s_store_label(&store, &id));
}

#[tokio::test]
async fn archive_gate_with_force_skips_the_deployer_entirely() {
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::k8s::K8sDeployerHandler;
    use crate::env_packs::k8s::cluster::InMemoryCluster;
    let h = K8sDeployerHandler::with_cluster(std::sync::Arc::new(InMemoryCluster::default()));
    let env = build_fixture_env();
    let evidence = archive_drain_gate(&h, &env, env.revisions[0].revision_id, None, true)
        .await
        .unwrap();
    assert!(matches!(evidence, DrainEvidence::Forced));
}

mod seam {
    use std::cell::RefCell;

    use super::*;
    use crate::env_packs::deployer::DrainOutcome;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::k8s::sweep::SweepReport;

    /// Records what the live half was asked and answers from canned values, so
    /// the store/validation logic around it runs with no cluster or cloud.
    #[derive(Default)]
    struct FakeBackend {
        drained: RefCell<Vec<RevisionId>>,
        swept: RefCell<Vec<bool>>,
        fail_drain: bool,
    }

    impl LiveBackend for FakeBackend {
        fn drain(
            &self,
            _store: &LocalFsStore,
            _env: &Environment,
            _env_id: &EnvId,
            _descriptor: &PackDescriptor,
            revision_id: RevisionId,
            _answers: Option<Value>,
        ) -> Result<DrainOutcome, OpError> {
            self.drained.borrow_mut().push(revision_id);
            if self.fail_drain {
                return Err(OpError::Conflict("injected live drain failure".into()));
            }
            Ok(DrainOutcome {
                waited_seconds: 7,
                evidence: DrainEvidence::Forced,
            })
        }

        fn sweep_k8s(
            &self,
            _store: &LocalFsStore,
            _env: &Environment,
            _env_id: &EnvId,
            _answers: Option<Value>,
            apply: bool,
        ) -> Result<SweepReport, OpError> {
            self.swept.borrow_mut().push(apply);
            Ok(SweepReport {
                namespace: "gtc-fixture".into(),
                label_selector: "sel".into(),
                store_label: "lbl".into(),
                dry_run: !apply,
                orphans: vec![],
                removed: vec![],
                kept: vec![],
                unattributed: vec![],
                skipped: vec![],
            })
        }
    }

    fn fixture_store(kind: &str) -> (tempfile::TempDir, LocalFsStore, Environment) {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = build_fixture_env();
        env.packs.push(make_binding(CapabilitySlot::Deployer, kind));
        store.save(&env).unwrap();
        (dir, store, env)
    }

    fn drain_args(env: &Environment, revision: RevisionId) -> EnvDrainRevisionArgs {
        EnvDrainRevisionArgs {
            env_id: env.environment_id.to_string(),
            revision_id: revision.to_string(),
            kind: None,
        }
    }

    #[test]
    fn draining_a_ready_revision_stamps_it_then_asks_the_live_half() {
        let (_d, store, env) = fixture_store("greentic.deployer.k8s@1.0.0");
        let ready = env
            .revisions
            .iter()
            .find(|r| r.lifecycle == RevisionLifecycle::Ready)
            .unwrap()
            .revision_id;
        let backend = FakeBackend::default();
        let out = drain_revision_with(
            &backend,
            &store,
            &EnvPackRegistry::with_builtins(),
            &OpFlags::default(),
            drain_args(&env, ready),
        )
        .unwrap();
        assert_eq!(out.result["stamped_draining"], true);
        assert_eq!(out.result["waited_seconds"], 7);
        assert_eq!(out.result["revision_id"], ready.to_string());
        assert_eq!(*backend.drained.borrow(), vec![ready]);
        let reloaded = store.load(&env.environment_id).unwrap();
        let stored = reloaded
            .revisions
            .iter()
            .find(|r| r.revision_id == ready)
            .unwrap();
        assert_eq!(stored.lifecycle, RevisionLifecycle::Draining);
    }

    #[test]
    fn draining_a_revision_that_is_not_ready_does_not_restamp_it() {
        let (_d, store, env) = fixture_store("greentic.deployer.k8s@1.0.0");
        let not_ready = env
            .revisions
            .iter()
            .find(|r| r.lifecycle != RevisionLifecycle::Ready)
            .unwrap()
            .revision_id;
        let backend = FakeBackend::default();
        let out = drain_revision_with(
            &backend,
            &store,
            &EnvPackRegistry::with_builtins(),
            &OpFlags::default(),
            drain_args(&env, not_ready),
        )
        .unwrap();
        assert_eq!(out.result["stamped_draining"], false);
        assert_eq!(backend.drained.borrow().len(), 1);
    }

    #[test]
    fn a_live_drain_failure_surfaces_unchanged() {
        let (_d, store, env) = fixture_store("greentic.deployer.k8s@1.0.0");
        let backend = FakeBackend {
            fail_drain: true,
            ..Default::default()
        };
        let err = drain_revision_with(
            &backend,
            &store,
            &EnvPackRegistry::with_builtins(),
            &OpFlags::default(),
            drain_args(&env, env.revisions[0].revision_id),
        )
        .unwrap_err();
        assert!(err.to_string().contains("injected live drain failure"));
    }

    #[test]
    fn sweep_defaults_to_a_dry_run_and_apply_deletes() {
        let (_d, store, env) = fixture_store("greentic.deployer.k8s@1.0.0");
        let backend = FakeBackend::default();
        for apply in [false, true] {
            let out = sweep_with(
                &backend,
                &store,
                &EnvPackRegistry::with_builtins(),
                &OpFlags::default(),
                EnvSweepArgs {
                    env_id: env.environment_id.to_string(),
                    apply,
                    kind: None,
                },
            )
            .unwrap();
            assert_eq!(out.result["dry_run"], !apply);
            assert_eq!(out.result["environment_id"], env.environment_id.as_str());
        }
        assert_eq!(*backend.swept.borrow(), vec![false, true]);
    }

    #[cfg(feature = "creds-gcp")]
    #[test]
    fn sweep_is_refused_on_a_remove_capable_deployer_that_is_not_k8s() {
        let (_d, store, env) = fixture_store("greentic.deployer.gcp-cloudrun@1.0.0");
        let backend = FakeBackend::default();
        let err = sweep_with(
            &backend,
            &store,
            &EnvPackRegistry::with_builtins(),
            &OpFlags::default(),
            EnvSweepArgs {
                env_id: env.environment_id.to_string(),
                apply: false,
                kind: None,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("label-scoped"), "{err}");
        assert!(backend.swept.borrow().is_empty());
    }

    #[cfg(feature = "k8s-client")]
    #[test]
    fn k8s_inputs_read_the_context_from_the_answers_and_need_no_cluster_without_a_bound_identity() {
        let (_d, store, env) = fixture_store("greentic.deployer.k8s@1.0.0");
        let answers = json!({"kubeconfig_context": "kind-greentic"});
        let (context, token) =
            live::k8s_inputs(&store, &env, &env.environment_id, Some(&answers)).unwrap();
        assert_eq!(context.as_deref(), Some("kind-greentic"));
        assert!(token.is_none(), "no credentials_ref is bound");
        let (context, _) = live::k8s_inputs(&store, &env, &env.environment_id, None).unwrap();
        assert!(context.is_none());
    }

    #[test]
    fn the_live_drain_dispatch_refuses_a_deployer_it_cannot_reach() {
        let (_d, store, env) = fixture_store(crate::defaults::LOCAL_DEPLOYER_PACK);
        let descriptor = PackDescriptor::try_new(crate::defaults::LOCAL_DEPLOYER_PACK).unwrap();
        let err = live::drain(
            &store,
            &env,
            &env.environment_id,
            &descriptor,
            env.revisions[0].revision_id,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot drain deployer"), "{err}");
    }
}
