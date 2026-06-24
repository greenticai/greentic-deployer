//! Live-account E2E for the AWS-ECS deployer env-pack (D-AWS-1 PR-4).
//!
//! The AWS-ECS deployer's decision logic — params parsing, the target-group
//! pool guard, the listener-rule routing/ownership, the conformance suite — is
//! unit-tested against the in-memory [`InMemoryEcs`] fake, which opens no
//! sockets. The thin `.send()` glue that drives the *real* AWS SDK
//! (`RegisterTaskDefinition` / `CreateService` / `CreateTaskSet` /
//! `ModifyListener` / `CreateRule` / `DescribeTags` / …) therefore has zero
//! end-to-end coverage. This test closes that gap by driving the full
//! `bootstrap → warm on Fargate → traffic split → archive` lifecycle through
//! the real CLI verbs against a real AWS account.
//!
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Why this is gated and operator-run (NOT in CI):
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Unlike the K8s E2E ([`k8s_reconcile_e2e`]), which stands up a free `kind`
//! cluster inside the CI `k8s-e2e` job, AWS Fargate has no free CI substrate:
//! LocalStack's ECS/Fargate + ALB target-health is a paid (Pro) feature and
//! shallow, so a CI run would mostly exercise the mock, not reality. This test
//! is therefore **manual / operator-run**: it is armed only when
//! [`E2E_GATE`]`=1` is set, and it bills a real account. It is never in the
//! default `cargo test` matrix.
//!
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Operator pre-provisioning (the test does NOT create these):
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//!   - An ECS cluster (`GTC_AWS_E2E_CLUSTER`).
//!   - An ECR repository under `GTC_AWS_E2E_ECR_PREFIX` holding a worker image
//!     tagged `<image_tag_prefix><revision-ulid>`. Bundle/image *delivery* is a
//!     non-goal of this train (`stage_revision` is a no-op), so the image must
//!     already be pushed — the deployer only references it by tag.
//!   - An ALB with a listener (`GTC_AWS_E2E_ALB_LISTENER_ARN`) and a pool of
//!     ≥2 target groups (`GTC_AWS_E2E_TARGET_GROUPS`) for blue/green shifting.
//!   - awsvpc subnets + security groups the Fargate ENIs attach to. Private
//!     subnets need a NAT (or set `GTC_AWS_E2E_ASSIGN_PUBLIC_IP=true`) to reach
//!     ECR.
//!   - IAM: a Fargate task **execution** role (`GTC_AWS_E2E_EXECUTION_ROLE_ARN`)
//!     and the deployer principal's own permissions — the `gtc op credentials
//!     bootstrap` rules pack renders a role with the exact verb set the deployer
//!     uses (see `VALIDATED_IAM_VERBS`).
//!
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Identity:
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! The deployer runs as the **ambient** AWS chain (env vars / `~/.aws`
//! profile / IRSA / IMDS) unless the env binds a deployer session. Keep
//! `assume_role_arn` UNSET for the ambient path — the fail-closed guard
//! (`pinned_role_without_session`) refuses to run a pinned role as the ambient
//! identity, so a binding that pins it requires `op env bootstrap --bind` first.
//! Point the host's ambient identity at the same account the scope vars name.
//!
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Env-var contract (read once the gate is set; a missing REQUIRED var while
//! armed is a hard failure — you opted in, so you must supply the scope):
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//!   REQUIRED:
//!     GTC_AWS_E2E_REGION              e.g. eu-west-1
//!     GTC_AWS_E2E_CLUSTER             ECS cluster name
//!     GTC_AWS_E2E_ECR_PREFIX         e.g. <acct>.dkr.ecr.<region>.amazonaws.com/greentic/
//!     GTC_AWS_E2E_EXECUTION_ROLE_ARN arn:aws:iam::<acct>:role/<task-exec-role>
//!     GTC_AWS_E2E_SUBNETS            comma-separated subnet-ids
//!     GTC_AWS_E2E_SECURITY_GROUPS    comma-separated sg-ids
//!     GTC_AWS_E2E_TARGET_GROUPS      comma-separated target-group ARNs/names (≥2)
//!     GTC_AWS_E2E_ALB_LISTENER_ARN   arn:aws:elasticloadbalancing:…:listener/…
//!   OPTIONAL:
//!     GTC_AWS_E2E_TASK_ROLE_ARN      app-level task role (default: none)
//!     GTC_AWS_E2E_ROUTING_HOST       per-deployment ALB host-header rule
//!     GTC_AWS_E2E_ROUTING_PATH       per-deployment ALB path-pattern rule
//!                                    (both unset → owns the listener default action)
//!     GTC_AWS_E2E_ASSIGN_PUBLIC_IP   "true"/"false" (default: false)
//!     GTC_AWS_E2E_CONTAINER_PORT     worker container port (default: 8080)
//!   Also honored (read by the deployer itself, not this test):
//!     GREENTIC_AWS_ECS_WARM_READY_TIMEOUT_SECS  bound the Fargate stabilize wait
//!
//! Run it (a real account is billed):
//!   GREENTIC_AWS_E2E=1 GTC_AWS_E2E_REGION=eu-west-1 GTC_AWS_E2E_CLUSTER=… \
//!     … cargo test --test aws_ecs_e2e -- --nocapture
//!
//! NOTE: this test has been written against the verified CLI/answer surface but
//! has not itself been executed against a live account (no account was
//! available at authoring time). The first operator run is the source of its
//! pass evidence — treat a first-run failure as a fixture/scope mismatch to
//! adjust here, not necessarily a deployer bug.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

/// Env that arms the test. Unset (the default in `cargo test`) → skip.
const E2E_GATE: &str = "GREENTIC_AWS_E2E";

/// The AWS-ECS deployer env-pack the env binds to its `deployer` slot. The
/// `@1.0.0` pin resolves against `AwsEcsDeployerHandler::VERSION_REQ`
/// (`>=1.0.0-dev, <2.0.0`).
const DESCRIPTOR: &str = "greentic.deployer.aws-ecs@1.0.0";

/// `local` is the env id the `LocalFsStore` CLI accepts without RBAC.
const ENV_ID: &str = "local";

fn deployer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

/// `true` when the test is armed. Unset → the caller returns early.
fn armed() -> bool {
    if std::env::var(E2E_GATE).is_err() {
        eprintln!(
            "skipping live-account AWS-ECS E2E: set {E2E_GATE}=1 (bills a real account; \
             needs the GTC_AWS_E2E_* scope vars — see the module doc)"
        );
        return false;
    }
    true
}

/// A required scope var. Missing while armed is a hard failure with a precise
/// message, so an operator who sets the gate but forgets a var gets the exact
/// var name, not an opaque AWS error three calls later.
fn required_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{E2E_GATE} is set but required scope var {name} is missing — see the module doc")
    })
}

/// Run `op … <args>` (optionally with `--answers <file>`) against `store`,
/// assert success, and return the parsed JSON envelope. Mirrors the K8s E2E
/// `op()` — the child inherits this process's env (the ambient AWS chain + any
/// `GREENTIC_AWS_ECS_WARM_READY_TIMEOUT_SECS` override).
fn op(store: &Path, answers: Option<&Path>, args: &[&str]) -> Value {
    let mut cmd = Command::new(deployer_bin());
    cmd.arg("op").arg("--store-root").arg(store);
    if let Some(path) = answers {
        cmd.arg("--answers").arg(path);
    }
    cmd.args(args);
    let out = cmd.output().expect("spawn greentic-deployer");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "`op {args:?}` failed:\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("`op {args:?}` stdout is not json ({e}):\n{stdout}"))
}

/// Write a JSON payload file under `store` and return its path.
fn payload(store: &Path, name: &str, body: Value) -> PathBuf {
    let path = store.join(name);
    std::fs::write(&path, serde_json::to_vec(&body).unwrap()).expect("write payload");
    path
}

/// The provider-agnostic bundle fixture used only to create a revision RECORD;
/// the Fargate task's image comes from `ecr_repository_prefix` + tag, not these
/// bytes (`stage_revision` is a no-op for AWS).
fn fixture_bundle() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/bundles/perf-smoke-bundle.gtbundle")
}

/// Assemble the AWS-ECS deployer answers from the scope vars. Optional keys are
/// emitted only when their var is set (the parser's "≥1 set" routing rule and
/// the all-or-nothing launch set both depend on absence vs. presence).
fn aws_answers() -> Value {
    let mut answers = json!({
        "region": required_var("GTC_AWS_E2E_REGION"),
        "ecs_cluster_name": required_var("GTC_AWS_E2E_CLUSTER"),
        "ecr_repository_prefix": required_var("GTC_AWS_E2E_ECR_PREFIX"),
        "execution_role_arn": required_var("GTC_AWS_E2E_EXECUTION_ROLE_ARN"),
        "subnets": required_var("GTC_AWS_E2E_SUBNETS"),
        "security_groups": required_var("GTC_AWS_E2E_SECURITY_GROUPS"),
        "target_group_arns": required_var("GTC_AWS_E2E_TARGET_GROUPS"),
        "alb_listener_arn": required_var("GTC_AWS_E2E_ALB_LISTENER_ARN"),
    });
    let obj = answers.as_object_mut().expect("answers object");
    for (var, key) in [
        ("GTC_AWS_E2E_TASK_ROLE_ARN", "task_role_arn"),
        ("GTC_AWS_E2E_ROUTING_HOST", "alb_routing_host"),
        ("GTC_AWS_E2E_ROUTING_PATH", "alb_routing_path"),
        ("GTC_AWS_E2E_ASSIGN_PUBLIC_IP", "assign_public_ip"),
        ("GTC_AWS_E2E_CONTAINER_PORT", "container_port"),
    ] {
        if let Ok(value) = std::env::var(var) {
            obj.insert(key.to_string(), json!(value));
        }
    }
    answers
}

/// Full live lifecycle: bind the AWS-ECS deployer → desired-state ceremony
/// (bundle/revision/traffic) → `env apply-revision` warms the revision on
/// Fargate → `env apply-traffic` shifts the ALB split → `env apply-revision`
/// (after archive) tears the task set down. Each `env apply-*` call is the
/// first to reach AWS; the asserts confirm the real `.send()` glue round-trips.
///
/// One sequential test (not several) so the expensive real-account provisioning
/// runs once; each step depends on the prior.
#[test]
fn aws_ecs_full_lifecycle_against_real_account() {
    if !armed() {
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = tmp.path();

    // 1. Create the env and bind the AWS-ECS deployer with the scope answers.
    let create = payload(
        store,
        "create.json",
        json!({"environment_id": ENV_ID, "name": ENV_ID}),
    );
    op(store, Some(&create), &["env", "create"]);

    std::fs::write(
        store.join(ENV_ID).join("deployer-answers.json"),
        serde_json::to_vec(&aws_answers()).expect("answers serialize"),
    )
    .expect("write deployer answers");
    let bind = payload(
        store,
        "bind.json",
        json!({
            "environment_id": ENV_ID,
            "slot": "deployer",
            "kind": DESCRIPTOR,
            "pack_ref": "builtin",
            "answers_ref": "deployer-answers.json",
        }),
    );
    op(store, Some(&bind), &["env-packs", "add"]);

    // 2. Trust root — the revenue-policy writer in `bundles add` refuses to
    //    sign without the operator key trusted for this env.
    op(store, None, &["trust-root", "bootstrap", ENV_ID]);

    // 3. Desired-state ceremony (provider-agnostic — records state, touches no
    //    AWS): add a bundle → stage + warm a revision (→ cluster presence) →
    //    route 100 % of traffic to it.
    let add = payload(
        store,
        "add.json",
        json!({
            "environment_id": ENV_ID,
            "bundle_id": "aws-ecs-e2e",
            "route_binding": {"path_prefixes": ["/e2e"]},
        }),
    );
    let deployment_id = op(store, Some(&add), &["bundles", "add"])["result"]["deployment_id"]
        .as_str()
        .expect("deployment_id")
        .to_string();

    let stage = payload(
        store,
        "stage.json",
        json!({
            "environment_id": ENV_ID,
            "deployment_id": deployment_id,
            "bundle_path": fixture_bundle().to_string_lossy(),
        }),
    );
    let revision_id = op(store, Some(&stage), &["revisions", "stage"])["result"]["revision_id"]
        .as_str()
        .expect("revision_id")
        .to_string();

    let warm = payload(
        store,
        "warm.json",
        json!({"environment_id": ENV_ID, "revision_id": revision_id}),
    );
    let warmed = op(store, Some(&warm), &["revisions", "warm"]);
    assert_eq!(
        warmed["result"]["lifecycle"], "ready",
        "revision reaches Ready (cluster presence) before the live warm"
    );

    let traffic = payload(
        store,
        "traffic.json",
        json!({
            "environment_id": ENV_ID,
            "deployment_id": deployment_id,
            "entries": [{"revision_id": revision_id, "weight_bps": 10000}],
            "idempotency_key": format!("aws-ecs-e2e-{revision_id}"),
        }),
    );
    op(store, Some(&traffic), &["traffic", "set"]);

    // 4. LIVE warm on Fargate: ensure the service + create the task set and wait
    //    for steady state. First call to reach AWS.
    let applied = op(
        store,
        None,
        &["env", "apply-revision", ENV_ID, &revision_id],
    );
    assert_eq!(
        applied["result"]["action"], "warmed",
        "present revision drives the live Fargate warm"
    );
    let warm_identity = applied["result"]["identity"]
        .as_str()
        .expect("apply-revision identity");
    assert!(
        warm_identity == "ambient" || warm_identity == "bound",
        "identity is ambient (no bound session) or bound, got {warm_identity:?}"
    );

    // 5. LIVE traffic shift: push the recorded split to the ALB listener (a
    //    per-deployment rule when a routing condition is set, else the listener
    //    default action). Asserts the enforced split echoes the recorded one.
    let shifted = op(
        store,
        None,
        &["env", "apply-traffic", ENV_ID, &deployment_id],
    );
    let entries = shifted["result"]["applied_entries"]
        .as_array()
        .expect("applied_entries");
    assert_eq!(entries.len(), 1, "single recorded entry shifted");
    assert_eq!(
        entries[0]["revision_id"], revision_id,
        "shifted the revision"
    );
    assert_eq!(entries[0]["weight_bps"], 10000, "shifted 100 %");

    // 6. LIVE teardown: archive (desired-state) then apply-revision on the now
    //    absent revision tears the task set down.
    let archive = payload(
        store,
        "archive.json",
        json!({"environment_id": ENV_ID, "revision_id": revision_id}),
    );
    let archived = op(store, Some(&archive), &["revisions", "archive"]);
    assert_eq!(
        archived["result"]["lifecycle"], "archived",
        "revision archived (desired-state)"
    );

    let torn_down = op(
        store,
        None,
        &["env", "apply-revision", ENV_ID, &revision_id],
    );
    assert_eq!(
        torn_down["result"]["action"], "archived",
        "absent revision drives the live task-set teardown"
    );
}
