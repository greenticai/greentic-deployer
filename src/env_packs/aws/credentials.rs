//! [`DeployerCredentials`] impl for the AWS-ECS deployer env-pack (C3).
//!
//! Validation goes through the typed AWS SDK (per plan §C3 rule: typed cloud
//! APIs, not shell-out to `aws` CLI):
//!
//! - **`aws.sts.caller-identity`** — `STS::GetCallerIdentity`. Proves the
//!   ambient AWS credential chain resolves to a usable principal.
//! - **One capability per validated IAM verb**, evaluated via
//!   `IAM::SimulatePrincipalPolicy` against the resolved caller ARN. The verb
//!   list ([`VALIDATED_IAM_VERBS`]) covers the full ECS task-set rollout
//!   surface that `RealEcsTarget` exercises (DescribeServices / CreateService,
//!   RegisterTaskDefinition / CreateTaskSet / DescribeTaskSets, DeleteTaskSet /
//!   DeregisterTaskDefinition, DescribeTargetGroups / ModifyListener) plus this
//!   handler's STS/IAM self-probes, `iam:PassRole`, and `ecr:PutImage` staging.
//!   Keeping the list in parity with the real target's runtime calls means a
//!   role that passes `gtc op credentials requirements` does not then fail on
//!   the first live warm / traffic-shift / archive.
//!
//! ## Sync trait + async SDK
//!
//! [`DeployerCredentials::validate`] is sync. The AWS SDK is async. We
//! isolate the async block in a freshly-built current-thread tokio runtime
//! running on a dedicated thread (`std::thread::scope`). This pattern was
//! codified by B12a's deployer fix: `tokio::task::block_in_place` panics on
//! a current-thread parent runtime, and the operator CLI may run on one;
//! a dedicated thread sidesteps that without leaking the runtime choice
//! through the trait. ~10ms thread overhead per validate; negligible
//! against AWS round-trips.
//!
//! ## Pluggable client for testability
//!
//! [`AwsValidatorClient`] is the seam unit tests mock. Production builds a
//! real client lazily on first validate via [`RealAwsClient::resolve`],
//! which walks the standard AWS credential chain
//! (`$AWS_PROFILE` → `~/.aws/credentials` → IMDS → IRSA …). The real client
//! is held behind a `Mutex<Option<Arc<dyn AwsValidatorClient>>>` so repeated
//! validates reuse the SDK client; the first call pays the chain-resolve
//! cost (~50-200ms), subsequent calls reuse it.
//!
//! ## Bootstrap
//!
//! [`bootstrap`](DeployerCredentials::bootstrap) emits a minimum-privilege
//! IAM role + inline policy Terraform module via [`super::bootstrap`].
//! Returns a [`BootstrapOutcome`] with `bound_credentials_ref: None` —
//! the admin applies the rules pack offline and binds the resulting role
//! ARN via `op credentials rotate`. The rules pack lands under
//! `rules/<env>/greentic.deployer.aws-ecs/aws-min-iam.tf` and the
//! customer's admin applies it via `tofu apply` / `terraform apply`
//! against their own state backend.

use std::sync::{Arc, Mutex};

use crate::credentials::{
    BootstrapError, BootstrapInput, BootstrapOutcome, Capability, CapabilityCheck,
    CapabilityStatus, DeployerCredentials, RequirementsReport, ValidationContext,
};

use super::bootstrap::{IamRulesPackInput, render_min_iam_rules_pack};

/// Stable ID for the STS caller-identity probe.
pub const AWS_STS_CALLER_IDENTITY_CAP: &str = "aws.sts.caller-identity";

/// IAM verbs this handler validates (one capability each, rendered by
/// `required_capabilities` in this order; tests derive their expectations from
/// this slice, so the grouping is free to change).
///
/// Covers the full ECS task-set rollout surface `RealEcsTarget` exercises at
/// deploy time, this handler's own STS/IAM self-probes, image-push staging, and
/// `iam:PassRole`. The runtime subset the real target actually calls is listed
/// in `real_target::REAL_ECS_TARGET_IAM_ACTIONS`; a test pins it ⊆ this list, so
/// adding an SDK call to the real target without a matching verb here fails CI
/// rather than the customer's first live deploy. Each verb maps to a capability
/// ID `aws.iam.allow:<verb>`.
pub const VALIDATED_IAM_VERBS: &[&str] = &[
    // Self-validation: this handler's own STS identity + IAM policy probes.
    "sts:GetCallerIdentity",
    "iam:SimulatePrincipalPolicy",
    // ECS service + task-set lifecycle driven by `RealEcsTarget` (one
    // EXTERNAL-controller service per deployment, one task set per revision).
    "ecs:DescribeServices",
    "ecs:CreateService",
    "ecs:UpdateService",
    "ecs:RegisterTaskDefinition",
    "ecs:CreateTaskSet",
    "ecs:DescribeTaskSets",
    "ecs:DeleteTaskSet",
    "ecs:DeregisterTaskDefinition",
    // Image-push staging + passing the task execution/task roles to ECS.
    "ecr:PutImage",
    "iam:PassRole",
    // ELBv2 weighted traffic shifting across the revisions' target groups.
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:ModifyListener",
];

/// Returns the canonical capability ID for an IAM verb.
fn iam_verb_capability_id(verb: &str) -> String {
    format!("aws.iam.allow:{verb}")
}

/// Caller identity returned by [`AwsValidatorClient::get_caller_identity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    pub arn: String,
    pub account: String,
}

/// Decision for a single IAM action under
/// [`AwsValidatorClient::simulate_principal_policy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IamDecision {
    /// `Allowed` from `SimulatePrincipalPolicy`.
    Allowed,
    /// `ImplicitDeny` or `ExplicitDeny`. Carries the raw decision string
    /// for the operator-facing failure message.
    Denied(String),
}

/// One entry in the simulate-policy result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDecision {
    pub action: String,
    pub decision: IamDecision,
}

/// Errors the client can surface to validate. All variants flow into a
/// `CapabilityStatus::Fail { reason }` — the trait doesn't distinguish
/// transport from auth failures because the operator's fix is the same:
/// `gtc op credentials requirements <env>` re-runs after the operator
/// reconfigures credentials.
#[derive(Debug, thiserror::Error)]
pub enum AwsClientError {
    #[error("AWS credential chain resolved no usable credentials: {0}")]
    NoCredentialChain(String),
    #[error("AWS STS rejected the credentials: {0}")]
    StsRejected(String),
    #[error("AWS IAM rejected the policy simulation: {0}")]
    IamRejected(String),
    #[error("AWS SDK transport error: {0}")]
    Transport(String),
}

/// Pluggable AWS client used by [`AwsDeployerCredentials::validate`]. Unit
/// tests mock this; production resolves [`RealAwsClient`] lazily.
///
/// The trait is `async_trait` because the AWS SDK is async; the validate
/// path bridges sync→async via a dedicated thread (see module docstring).
#[async_trait::async_trait]
pub trait AwsValidatorClient: std::fmt::Debug + Send + Sync {
    async fn get_caller_identity(&self) -> Result<CallerIdentity, AwsClientError>;

    /// `actions` are the IAM verbs to evaluate against `principal_arn`'s
    /// effective policy. Returns one [`ActionDecision`] per verb in the
    /// same order as the input slice; missing-from-response is the
    /// client's responsibility to detect and surface as
    /// [`AwsClientError::IamRejected`].
    ///
    /// Borrowed `&[&str]` (not `&[String]`) so the call site can pass
    /// `VALIDATED_IAM_VERBS` directly. Real impls that need owned
    /// `Vec<String>` for the SDK do the conversion locally. The shared
    /// `'a` lifetime is required by `async_trait` to unify the nested
    /// references in the returned future.
    async fn simulate_principal_policy<'a>(
        &'a self,
        principal_arn: &'a str,
        actions: &'a [&'a str],
    ) -> Result<Vec<ActionDecision>, AwsClientError>;
}

/// Production AWS client. Built lazily on first [`validate`] — the SDK
/// credential chain resolution is ~50-200ms and we don't want to pay it
/// for a no-op `requirements` call when AWS isn't configured.
#[derive(Debug)]
struct RealAwsClient {
    sts: aws_sdk_sts::Client,
    iam: aws_sdk_iam::Client,
}

impl RealAwsClient {
    /// Resolve the AWS credential chain and build the STS + IAM clients.
    ///
    /// Walks: `$AWS_*` env vars → `$AWS_PROFILE` / `~/.aws/credentials` →
    /// IMDS / IRSA / EKS pod identity → SSO. Same chain the rest of the
    /// codebase's AWS code uses (`bundle_upload/s3.rs`,
    /// `runtime_secrets/aws.rs`).
    async fn resolve() -> Result<Self, AwsClientError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        // Empty credentials provider = no chain resolved. Probe by asking
        // for credentials directly — if the provider chain is empty, the
        // call returns NoMatchingTraits or CredentialsNotLoaded.
        let creds_provider = config.credentials_provider().ok_or_else(|| {
            AwsClientError::NoCredentialChain(
                "no AWS credentials provider in the resolved SDK config — set AWS_PROFILE or \
                 AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY"
                    .to_string(),
            )
        })?;
        // ProvideCredentials trait lives in aws_credential_types, but we
        // don't list it as a direct dep — pull the re-export through
        // aws-sdk-sts (which is a direct dep) to keep the Cargo manifest
        // small. Same trait either way.
        use aws_sdk_sts::config::ProvideCredentials;
        creds_provider
            .provide_credentials()
            .await
            .map_err(|e| AwsClientError::NoCredentialChain(e.to_string()))?;

        let sts = aws_sdk_sts::Client::new(&config);
        let iam = aws_sdk_iam::Client::new(&config);
        Ok(Self { sts, iam })
    }
}

#[async_trait::async_trait]
impl AwsValidatorClient for RealAwsClient {
    async fn get_caller_identity(&self) -> Result<CallerIdentity, AwsClientError> {
        let out = self
            .sts
            .get_caller_identity()
            .send()
            .await
            .map_err(|e| AwsClientError::StsRejected(format!("{e}")))?;
        let arn = out.arn().ok_or_else(|| {
            AwsClientError::StsRejected("STS returned no ARN for the caller".to_string())
        })?;
        let account = out.account().ok_or_else(|| {
            AwsClientError::StsRejected("STS returned no account for the caller".to_string())
        })?;
        Ok(CallerIdentity {
            arn: arn.to_string(),
            account: account.to_string(),
        })
    }

    async fn simulate_principal_policy<'a>(
        &'a self,
        principal_arn: &'a str,
        actions: &'a [&'a str],
    ) -> Result<Vec<ActionDecision>, AwsClientError> {
        // SDK wants owned `Vec<String>`; convert at the edge.
        let action_names: Vec<String> = actions.iter().map(|a| (*a).to_string()).collect();
        let out = self
            .iam
            .simulate_principal_policy()
            .policy_source_arn(principal_arn)
            .set_action_names(Some(action_names))
            .send()
            .await
            .map_err(|e| AwsClientError::IamRejected(format!("{e}")))?;

        // The API returns one EvaluationResult per (action, resource) pair.
        // We didn't pass resource ARNs, so resource is implicit-* — one
        // entry per action. Build a lookup map and emit decisions in the
        // requested order so callers can zip results to requests. HashMap
        // because lookup order isn't observed (the output is built by
        // re-iterating the request slice).
        let mut by_action: std::collections::HashMap<&str, IamDecision> =
            std::collections::HashMap::with_capacity(out.evaluation_results().len());
        for r in out.evaluation_results() {
            let decision = r.eval_decision().as_str();
            let interp = if decision.eq_ignore_ascii_case("allowed") {
                IamDecision::Allowed
            } else {
                IamDecision::Denied(decision.to_string())
            };
            by_action.insert(r.eval_action_name(), interp);
        }
        let mut out = Vec::with_capacity(actions.len());
        for action in actions {
            let decision = by_action.get(*action).cloned().ok_or_else(|| {
                AwsClientError::IamRejected(format!(
                    "IAM SimulatePrincipalPolicy returned no decision for `{action}`"
                ))
            })?;
            out.push(ActionDecision {
                action: (*action).to_string(),
                decision,
            });
        }
        Ok(out)
    }
}

/// AWS-ECS deployer credentials handler.
///
/// Holds a lazy-init client behind an `Arc<Mutex<...>>`. Tests inject a
/// mock via [`with_client`](Self::with_client). The default constructor
/// defers SDK setup until the first validate, so building the handler is
/// free even on a host with no AWS credentials.
#[derive(Debug, Default)]
pub struct AwsDeployerCredentials {
    client: Mutex<Option<Arc<dyn AwsValidatorClient>>>,
}

impl AwsDeployerCredentials {
    /// Construct with a pre-built client. Used by tests + by callers that
    /// want to inject a mock or pre-configured production client.
    pub fn with_client(client: Arc<dyn AwsValidatorClient>) -> Self {
        Self {
            client: Mutex::new(Some(client)),
        }
    }

    /// Return the held client or build a real one. Cheap on the hot path:
    /// only the first validate pays the chain-resolve cost.
    fn resolve_client(&self) -> Result<Arc<dyn AwsValidatorClient>, AwsClientError> {
        // Fast path: client already built.
        if let Some(c) = self.client.lock().expect("mutex not poisoned").as_ref() {
            return Ok(Arc::clone(c));
        }
        // Slow path: build the real client on a dedicated thread + runtime.
        // See module docstring: `block_in_place` panics on a current-thread
        // parent runtime, so we always isolate via std::thread::scope.
        let built = run_aws_async(RealAwsClient::resolve())?;
        let arc: Arc<dyn AwsValidatorClient> = Arc::new(built);
        let mut slot = self.client.lock().expect("mutex not poisoned");
        // Another thread may have raced us — keep their client to avoid
        // tearing down a perfectly good SDK client.
        if let Some(c) = slot.as_ref() {
            return Ok(Arc::clone(c));
        }
        *slot = Some(Arc::clone(&arc));
        Ok(arc)
    }

    fn caller_identity_capability(&self) -> Capability {
        Capability::new(
            AWS_STS_CALLER_IDENTITY_CAP,
            "AWS credential chain resolves to a caller identity (STS GetCallerIdentity)",
        )
    }

    fn iam_verb_capability(&self, verb: &str) -> Capability {
        Capability::new(
            iam_verb_capability_id(verb),
            format!("IAM principal is allowed to perform `{verb}`"),
        )
    }

    /// Mixed-status report for the case where STS succeeded but the
    /// downstream IAM SimulatePrincipalPolicy call errored. STS cap
    /// passes (we have a usable caller identity); every verb cap fails
    /// with the same Simulate-error reason. Mirrors `all_failed` for
    /// the STS-already-passed case so the validate path stays a
    /// straight-line sequence of helper calls instead of carrying an
    /// inline 14-line CapabilityCheck construction.
    fn sts_pass_verbs_failed(&self, reason: &str) -> RequirementsReport {
        let mut checks = Vec::with_capacity(1 + VALIDATED_IAM_VERBS.len());
        checks.push(CapabilityCheck {
            capability: self.caller_identity_capability(),
            status: CapabilityStatus::Pass,
        });
        for verb in VALIDATED_IAM_VERBS {
            checks.push(CapabilityCheck {
                capability: self.iam_verb_capability(verb),
                status: CapabilityStatus::Fail {
                    reason: reason.to_string(),
                },
            });
        }
        RequirementsReport::new(checks)
    }
}

impl DeployerCredentials for AwsDeployerCredentials {
    fn requires_credentials_material(&self) -> bool {
        true
    }

    fn required_capabilities(&self) -> Vec<Capability> {
        let mut caps = Vec::with_capacity(1 + VALIDATED_IAM_VERBS.len());
        caps.push(self.caller_identity_capability());
        for verb in VALIDATED_IAM_VERBS {
            caps.push(self.iam_verb_capability(verb));
        }
        caps
    }

    fn validate(&self, _ctx: &ValidationContext<'_>) -> RequirementsReport {
        // Hoist caps once — every early-return arm reuses it.
        let caps = self.required_capabilities();

        let client = match self.resolve_client() {
            Ok(c) => c,
            Err(AwsClientError::NoCredentialChain(reason)) => {
                // No credentials at all — for a deployer that requires
                // credential material, missing chain is an auth failure,
                // not a "we couldn't check" skip. Fail every cap so
                // `report.passed()` is false and the downstream doc
                // stamps `result: Fail`.
                return all_failed(&caps, &reason);
            }
            Err(e) => {
                return all_failed(&caps, &e.to_string());
            }
        };

        let arn = match run_aws_async(client.get_caller_identity()) {
            Ok(id) => id.arn,
            Err(e) => {
                // STS rejected the chain — fail every cap with the same
                // diagnostic; downstream IAM simulate can't run without
                // a principal ARN.
                return all_failed(&caps, &format!("STS GetCallerIdentity failed: {e}"));
            }
        };

        // STS passed; now SimulatePrincipalPolicy for the verb list.
        let decisions =
            match run_aws_async(client.simulate_principal_policy(&arn, VALIDATED_IAM_VERBS)) {
                Ok(v) => v,
                Err(e) => {
                    // STS passed but IAM Simulate failed — STS cap passes,
                    // every verb cap fails with the simulate error.
                    return self.sts_pass_verbs_failed(&format!(
                        "IAM SimulatePrincipalPolicy failed: {e}"
                    ));
                }
            };

        let mut checks = Vec::with_capacity(1 + decisions.len());
        checks.push(CapabilityCheck {
            capability: self.caller_identity_capability(),
            status: CapabilityStatus::Pass,
        });
        for (verb, decision) in VALIDATED_IAM_VERBS.iter().zip(decisions.iter()) {
            let status = match &decision.decision {
                IamDecision::Allowed => CapabilityStatus::Pass,
                IamDecision::Denied(raw) => CapabilityStatus::Fail {
                    reason: format!("IAM denied `{verb}` ({raw})"),
                },
            };
            checks.push(CapabilityCheck {
                capability: self.iam_verb_capability(verb),
                status,
            });
        }
        RequirementsReport::new(checks)
    }

    fn bootstrap(&self, input: &BootstrapInput<'_>) -> Result<BootstrapOutcome, BootstrapError> {
        // C3 stub: emit Terraform; admin material is the named AWS profile
        // (the customer's admin-IAM role to be referenced in the rules
        // pack's `aws_iam_role.trust_policy.assume_role_policy`). No live
        // AWS calls in C3 bootstrap — the customer's admin runs the
        // Terraform against their own state backend (per Phase D plan).
        let admin_profile = input.admin.profile();
        if admin_profile.is_empty() {
            return Err(BootstrapError::AdminRejected(
                "AWS bootstrap requires --admin-profile to identify the trust principal; \
                 pass an IAM role/user ARN or a named AWS profile that will execute the rules \
                 pack."
                    .to_string(),
            ));
        }

        let rules_pack = render_min_iam_rules_pack(&IamRulesPackInput {
            env_id: input.env_id.as_str(),
            admin_identity_hint: admin_profile,
            allowed_actions: VALIDATED_IAM_VERBS,
        });

        // C3 stub: the admin applies the rules pack offline (Terraform),
        // then binds the resulting role ARN via `op credentials rotate`.
        // No credentials are minted here — `bound_credentials_ref: None`
        // tells the runner NOT to mark the env as credentialed. Phase D
        // AWS will return `Some` once the deployer can mint a session
        // token directly.
        Ok(BootstrapOutcome {
            rules_pack,
            bound_credentials_ref: None,
            bound_expiry: None,
            bound_secret_material: None,
        })
    }
}

/// Build every-capability-failed report with the same reason. Used when
/// the credential chain doesn't resolve or the SDK errors in a way that
/// is neither verb-specific denial nor a transport issue the operator can
/// distinguish from auth failure.
fn all_failed(caps: &[Capability], reason: &str) -> RequirementsReport {
    RequirementsReport::new(
        caps.iter()
            .map(|c| CapabilityCheck {
                capability: c.clone(),
                status: CapabilityStatus::Fail {
                    reason: reason.to_string(),
                },
            })
            .collect(),
    )
}

/// Run an async block in a dedicated thread with its own current-thread
/// tokio runtime. The trait surface is sync; this is the bridge.
///
/// Why a dedicated thread + current-thread runtime instead of
/// `block_in_place` or `Handle::current().block_on`:
///
/// - `block_in_place` panics on a current-thread parent runtime (the
///   operator CLI uses one — confirmed in B12a's deployer-fix incident).
/// - `Handle::current().block_on` is a self-deadlock if called from
///   inside any runtime, current-thread or multi-thread.
///
/// `std::thread::scope` + `Builder::new_current_thread().build().block_on`
/// is the pattern B12a settled on (see
/// `project_next_gen_deployment_phase_b.md` precedents). ~10ms overhead
/// per invocation — negligible against AWS round-trips.
fn run_aws_async<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build current-thread tokio runtime");
                rt.block_on(fut)
            })
            .join()
            .expect("AWS validate thread did not panic")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::ZeroizedAdmin;
    use greentic_deploy_spec::{EnvId, EnvironmentHostConfig};
    use std::path::Path;
    use std::sync::Mutex;
    use tempfile::tempdir;

    fn default_host_config(env_id: &EnvId) -> EnvironmentHostConfig {
        EnvironmentHostConfig {
            env_id: env_id.clone(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
            gui_enabled: None,
        }
    }

    fn ctx<'a>(
        env_root: &'a Path,
        env_id: &'a EnvId,
        host_config: &'a EnvironmentHostConfig,
    ) -> ValidationContext<'a> {
        ValidationContext {
            env_id,
            env_root,
            host_config,
        }
    }

    /// Test double recording received calls; outputs are scripted.
    #[derive(Debug, Default)]
    struct MockAwsClient {
        sts_response: Mutex<Option<Result<CallerIdentity, AwsClientError>>>,
        simulate_response: Mutex<Option<Result<Vec<ActionDecision>, AwsClientError>>>,
        simulate_calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl MockAwsClient {
        fn with_sts(self, r: Result<CallerIdentity, AwsClientError>) -> Self {
            *self.sts_response.lock().unwrap() = Some(r);
            self
        }
        fn with_simulate(self, r: Result<Vec<ActionDecision>, AwsClientError>) -> Self {
            *self.simulate_response.lock().unwrap() = Some(r);
            self
        }
    }

    #[async_trait::async_trait]
    impl AwsValidatorClient for MockAwsClient {
        async fn get_caller_identity(&self) -> Result<CallerIdentity, AwsClientError> {
            self.sts_response
                .lock()
                .unwrap()
                .take()
                .expect("test must wire sts_response")
        }
        async fn simulate_principal_policy<'a>(
            &'a self,
            principal_arn: &'a str,
            actions: &'a [&'a str],
        ) -> Result<Vec<ActionDecision>, AwsClientError> {
            // Snapshot the borrowed slice into owned Strings for the call
            // recorder — tests need a stable record even after `actions`
            // goes out of scope.
            let snapshot: Vec<String> = actions.iter().map(|a| (*a).to_string()).collect();
            self.simulate_calls
                .lock()
                .unwrap()
                .push((principal_arn.to_string(), snapshot));
            self.simulate_response
                .lock()
                .unwrap()
                .take()
                .expect("test must wire simulate_response")
        }
    }

    fn arn_user() -> CallerIdentity {
        CallerIdentity {
            arn: "arn:aws:iam::111122223333:user/cust-admin".into(),
            account: "111122223333".into(),
        }
    }

    fn all_allowed_decisions() -> Vec<ActionDecision> {
        VALIDATED_IAM_VERBS
            .iter()
            .map(|v| ActionDecision {
                action: v.to_string(),
                decision: IamDecision::Allowed,
            })
            .collect()
    }

    #[test]
    fn required_capabilities_listed_in_documented_order() {
        let creds = AwsDeployerCredentials::default();
        let ids: Vec<String> = creds
            .required_capabilities()
            .into_iter()
            .map(|c| c.id)
            .collect();
        let mut expected = vec![AWS_STS_CALLER_IDENTITY_CAP.to_string()];
        for v in VALIDATED_IAM_VERBS {
            expected.push(format!("aws.iam.allow:{v}"));
        }
        assert_eq!(ids, expected);
        // Sanity on the count — STS + one cap per verb.
        assert_eq!(ids.len(), 1 + VALIDATED_IAM_VERBS.len());
    }

    #[test]
    fn requires_credentials_material_is_true() {
        let creds = AwsDeployerCredentials::default();
        assert!(creds.requires_credentials_material());
    }

    #[test]
    fn validate_passes_when_sts_and_all_verbs_allowed() {
        let mock = Arc::new(
            MockAwsClient::default()
                .with_sts(Ok(arn_user()))
                .with_simulate(Ok(all_allowed_decisions())),
        );
        let creds = AwsDeployerCredentials::with_client(mock.clone());
        let env_id = EnvId::try_from("prod-eu").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(report.passed(), "report: {report:?}");
        assert!(
            report.missing().is_empty(),
            "no missing caps; got {:?}",
            report.missing()
        );
        // Verify the principal ARN was threaded through to simulate.
        let calls = mock.simulate_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, arn_user().arn);
        assert_eq!(calls[0].1.len(), VALIDATED_IAM_VERBS.len());
    }

    #[test]
    fn validate_fails_specific_verb_when_iam_denies() {
        // Deny `ecs:CreateTaskSet`; all other verbs allowed.
        let decisions: Vec<ActionDecision> = VALIDATED_IAM_VERBS
            .iter()
            .map(|v| ActionDecision {
                action: v.to_string(),
                decision: if *v == "ecs:CreateTaskSet" {
                    IamDecision::Denied("implicitDeny".into())
                } else {
                    IamDecision::Allowed
                },
            })
            .collect();
        let mock = Arc::new(
            MockAwsClient::default()
                .with_sts(Ok(arn_user()))
                .with_simulate(Ok(decisions)),
        );
        let creds = AwsDeployerCredentials::with_client(mock);
        let env_id = EnvId::try_from("prod-eu").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(!report.passed());
        let missing = report.missing();
        assert_eq!(missing.len(), 1, "only one verb denied; got {missing:?}");
        assert!(
            missing[0].ends_with("ecs:CreateTaskSet"),
            "missing id should name the denied verb; got {missing:?}"
        );
        // The matching check carries the raw denial reason.
        let denied = report
            .checks
            .iter()
            .find(|c| c.capability.id == "aws.iam.allow:ecs:CreateTaskSet")
            .unwrap();
        match &denied.status {
            CapabilityStatus::Fail { reason } => {
                assert!(reason.contains("implicitDeny"), "reason: {reason}");
                assert!(reason.contains("ecs:CreateTaskSet"), "reason: {reason}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// `NoCredentialChain` must produce `Fail` for every capability —
    /// missing credentials is an auth failure for a deployer that requires
    /// material, not a "we couldn't check" skip. This test exercises the
    /// validate path end-to-end via a mock client that surfaces
    /// `NoCredentialChain` at the STS call (the closest we can get to
    /// triggering the `resolve_client` chain-error path through the mock).
    #[test]
    fn validate_fails_every_cap_when_no_credential_chain() {
        let mock = Arc::new(MockAwsClient::default().with_sts(Err(
            AwsClientError::NoCredentialChain("no AWS chain configured".into()),
        )));
        let creds = AwsDeployerCredentials::with_client(mock);
        let env_id = EnvId::try_from("prod-eu").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(
            !report.passed(),
            "NoCredentialChain must block overall pass"
        );
        let missing = report.missing();
        assert_eq!(
            missing.len(),
            creds.required_capabilities().len(),
            "every cap must be missing; got {missing:?}"
        );
        for check in &report.checks {
            match &check.status {
                CapabilityStatus::Fail { reason } => {
                    assert!(
                        reason.contains("no AWS chain configured"),
                        "reason: {reason}"
                    );
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_fails_every_cap_when_sts_rejects() {
        let mock = Arc::new(
            MockAwsClient::default()
                .with_sts(Err(AwsClientError::StsRejected("expired session".into()))),
        );
        let creds = AwsDeployerCredentials::with_client(mock);
        let env_id = EnvId::try_from("prod-eu").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(!report.passed());
        for check in &report.checks {
            match &check.status {
                CapabilityStatus::Fail { reason } => {
                    assert!(reason.contains("STS GetCallerIdentity"), "reason: {reason}");
                    assert!(reason.contains("expired session"), "reason: {reason}");
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_passes_sts_but_fails_verbs_when_iam_simulate_errors() {
        let mock = Arc::new(
            MockAwsClient::default()
                .with_sts(Ok(arn_user()))
                .with_simulate(Err(AwsClientError::IamRejected("throttled".into()))),
        );
        let creds = AwsDeployerCredentials::with_client(mock);
        let env_id = EnvId::try_from("prod-eu").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(!report.passed());
        let sts_check = report
            .checks
            .iter()
            .find(|c| c.capability.id == AWS_STS_CALLER_IDENTITY_CAP)
            .unwrap();
        assert!(matches!(sts_check.status, CapabilityStatus::Pass));
        for verb in VALIDATED_IAM_VERBS {
            let id = format!("aws.iam.allow:{verb}");
            let check = report
                .checks
                .iter()
                .find(|c| c.capability.id == id)
                .unwrap();
            match &check.status {
                CapabilityStatus::Fail { reason } => {
                    assert!(reason.contains("throttled"), "reason: {reason}");
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }
    }

    #[test]
    fn bootstrap_rejects_empty_admin_profile() {
        let creds = AwsDeployerCredentials::default();
        let env_id = EnvId::try_from("prod-eu").unwrap();
        let dir = tempdir().unwrap();
        let admin = ZeroizedAdmin::new("", "irrelevant".to_string());
        let input = BootstrapInput {
            env_id: &env_id,
            env_root: dir.path(),
            admin: &admin,
        };
        let err = creds.bootstrap(&input).unwrap_err();
        match err {
            BootstrapError::AdminRejected(msg) => {
                assert!(msg.contains("--admin-profile"), "msg: {msg}");
            }
            other => panic!("expected AdminRejected, got {other:?}"),
        }
    }

    #[test]
    fn bootstrap_returns_rules_pack_without_binding_credentials() {
        let creds = AwsDeployerCredentials::default();
        let env_id = EnvId::try_from("prod-eu").unwrap();
        let dir = tempdir().unwrap();
        let admin = ZeroizedAdmin::new(
            "arn:aws:iam::111122223333:role/customer-admin",
            String::new(),
        );
        let input = BootstrapInput {
            env_id: &env_id,
            env_root: dir.path(),
            admin: &admin,
        };
        let outcome = creds.bootstrap(&input).expect("bootstrap renders");
        // C3 stub returns None — the admin applies Terraform offline,
        // then binds via `op credentials rotate`.
        assert!(
            outcome.bound_credentials_ref.is_none(),
            "AWS C3 bootstrap must not bind credentials directly"
        );
        assert!(
            !outcome.rules_pack.is_empty(),
            "rules pack must not be empty"
        );
        // The HCL must mention every validated action so the customer's
        // admin can audit it.
        let combined: String = outcome
            .rules_pack
            .entries
            .iter()
            .map(|e| e.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for verb in VALIDATED_IAM_VERBS {
            assert!(
                combined.contains(verb),
                "rules pack must mention `{verb}`; content:\n{combined}"
            );
        }
        // The admin profile/ARN must appear in the trust policy so the
        // customer sees who can assume the generated role.
        assert!(
            combined.contains("arn:aws:iam::111122223333:role/customer-admin"),
            "rules pack must mention the admin trust principal; content:\n{combined}"
        );
    }

    #[test]
    fn rotate_at_is_none_until_the_sts_producer_lands() {
        // AWS bootstrap is render-only today (mints no bound material), so it
        // inherits the default `rotate_at` => None. The STS session-token
        // producer will override this with the credential's STS expiry window.
        let creds = AwsDeployerCredentials::default();
        assert!(creds.rotate_at("any-material").is_none());
        // Fail-open: with no decodable lifetime, the material is treated as due.
        assert!(creds.rotation_due("any-material", chrono::Utc::now()));
    }
}
