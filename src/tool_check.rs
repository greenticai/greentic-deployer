//! Tool preflight (`C3`).
//!
//! Cross-cutting preflight checks for external tools an env-pack handler needs
//! to do real work (e.g. `terraform`/`kubectl`/`helm`/`docker`/`aws`/`gcloud`/
//! `az`). The Phase A surface ships:
//!
//! - [`ToolCheck`] / [`ToolCheckOutcome`] — the result shape every check
//!   returns, with structured `Missing` / `VersionMismatch` / `AuthFailed` /
//!   `Unreachable` / `ProbeError` variants and an honest `install_hint`.
//! - Generic primitives: [`check_binary_present`] and [`check_version_probe`]
//!   — handlers compose these into per-tool checks.
//! - A **named-tool catalog** ([`terraform`], [`tofu`], [`kubectl`], [`helm`],
//!   [`docker`], [`podman`], [`aws`], [`gcloud`], [`az`]) with minimum-version
//!   defaults the catalog tracks and honest install-hint text.
//! - Auth/scope probes ([`aws_caller_identity`], [`gcloud_auth_list`],
//!   [`az_account_show`], [`kubectl_can_i`]) that go beyond binary presence
//!   to verify credentials and required permissions.
//!
//! Phase A handlers (`local-process`, `dev-store`, `stdout`, `in-memory`) are
//! all in-process and return an empty preflight via the default
//! [`crate::env_packs::EnvPackHandler::preflight`]. Phase D handlers (K8s,
//! cloud) compose this catalog by name.
//!
//! `gtc op env tool-check <env_id>` aggregates per-binding [`ToolCheck`]s into
//! a structured JSON outcome.
//!
//! No timeout discipline is enforced here — built-in Phase A handlers don't
//! shell out, so a hanging probe can't surface yet. Phase D plumbing should
//! wrap the slow primitives in `wait_timeout`-style guards before live use.

use std::io::ErrorKind;
use std::process::Command;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

/// Outcome of a single [`ToolCheck`].
///
/// All failure variants carry an `install_hint` (or equivalent recovery hint)
/// so the operator sees an actionable message, not just "missing kubectl".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ToolCheckOutcome {
    /// The check passed. `detail` typically holds the observed version or a
    /// short success line (e.g. caller identity ARN).
    Ok { detail: Option<String> },
    /// The binary is not on `$PATH`.
    Missing { install_hint: String },
    /// Binary present but its version is outside the required range.
    VersionMismatch {
        found: String,
        required: String,
        install_hint: String,
    },
    /// Binary present but authentication / credentials are not valid.
    AuthFailed {
        detail: String,
        recovery_hint: String,
    },
    /// Network or cluster endpoint is unreachable.
    Unreachable {
        detail: String,
        recovery_hint: String,
    },
    /// Probe ran but produced output we couldn't make sense of, or exited
    /// non-zero for a reason we don't model. Carries the raw detail so the
    /// operator can investigate.
    ProbeError { detail: String },
}

impl ToolCheckOutcome {
    /// `true` if the outcome is [`ToolCheckOutcome::Ok`].
    pub fn is_ok(&self) -> bool {
        matches!(self, ToolCheckOutcome::Ok { .. })
    }
}

/// A single preflight check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCheck {
    /// Short identifier shown to operators (e.g. `terraform`,
    /// `aws.caller-identity`).
    pub name: String,
    /// Human-readable description of what this check verifies.
    pub description: String,
    pub outcome: ToolCheckOutcome,
}

impl ToolCheck {
    pub fn ok(
        name: impl Into<String>,
        description: impl Into<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            outcome: ToolCheckOutcome::Ok { detail },
        }
    }

    pub fn missing(
        name: impl Into<String>,
        description: impl Into<String>,
        install_hint: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            outcome: ToolCheckOutcome::Missing {
                install_hint: install_hint.into(),
            },
        }
    }

    pub fn version_mismatch(
        name: impl Into<String>,
        description: impl Into<String>,
        found: impl Into<String>,
        required: impl Into<String>,
        install_hint: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            outcome: ToolCheckOutcome::VersionMismatch {
                found: found.into(),
                required: required.into(),
                install_hint: install_hint.into(),
            },
        }
    }

    pub fn auth_failed(
        name: impl Into<String>,
        description: impl Into<String>,
        detail: impl Into<String>,
        recovery_hint: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            outcome: ToolCheckOutcome::AuthFailed {
                detail: detail.into(),
                recovery_hint: recovery_hint.into(),
            },
        }
    }

    pub fn unreachable(
        name: impl Into<String>,
        description: impl Into<String>,
        detail: impl Into<String>,
        recovery_hint: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            outcome: ToolCheckOutcome::Unreachable {
                detail: detail.into(),
                recovery_hint: recovery_hint.into(),
            },
        }
    }

    pub fn probe_error(
        name: impl Into<String>,
        description: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            outcome: ToolCheckOutcome::ProbeError {
                detail: detail.into(),
            },
        }
    }
}

/// Run `binary` with the given `args` and capture stdout. Returns:
/// - `Ok(stdout_string)` on exit-0.
/// - `Err(ProbeFailure::NotFound)` when the binary is not on `$PATH`.
/// - `Err(ProbeFailure::NonZero { stderr, code })` on a non-zero exit.
/// - `Err(ProbeFailure::Io(detail))` for any other I/O failure.
fn probe(binary: &str, args: &[&str]) -> Result<String, ProbeFailure> {
    let output = Command::new(binary).args(args).output().map_err(|e| {
        if e.kind() == ErrorKind::NotFound {
            ProbeFailure::NotFound
        } else {
            ProbeFailure::Io(e.to_string())
        }
    })?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(ProbeFailure::NonZero {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Debug)]
enum ProbeFailure {
    NotFound,
    NonZero { code: Option<i32>, stderr: String },
    Io(String),
}

/// Verify a binary is on `$PATH` by invoking it with the given `args`
/// (typically `--version`).
pub fn check_binary_present(
    name: &str,
    binary: &str,
    args: &[&str],
    install_hint: &str,
) -> ToolCheck {
    let description = format!("`{binary}` is on $PATH");
    match probe(binary, args) {
        Ok(stdout) => {
            let detail = stdout.lines().next().map(|s| s.trim().to_string());
            ToolCheck::ok(name, description, detail)
        }
        Err(ProbeFailure::NotFound) => ToolCheck::missing(name, description, install_hint),
        Err(ProbeFailure::NonZero { code, stderr, .. }) => ToolCheck::probe_error(
            name,
            description,
            format!(
                "exit {}: {}",
                code.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                stderr.trim()
            ),
        ),
        Err(ProbeFailure::Io(detail)) => ToolCheck::probe_error(name, description, detail),
    }
}

/// Verify a binary's `--version`-style output parses to a [`Version`] that
/// satisfies `required`. The `parser` extracts a [`Version`] from the raw
/// stdout — different tools embed their version in different shapes, so the
/// caller owns the regex / `split_whitespace` choice.
///
/// On non-zero exit or parse failure the check returns `ProbeError` with the
/// raw output so the operator can debug.
pub fn check_version_probe(
    name: &str,
    binary: &str,
    args: &[&str],
    parser: fn(&str) -> Option<Version>,
    required: &VersionReq,
    install_hint: &str,
) -> ToolCheck {
    let description = format!("`{binary}` version satisfies `{required}`");
    let stdout = match probe(binary, args) {
        Ok(s) => s,
        Err(ProbeFailure::NotFound) => {
            return ToolCheck::missing(name, description, install_hint);
        }
        Err(ProbeFailure::NonZero { code, stderr, .. }) => {
            return ToolCheck::probe_error(
                name,
                description,
                format!(
                    "exit {}: {}",
                    code.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                    stderr.trim()
                ),
            );
        }
        Err(ProbeFailure::Io(detail)) => {
            return ToolCheck::probe_error(name, description, detail);
        }
    };
    let Some(found) = parser(&stdout) else {
        return ToolCheck::probe_error(
            name,
            description,
            format!("could not parse version from: {}", stdout.trim()),
        );
    };
    if required.matches(&found) {
        ToolCheck::ok(name, description, Some(found.to_string()))
    } else {
        ToolCheck::version_mismatch(
            name,
            description,
            found.to_string(),
            required.to_string(),
            install_hint,
        )
    }
}

/// Extract a `MAJOR.MINOR.PATCH` from the first token that parses as one.
/// Strips a leading `v` and drops any suffix after `-`/`+` so `v1.5.7-rc1`
/// parses as `1.5.7`. `/` is a separator so `aws-cli/2.15.0 Python/3.11.6`
/// yields `2.15.0`.
pub fn parse_first_semver_token(stdout: &str) -> Option<Version> {
    for token in stdout.split(|c: char| c.is_whitespace() || matches!(c, ',' | '(' | ')' | '/')) {
        let cleaned = token.trim_start_matches('v');
        // Pre-release/build suffixes break VersionReq matching.
        let core = cleaned.split(['-', '+']).next().unwrap_or(cleaned);
        // Require two dots so a stray "2" or "1.0" isn't taken for a version.
        if core.matches('.').count() < 2 {
            continue;
        }
        if let Ok(v) = Version::parse(core) {
            return Some(v);
        }
    }
    None
}

/// Parses the first `MAJOR.MINOR.PATCH` from a `kubectl version --client
/// --output=yaml`-style or plain `--version` string. Falls back to
/// [`parse_first_semver_token`].
pub fn parse_kubectl_version(stdout: &str) -> Option<Version> {
    // `kubectl version --client` prints `Client Version: v1.30.0` with optional
    // build metadata; the generic parser handles that. Some older builds
    // print `GitVersion:"v1.27.0"` — strip the quote in that case.
    let cleaned = stdout.replace('"', " ");
    parse_first_semver_token(&cleaned)
}

/// Minimum supported OpenTofu version. Bumped as the deployer adopts newer
/// HCL features.
pub const MIN_TOFU_VERSION: &str = "1.6.0";
/// Minimum supported Terraform version. We prefer OpenTofu (see plan §7 C3);
/// Terraform is still accepted for environments stuck on it.
pub const MIN_TERRAFORM_VERSION: &str = "1.5.0";
/// Minimum supported kubectl version.
pub const MIN_KUBECTL_VERSION: &str = "1.27.0";
/// Minimum supported Helm version.
pub const MIN_HELM_VERSION: &str = "3.12.0";
/// Minimum supported Docker version.
pub const MIN_DOCKER_VERSION: &str = "24.0.0";
/// Minimum supported Podman version (Docker-equivalent OCI runtime).
pub const MIN_PODMAN_VERSION: &str = "4.5.0";
/// Minimum supported AWS CLI v2 version.
pub const MIN_AWS_VERSION: &str = "2.13.0";
/// Minimum supported gcloud version.
pub const MIN_GCLOUD_VERSION: &str = "450.0.0";
/// Minimum supported Azure CLI version.
pub const MIN_AZ_VERSION: &str = "2.50.0";

/// `>=min`, unbounded above: these are external CLIs we don't own, and a newer
/// major (terraform 2.x, kubectl 1.31, ...) is the normal upgrade path, not a
/// break — so we don't cap with a caret the way we do for our own descriptors.
fn version_req_at_least(min: &str) -> VersionReq {
    format!(">={min}")
        .parse()
        .expect("hardcoded version requirement parses")
}

/// Check `tofu` is installed and at or above [`MIN_TOFU_VERSION`].
pub fn tofu() -> ToolCheck {
    check_version_probe(
        "tofu",
        "tofu",
        &["version", "-json"],
        parse_first_semver_token,
        &version_req_at_least(MIN_TOFU_VERSION),
        "Install OpenTofu from https://opentofu.org/docs/intro/install/ (preferred over Terraform).",
    )
}

/// Check `terraform` is installed and at or above [`MIN_TERRAFORM_VERSION`].
/// Prefer [`tofu`] for new environments — Terraform shells are accepted for
/// legacy compatibility only.
pub fn terraform() -> ToolCheck {
    check_version_probe(
        "terraform",
        "terraform",
        &["version", "-json"],
        parse_first_semver_token,
        &version_req_at_least(MIN_TERRAFORM_VERSION),
        "Install Terraform >= 1.5.0 from https://developer.hashicorp.com/terraform/install — but prefer `tofu` (OpenTofu).",
    )
}

/// Check `kubectl` is installed and at or above [`MIN_KUBECTL_VERSION`].
pub fn kubectl() -> ToolCheck {
    check_version_probe(
        "kubectl",
        "kubectl",
        &["version", "--client", "--output=yaml"],
        parse_kubectl_version,
        &version_req_at_least(MIN_KUBECTL_VERSION),
        "Install kubectl from https://kubernetes.io/docs/tasks/tools/#kubectl.",
    )
}

/// Check `helm` is installed and at or above [`MIN_HELM_VERSION`].
pub fn helm() -> ToolCheck {
    check_version_probe(
        "helm",
        "helm",
        &["version", "--short"],
        parse_first_semver_token,
        &version_req_at_least(MIN_HELM_VERSION),
        "Install Helm from https://helm.sh/docs/intro/install/.",
    )
}

/// Check `docker` is installed and at or above [`MIN_DOCKER_VERSION`].
pub fn docker() -> ToolCheck {
    check_version_probe(
        "docker",
        "docker",
        &["version", "--format", "{{.Client.Version}}"],
        parse_first_semver_token,
        &version_req_at_least(MIN_DOCKER_VERSION),
        "Install Docker from https://docs.docker.com/engine/install/ or use Podman.",
    )
}

/// Check `podman` is installed and at or above [`MIN_PODMAN_VERSION`].
pub fn podman() -> ToolCheck {
    check_version_probe(
        "podman",
        "podman",
        &["version", "--format", "{{.Client.Version}}"],
        parse_first_semver_token,
        &version_req_at_least(MIN_PODMAN_VERSION),
        "Install Podman from https://podman.io/docs/installation.",
    )
}

/// Check `aws` is installed and at or above [`MIN_AWS_VERSION`].
pub fn aws() -> ToolCheck {
    check_version_probe(
        "aws",
        "aws",
        &["--version"],
        parse_first_semver_token,
        &version_req_at_least(MIN_AWS_VERSION),
        "Install AWS CLI v2 from https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html.",
    )
}

/// Check `gcloud` is installed and at or above [`MIN_GCLOUD_VERSION`].
pub fn gcloud() -> ToolCheck {
    check_version_probe(
        "gcloud",
        "gcloud",
        &["version", "--format=value(\"Google Cloud SDK\")"],
        parse_first_semver_token,
        &version_req_at_least(MIN_GCLOUD_VERSION),
        "Install gcloud from https://cloud.google.com/sdk/docs/install.",
    )
}

/// Check `az` is installed and at or above [`MIN_AZ_VERSION`].
pub fn az() -> ToolCheck {
    check_version_probe(
        "az",
        "az",
        &["version", "--output", "tsv", "--query", "\"azure-cli\""],
        parse_first_semver_token,
        &version_req_at_least(MIN_AZ_VERSION),
        "Install Azure CLI from https://learn.microsoft.com/cli/azure/install-azure-cli.",
    )
}

/// `aws sts get-caller-identity` — verifies AWS credentials are configured
/// and usable. `region` is optional; when present it is passed as
/// `--region`.
pub fn aws_caller_identity(region: Option<&str>) -> ToolCheck {
    let name = "aws.caller-identity";
    let description = "AWS credentials resolve to a caller identity".to_string();
    let mut args: Vec<&str> = vec!["sts", "get-caller-identity", "--output", "text"];
    if let Some(r) = region {
        args.push("--region");
        args.push(r);
    }
    match probe("aws", &args) {
        Ok(stdout) => ToolCheck::ok(
            name,
            description,
            stdout.lines().next().map(|s| s.trim().to_string()),
        ),
        Err(ProbeFailure::NotFound) => ToolCheck::missing(
            name,
            description,
            "AWS CLI v2 not installed; see `aws` check.",
        ),
        Err(ProbeFailure::NonZero { stderr, .. }) => ToolCheck::auth_failed(
            name,
            description,
            stderr.trim().to_string(),
            "Run `aws configure sso` or set AWS_PROFILE / AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.",
        ),
        Err(ProbeFailure::Io(detail)) => ToolCheck::probe_error(name, description, detail),
    }
}

/// Shared shape for "the first non-empty stdout line is the authenticated
/// identity". An empty stdout on exit-0 (nothing active) and a non-zero exit
/// both mean "no usable session" — distinguished only by the detail string.
/// `gcloud auth list` and `az account show` both fit; `aws_caller_identity`
/// does not (it has no empty-stdout case) and `kubectl_can_i` parses a
/// yes/no answer, so they stay bespoke.
fn auth_probe_first_line(
    name: &str,
    description: &str,
    binary: &str,
    args: &[&str],
    empty_detail: &str,
    missing_hint: &str,
    recovery_hint: &str,
) -> ToolCheck {
    match probe(binary, args) {
        Ok(stdout) => {
            let first = stdout.lines().next().map(|s| s.trim()).unwrap_or("");
            if first.is_empty() {
                ToolCheck::auth_failed(name, description, empty_detail, recovery_hint)
            } else {
                ToolCheck::ok(name, description, Some(first.to_string()))
            }
        }
        Err(ProbeFailure::NotFound) => ToolCheck::missing(name, description, missing_hint),
        Err(ProbeFailure::NonZero { stderr, .. }) => {
            ToolCheck::auth_failed(name, description, stderr.trim().to_string(), recovery_hint)
        }
        Err(ProbeFailure::Io(detail)) => ToolCheck::probe_error(name, description, detail),
    }
}

/// `gcloud auth list --filter=status:ACTIVE` — verifies a gcloud
/// authentication is active.
pub fn gcloud_auth_list() -> ToolCheck {
    auth_probe_first_line(
        "gcloud.auth",
        "gcloud has an ACTIVE authentication",
        "gcloud",
        &[
            "auth",
            "list",
            "--filter=status:ACTIVE",
            "--format=value(account)",
        ],
        "no ACTIVE account found",
        "gcloud not installed; see `gcloud` check.",
        "Run `gcloud auth login` (or `gcloud auth activate-service-account`).",
    )
}

/// `az account show` — verifies an Azure subscription is selected and the
/// session is not expired.
pub fn az_account_show() -> ToolCheck {
    auth_probe_first_line(
        "az.account",
        "Azure CLI session has an active subscription",
        "az",
        &["account", "show", "--output", "tsv", "--query", "id"],
        "no active subscription",
        "Azure CLI not installed; see `az` check.",
        "Run `az login` and `az account set --subscription <id>`.",
    )
}

/// `kubectl auth can-i <verb> <resource> [-n <namespace>]` — verifies the
/// configured kubeconfig has the requested permission on the cluster. This
/// goes beyond binary-present: it surfaces both kubeconfig reachability and
/// RBAC sufficiency in one probe.
pub fn kubectl_can_i(verb: &str, resource: &str, namespace: Option<&str>) -> ToolCheck {
    let name = format!("kubectl.can-i:{verb}:{resource}");
    let description = match namespace {
        Some(ns) => format!("`kubectl auth can-i {verb} {resource} -n {ns}` is allowed"),
        None => format!("`kubectl auth can-i {verb} {resource}` is allowed"),
    };
    let mut args: Vec<&str> = vec!["auth", "can-i", verb, resource];
    if let Some(ns) = namespace {
        args.push("-n");
        args.push(ns);
    }
    match probe("kubectl", &args) {
        Ok(stdout) => {
            let answer = stdout.lines().next().map(|s| s.trim()).unwrap_or("");
            if answer.eq_ignore_ascii_case("yes") {
                ToolCheck::ok(name, description, Some(answer.to_string()))
            } else {
                ToolCheck::auth_failed(
                    name,
                    description,
                    answer.to_string(),
                    "Grant the required role/binding via the env-pack credentials bootstrap (Phase C/D).",
                )
            }
        }
        Err(ProbeFailure::NotFound) => ToolCheck::missing(
            name,
            description,
            "kubectl not installed; see `kubectl` check.",
        ),
        Err(ProbeFailure::NonZero { stderr, .. }) => {
            let stderr_lc = stderr.to_lowercase();
            // kubectl uses "couldn't get current server" / "Unable to connect"
            // for unreachable endpoints; everything else we surface as
            // AuthFailed so the operator sees the kubectl-side message.
            if stderr_lc.contains("unable to connect")
                || stderr_lc.contains("couldn't get current server")
                || stderr_lc.contains("no such host")
            {
                ToolCheck::unreachable(
                    name,
                    description,
                    stderr.trim().to_string(),
                    "Verify $KUBECONFIG points at a reachable cluster.",
                )
            } else {
                ToolCheck::auth_failed(
                    name,
                    description,
                    stderr.trim().to_string(),
                    "Inspect the kubectl error and grant the required role.",
                )
            }
        }
        Err(ProbeFailure::Io(detail)) => ToolCheck::probe_error(name, description, detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_serializes_with_status_tag() {
        let ok = ToolCheckOutcome::Ok {
            detail: Some("1.6.0".into()),
        };
        let s = serde_json::to_string(&ok).unwrap();
        assert!(s.contains("\"status\":\"ok\""));
        assert!(s.contains("\"detail\":\"1.6.0\""));

        let missing = ToolCheckOutcome::Missing {
            install_hint: "brew install tofu".into(),
        };
        let s = serde_json::to_string(&missing).unwrap();
        assert!(s.contains("\"status\":\"missing\""));
        assert!(s.contains("install_hint"));

        let auth = ToolCheckOutcome::AuthFailed {
            detail: "no creds".into(),
            recovery_hint: "aws configure".into(),
        };
        let s = serde_json::to_string(&auth).unwrap();
        assert!(s.contains("\"status\":\"auth_failed\""));
        assert!(s.contains("recovery_hint"));
    }

    #[test]
    fn is_ok_only_matches_ok() {
        assert!(
            ToolCheckOutcome::Ok { detail: None }.is_ok(),
            "Ok must report is_ok"
        );
        assert!(
            !ToolCheckOutcome::Missing {
                install_hint: String::new(),
            }
            .is_ok(),
            "Missing must not report is_ok"
        );
    }

    #[test]
    fn parse_first_semver_token_handles_common_shapes() {
        // `tofu --version`: `OpenTofu v1.6.2`
        assert_eq!(
            parse_first_semver_token("OpenTofu v1.6.2\non darwin_amd64"),
            Some(Version::new(1, 6, 2))
        );
        // `terraform version`: `Terraform v1.7.0`
        assert_eq!(
            parse_first_semver_token("Terraform v1.7.0"),
            Some(Version::new(1, 7, 0))
        );
        // `helm version --short`: `v3.13.1+gabcdef1`
        assert_eq!(
            parse_first_semver_token("v3.13.1+gabcdef1"),
            Some(Version::new(3, 13, 1))
        );
        // `aws --version`: `aws-cli/2.15.0 Python/3.11.6 Linux/...` — the `/`
        // separator lets us reach the `2.15.0` token (the `aws-cli` prefix and
        // the `Python/3.11.6` runtime version are skipped: prefix has no dots,
        // and `2.15.0` is the first 3-part token).
        let aws_out = "aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0 source/x86_64";
        assert_eq!(
            parse_first_semver_token(aws_out),
            Some(Version::new(2, 15, 0))
        );
        // Plain semver: `1.30.0`
        assert_eq!(
            parse_first_semver_token("1.30.0"),
            Some(Version::new(1, 30, 0))
        );
        // Pre-release suffix is dropped for matching: `1.6.0-rc1` → 1.6.0
        assert_eq!(
            parse_first_semver_token("v1.6.0-rc1"),
            Some(Version::new(1, 6, 0))
        );
    }

    #[test]
    fn parse_first_semver_token_rejects_short_numbers() {
        // A stray `2` should not be picked up as `2.0.0`.
        assert_eq!(parse_first_semver_token("foo 2 bar"), None);
        // A stray `1.0` should not be picked up either — we require 3-part.
        assert_eq!(parse_first_semver_token("foo 1.0 bar"), None);
    }

    #[test]
    fn parse_kubectl_version_strips_quotes_in_yaml_form() {
        let yaml = "clientVersion:\n  gitVersion: \"v1.30.0\"\n  ...\n";
        assert_eq!(parse_kubectl_version(yaml), Some(Version::new(1, 30, 0)));
    }

    #[test]
    fn missing_binary_reports_missing() {
        // We exploit `Command::new` returning `ErrorKind::NotFound` for a
        // bogus binary so the check returns the structured Missing outcome
        // with the install-hint preserved verbatim.
        let check = check_binary_present(
            "noexist",
            "definitely-not-a-real-binary-c3-test",
            &["--version"],
            "Install foobar from https://example.test/install.",
        );
        match &check.outcome {
            ToolCheckOutcome::Missing { install_hint } => {
                assert!(install_hint.contains("https://example.test/install"));
            }
            other => panic!("expected Missing, got {other:?}"),
        }
        assert_eq!(check.name, "noexist");
    }

    #[test]
    fn version_probe_missing_binary_reports_missing() {
        let req: VersionReq = ">=1.0.0".parse().unwrap();
        let check = check_version_probe(
            "noexist",
            "definitely-not-a-real-binary-c3-test",
            &["--version"],
            parse_first_semver_token,
            &req,
            "install hint here",
        );
        assert!(matches!(check.outcome, ToolCheckOutcome::Missing { .. }));
    }

    #[test]
    fn install_hints_carry_actionable_text() {
        // Spot-check that every named-tool catalog entry has a non-empty
        // install_hint when its binary isn't present (which it won't be in
        // CI by default for at least a few of these). We don't assert which
        // ones are missing — just that every catalog entry produces a
        // ToolCheck with a non-empty install_hint when Missing.
        for check in [
            tofu(),
            terraform(),
            kubectl(),
            helm(),
            docker(),
            podman(),
            aws(),
            gcloud(),
            az(),
        ] {
            if let ToolCheckOutcome::Missing { install_hint } = &check.outcome {
                assert!(
                    !install_hint.trim().is_empty(),
                    "named check `{}` returned an empty install_hint",
                    check.name
                );
            }
        }
    }

    #[test]
    fn catalog_minimum_versions_are_valid_semver() {
        // Guard against typo-introduced unparseable minimums.
        for min in [
            MIN_TOFU_VERSION,
            MIN_TERRAFORM_VERSION,
            MIN_KUBECTL_VERSION,
            MIN_HELM_VERSION,
            MIN_DOCKER_VERSION,
            MIN_PODMAN_VERSION,
            MIN_AWS_VERSION,
            MIN_GCLOUD_VERSION,
            MIN_AZ_VERSION,
        ] {
            let _: Version = min.parse().unwrap_or_else(|e| {
                panic!("MIN_*_VERSION `{min}` is not valid semver: {e}");
            });
            let _ = version_req_at_least(min);
        }
    }

    #[test]
    fn check_binary_present_with_real_binary() {
        // `true` is universally available on Unix, exits 0 with no output.
        let check = check_binary_present("true-check", "true", &[], "N/A");
        assert!(
            check.outcome.is_ok(),
            "expected Ok, got {:?}",
            check.outcome
        );
        assert_eq!(check.name, "true-check");
    }

    #[test]
    fn check_version_probe_with_unparseable_version() {
        // `true` exits 0 but prints nothing parseable as semver.
        let req: VersionReq = ">=1.0.0".parse().unwrap();
        let check = check_version_probe(
            "parse-fail",
            "true",
            &[],
            parse_first_semver_token,
            &req,
            "install hint",
        );
        assert!(
            matches!(check.outcome, ToolCheckOutcome::ProbeError { .. }),
            "expected ProbeError for unparseable version, got {:?}",
            check.outcome
        );
    }

    #[test]
    fn tool_check_constructors_set_fields() {
        let missing = ToolCheck::missing("m", "desc-m", "hint-m");
        assert_eq!(missing.name, "m");
        assert!(!missing.outcome.is_ok());

        let vm = ToolCheck::version_mismatch("v", "desc-v", "1.0.0", ">=2.0.0", "hint-v");
        assert_eq!(vm.name, "v");
        if let ToolCheckOutcome::VersionMismatch {
            found, required, ..
        } = &vm.outcome
        {
            assert_eq!(found, "1.0.0");
            assert_eq!(required, ">=2.0.0");
        } else {
            panic!("expected VersionMismatch");
        }

        let af = ToolCheck::auth_failed("a", "desc-a", "no creds", "fix it");
        assert_eq!(af.name, "a");
        assert!(matches!(af.outcome, ToolCheckOutcome::AuthFailed { .. }));

        let ur = ToolCheck::unreachable("u", "desc-u", "timeout", "check network");
        assert_eq!(ur.name, "u");
        assert!(matches!(ur.outcome, ToolCheckOutcome::Unreachable { .. }));

        let pe = ToolCheck::probe_error("p", "desc-p", "unknown");
        assert_eq!(pe.name, "p");
        assert!(matches!(pe.outcome, ToolCheckOutcome::ProbeError { .. }));
    }

    #[test]
    fn outcome_deserializes_from_json() {
        let json = r#"{"status":"version_mismatch","found":"1.0.0","required":">=2.0.0","install_hint":"upgrade"}"#;
        let outcome: ToolCheckOutcome = serde_json::from_str(json).unwrap();
        assert!(matches!(outcome, ToolCheckOutcome::VersionMismatch { .. }));

        let json = r#"{"status":"unreachable","detail":"timeout","recovery_hint":"retry"}"#;
        let outcome: ToolCheckOutcome = serde_json::from_str(json).unwrap();
        assert!(matches!(outcome, ToolCheckOutcome::Unreachable { .. }));

        let json = r#"{"status":"probe_error","detail":"unknown failure"}"#;
        let outcome: ToolCheckOutcome = serde_json::from_str(json).unwrap();
        assert!(matches!(outcome, ToolCheckOutcome::ProbeError { .. }));
    }

    #[test]
    fn version_req_at_least_accepts_matching() {
        let req = version_req_at_least("1.5.0");
        assert!(req.matches(&Version::new(1, 5, 0)));
        assert!(req.matches(&Version::new(2, 0, 0)));
        assert!(!req.matches(&Version::new(1, 4, 9)));
    }
}
