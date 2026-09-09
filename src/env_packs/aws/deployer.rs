//! [`Deployer`] impl for the AWS-ECS env-pack.
//!
//! Verbs follow the contract's order: pure-spec preconditions first (shared
//! helpers — `require_revision`, `enforce_split_invariants`), provider work
//! second. The provider work drives the [`EcsDeployTarget`] seam (the AWS twin
//! of `K8sCluster`).
//!
//! **Answers:** `warm_revision` / `archive_revision` / `apply_traffic_split`
//! take the binding's wizard answers and render through
//! [`AwsEcsParams::from_answers`] (`None` → [`AwsEcsParams::for_env`] sandbox
//! defaults), so a verb scopes to the same region / cluster / listener the
//! operator bound. A malformed answers blob fails BEFORE any AWS call.
//!
//! | Verb | Provider side-effect |
//! |---|---|
//! | `stage_revision` | None. Image/bundle delivery is a separate cross-provider slice (K8s defers it too). |
//! | `warm_revision` | Ensure the deployment's `EXTERNAL`-controller service + create the revision's task set; wait until it stabilizes. |
//! | `drain_revision` | None — routing-side. Traffic shifts via `apply_traffic_split`; target-group deregistration-delay drains in-flight. |
//! | `archive_revision` | Delete the revision's task set + deregister its task definition (idempotent against absent). |
//! | `apply_traffic_split` | Write the listener rule's weighted forward action across the deployment's task-set target groups. Never re-creates task sets. |
//!
//! Idempotency falls out of the seam's contract: `ensure_service` /
//! `create_task_set` upsert, `delete_task_set` of an absent set is `Ok`. The
//! conformance bench runs against [`InMemoryEcs`](super::deploy_target::InMemoryEcs);
//! the real aws-sdk-backed target inherits these verbs unchanged once it lands.

use std::time::Duration;

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, Environment, Revision, RevisionId};
use serde_json::Value;
use tokio::time::{Instant, sleep};

use super::AwsEcsDeployerHandler;
use super::deploy_target::{
    EcsDeployTarget, EcsTargetError, ListenerRef, ListenerRouting, ServiceSpec, TargetGroupWeight,
    TaskSetRef, TaskSetSpec,
};
use crate::env_packs::deployer::{
    ArchiveOutcome, Deployer, DeployerError, DrainOutcome, StageOutcome, TrafficSplitOutcome,
    WarmOutcome, enforce_split_invariants, require_revision,
};

/// Default container image base when the binding supplies no
/// `ecr_repository_prefix`. The in-memory path never pulls it; the real target
/// requires the operator to scope `ecr_repository_prefix` to their account.
const DEFAULT_IMAGE_BASE: &str = "greentic/operator";

/// Default image-tag prefix when the binding supplies no
/// `container_image_tag_prefix`. Matches the wizard's `default_value`.
const DEFAULT_IMAGE_TAG_PREFIX: &str = "rev-";

/// Seam failures surface as provider failures — the verb's preconditions have
/// already passed by the time the target is touched.
fn provider(err: EcsTargetError) -> DeployerError {
    DeployerError::Provider(err.to_string())
}

/// Per-binding Fargate launch config the real ECS target needs to stand up a
/// task definition + task set, but which the per-revision seam specs
/// deliberately do not carry (it is stable across a binding's revisions, not
/// per-revision). Pure data (no aws-sdk types) so it lives in the always-
/// compiled deployer module and is parsed by [`AwsEcsParams::from_answers`];
/// the feature-gated `real_target` re-exports it and consumes it at
/// `create_task_set`.
#[derive(Clone, PartialEq, Eq)]
pub struct FargateLaunchConfig {
    /// IAM role the ECS agent assumes to pull the image + write logs.
    pub execution_role_arn: String,
    /// Optional IAM role the task's containers assume (app-level AWS access).
    pub task_role_arn: Option<String>,
    /// awsvpc subnets the Fargate ENIs attach to (at least one).
    pub subnets: Vec<String>,
    /// Security groups applied to the task ENIs.
    pub security_groups: Vec<String>,
    /// Whether tasks get a public IP (public subnets without a NAT need this to
    /// reach ECR / the image registry).
    pub assign_public_ip: bool,
    /// Task-level CPU units (Fargate requires it at the task level), e.g. `256`.
    pub cpu: String,
    /// Task-level memory (MiB) as a string, e.g. `512`.
    pub memory: String,
    /// Logical container name in the task definition; also the `containerName`
    /// the load balancer routes to.
    pub container_name: String,
    /// Port the container listens on / the target group forwards to.
    pub container_port: i32,
    /// Operator-supplied environment variables projected onto the app
    /// container, from the `container_env` answer. Sorted by name at parse
    /// time so the rendered task definition is deterministic (ECS registers a
    /// new task-definition revision per warm; a reordered environment array
    /// would make every re-register look like a change).
    ///
    /// **Values are secret-bearing by assumption** — this is the escape hatch
    /// operators reach for when a setting has no dedicated answer, and broker
    /// URLs, connection strings and API keys all arrive through it. Nothing
    /// may render a value: [`FargateLaunchConfig`]'s [`std::fmt::Debug`] prints
    /// names only, and no [`AwsEcsParamsError`] variant carries one.
    pub environment: Vec<(String, String)>,
    /// Extra containers placed in the same task definition as the app, from
    /// the `sidecars` answer. Empty for the single-container default. The app
    /// container is always registered first — see
    /// [`SidecarContainer`] for what the surface deliberately omits.
    pub sidecars: Vec<SidecarContainer>,
}

/// Renders `environment` / `env` pairs as their NAMES only. A launch config
/// that carried a broker URL with an embedded password would otherwise print
/// it in full anywhere a `{:?}` reaches — `RealEcsTarget` derives `Debug` and
/// holds one, and `AwsEcsParams` holds one too. Names are kept because
/// "which variables are set" is the diagnostic question; "what they are set
/// to" never is.
fn fmt_env_names(f: &mut std::fmt::Formatter<'_>, env: &[(String, String)]) -> std::fmt::Result {
    f.debug_list().entries(env.iter().map(|(k, _)| k)).finish()
}

/// Wrapper so [`fmt_env_names`] can be handed to `debug_struct().field(..)`,
/// which takes a `&dyn Debug` rather than a closure.
struct EnvNames<'a>(&'a [(String, String)]);

impl std::fmt::Debug for EnvNames<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_env_names(f, self.0)
    }
}

impl std::fmt::Debug for FargateLaunchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FargateLaunchConfig")
            .field("execution_role_arn", &self.execution_role_arn)
            .field("task_role_arn", &self.task_role_arn)
            .field("subnets", &self.subnets)
            .field("security_groups", &self.security_groups)
            .field("assign_public_ip", &self.assign_public_ip)
            .field("cpu", &self.cpu)
            .field("memory", &self.memory)
            .field("container_name", &self.container_name)
            .field("container_port", &self.container_port)
            // Names only — see `fmt_env_names`.
            .field("environment", &EnvNames(&self.environment))
            .field("sidecars", &self.sidecars)
            .finish()
    }
}

/// One extra container placed beside the app in the same task definition, so a
/// small dependency (a broker, a metrics shipper) can run in the task and be
/// reached by the app on `127.0.0.1` — Fargate bills the task's reservation,
/// not the container count, so a sidecar on a task with headroom costs nothing.
///
/// **Deliberately small.** No health check, no `dependsOn` ordering, no volume
/// mounts, no `secret://` valueFrom, and no CPU share. Each is a real need for
/// some workload; none is needed to run a broker beside the app, which is the
/// case this exists for. Adding one later is additive, whereas shipping five
/// knobs nobody exercises is a surface to keep working forever.
///
/// `essential` is absent for a different reason — it is not a deferred knob but
/// a decision. A sidecar is always non-essential, because ECS stops the WHOLE
/// task when an essential container exits: an essential broker could take the
/// app down with it, and would do so through the blue/green rollout, where the
/// task set never stabilizes and the warm fails on a timeout naming the app.
/// The rendering side states the same rule at the point it is applied
/// (`real_target::sidecar_def`).
#[derive(Clone, PartialEq, Eq)]
pub struct SidecarContainer {
    /// Container name inside the task definition. Must be unique across the
    /// task and must not collide with
    /// [`FargateLaunchConfig::container_name`] — the load balancer routes by
    /// container name, so a collision would make the routing target ambiguous.
    pub name: String,
    /// Image the sidecar runs. Unlike the app image (which the deployer builds
    /// per revision from `ecr_repository_prefix` + the revision ULID), this is
    /// pinned by the operator and identical across revisions.
    pub image: String,
    /// Port the sidecar listens on, if any. Under `awsvpc` every container in
    /// the task shares one ENI, so this is what the app reaches on
    /// `127.0.0.1:<port>`. `None` for a sidecar that opens no socket.
    pub port: Option<i32>,
    /// Soft memory limit in MiB (ECS `memoryReservation`). `None` leaves the
    /// sidecar sharing the task reservation without a floor.
    pub memory_reservation_mib: Option<i32>,
    /// Environment variables for THIS container only. Same parse rules,
    /// reserved names and redaction as
    /// [`FargateLaunchConfig::environment`].
    pub environment: Vec<(String, String)>,
}

impl std::fmt::Debug for SidecarContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarContainer")
            .field("name", &self.name)
            .field("image", &self.image)
            .field("port", &self.port)
            .field("memory_reservation_mib", &self.memory_reservation_mib)
            // Names only — see `fmt_env_names`.
            .field("environment", &EnvNames(&self.environment))
            .finish()
    }
}

/// Environment-variable names the DEPLOYER owns on the task's containers, and
/// which `container_env` / a sidecar's `env` therefore may not set.
///
/// These carry the deployment's identity: which environment, which deployment,
/// which revision, which bundle. Their values are minted per warm from the
/// revision the deployer is placing, so an operator-supplied value is not a
/// preference that could be honored — it is a statement about identity that is
/// either redundant or false.
///
/// **Reserved before rendered, deliberately.** The AWS-ECS container definition
/// projects none of these today (its Cloud Run and K8s siblings both do, via
/// their `runtime_boot_env`; ECS has no equivalent yet). Reserving now costs an
/// operator nothing — nobody can be relying on a variable the runtime does not
/// read — whereas reserving later means the day the boot env lands, a manifest
/// that pinned `GREENTIC_REVISION_ID` starts being silently overwritten, in
/// production, having worked until then. Refusing at parse time is the only
/// point where that is cheap.
pub const DEPLOYER_MANAGED_ENV_KEYS: &[&str] = &[
    "GREENTIC_BUNDLE_DIGEST",
    "GREENTIC_BUNDLE_ID",
    "GREENTIC_DEPLOYMENT_ID",
    "GREENTIC_ENV",
    "GREENTIC_ENV_ID",
    "GREENTIC_REVISION_ID",
    "GREENTIC_SEED_DIR",
];

/// Resolved scope for the AWS-ECS verbs, built from the binding's wizard
/// answers (`None` → sandbox defaults). Holds the non-secret identifiers the
/// verbs need plus the per-binding real-target config (launch + target-group
/// pool) the construction path consumes; credential MATERIAL is never here (it
/// rides the bound STS session in the real target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEcsParams {
    /// AWS region the cluster lives in.
    pub region: String,
    /// ECS cluster name the deployer manages services in.
    pub cluster: String,
    /// Container image base every revision's image is built from.
    pub image_base: String,
    /// Prefix the revision's image tag is built from (wizard default `rev-`).
    /// Blank tags with the raw revision ULID.
    pub image_tag_prefix: String,
    /// ALB listener ARN the weighted forward action is written to. `None`
    /// means no ALB mirror is configured: `apply_traffic_split` skips the
    /// listener update and the runtime dispatcher stays authoritative.
    pub listener_arn: Option<String>,
    /// Scoped deployer role ARN to assume for a bound STS session (the role
    /// the rules-pack Terraform creates). `None` means no role hop: render-only
    /// bootstrap, and `op credentials bootstrap --bind` is rejected for this
    /// env. Read by the `--bind` STS minter, not the deploy verbs.
    pub assume_role_arn: Option<String>,
    /// Per-binding Fargate launch config for the real ECS target. `None` when
    /// the binding records no launch answers (sandbox / verb-only paths);
    /// `Some` only when the complete required set is present (all-or-nothing).
    /// Consumed by the construction path (PR-3c), not the verbs here.
    pub launch: Option<FargateLaunchConfig>,
    /// Operator-provided pool of pre-provisioned ALB target groups (ARNs or
    /// names ≤32 chars) the real target assigns revisions to for blue/green
    /// traffic shifting. Empty when the binding records no pool. Consumed by
    /// the construction path (PR-3c), not the verbs here.
    pub target_group_pool: Vec<String>,
    /// Per-deployment ALB routing condition (host/path) that scopes this
    /// deployment's weighted forward to its own listener rule. `None` when the
    /// binding records no routing answers — the listener's default action is
    /// written instead (one deployment per listener). Consumed by
    /// `apply_traffic_split`.
    pub routing: Option<ListenerRouting>,
}

/// Why a wizard answers blob could not be read into [`AwsEcsParams`].
#[derive(Debug, thiserror::Error)]
pub enum AwsEcsParamsError {
    #[error("answers must be a JSON object")]
    NotAnObject,
    #[error("answer `{0}` must be a string")]
    NotAString(String),
    #[error("unknown answer key `{0}`")]
    UnknownKey(String),
    #[error("answer `{key}` is invalid: {detail}")]
    Invalid { key: String, detail: String },
    #[error("launch config is incomplete: `{field}` is required")]
    MissingLaunchField { field: &'static str },
    /// The whole `container_env` / `sidecars[].env` answer was not a mapping.
    #[error("answer `{key}` must be a JSON object of `NAME: value` pairs")]
    EnvNotAnObject { key: String },
    /// One entry's value was not a string. Names only — see
    /// [`FargateLaunchConfig::environment`] on why no variant carries a value.
    #[error("environment variable `{name}` in answer `{key}` must be a string value")]
    EnvValueNotAString { key: String, name: String },
    /// One entry's name is not a legal environment-variable identifier.
    #[error(
        "environment variable name `{name}` in answer `{key}` is not a valid identifier \
         (letters, digits and `_`, not starting with a digit)"
    )]
    EnvNameInvalid { key: String, name: String },
    /// One entry's name is in [`DEPLOYER_MANAGED_ENV_KEYS`].
    #[error(
        "environment variable `{name}` in answer `{key}` is managed by the deployer and cannot \
         be set from a binding answer — it carries the deployment's identity, which the deployer \
         mints per revision. Remove it; every other name is yours."
    )]
    EnvNameReserved { key: String, name: String },
    /// The `sidecars` answer was not an array of objects.
    #[error("answer `sidecars` must be a JSON array of objects")]
    SidecarsNotAnArray,
    /// A sidecar omitted a field with no sensible default.
    #[error("sidecar `{name}` is missing required field `{field}`")]
    SidecarMissingField { name: String, field: &'static str },
    /// A sidecar field was present but the wrong JSON type / shape.
    #[error("sidecar `{name}` field `{field}` is invalid: {detail}")]
    SidecarInvalid {
        name: String,
        field: &'static str,
        detail: String,
    },
    /// Two sidecars, or a sidecar and the app container, share a name. ECS
    /// keys the load-balancer binding on the container name, so a duplicate
    /// makes the routing target ambiguous rather than merely untidy.
    #[error(
        "container name `{name}` is used twice in the task definition (a sidecar collides with \
         the app container or with another sidecar); container names must be unique"
    )]
    DuplicateContainerName { name: String },
}

/// True for a POSIX-shell-legal environment variable name. Deliberately
/// stricter than what ECS itself accepts: a name outside this set is far more
/// likely to be a mis-typed answer (a stray quote, a `KEY=VALUE` string pasted
/// as the name) than a real variable the workload reads.
fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse a `{NAME: value}` environment mapping (the `container_env` answer, or
/// a sidecar's `env`) into sorted name/value pairs.
///
/// `key` names the answer being parsed and appears in every error; no error
/// carries a VALUE. Sorted because the rendered ECS `environment` array is
/// compared on re-register, and because a `serde_json::Map` iterated in
/// insertion order would make the task definition depend on how the operator
/// happened to type their YAML.
fn parse_env_map(key: &str, value: &Value) -> Result<Vec<(String, String)>, AwsEcsParamsError> {
    let obj = value
        .as_object()
        .ok_or_else(|| AwsEcsParamsError::EnvNotAnObject {
            key: key.to_string(),
        })?;
    let mut out = Vec::with_capacity(obj.len());
    for (name, raw) in obj {
        if !valid_env_name(name) {
            return Err(AwsEcsParamsError::EnvNameInvalid {
                key: key.to_string(),
                name: name.clone(),
            });
        }
        if DEPLOYER_MANAGED_ENV_KEYS.contains(&name.as_str()) {
            return Err(AwsEcsParamsError::EnvNameReserved {
                key: key.to_string(),
                name: name.clone(),
            });
        }
        // Only strings. A number or bool would have an obvious rendering
        // (`8080`, `true`), but accepting them means an operator's YAML
        // `value: 08` silently becomes `8`, and `value: no` silently becomes
        // `false` — the classic YAML foot-guns, landing in a live container.
        let v = raw
            .as_str()
            .ok_or_else(|| AwsEcsParamsError::EnvValueNotAString {
                key: key.to_string(),
                name: name.clone(),
            })?;
        out.push((name.clone(), v.to_string()));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Read an optional sidecar integer field, bounded by `range`.
fn sidecar_int(
    name: &str,
    field: &'static str,
    value: &Value,
    range: std::ops::RangeInclusive<i64>,
) -> Result<Option<i32>, AwsEcsParamsError> {
    if value.is_null() {
        return Ok(None);
    }
    let invalid = |detail: String| AwsEcsParamsError::SidecarInvalid {
        name: name.to_string(),
        field,
        detail,
    };
    // Accept the JSON number and the string form: a manifest hand-written in
    // YAML quotes numbers as often as not, and the sibling answers
    // (`container_port`, `cpu`) are string-typed for exactly that reason.
    let n: i64 = match value {
        Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| invalid(format!("`{n}` is not an integer")))?,
        Value::String(s) => s
            .parse()
            .map_err(|_| invalid(format!("`{s}` is not an integer")))?,
        other => return Err(invalid(format!("expected an integer, got {other}"))),
    };
    if !range.contains(&n) {
        return Err(invalid(format!(
            "{n} is outside {}..={}",
            range.start(),
            range.end()
        )));
    }
    i32::try_from(n)
        .map(Some)
        .map_err(|_| invalid(format!("{n} does not fit in an i32")))
}

/// Parse the `sidecars` answer: an array of `{name, image, port?,
/// memory_reservation_mib?, env?}` objects. Name uniqueness (including against
/// the app container) is enforced later, in [`LaunchFields::build`], where the
/// app container's name is resolved — it may come from `container_name` or
/// from that answer's default, and only `build` knows which.
fn parse_sidecars(value: &Value) -> Result<Vec<SidecarContainer>, AwsEcsParamsError> {
    let items = value
        .as_array()
        .ok_or(AwsEcsParamsError::SidecarsNotAnArray)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let obj = item
            .as_object()
            .ok_or(AwsEcsParamsError::SidecarsNotAnArray)?;
        // Read the name first so every later error can name the sidecar.
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(AwsEcsParamsError::SidecarMissingField {
                name: "<unnamed>".to_string(),
                field: "name",
            })?
            .to_string();
        if !valid_container_name(&name) {
            return Err(AwsEcsParamsError::SidecarInvalid {
                name: name.clone(),
                field: "name",
                detail: "must be 1..=255 characters of letters, digits, `_` or `-`".to_string(),
            });
        }
        let image = obj
            .get("image")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AwsEcsParamsError::SidecarMissingField {
                name: name.clone(),
                field: "image",
            })?
            .to_string();
        let port = match obj.get("port") {
            Some(v) => sidecar_int(&name, "port", v, 1..=65535)?,
            None => None,
        };
        let memory_reservation_mib = match obj.get("memory_reservation_mib") {
            Some(v) => sidecar_int(&name, "memory_reservation_mib", v, 1..=i64::from(i32::MAX))?,
            None => None,
        };
        let environment = match obj.get("env") {
            Some(Value::Null) | None => Vec::new(),
            Some(v) => parse_env_map(&format!("sidecars[{name}].env"), v)?,
        };
        for field in obj.keys() {
            // Deny-by-default inside the sidecar object too: the enclosing
            // answers loop rejects unknown top-level keys, and a typo'd
            // `immage:` would otherwise be dropped in silence.
            if !matches!(
                field.as_str(),
                "name" | "image" | "port" | "memory_reservation_mib" | "env"
            ) {
                return Err(AwsEcsParamsError::SidecarInvalid {
                    name: name.clone(),
                    field: "<unknown>",
                    detail: format!("unknown field `{field}`"),
                });
            }
        }
        out.push(SidecarContainer {
            name,
            image,
            port,
            memory_reservation_mib,
            environment,
        });
    }
    Ok(out)
}

/// Container-name shape ECS accepts, mirroring the `container_name` answer's
/// wizard constraint.
fn valid_container_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn answer_string(key: &str, value: &Value) -> Result<String, AwsEcsParamsError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| AwsEcsParamsError::NotAString(key.to_string()))
}

/// Read an optional string answer, mapping a blank / whitespace-only value to
/// `None`. Operators are told to "leave blank" optional fields, and
/// `load_render_answers` loads staged answer JSON verbatim, so a persisted
/// empty string is a plausible "unset" — not a real value. Without this a blank
/// `Some("")` would reach the SDK (e.g. an empty `taskRoleArn`) or break the
/// shared parser, which `--bind` reuses just to read `assume_role_arn`.
fn optional_string(key: &str, value: &Value) -> Result<Option<String>, AwsEcsParamsError> {
    let s = answer_string(key, value)?;
    Ok(if s.trim().is_empty() { None } else { Some(s) })
}

/// Read the optional `alb_routing_path` answer. Blank → `None` (the routing
/// condition is opt-in, like every other ALB answer). A present value must be
/// an ELBv2 path pattern (leading `/`), validated here so a malformed answer
/// fails at parse time rather than as an opaque `CreateRule` API error — the
/// same fail-at-parse posture as `parse_target_group_pool`.
fn parse_routing_path(key: &str, value: &Value) -> Result<Option<String>, AwsEcsParamsError> {
    let Some(path) = optional_string(key, value)? else {
        return Ok(None);
    };
    if !path.starts_with('/') {
        return Err(AwsEcsParamsError::Invalid {
            key: key.to_string(),
            detail: format!("path pattern `{path}` must start with `/`"),
        });
    }
    Ok(Some(path))
}

/// Split a comma-separated string answer into trimmed, non-empty entries.
fn csv_list(key: &str, value: &Value) -> Result<Vec<String>, AwsEcsParamsError> {
    Ok(answer_string(key, value)?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// Parse a `"true"` / `"false"` string answer (the `assign_public_ip` enum) to
/// a bool.
fn parse_bool(key: &str, value: &Value) -> Result<bool, AwsEcsParamsError> {
    match answer_string(key, value)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(AwsEcsParamsError::Invalid {
            key: key.to_string(),
            detail: format!("expected `true` or `false`, got `{other}`"),
        }),
    }
}

/// Parse a container-port string answer to an `i32` in the valid TCP range.
fn parse_port(key: &str, value: &Value) -> Result<i32, AwsEcsParamsError> {
    let raw = answer_string(key, value)?;
    let port: i32 = raw.parse().map_err(|_| AwsEcsParamsError::Invalid {
        key: key.to_string(),
        detail: format!("`{raw}` is not an integer"),
    })?;
    if (1..=65535).contains(&port) {
        Ok(port)
    } else {
        Err(AwsEcsParamsError::Invalid {
            key: key.to_string(),
            detail: format!("port {port} is outside 1..=65535"),
        })
    }
}

/// Parse the `target_group_arns` pool: comma-separated entries, each an ELBv2
/// target-group ARN or a name (≤32 chars, the ELBv2 name limit). A blank /
/// whitespace-only answer means the optional pool is unset (operators leave it
/// blank when no ALB mirror is configured) and parses to an empty pool, not an
/// error. The minimum pool size for blue/green and free-slot assignment is
/// enforced by the real target (PR-3c construction wiring), not here — this
/// only validates the per-entry identity shape so a malformed pool fails at
/// parse time.
fn parse_target_group_pool(key: &str, value: &Value) -> Result<Vec<String>, AwsEcsParamsError> {
    let pool = csv_list(key, value)?;
    for entry in &pool {
        if !valid_target_group_identity(entry) {
            return Err(AwsEcsParamsError::Invalid {
                key: key.to_string(),
                detail: format!(
                    "`{entry}` is neither an ELBv2 target-group ARN nor a valid \
                     name (≤32 chars, alphanumeric/hyphen, not starting with `-`)"
                ),
            });
        }
    }
    Ok(pool)
}

/// True for an ELBv2 target-group ARN or a valid target-group name.
fn valid_target_group_identity(s: &str) -> bool {
    if s.starts_with("arn:aws:elasticloadbalancing:") && s.contains(":targetgroup/") {
        return true;
    }
    !s.is_empty()
        && s.len() <= 32
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Optional launch-config fields gathered from the answers loop, assembled into
/// a [`FargateLaunchConfig`] all-or-nothing by [`LaunchFields::build`].
#[derive(Default, PartialEq, Eq)]
struct LaunchFields {
    execution_role_arn: Option<String>,
    task_role_arn: Option<String>,
    subnets: Option<Vec<String>>,
    security_groups: Option<Vec<String>>,
    assign_public_ip: Option<bool>,
    cpu: Option<String>,
    memory: Option<String>,
    container_name: Option<String>,
    container_port: Option<i32>,
    environment: Option<Vec<(String, String)>>,
    sidecars: Option<Vec<SidecarContainer>>,
}

impl LaunchFields {
    /// Assemble the launch config. Returns `None` when no launch field was
    /// supplied (verb-only blobs), `Some` when the required set
    /// (`execution_role_arn` + `subnets` + `security_groups`) is complete, and
    /// an error when only a partial set is present. CPU / memory / container
    /// name / port / public-IP default to the wizard's defaults when omitted.
    fn build(self) -> Result<Option<FargateLaunchConfig>, AwsEcsParamsError> {
        // No launch field supplied (verb-only blob) → no launch config.
        if self == LaunchFields::default() {
            return Ok(None);
        }
        let execution_role_arn =
            self.execution_role_arn
                .ok_or(AwsEcsParamsError::MissingLaunchField {
                    field: "execution_role_arn",
                })?;
        let subnets = self
            .subnets
            .filter(|s| !s.is_empty())
            .ok_or(AwsEcsParamsError::MissingLaunchField { field: "subnets" })?;
        let security_groups = self.security_groups.filter(|s| !s.is_empty()).ok_or(
            AwsEcsParamsError::MissingLaunchField {
                field: "security_groups",
            },
        )?;
        let container_name = self.container_name.unwrap_or_else(|| "worker".to_string());
        let sidecars = self.sidecars.unwrap_or_default();
        // Every container in the task must have a distinct name — the app's
        // included. ECS binds the load balancer by container name, so a
        // duplicate is not cosmetic: it makes "which container does the target
        // group forward to" unanswerable. Checked here rather than in
        // `parse_sidecars` because only `build` knows the app container's
        // resolved name (the answer may have been omitted and defaulted).
        let mut seen = vec![container_name.as_str()];
        for sidecar in &sidecars {
            if seen.contains(&sidecar.name.as_str()) {
                return Err(AwsEcsParamsError::DuplicateContainerName {
                    name: sidecar.name.clone(),
                });
            }
            seen.push(&sidecar.name);
        }
        Ok(Some(FargateLaunchConfig {
            execution_role_arn,
            task_role_arn: self.task_role_arn,
            subnets,
            security_groups,
            assign_public_ip: self.assign_public_ip.unwrap_or(false),
            cpu: self.cpu.unwrap_or_else(|| "256".to_string()),
            memory: self.memory.unwrap_or_else(|| "512".to_string()),
            container_name,
            container_port: self.container_port.unwrap_or(8080),
            environment: self.environment.unwrap_or_default(),
            sidecars,
        }))
    }
}

impl AwsEcsParams {
    /// Sandbox defaults derived from the env (no binding answers).
    pub fn for_env(env: &Environment) -> Self {
        Self {
            region: env
                .host_config
                .region
                .clone()
                .unwrap_or_else(|| "us-east-1".to_string()),
            cluster: format!("greentic-{}", env.environment_id.as_str()),
            image_base: DEFAULT_IMAGE_BASE.to_string(),
            image_tag_prefix: DEFAULT_IMAGE_TAG_PREFIX.to_string(),
            listener_arn: None,
            assume_role_arn: None,
            launch: None,
            target_group_pool: Vec::new(),
            routing: None,
        }
    }

    /// Overlay the binding's recorded wizard answers onto [`Self::for_env`].
    ///
    /// Keys mirror `wizard.qaspec.yaml`. Unknown keys are rejected (deny-by-
    /// default, so an operator typo fails loudly rather than being silently
    /// dropped). `assume_role_arn` is captured here (the `--bind` STS minter
    /// reads it); `aws_profile` is validated as a string and accepted so a full
    /// binding's answers deserialize, but is consumed by the SDK client builder
    /// in a later slice, not by these verbs.
    ///
    /// `container_env` (a `{NAME: value}` mapping) and `sidecars` (an array of
    /// container objects) are the two STRUCTURED answers — every other key is a
    /// string, matching what the wizard form can collect. They are structured
    /// because no string encoding of them is safe: the delimiter this pack uses
    /// for its other multi-valued answers is a comma, and a comma is an
    /// ordinary character inside a broker URL list or a connection string, so a
    /// CSV `container_env` would silently split exactly the values it exists to
    /// carry. `oci_insecure_registries` in the K8s pack sets the precedent for a
    /// structured answer whose wizard form is a string; here only the structured
    /// form exists, and the wizard spec says so rather than offering a lossy one.
    ///
    /// The Fargate launch-config keys (`execution_role_arn`, `subnets`, …) and
    /// the `target_group_arns` pool are parsed here too — every known key has
    /// exactly one home so deny-by-default stays coherent across the verbs and
    /// the construction path. The launch config is all-or-nothing: present only
    /// when its complete required set is supplied (so verb-only blobs that omit
    /// it parse to [`None`]); a partial set is an error rather than a silent
    /// half-config.
    pub fn from_answers(
        env: &Environment,
        answers: Option<&Value>,
    ) -> Result<Self, AwsEcsParamsError> {
        let mut params = Self::for_env(env);
        let Some(answers) = answers else {
            return Ok(params);
        };
        let obj = answers.as_object().ok_or(AwsEcsParamsError::NotAnObject)?;
        // Launch-config fields are gathered here and assembled after the loop
        // (all-or-nothing — see `build_launch`). The routing condition is two
        // optional answers assembled the same way (≥1 set → `Some`).
        let mut launch = LaunchFields::default();
        let mut routing_host = None;
        let mut routing_path = None;
        for (key, value) in obj {
            match key.as_str() {
                "region" => params.region = answer_string(key, value)?,
                "ecs_cluster_name" => params.cluster = answer_string(key, value)?,
                "ecr_repository_prefix" => params.image_base = answer_string(key, value)?,
                "container_image_tag_prefix" => {
                    params.image_tag_prefix = answer_string(key, value)?
                }
                "alb_listener_arn" => params.listener_arn = optional_string(key, value)?,
                "alb_routing_host" => routing_host = optional_string(key, value)?,
                "alb_routing_path" => routing_path = parse_routing_path(key, value)?,
                "assume_role_arn" => params.assume_role_arn = optional_string(key, value)?,
                "aws_profile" => {
                    answer_string(key, value)?;
                }
                "execution_role_arn" => launch.execution_role_arn = optional_string(key, value)?,
                "task_role_arn" => launch.task_role_arn = optional_string(key, value)?,
                "subnets" => launch.subnets = Some(csv_list(key, value)?),
                "security_groups" => launch.security_groups = Some(csv_list(key, value)?),
                "assign_public_ip" => launch.assign_public_ip = Some(parse_bool(key, value)?),
                "cpu" => launch.cpu = Some(answer_string(key, value)?),
                "memory" => launch.memory = Some(answer_string(key, value)?),
                "container_name" => launch.container_name = Some(answer_string(key, value)?),
                "container_port" => launch.container_port = Some(parse_port(key, value)?),
                "container_env" => launch.environment = Some(parse_env_map(key, value)?),
                "sidecars" => launch.sidecars = Some(parse_sidecars(value)?),
                "target_group_arns" => {
                    params.target_group_pool = parse_target_group_pool(key, value)?
                }
                other => return Err(AwsEcsParamsError::UnknownKey(other.to_string())),
            }
        }
        params.launch = launch.build()?;
        params.routing = match (routing_host, routing_path) {
            (None, None) => None,
            (host, path) => Some(ListenerRouting { host, path }),
        };
        Ok(params)
    }

    /// Image the revision's Fargate task runs (image base + the configured
    /// tag prefix + the revision ULID).
    fn image_for(&self, revision_id: RevisionId) -> String {
        format!(
            "{}:{}{}",
            self.image_base, self.image_tag_prefix, revision_id.0
        )
    }
}

/// Build params from the binding's answers, mapping a malformed blob to a
/// provider error BEFORE any AWS call (no typed answers-rejection variant;
/// mirrors the K8s deployer).
fn params_from_answers(
    env: &Environment,
    answers: Option<&Value>,
) -> Result<AwsEcsParams, DeployerError> {
    AwsEcsParams::from_answers(env, answers)
        .map_err(|e| DeployerError::Provider(format!("invalid answers: {e}")))
}

/// Default upper bound on the warm stabilization wait. A task set that has not
/// reached steady state within this window fails the warm rather than letting a
/// revision promote `Warming → Ready` over tasks that never became healthy.
const WARM_STABILIZE_TIMEOUT: Duration = Duration::from_secs(300);

/// Env override for [`WARM_STABILIZE_TIMEOUT`] (whole seconds). The live E2E
/// sets a short value so the gate's failure path is observable without a
/// multi-minute hang. An unset / unparseable value falls back to the default.
const WARM_STABILIZE_TIMEOUT_ENV: &str = "GREENTIC_AWS_ECS_WARM_READY_TIMEOUT_SECS";

/// Poll cadence while waiting for the task set to stabilize.
const WARM_STABILIZE_POLL_INTERVAL: Duration = Duration::from_secs(5);

fn warm_stabilize_timeout() -> Duration {
    std::env::var(WARM_STABILIZE_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(WARM_STABILIZE_TIMEOUT)
}

/// Block until the task set reaches steady state, or fail on timeout.
///
/// `timeout` / `poll_interval` are parameters (not the module consts) so the
/// unit tests drive the loop deterministically under a paused clock.
async fn wait_for_task_set_stability(
    target: &dyn EcsDeployTarget,
    task_set: &TaskSetRef,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<(), DeployerError> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = target
            .task_set_stability(task_set)
            .await
            .map_err(provider)?;
        if status.stabilized {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(DeployerError::Provider(format!(
                "task set for revision `{}` (deployment `{}`) did not stabilize within {}s \
                 (running {}/{})",
                task_set.revision_id.0,
                task_set.deployment_id.0,
                timeout.as_secs(),
                status.running,
                status.desired,
            )));
        }
        sleep(poll_interval).await;
    }
}

impl AwsEcsDeployerHandler {
    /// Locate the revision (the caller already passed `require_revision`, so
    /// the lookup is infallible by construction — keep it total anyway).
    fn revision(env: &Environment, revision_id: RevisionId) -> Option<&Revision> {
        env.revisions.iter().find(|r| r.revision_id == revision_id)
    }
}

#[async_trait]
impl Deployer for AwsEcsDeployerHandler {
    async fn stage_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<StageOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        // No AWS work at stage time — see the module table.
        Ok(StageOutcome::default())
    }

    async fn warm_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<WarmOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        let revision = Self::revision(env, revision_id).expect("require_revision passed");
        let params = params_from_answers(env, answers)?;
        let deployment_id = revision.deployment_id;

        self.target
            .ensure_service(&ServiceSpec {
                deployment_id,
                cluster: params.cluster.clone(),
                region: params.region.clone(),
            })
            .await
            .map_err(provider)?;
        self.target
            .create_task_set(&TaskSetSpec {
                deployment_id,
                revision_id,
                cluster: params.cluster.clone(),
                region: params.region.clone(),
                image: params.image_for(revision_id),
            })
            .await
            .map_err(provider)?;

        // The task set is created; the revision is only Ready once it reaches
        // steady state (running == desired AND its target group is healthy). A
        // task set that never stabilizes fails the warm, so the operator sees
        // the stall instead of a revision silently promoted over non-serving
        // tasks.
        wait_for_task_set_stability(
            self.target.as_ref(),
            &TaskSetRef {
                deployment_id,
                revision_id,
                cluster: params.cluster.clone(),
                region: params.region.clone(),
            },
            warm_stabilize_timeout(),
            WARM_STABILIZE_POLL_INTERVAL,
        )
        .await?;

        Ok(WarmOutcome::default())
    }

    async fn drain_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<DrainOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        // Routing-side only — see the module table. Task sets stay up so
        // in-flight sessions complete; archive tears them down.
        Ok(DrainOutcome::default())
    }

    async fn archive_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<ArchiveOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        let revision = Self::revision(env, revision_id).expect("require_revision passed");
        let params = params_from_answers(env, answers)?;
        self.target
            .delete_task_set(&TaskSetRef {
                deployment_id: revision.deployment_id,
                revision_id,
                cluster: params.cluster,
                region: params.region,
            })
            .await
            .map_err(provider)?;
        Ok(ArchiveOutcome::default())
    }

    async fn apply_traffic_split(
        &self,
        env: &Environment,
        deployment_id: DeploymentId,
        answers: Option<&Value>,
    ) -> Result<TrafficSplitOutcome, DeployerError> {
        // Preconditions + outcome construction BEFORE any AWS call.
        let outcome = enforce_split_invariants(env, deployment_id)?;
        let params = params_from_answers(env, answers)?;
        // Only touch the ALB when a listener is configured; with no
        // `alb_listener_arn` the runtime dispatcher stays authoritative for
        // traffic splitting, so there is no listener to write.
        if let Some(listener_arn) = &params.listener_arn {
            let weights: Vec<TargetGroupWeight> = outcome
                .applied_entries
                .iter()
                .map(|entry| TargetGroupWeight {
                    revision_id: entry.revision_id,
                    weight_bps: entry.weight_bps,
                })
                .collect();
            self.target
                .apply_listener_weights(
                    &ListenerRef {
                        deployment_id,
                        listener_arn: listener_arn.clone(),
                        cluster: params.cluster.clone(),
                        routing: params.routing.clone(),
                    },
                    &weights,
                )
                .await
                .map_err(provider)?;
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::env_packs::aws::deploy_target::{InMemoryEcs, TaskSetHandle, TaskSetStability};
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::deployer::run_conformance;
    use ulid::Ulid;

    fn handler_with_fake() -> (AwsEcsDeployerHandler, Arc<InMemoryEcs>) {
        let target = Arc::new(InMemoryEcs::default());
        (AwsEcsDeployerHandler::with_target(target.clone()), target)
    }

    // ---- conformance: the Phase D entry gate ----------------------------

    #[tokio::test]
    async fn aws_ecs_deployer_passes_conformance() {
        let (handler, _target) = handler_with_fake();
        run_conformance(&handler)
            .await
            .expect("AWS-ECS deployer satisfies the Phase D conformance contract");
    }

    // ---- verb behavior against the in-memory fake -----------------------

    #[tokio::test]
    async fn warm_ensures_service_and_creates_the_task_set() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];

        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();

        assert!(
            target.services().contains(&rev.deployment_id),
            "warm ensures the deployment's service"
        );
        let sets = target.task_sets();
        assert_eq!(sets.len(), 1, "exactly one task set");
        assert!(
            sets.contains_key(&(rev.deployment_id, rev.revision_id)),
            "task set keyed by (deployment, revision)"
        );
    }

    #[tokio::test]
    async fn warm_is_idempotent() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];

        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        let first = target.task_sets();
        // Warm again: upsert, still exactly one task set with the same handle.
        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        assert_eq!(target.task_sets(), first, "warm is idempotent");
    }

    #[tokio::test]
    async fn warm_honors_a_cluster_answer() {
        let (handler, _target) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];
        // A custom cluster answer scopes the verb; the fake records identity
        // not cluster, so assert via the params path that the answer parses
        // and the verb still lands a task set (the real target threads the
        // cluster into the SDK call).
        let answers = serde_json::json!({ "ecs_cluster_name": "custom-cluster" });
        handler
            .warm_revision(&env, rev.revision_id, Some(&answers))
            .await
            .unwrap();
        let params = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(params.cluster, "custom-cluster");
    }

    #[tokio::test]
    async fn warm_rejects_invalid_answers_before_touching_the_target() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];
        let answers = serde_json::json!({ "unknown_key": "x" });

        let err = handler
            .warm_revision(&env, rev.revision_id, Some(&answers))
            .await
            .unwrap_err();
        match err {
            DeployerError::Provider(msg) => assert!(msg.contains("invalid answers"), "msg: {msg}"),
            other => panic!("expected Provider, got {other:?}"),
        }
        assert!(
            target.task_sets().is_empty() && target.services().is_empty(),
            "invalid answers must not touch the target"
        );
    }

    #[tokio::test]
    async fn archive_deletes_the_task_set_and_tolerates_absence() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];

        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        assert_eq!(target.task_sets().len(), 1);

        handler
            .archive_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        assert!(target.task_sets().is_empty());

        // Retried archive against an already-deleted set is Ok.
        handler
            .archive_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
    }

    /// A valid ALB listener ARN (passes the wizard's `^arn:...:listener/.+$`
    /// constraint) to drive the ALB-mirror path in the split tests.
    const TEST_LISTENER_ARN: &str =
        "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/x/y/z";

    #[tokio::test]
    async fn traffic_split_applies_weights_mirroring_the_split() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let dep = env.bundles[0].deployment_id;
        let answers = serde_json::json!({ "alb_listener_arn": TEST_LISTENER_ARN });

        let outcome = handler
            .apply_traffic_split(&env, dep, Some(&answers))
            .await
            .unwrap();
        assert_eq!(outcome.applied_deployment_id, dep);

        let weights = target.weights_for(dep).expect("weights applied");
        let split = env
            .traffic_splits
            .iter()
            .find(|s| s.deployment_id == dep)
            .unwrap();
        assert_eq!(weights.len(), split.entries.len());
        for entry in &split.entries {
            assert!(
                weights
                    .iter()
                    .any(|w| w.revision_id == entry.revision_id && w.weight_bps == entry.weight_bps),
                "weight for revision {} must mirror the split entry",
                entry.revision_id.0
            );
        }
    }

    /// A binding's ALB routing answers flow through to the `ListenerRef` the
    /// target receives: with a routing condition the verb carries `Some`
    /// (the target writes a per-deployment rule); without one it carries the
    /// legacy `None` (the target writes the listener default action).
    #[tokio::test]
    async fn traffic_split_carries_routing_to_the_listener() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let dep = env.bundles[0].deployment_id;

        let routed = serde_json::json!({
            "alb_listener_arn": TEST_LISTENER_ARN,
            "alb_routing_host": "app.example.com",
            "alb_routing_path": "/app/*",
        });
        handler
            .apply_traffic_split(&env, dep, Some(&routed))
            .await
            .unwrap();
        assert_eq!(
            target.routing_for(dep),
            Some(Some(ListenerRouting {
                host: Some("app.example.com".into()),
                path: Some("/app/*".into()),
            })),
            "a routing condition must reach the target as `Some`"
        );

        let unrouted = serde_json::json!({ "alb_listener_arn": TEST_LISTENER_ARN });
        handler
            .apply_traffic_split(&env, dep, Some(&unrouted))
            .await
            .unwrap();
        assert_eq!(
            target.routing_for(dep),
            Some(None),
            "no routing condition must reach the target as the legacy `None`"
        );
    }

    /// A split for deployment A must not perturb deployment B's recorded
    /// weights (cross-deployment independence at the seam level).
    #[tokio::test]
    async fn traffic_split_is_independent_across_deployments() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let dep_a = env.bundles[0].deployment_id;
        let dep_b = env.bundles[1].deployment_id;
        let answers = serde_json::json!({ "alb_listener_arn": TEST_LISTENER_ARN });

        handler
            .apply_traffic_split(&env, dep_a, Some(&answers))
            .await
            .unwrap();
        assert!(
            target.weights_for(dep_b).is_none(),
            "applying A's split must not write B's weights"
        );
        handler
            .apply_traffic_split(&env, dep_b, Some(&answers))
            .await
            .unwrap();
        // A's weights are still its own.
        let split_a = env
            .traffic_splits
            .iter()
            .find(|s| s.deployment_id == dep_a)
            .unwrap();
        assert_eq!(
            target.weights_for(dep_a).unwrap().len(),
            split_a.entries.len()
        );
    }

    /// With no `alb_listener_arn` configured, the split still produces the
    /// right outcome but the deployer leaves the ALB untouched — the runtime
    /// dispatcher stays authoritative for traffic splitting.
    #[tokio::test]
    async fn traffic_split_without_a_listener_skips_the_alb() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let dep = env.bundles[0].deployment_id;

        let outcome = handler.apply_traffic_split(&env, dep, None).await.unwrap();
        assert_eq!(outcome.applied_deployment_id, dep);
        assert!(
            target.weights_for(dep).is_none(),
            "no listener configured: the ALB must be left untouched"
        );
    }

    /// Preconditions run BEFORE any target call: unknown revision / invalid
    /// split must leave the target untouched.
    #[tokio::test]
    async fn preconditions_reject_before_any_target_call() {
        let (handler, target) = handler_with_fake();
        let mut env = build_fixture_env();
        let unknown = RevisionId(Ulid::from(0xFFFF_u128));

        let err = handler
            .warm_revision(&env, unknown, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DeployerError::RevisionNotFound { .. }));

        // Invalid split (sum != 10000) on deployment A.
        env.traffic_splits[0].entries[0].weight_bps = 1;
        let dep = env.bundles[0].deployment_id;
        let err = handler
            .apply_traffic_split(&env, dep, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DeployerError::InvalidSplit { .. }));

        assert!(
            target.task_sets().is_empty()
                && target.services().is_empty()
                && target.weights_for(dep).is_none(),
            "rejected preconditions must not touch the target"
        );
    }

    /// The default handler (no real ECS client) fails provider verbs honestly
    /// instead of pretending the work happened.
    #[tokio::test]
    async fn unconfigured_target_surfaces_a_provider_error() {
        let handler = AwsEcsDeployerHandler::default();
        let env = build_fixture_env();
        let err = handler
            .warm_revision(&env, env.revisions[0].revision_id, None)
            .await
            .unwrap_err();
        match err {
            DeployerError::Provider(msg) => {
                assert!(msg.contains("no ECS API client"), "msg: {msg}");
            }
            other => panic!("expected Provider, got {other:?}"),
        }
        // Pure preconditions still come first even unconfigured.
        let unknown = RevisionId(Ulid::from(0xFFFF_u128));
        assert!(matches!(
            handler
                .warm_revision(&env, unknown, None)
                .await
                .unwrap_err(),
            DeployerError::RevisionNotFound { .. }
        ));
    }

    // ---- warm stabilization wait ----------------------------------------

    /// A target whose task set reports "not stable" for the first
    /// `stable_after` polls, then stable. Other methods are no-ops.
    #[derive(Debug)]
    struct ScriptedStabilityTarget {
        stable_after: usize,
        polls: AtomicUsize,
    }

    #[async_trait]
    impl EcsDeployTarget for ScriptedStabilityTarget {
        async fn ensure_service(&self, _spec: &ServiceSpec) -> Result<(), EcsTargetError> {
            Ok(())
        }
        async fn create_task_set(
            &self,
            _spec: &TaskSetSpec,
        ) -> Result<TaskSetHandle, EcsTargetError> {
            Ok(TaskSetHandle {
                task_set_id: "ts".into(),
                task_def_arn: "td".into(),
            })
        }
        async fn task_set_stability(
            &self,
            _task_set: &TaskSetRef,
        ) -> Result<TaskSetStability, EcsTargetError> {
            let n = self.polls.fetch_add(1, Ordering::SeqCst);
            Ok(TaskSetStability {
                stabilized: n >= self.stable_after,
                running: if n >= self.stable_after { 1 } else { 0 },
                desired: 1,
            })
        }
        async fn delete_task_set(&self, _task_set: &TaskSetRef) -> Result<(), EcsTargetError> {
            Ok(())
        }
        async fn apply_listener_weights(
            &self,
            _listener: &ListenerRef,
            _weights: &[TargetGroupWeight],
        ) -> Result<(), EcsTargetError> {
            Ok(())
        }
    }

    fn task_set_ref() -> TaskSetRef {
        TaskSetRef {
            deployment_id: DeploymentId(Ulid::from(0x01_u128)),
            revision_id: RevisionId(Ulid::from(0x10_u128)),
            cluster: "greentic-test".into(),
            region: "us-east-1".into(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn warm_stabilize_wait_resolves_once_the_task_set_is_stable() {
        let target = ScriptedStabilityTarget {
            stable_after: 3,
            polls: AtomicUsize::new(0),
        };
        wait_for_task_set_stability(
            &target,
            &task_set_ref(),
            Duration::from_secs(60),
            Duration::from_secs(2),
        )
        .await
        .expect("stabilizes once the task set reports steady state");
        assert!(
            target.polls.load(Ordering::SeqCst) >= 4,
            "must keep polling until stable"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn warm_stabilize_wait_times_out_when_never_stable() {
        let target = ScriptedStabilityTarget {
            stable_after: usize::MAX,
            polls: AtomicUsize::new(0),
        };
        let err = wait_for_task_set_stability(
            &target,
            &task_set_ref(),
            Duration::from_secs(10),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        match err {
            DeployerError::Provider(msg) => {
                assert!(msg.contains("did not stabilize"), "msg: {msg}");
                assert!(msg.contains("running 0/1"), "msg: {msg}");
            }
            other => panic!("expected a Provider timeout error, got {other:?}"),
        }
    }

    // ---- AwsEcsParams ---------------------------------------------------

    #[test]
    fn from_answers_none_equals_for_env() {
        let env = build_fixture_env();
        assert_eq!(
            AwsEcsParams::from_answers(&env, None).unwrap(),
            AwsEcsParams::for_env(&env)
        );
    }

    #[test]
    fn from_answers_overlays_known_keys() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "region": "eu-west-1",
            "ecs_cluster_name": "prod",
            "ecr_repository_prefix": "123.dkr.ecr/greentic/",
            "container_image_tag_prefix": "v",
            "alb_listener_arn": "arn:aws:elasticloadbalancing:eu-west-1:111122223333:listener/app/x/y/z",
            "aws_profile": "prod-admin",
            "assume_role_arn": "arn:aws:iam::111122223333:role/greentic-deployer",
        });
        let params = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(params.region, "eu-west-1");
        assert_eq!(params.cluster, "prod");
        assert_eq!(params.image_base, "123.dkr.ecr/greentic/");
        assert_eq!(params.image_tag_prefix, "v");
        assert!(params.listener_arn.is_some());
        // `assume_role_arn` is captured (the `--bind` STS minter reads it);
        // `aws_profile` is still validated-but-dropped.
        assert_eq!(
            params.assume_role_arn.as_deref(),
            Some("arn:aws:iam::111122223333:role/greentic-deployer")
        );
    }

    #[test]
    fn image_for_honors_the_configured_tag_prefix() {
        let env = build_fixture_env();
        let rev = env.revisions[0].revision_id;

        // Default prefix → `<base>:rev-<ulid>`.
        let default = AwsEcsParams::for_env(&env);
        assert_eq!(
            default.image_for(rev),
            format!("{}:rev-{}", default.image_base, rev.0)
        );

        // Blank prefix → raw revision ULID tag (`<base>:<ulid>`), matching the
        // wizard's "leave blank to tag with the raw revision ULID".
        let blank = AwsEcsParams::from_answers(
            &env,
            Some(&serde_json::json!({ "container_image_tag_prefix": "" })),
        )
        .unwrap();
        assert_eq!(
            blank.image_for(rev),
            format!("{}:{}", blank.image_base, rev.0)
        );
    }

    #[test]
    fn from_answers_rejects_unknown_key() {
        let env = build_fixture_env();
        let answers = serde_json::json!({ "bogus": "x" });
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(err, AwsEcsParamsError::UnknownKey(k) if k == "bogus"));
    }

    #[test]
    fn from_answers_rejects_non_string_value() {
        let env = build_fixture_env();
        let answers = serde_json::json!({ "region": 123 });
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(err, AwsEcsParamsError::NotAString(k) if k == "region"));
    }

    #[test]
    fn from_answers_rejects_non_object() {
        let env = build_fixture_env();
        let answers = serde_json::json!("not an object");
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(err, AwsEcsParamsError::NotAnObject));
    }

    // ---- Fargate launch config + target-group pool (PR-3c) --------------

    /// A complete launch set parses into `Some(FargateLaunchConfig)`, splitting
    /// the comma lists and parsing the typed fields; the pool is captured.
    #[test]
    fn from_answers_parses_full_launch_config_and_target_group_pool() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "execution_role_arn": "arn:aws:iam::111122223333:role/exec",
            "task_role_arn": "arn:aws:iam::111122223333:role/task",
            "subnets": "subnet-aaaa, subnet-bbbb",
            "security_groups": "sg-1111,sg-2222",
            "assign_public_ip": "true",
            "cpu": "512",
            "memory": "1024",
            "container_name": "worker",
            "container_port": "9090",
            "target_group_arns": "tg-blue,tg-green",
        });
        let params = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap();
        let launch = params.launch.expect("complete launch set parses to Some");
        assert_eq!(
            launch.execution_role_arn,
            "arn:aws:iam::111122223333:role/exec"
        );
        assert_eq!(
            launch.task_role_arn.as_deref(),
            Some("arn:aws:iam::111122223333:role/task")
        );
        // Comma lists are split and trimmed.
        assert_eq!(launch.subnets, ["subnet-aaaa", "subnet-bbbb"]);
        assert_eq!(launch.security_groups, ["sg-1111", "sg-2222"]);
        assert!(launch.assign_public_ip);
        assert_eq!(launch.cpu, "512");
        assert_eq!(launch.memory, "1024");
        assert_eq!(launch.container_name, "worker");
        assert_eq!(launch.container_port, 9090);
        assert_eq!(params.target_group_pool, ["tg-blue", "tg-green"]);
        // Absent `container_env` / `sidecars` mean "none", not "invalid".
        assert!(launch.environment.is_empty());
        assert!(launch.sidecars.is_empty());
    }

    // ---- `container_env` passthrough -----------------------------------

    /// The minimum launch set, so a `container_env` test does not have to
    /// restate the Fargate scaffolding.
    fn launch_answers(extra: serde_json::Value) -> serde_json::Value {
        let mut base = serde_json::json!({
            "execution_role_arn": "arn:aws:iam::111122223333:role/exec",
            "subnets": "subnet-aaaa",
            "security_groups": "sg-1111",
        });
        let (Some(base_obj), Some(extra_obj)) = (base.as_object_mut(), extra.as_object()) else {
            panic!("launch_answers takes JSON objects");
        };
        for (k, v) in extra_obj {
            base_obj.insert(k.clone(), v.clone());
        }
        base
    }

    fn launch_from(answers: &serde_json::Value) -> FargateLaunchConfig {
        let env = build_fixture_env();
        AwsEcsParams::from_answers(&env, Some(answers))
            .expect("answers parse")
            .launch
            .expect("complete launch set parses to Some")
    }

    /// The unblocking case: an operator-supplied variable with no dedicated
    /// answer reaches the launch config, and a value containing commas — a
    /// multi-endpoint broker URL — survives intact, which no comma-delimited
    /// encoding of this answer could promise.
    #[test]
    fn container_env_carries_operator_variables_including_comma_bearing_values() {
        let launch = launch_from(&launch_answers(serde_json::json!({
            "container_env": {
                "RUST_LOG": "info",
                "GREENTIC_EVENTS_NATS_URL": "nats://a.example:4222,nats://b.example:4222",
            },
        })));
        assert_eq!(
            launch.environment,
            [
                (
                    "GREENTIC_EVENTS_NATS_URL".to_string(),
                    "nats://a.example:4222,nats://b.example:4222".to_string()
                ),
                ("RUST_LOG".to_string(), "info".to_string()),
            ],
            "pairs are carried verbatim and sorted by name"
        );
    }

    /// Sorting is by NAME, independent of the order the operator wrote them:
    /// a re-register whose only difference is YAML ordering must not look like
    /// a configuration change.
    #[test]
    fn container_env_is_sorted_by_name_not_by_authoring_order() {
        let a = launch_from(&launch_answers(serde_json::json!({
            "container_env": {"ZULU": "1", "ALPHA": "2"},
        })));
        let b = launch_from(&launch_answers(serde_json::json!({
            "container_env": {"ALPHA": "2", "ZULU": "1"},
        })));
        assert_eq!(a.environment, b.environment);
        assert_eq!(
            a.environment.first().map(|(k, _)| k.as_str()),
            Some("ALPHA")
        );
    }

    /// The collision rule: a deployer-managed name is REFUSED, at parse time,
    /// before any AWS call. Not last-wins (which would let a binding answer
    /// misstate the revision the task is serving) and not first-wins (which
    /// would drop the operator's value in silence — the very failure this
    /// answer exists to end).
    #[test]
    fn container_env_refuses_a_deployer_managed_name() {
        let env = build_fixture_env();
        for name in DEPLOYER_MANAGED_ENV_KEYS {
            let answers = launch_answers(serde_json::json!({
                "container_env": {(*name).to_string(): "operator-supplied"},
            }));
            let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
            assert!(
                matches!(&err, AwsEcsParamsError::EnvNameReserved { name: n, .. } if n == name),
                "`{name}` must be refused, got {err:?}"
            );
        }
    }

    /// A name the deployer does not manage is accepted even when it shares the
    /// `GREENTIC_` prefix. Reserving the prefix wholesale would have been
    /// simpler and would have blocked `GREENTIC_EVENTS_NATS_URL`, the variable
    /// this whole answer was added to deliver.
    #[test]
    fn container_env_reserves_names_not_the_greentic_prefix() {
        let launch = launch_from(&launch_answers(serde_json::json!({
            "container_env": {"GREENTIC_EVENTS_NATS_URL": "nats://127.0.0.1:4222"},
        })));
        assert_eq!(launch.environment.len(), 1);
    }

    #[test]
    fn container_env_rejects_non_object_non_string_and_malformed_names() {
        let env = build_fixture_env();
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (serde_json::json!("A=1"), "a bare string is not a mapping"),
            (serde_json::json!(["A=1"]), "an array is not a mapping"),
        ];
        for (value, why) in cases {
            let answers = launch_answers(serde_json::json!({ "container_env": value }));
            let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
            assert!(
                matches!(err, AwsEcsParamsError::EnvNotAnObject { .. }),
                "{why}"
            );
        }

        let answers = launch_answers(serde_json::json!({"container_env": {"PORT": 8080}}));
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(
            matches!(&err, AwsEcsParamsError::EnvValueNotAString { name, .. } if name == "PORT"),
            "a YAML number must be refused rather than stringified, got {err:?}"
        );

        let answers = launch_answers(serde_json::json!({"container_env": {"2FA": "x"}}));
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(
            matches!(&err, AwsEcsParamsError::EnvNameInvalid { name, .. } if name == "2FA"),
            "got {err:?}"
        );
    }

    /// Values are secret-bearing by assumption, so no rendered string may
    /// carry one: not the `Display` of any error, and not the `Debug` of the
    /// launch config (which `RealEcsTarget` holds and derives `Debug` over).
    #[test]
    fn no_rendered_string_carries_an_environment_value() {
        const SECRET: &str = "sk-live-must-never-be-rendered";
        let env = build_fixture_env();

        // Every error path that can see a value.
        let cases = [
            serde_json::json!({"GREENTIC_REVISION_ID": SECRET}),
            serde_json::json!({"2FA": SECRET}),
        ];
        for value in cases {
            let answers = launch_answers(serde_json::json!({ "container_env": value }));
            let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
            assert!(
                !err.to_string().contains(SECRET) && !format!("{err:?}").contains(SECRET),
                "error rendered the value: {err}"
            );
        }

        // And the happy path's Debug — names survive, values do not.
        let launch = launch_from(&launch_answers(serde_json::json!({
            "container_env": {"BROKER_URL": SECRET},
            "sidecars": [{"name": "broker", "image": "nats:2", "env": {"PASSWORD": SECRET}}],
        })));
        let rendered = format!("{launch:?}");
        assert!(
            !rendered.contains(SECRET),
            "Debug rendered a value: {rendered}"
        );
        assert!(
            rendered.contains("BROKER_URL") && rendered.contains("PASSWORD"),
            "Debug must keep NAMES — they are the diagnostic half: {rendered}"
        );
        // The same object nested inside `AwsEcsParams`, which derives Debug.
        let params = AwsEcsParams::from_answers(
            &env,
            Some(&launch_answers(
                serde_json::json!({"container_env": {"BROKER_URL": SECRET}}),
            )),
        )
        .expect("answers parse");
        assert!(!format!("{params:?}").contains(SECRET));
    }

    // ---- sidecars ------------------------------------------------------

    #[test]
    fn sidecars_parse_with_port_memory_and_their_own_env() {
        let launch = launch_from(&launch_answers(serde_json::json!({
            "sidecars": [{
                "name": "nats",
                "image": "public.ecr.aws/nats/nats:2.10",
                "port": "4222",
                "memory_reservation_mib": 128,
                "env": {"NATS_DEBUG": "false"},
            }],
        })));
        let sidecar = launch.sidecars.first().expect("one sidecar");
        assert_eq!(sidecar.name, "nats");
        assert_eq!(sidecar.image, "public.ecr.aws/nats/nats:2.10");
        assert_eq!(sidecar.port, Some(4222));
        assert_eq!(sidecar.memory_reservation_mib, Some(128));
        assert_eq!(
            sidecar.environment,
            [("NATS_DEBUG".to_string(), "false".to_string())]
        );
    }

    /// A sidecar sharing the app container's name makes the load-balancer
    /// binding ambiguous, so it is refused — including when the app container
    /// took its name from the answer's default rather than from the answers.
    #[test]
    fn sidecar_name_may_not_collide_with_the_app_container_or_another_sidecar() {
        let env = build_fixture_env();

        let answers = launch_answers(serde_json::json!({
            "sidecars": [{"name": "worker", "image": "nats:2"}],
        }));
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(
            matches!(&err, AwsEcsParamsError::DuplicateContainerName { name } if name == "worker"),
            "the DEFAULTED app container name must still collide, got {err:?}"
        );

        let answers = launch_answers(serde_json::json!({
            "container_name": "app",
            "sidecars": [{"name": "app", "image": "nats:2"}],
        }));
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(
            err,
            AwsEcsParamsError::DuplicateContainerName { .. }
        ));

        let answers = launch_answers(serde_json::json!({
            "sidecars": [
                {"name": "nats", "image": "nats:2"},
                {"name": "nats", "image": "nats:2"},
            ],
        }));
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(
            matches!(&err, AwsEcsParamsError::DuplicateContainerName { name } if name == "nats")
        );
    }

    #[test]
    fn sidecars_reject_missing_fields_unknown_fields_and_bad_shapes() {
        let env = build_fixture_env();
        let bad: Vec<(serde_json::Value, &str)> = vec![
            (serde_json::json!({"image": "nats:2"}), "name"),
            (serde_json::json!({"name": "nats"}), "image"),
        ];
        for (sidecar, field) in bad {
            let answers = launch_answers(serde_json::json!({ "sidecars": [sidecar] }));
            let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
            assert!(
                matches!(&err, AwsEcsParamsError::SidecarMissingField { field: f, .. } if *f == field),
                "expected missing `{field}`, got {err:?}"
            );
        }

        // Deny-by-default inside the object, matching the top-level answers loop.
        let answers = launch_answers(serde_json::json!({
            "sidecars": [{"name": "nats", "image": "nats:2", "immage": "typo"}],
        }));
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(
            matches!(&err, AwsEcsParamsError::SidecarInvalid { detail, .. }
                if detail.contains("immage")),
            "got {err:?}"
        );

        let answers = launch_answers(serde_json::json!({
            "sidecars": [{"name": "nats", "image": "nats:2", "port": 70000}],
        }));
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(
            matches!(&err, AwsEcsParamsError::SidecarInvalid { field, .. } if *field == "port"),
            "got {err:?}"
        );

        let answers = launch_answers(serde_json::json!({"sidecars": {"name": "nats"}}));
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(err, AwsEcsParamsError::SidecarsNotAnArray));
    }

    /// `container_env` / `sidecars` are launch-config fields, so supplying one
    /// alone hits the same all-or-nothing rule as `cpu` alone: the incomplete
    /// launch set is an error, never a half-config.
    #[test]
    fn container_env_alone_is_an_incomplete_launch_config() {
        let env = build_fixture_env();
        let answers = serde_json::json!({"container_env": {"RUST_LOG": "info"}});
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(
            err,
            AwsEcsParamsError::MissingLaunchField {
                field: "execution_role_arn"
            }
        ));
    }

    #[test]
    fn from_answers_parses_routing_host_and_path() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "alb_routing_host": "app.example.com",
            "alb_routing_path": "/app/*",
        });
        let params = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(
            params.routing,
            Some(ListenerRouting {
                host: Some("app.example.com".into()),
                path: Some("/app/*".into()),
            })
        );
    }

    #[test]
    fn from_answers_routing_host_or_path_alone_is_some() {
        let env = build_fixture_env();
        let host_only =
            AwsEcsParams::from_answers(&env, Some(&serde_json::json!({ "alb_routing_host": "h" })))
                .unwrap();
        assert_eq!(
            host_only.routing,
            Some(ListenerRouting {
                host: Some("h".into()),
                path: None,
            })
        );
        let path_only = AwsEcsParams::from_answers(
            &env,
            Some(&serde_json::json!({ "alb_routing_path": "/p" })),
        )
        .unwrap();
        assert_eq!(
            path_only.routing,
            Some(ListenerRouting {
                host: None,
                path: Some("/p".into()),
            })
        );
    }

    #[test]
    fn from_answers_blank_routing_is_none() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "alb_routing_host": "  ",
            "alb_routing_path": "",
        });
        let params = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(
            params.routing, None,
            "all-blank routing answers parse to None"
        );
    }

    #[test]
    fn from_answers_rejects_routing_path_without_leading_slash() {
        let env = build_fixture_env();
        let answers = serde_json::json!({ "alb_routing_path": "app/*" });
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(
            matches!(err, AwsEcsParamsError::Invalid { ref key, .. } if key == "alb_routing_path"),
            "expected Invalid for alb_routing_path, got {err:?}"
        );
    }

    /// The minimum required launch set yields the wizard's defaults for the
    /// optional fields.
    #[test]
    fn from_answers_defaults_optional_launch_fields() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "execution_role_arn": "arn:aws:iam::111122223333:role/exec",
            "subnets": "subnet-aaaa",
            "security_groups": "sg-1111",
        });
        let launch = AwsEcsParams::from_answers(&env, Some(&answers))
            .unwrap()
            .launch
            .expect("required launch set parses to Some");
        assert_eq!(launch.task_role_arn, None);
        assert!(!launch.assign_public_ip);
        assert_eq!(launch.cpu, "256");
        assert_eq!(launch.memory, "512");
        assert_eq!(launch.container_name, "worker");
        assert_eq!(launch.container_port, 8080);
    }

    /// A partial launch set (execution role without subnets) is an error, not a
    /// silent half-config.
    #[test]
    fn from_answers_rejects_partial_launch_config() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "execution_role_arn": "arn:aws:iam::111122223333:role/exec",
            "security_groups": "sg-1111",
        });
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(
            err,
            AwsEcsParamsError::MissingLaunchField { field } if field == "subnets"
        ));
    }

    /// Launch fields without the anchor execution role fail loudly.
    #[test]
    fn from_answers_rejects_launch_fields_without_execution_role() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "subnets": "subnet-aaaa",
            "security_groups": "sg-1111",
        });
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(
            err,
            AwsEcsParamsError::MissingLaunchField { field } if field == "execution_role_arn"
        ));
    }

    #[test]
    fn from_answers_rejects_out_of_range_container_port() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "execution_role_arn": "arn:aws:iam::111122223333:role/exec",
            "subnets": "subnet-aaaa",
            "security_groups": "sg-1111",
            "container_port": "70000",
        });
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(
            err,
            AwsEcsParamsError::Invalid { key, .. } if key == "container_port"
        ));
    }

    #[test]
    fn from_answers_rejects_invalid_assign_public_ip() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "execution_role_arn": "arn:aws:iam::111122223333:role/exec",
            "subnets": "subnet-aaaa",
            "security_groups": "sg-1111",
            "assign_public_ip": "yes",
        });
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(
            err,
            AwsEcsParamsError::Invalid { key, .. } if key == "assign_public_ip"
        ));
    }

    /// The pool accepts ELBv2 ARNs and ≤32-char names, and rejects a malformed
    /// entry.
    #[test]
    fn from_answers_validates_target_group_pool_entries() {
        let env = build_fixture_env();
        let arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/blue/abc123";
        let ok = serde_json::json!({ "target_group_arns": format!("{arn},green-tg") });
        let pool = AwsEcsParams::from_answers(&env, Some(&ok))
            .unwrap()
            .target_group_pool;
        assert_eq!(pool, [arn, "green-tg"]);

        // An entry that is neither an ARN nor a valid name (>32 chars) is rejected.
        let too_long = "g".repeat(33);
        let bad = serde_json::json!({ "target_group_arns": too_long });
        let err = AwsEcsParams::from_answers(&env, Some(&bad)).unwrap_err();
        assert!(matches!(
            err,
            AwsEcsParamsError::Invalid { key, .. } if key == "target_group_arns"
        ));
    }

    #[test]
    fn from_answers_treats_blank_target_group_pool_as_unset() {
        let env = build_fixture_env();
        let answers = serde_json::json!({ "target_group_arns": "  ,  " });
        let params = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap();
        assert!(
            params.target_group_pool.is_empty(),
            "a blank optional pool is unset, not an error"
        );
    }

    /// Blank optional string answers (operators are told to leave them blank,
    /// and staged answer JSON is loaded verbatim) parse to unset — not `Some("")`
    /// and not an error — so the shared parser never sends an empty value to the
    /// SDK and never breaks `--bind` (which reuses it to read `assume_role_arn`).
    #[test]
    fn from_answers_treats_blank_optional_strings_as_unset() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "assume_role_arn": "",
            "alb_listener_arn": "",
            "target_group_arns": "",
            "execution_role_arn": "arn:aws:iam::111122223333:role/exec",
            "task_role_arn": "",
            "subnets": "subnet-aaaa",
            "security_groups": "sg-1111",
        });
        let params = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(params.assume_role_arn, None);
        assert_eq!(params.listener_arn, None);
        assert!(params.target_group_pool.is_empty());
        let launch = params.launch.expect("required launch fields are present");
        assert_eq!(launch.task_role_arn, None, "a blank task role ARN is unset");
    }
}
