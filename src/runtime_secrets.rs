use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use greentic_secrets_lib::{
    DevStore, GeneratedSecretRequirement, GeneratedSecretScope, SecretsStore, TEAM_PLACEHOLDER,
    canonical_secret_name, canonical_secret_store_key, generated_scope_team, normalize_team,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zip::{ZipArchive, result::ZipError};

use crate::config::{DeployerConfig, Provider};
use crate::contract::DeployerCapability;
use crate::environment::{EnvironmentStore, LocalFsStore};
use crate::error::{DeployerError, Result};
use greentic_deploy_spec::{EnvId, Environment};

const DEV_SECRETS_PATH_ENV: &str = "GREENTIC_DEV_SECRETS_PATH";
const SECRET_ASSET_PATHS: &[&str] = &[
    "assets/secret-requirements.json",
    "assets/secret_requirements.json",
    "secret-requirements.json",
    "secret_requirements.json",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSecretRequirement {
    pub uri: String,
    pub provider_id: String,
    pub key: String,
    pub required: bool,
    pub default_value: Option<String>,
    /// Canonicalized alternate names a previously-seeded value may live under.
    /// Resolution checks these URIs too, mirroring greentic-start so a value
    /// stored under a legacy/aliased key is still found and promoted.
    pub aliases: Vec<String>,
    /// Generation policy when the secret is system-generated; `None` =
    /// operator-supplied. Carried (parsed into the shared `greentic-secrets`
    /// model) so the deployer is *aware* which secrets are system-minted — used
    /// today for a clearer missing-secret diagnostic; the active mint/promote
    /// pass is a deferred follow-up.
    pub generated: Option<GeneratedSecretRequirement>,
    pub source: PathBuf,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRuntimeSecret {
    pub requirement: RuntimeSecretRequirement,
    pub value: SecretValue,
    pub source: SecretValueSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretValueSource {
    Env { key: String },
    DevStore { path: PathBuf },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingRuntimeSecret {
    pub requirement: RuntimeSecretRequirement,
    pub checked_sources: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSecretResolution {
    pub resolved: Vec<ResolvedRuntimeSecret>,
    pub missing: Vec<MissingRuntimeSecret>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromotedRuntimeSecret {
    pub uri: String,
    pub remote_name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PromoteRuntimeSecretsReport {
    pub promoted: Vec<PromotedRuntimeSecret>,
    pub skipped: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RuntimeSecretContext {
    pub bundle_root: PathBuf,
    pub pack_paths: Vec<PathBuf>,
    pub environment: String,
    pub tenant: String,
    pub team: Option<String>,
    /// Dev-store roots beyond `bundle_root` to also search for secret values —
    /// e.g. the operator env directory (`~/.greentic/environments/<env>`) where
    /// `op messaging add` and `gtc setup` write. Cloud-apply populates this so
    /// per-endpoint webhook secrets and setup-minted generated secrets resolve;
    /// other callers leave it empty.
    pub extra_dev_store_roots: Vec<PathBuf>,
}

/// Shared cloud-apply secret inputs: resolves the bundle root + pack paths,
/// best-effort loads the operator `Environment`, and returns the resolution
/// context plus the pack-declared and per-endpoint (webhook) requirements.
/// Endpoint requirements are deduped against pack URIs HERE — the single place
/// that "pack wins on URI collision" policy lives — so the promote path and the
/// env-map both see exactly one remote name per URI. `Ok(None)` when there is
/// no bundle root to scan; callers map that to their own empty result.
struct CloudSecretInputs {
    ctx: RuntimeSecretContext,
    pack_requirements: Vec<RuntimeSecretRequirement>,
    endpoint_requirements: Vec<RuntimeSecretRequirement>,
}

fn collect_cloud_secret_inputs(config: &DeployerConfig) -> Result<Option<CloudSecretInputs>> {
    let Some(bundle_root) = config.bundle_root.clone().or_else(|| {
        config
            .pack_path
            .as_deref()
            .and_then(infer_bundle_root_from_pack_path)
    }) else {
        return Ok(None);
    };

    let mut pack_paths: Vec<PathBuf> = config.pack_path.clone().into_iter().collect();
    if let Some(provider_pack) = config.provider_pack.as_ref() {
        pack_paths.push(provider_pack.clone());
    }
    pack_paths.extend(discover_bundle_pack_paths(&bundle_root)?);
    pack_paths = dedup_paths(pack_paths);

    let loaded_env = load_environment_for_config(config)?;
    let extra_dev_store_roots = loaded_env
        .as_ref()
        .map(|(_, env_dir)| vec![env_dir.clone()])
        .unwrap_or_default();
    let ctx = RuntimeSecretContext {
        bundle_root,
        pack_paths,
        environment: config.environment.clone(),
        tenant: config.tenant.clone(),
        team: None,
        extra_dev_store_roots,
    };

    let pack_requirements = collect_requirements(&ctx)?;
    let mut endpoint_requirements = match loaded_env.as_ref() {
        Some((env, _)) => collect_endpoint_webhook_requirements(env)?,
        None => Vec::new(),
    };
    // Pack-declared requirements win on any URI collision: drop a per-endpoint
    // requirement whose URI a pack already declares so promotion and the env-map
    // never disagree on which remote name backs a URI.
    if !endpoint_requirements.is_empty() {
        let pack_uris: BTreeSet<&str> = pack_requirements.iter().map(|r| r.uri.as_str()).collect();
        endpoint_requirements.retain(|r| !pack_uris.contains(r.uri.as_str()));
    }

    Ok(Some(CloudSecretInputs {
        ctx,
        pack_requirements,
        endpoint_requirements,
    }))
}

pub async fn resolve_for_cloud_apply(
    config: &DeployerConfig,
) -> Result<Option<RuntimeSecretResolution>> {
    if !matches!(
        config.provider,
        Provider::Aws | Provider::Azure | Provider::Gcp
    ) || config.capability != DeployerCapability::Apply
        || !config.execute_local
    {
        return Ok(None);
    }
    let Some(CloudSecretInputs {
        ctx,
        mut pack_requirements,
        endpoint_requirements,
    }) = collect_cloud_secret_inputs(config)?
    else {
        return Ok(None);
    };
    // Endpoint requirements are already deduped against pack URIs, so merging is
    // a plain extend. Per-endpoint webhook secrets aren't pack-declared, so this
    // is how they get resolved from the env dev-store and promoted.
    pack_requirements.extend(endpoint_requirements);
    if pack_requirements.is_empty() {
        return Ok(None);
    }

    let resolution = resolve_runtime_secrets(&ctx, &pack_requirements).await;
    if !resolution.missing.is_empty() {
        return Err(DeployerError::Config(format_missing_runtime_secrets(
            &resolution.missing,
        )));
    }
    Ok(Some(resolution))
}

fn load_environment_for_config(config: &DeployerConfig) -> Result<Option<(Environment, PathBuf)>> {
    // Not a valid env id, or no per-user store root to look under → no
    // operator environment to enumerate; the pack-only path is unaffected.
    // A non-default `--store-root` is not visible from `DeployerConfig`, so
    // such deploys also land here (documented limitation).
    let Ok(env_id) = EnvId::try_from(config.environment.as_str()) else {
        return Ok(None);
    };
    let Some(root) = LocalFsStore::default_root() else {
        return Ok(None);
    };
    load_environment_from_store(&LocalFsStore::new(root), &env_id)
}

/// Load an environment, failing CLOSED once we know it exists: a present-but
/// unreadable `environment.json` (or an `env_dir` failure) must surface, not
/// be silently treated as "no env" — that would drop required endpoint
/// secrets from promotion with no deploy-time signal.
fn load_environment_from_store(
    store: &LocalFsStore,
    env_id: &EnvId,
) -> Result<Option<(Environment, PathBuf)>> {
    if !store
        .exists(env_id)
        .map_err(|e| DeployerError::Config(format!("environment store: {e}")))?
    {
        return Ok(None);
    }
    let env = store
        .load(env_id)
        .map_err(|e| DeployerError::Config(format!("load environment {env_id}: {e}")))?;
    let env_dir = store
        .env_dir(env_id)
        .map_err(|e| DeployerError::Config(format!("environment dir {env_id}: {e}")))?;
    Ok(Some((env, env_dir)))
}

const WEBHOOK_SECRET_KEY: &str = "webhook_secret";

/// Synthesize a runtime-secret requirement for each per-endpoint webhook secret
/// recorded on the environment. The value already lives in the env dev-store
/// (minted by `op messaging add`/`rotate`); cloud-apply must promote it so the
/// runtime — which reads it by the same `secrets://…` URI — finds it in the
/// cloud secret manager. These are never pack-declared, which is the gap this
/// closes. `provider_id` embeds the (lowercased) endpoint id so each webhook
/// promotes to a distinct cloud secret name.
fn collect_endpoint_webhook_requirements(
    env: &Environment,
) -> Result<Vec<RuntimeSecretRequirement>> {
    let mut out = Vec::new();
    for endpoint in &env.messaging_endpoints {
        let Some(secret_ref) = endpoint.webhook_secret_ref.as_ref() else {
            continue;
        };
        let uri = secret_ref
            .to_store_uri()
            .map_err(|e| {
                DeployerError::Config(format!(
                    "messaging endpoint {} webhook_secret_ref: {e}",
                    endpoint.endpoint_id
                ))
            })?
            .to_string();
        let eid_lower = endpoint.endpoint_id.to_string().to_lowercase();
        out.push(RuntimeSecretRequirement {
            uri,
            provider_id: format!("messaging-{eid_lower}"),
            key: WEBHOOK_SECRET_KEY.to_string(),
            required: true,
            default_value: None,
            aliases: Vec::new(),
            generated: None,
            source: PathBuf::from("environment.json"),
        });
    }
    Ok(out)
}

/// The cloud secret-manager resource name a requirement promotes to, scoped to
/// the active cloud provider's naming rules. `None` for non-cloud providers.
fn cloud_remote_name(
    provider: Provider,
    prefix: &str,
    requirement: &RuntimeSecretRequirement,
) -> Option<String> {
    match provider {
        Provider::Aws => Some(cloud_secret_name(
            prefix,
            &requirement.provider_id,
            &requirement.key,
        )),
        Provider::Azure => Some(flat_cloud_secret_name(
            prefix,
            &requirement.provider_id,
            &requirement.key,
            127,
        )),
        Provider::Gcp => Some(flat_cloud_secret_name(
            prefix,
            &requirement.provider_id,
            &requirement.key,
            255,
        )),
        _ => None,
    }
}

fn build_cloud_env_map(
    provider: Provider,
    prefix: &str,
    pack_requirements: &[RuntimeSecretRequirement],
    endpoint_requirements: &[RuntimeSecretRequirement],
    resolved_uris: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut env_map = BTreeMap::new();
    for requirement in pack_requirements {
        if !requirement.required && !resolved_uris.contains(&requirement.uri) {
            continue;
        }
        let Some(remote_name) = cloud_remote_name(provider, prefix, requirement) else {
            continue;
        };
        env_map.insert(requirement.uri.clone(), remote_name.clone());
        env_map.insert(requirement.key.clone(), remote_name);
    }
    // Per-endpoint webhook secrets key the env-map by URI ONLY (every
    // endpoint's `key` is the literal `webhook_secret`, so a bare-key alias
    // would collide across endpoints). The `contains_key` guard is defensive:
    // `collect_cloud_secret_inputs` already drops endpoint URIs a pack declares,
    // but keeping it makes this pure helper correct on any input (pack wins).
    for requirement in endpoint_requirements {
        if env_map.contains_key(&requirement.uri) {
            continue;
        }
        if !requirement.required && !resolved_uris.contains(&requirement.uri) {
            continue;
        }
        let Some(remote_name) = cloud_remote_name(provider, prefix, requirement) else {
            continue;
        };
        env_map.insert(requirement.uri.clone(), remote_name);
    }
    env_map
}

pub fn default_cloud_secret_prefix(environment: &str, tenant: &str, team: Option<&str>) -> String {
    let team = normalize_team(team);
    format!(
        "greentic/{environment}/{tenant}/{}",
        team.as_deref().unwrap_or(TEAM_PLACEHOLDER)
    )
}

pub fn collect_requirements(ctx: &RuntimeSecretContext) -> Result<Vec<RuntimeSecretRequirement>> {
    let mut by_uri = BTreeMap::new();
    for pack_path in &ctx.pack_paths {
        if !pack_path.exists() {
            continue;
        }
        let provider_id = provider_id_from_pack_path(pack_path);
        for req in load_secret_requirements_from_pack(pack_path)? {
            let key = canonical_secret_name(&req.key);
            let generated = req
                .generated
                .as_ref()
                .map(AssetGeneratedSecret::to_requirement);
            // A system-generated secret is minted under the team its scope
            // resolves to (`generated_scope_team`) — NOT the context team — so
            // the deployer reads/promotes it from exactly where the runtime
            // seeded it. Operator-supplied secrets stay on the context team.
            let team = match &generated {
                Some(generated) => generated_scope_team(generated, ctx.team.as_deref()),
                None => ctx.team.as_deref(),
            };
            let uri = canonical_secret_uri(&ctx.environment, &ctx.tenant, team, &provider_id, &key);
            let aliases = req
                .aliases
                .iter()
                .map(|alias| canonical_secret_name(alias))
                .collect();
            by_uri
                .entry(uri.clone())
                .or_insert(RuntimeSecretRequirement {
                    uri,
                    provider_id: provider_id.clone(),
                    key,
                    required: req.required,
                    default_value: req.default_value,
                    aliases,
                    generated,
                    source: pack_path.clone(),
                });
        }
    }
    Ok(by_uri.into_values().collect())
}

/// Secret requirements a built bundle declares, for the env-manifest
/// wizard's "ask only what's needed" secrets step.
///
/// `bundle_root` is the bundle workspace directory (the parent of the
/// `.gtbundle` artifact), where `packs/` and `providers/` live. Each pack's
/// `secret-requirements.json` is read and scoped to `environment`/`tenant`
/// (team `_`) via the same [`collect_requirements`] the cloud-apply path
/// uses — so the wizard derives exactly the paths the apply engine later
/// writes. Returns an empty vec when the bundle declares no secrets (or has
/// not been built yet — `packs/` absent).
pub fn bundle_secret_requirements(
    bundle_root: &Path,
    environment: &str,
    tenant: &str,
) -> Result<Vec<RuntimeSecretRequirement>> {
    let pack_paths = discover_bundle_pack_paths(bundle_root)?;
    let ctx = RuntimeSecretContext {
        bundle_root: bundle_root.to_path_buf(),
        pack_paths,
        environment: environment.to_string(),
        tenant: tenant.to_string(),
        team: None,
        extra_dev_store_roots: Vec::new(),
    };
    collect_requirements(&ctx)
}

/// The dev-store manifest `path` (`<tenant>/<team>/<pack>/<name>`) carried
/// by a `secrets://<environment>/...` URI — the inverse of
/// [`canonical_secret_uri`]'s prefix. `None` when `uri` is not a
/// `secrets://` URI scoped to `environment`.
pub fn manifest_secret_path(uri: &str, environment: &str) -> Option<String> {
    uri.strip_prefix(&format!("secrets://{environment}/"))
        .map(str::to_string)
}

pub fn runtime_secret_env_map_for_cloud(
    config: &DeployerConfig,
) -> Result<BTreeMap<String, String>> {
    if !matches!(
        config.provider,
        Provider::Aws | Provider::Azure | Provider::Gcp
    ) {
        return Ok(BTreeMap::new());
    }
    let Some(CloudSecretInputs {
        ctx,
        pack_requirements,
        endpoint_requirements,
    }) = collect_cloud_secret_inputs(config)?
    else {
        return Ok(BTreeMap::new());
    };
    let prefix = default_cloud_secret_prefix(&config.environment, &config.tenant, None);

    // Unify env-map generation with the resolution that the cloud-secret
    // promotion path uses. `resolve_runtime_secrets` consults env vars AND
    // every dev secrets store on disk, so optional secrets backed only by
    // the DevStore are included in the env_map (Codex review F1: previously
    // the env-only filter silently skipped DevStore-backed optionals while
    // the AWS/GCP/Azure apply paths still promoted them, producing
    // runtime auth failures because Terraform was never given the URI).
    let all_requirements: Vec<RuntimeSecretRequirement> = pack_requirements
        .iter()
        .chain(endpoint_requirements.iter())
        .cloned()
        .collect();
    let resolution = block_on_async_resolution(&ctx, &all_requirements);
    let resolved_uris: BTreeSet<String> = resolution
        .resolved
        .into_iter()
        .map(|r| r.requirement.uri)
        .collect();

    let env_map = build_cloud_env_map(
        config.provider,
        &prefix,
        &pack_requirements,
        &endpoint_requirements,
        &resolved_uris,
    );
    Ok(env_map)
}

/// Run `resolve_runtime_secrets` from a sync context, regardless of the
/// caller's runtime.
///
/// The deployer's production call chain is `run_cloud_backend` →
/// `run_backend_operation` (which builds a **current-thread** runtime via
/// `Builder::new_current_thread().block_on(apply::run)`) → several sync
/// helpers → `runtime_secret_env_map_for_cloud` → here. We therefore CANNOT
/// use `tokio::task::block_in_place` (it panics on a current-thread runtime)
/// nor `Handle::current().block_on` (re-entrant block_on on the same
/// current-thread runtime panics).
///
/// Instead, hop to a dedicated OS thread that owns its own current-thread
/// runtime. `std::thread::scope` lets the closure borrow `ctx`/`requirements`
/// without a `'static` bound; the inner runtime is fully independent of the
/// caller's, so this works whether the caller is on a current-thread runtime,
/// a multi-thread runtime, or no runtime at all.
fn block_on_async_resolution(
    ctx: &RuntimeSecretContext,
    requirements: &[RuntimeSecretRequirement],
) -> RuntimeSecretResolution {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build runtime for runtime-secret resolution")
                    .block_on(resolve_runtime_secrets(ctx, requirements))
            })
            .join()
            .expect("runtime-secret resolution thread panicked")
    })
}

pub async fn resolve_runtime_secrets(
    ctx: &RuntimeSecretContext,
    requirements: &[RuntimeSecretRequirement],
) -> RuntimeSecretResolution {
    let store_paths = dev_store_paths(&ctx.bundle_root, &ctx.extra_dev_store_roots);
    let mut resolved = Vec::new();
    let mut missing = Vec::new();

    for requirement in requirements {
        let mut checked_sources = Vec::new();
        // Candidate store URIs: the primary, then any aliases (a value seeded
        // under a legacy/aliased name still satisfies the requirement, mirroring
        // greentic-start). Alias URIs must share the primary's resolved scope:
        // a generated secret lives under `generated_scope_team`, not the context
        // team (the same derivation `collect_requirements` used for the primary).
        let team = match &requirement.generated {
            Some(generated) => generated_scope_team(generated, ctx.team.as_deref()),
            None => ctx.team.as_deref(),
        };
        let candidate_uris: Vec<String> = std::iter::once(requirement.uri.clone())
            .chain(requirement.aliases.iter().map(|alias| {
                canonical_secret_uri(
                    &ctx.environment,
                    &ctx.tenant,
                    team,
                    &requirement.provider_id,
                    alias,
                )
            }))
            .collect();

        let mut found = None;
        'candidates: for uri in &candidate_uris {
            if let Some(env_key) = canonical_secret_store_key(uri) {
                checked_sources.push(format!("env {env_key}"));
                if let Ok(value) = env::var(&env_key)
                    && !value.is_empty()
                {
                    if is_placeholder_secret_value(&value, uri) {
                        checked_sources
                            .push(format!("env {env_key} (auto-seeded placeholder, ignored)"));
                    } else {
                        found = Some((SecretValueSource::Env { key: env_key }, value));
                        break 'candidates;
                    }
                }
            }

            for path in &store_paths {
                checked_sources.push(path.display().to_string());
                if !path.exists() {
                    continue;
                }
                if let Ok(store) = DevStore::with_path(path)
                    && let Ok(bytes) = store.get(uri).await
                    && let Ok(value) = String::from_utf8(bytes)
                    && !value.is_empty()
                {
                    // `gtc setup --non-interactive` writes raw `${VAR}`
                    // placeholders into the dev secrets store. Expand them here
                    // against the process env so the promoted cloud secret
                    // carries the actual value, not the placeholder string. If
                    // the env var is unset, treat the dev-store entry as
                    // unresolved and keep looking.
                    if let Some(env_key) = extract_env_placeholder(&value) {
                        checked_sources.push(format!("env ${{{env_key}}} (from dev store)"));
                        match env::var(&env_key) {
                            Ok(expanded)
                                if !expanded.is_empty()
                                    && !is_placeholder_secret_value(&expanded, uri) =>
                            {
                                found = Some((
                                    SecretValueSource::DevStore { path: path.clone() },
                                    expanded,
                                ));
                                break 'candidates;
                            }
                            _ => continue,
                        }
                    }
                    // A `greentic-start`-seeded placeholder is not a real
                    // secret. Treat it as unresolved and keep searching: if no
                    // real value turns up, a required secret fails the deploy
                    // (it lands in `missing`); an optional one is skipped, so a
                    // value an operator pre-seeded directly in the cloud secret
                    // manager survives instead of being clobbered.
                    if is_placeholder_secret_value(&value, uri) {
                        checked_sources.push(format!(
                            "{} (auto-seeded placeholder, ignored)",
                            path.display()
                        ));
                        continue;
                    }
                    found = Some((SecretValueSource::DevStore { path: path.clone() }, value));
                    break 'candidates;
                }
            }
        }

        if let Some((source, value)) = found {
            resolved.push(ResolvedRuntimeSecret {
                requirement: requirement.clone(),
                value: SecretValue(value),
                source,
            });
        } else if requirement.required {
            missing.push(MissingRuntimeSecret {
                requirement: requirement.clone(),
                checked_sources,
            });
        }
    }

    RuntimeSecretResolution { resolved, missing }
}

pub fn format_missing_runtime_secrets(missing: &[MissingRuntimeSecret]) -> String {
    let mut out = String::from("missing required runtime secrets:\n");
    for entry in missing {
        out.push_str(&format!("  - {}\n", entry.requirement.uri));
        if entry.requirement.generated.is_some() {
            out.push_str(
                "    (system-generated — run `gtc setup` / provisioning to mint it before deploy)\n",
            );
        }
        out.push_str("    checked:\n");
        for source in &entry.checked_sources {
            out.push_str(&format!("      - {source}\n"));
        }
    }
    out
}

pub fn cloud_secret_name(prefix: &str, provider_id: &str, key: &str) -> String {
    format!(
        "{}/{}/{}",
        prefix.trim_matches('/'),
        canonical_secret_name(provider_id),
        canonical_secret_name(key)
    )
}

pub fn flat_cloud_secret_name(
    prefix: &str,
    provider_id: &str,
    key: &str,
    max_len: usize,
) -> String {
    let raw = format!("{}-{}-{}", prefix.trim_matches('/'), provider_id, key);
    let mut normalized = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        let next = match ch {
            'A'..='Z' => ch.to_ascii_lowercase(),
            'a'..='z' | '0'..='9' => ch,
            '-' => '-',
            '_' | '/' | '.' | ' ' => '-',
            _ => continue,
        };
        if next == '-' {
            if prev_dash {
                continue;
            }
            prev_dash = true;
        } else {
            prev_dash = false;
        }
        normalized.push(next);
    }
    let normalized = normalized.trim_matches('-');
    if normalized.len() <= max_len {
        return normalized.to_string();
    }

    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let digest = hex::encode(hasher.finalize());
    let suffix = format!("-{}", &digest[..12]);
    let keep = max_len.saturating_sub(suffix.len());
    format!("{}{}", normalized[..keep].trim_matches('-'), suffix)
}

/// Build a canonical runtime secret store URI
/// (`secrets://<env>/<tenant>/<team|_>/<provider>/<name>`).
///
/// Team normalization (`default`/empty → `_`) and name normalization both come
/// from `greentic-secrets` so this can never drift from the runtime reader. The
/// `provider` segment is taken verbatim — pack ids carry hyphens the runtime
/// preserves. `canonical_secret_store_key`, `canonical_secret_name`, and
/// `normalize_team`/`TEAM_PLACEHOLDER` are likewise the shared library
/// definitions (imported above).
pub fn canonical_secret_uri(
    env: &str,
    tenant: &str,
    team: Option<&str>,
    provider: &str,
    key: &str,
) -> String {
    let team = normalize_team(team);
    format!(
        "secrets://{}/{}/{}/{}/{}",
        env,
        tenant,
        team.as_deref().unwrap_or(TEAM_PLACEHOLDER),
        provider,
        canonical_secret_name(key)
    )
}

fn dev_store_paths(bundle_root: &Path, extra_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = env::var_os(DEV_SECRETS_PATH_ENV) {
        paths.push(PathBuf::from(path));
    }
    for root in std::iter::once(bundle_root).chain(extra_roots.iter().map(PathBuf::as_path)) {
        paths.push(root.join(".greentic/dev/.dev.secrets.env"));
        paths.push(root.join(".greentic/state/dev/.dev.secrets.env"));
    }

    let mut seen = BTreeSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

fn discover_bundle_pack_paths(bundle_root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_pack_paths_from_dir(&bundle_root.join("packs"), &mut out)?;
    collect_pack_paths_from_dir(&bundle_root.join("providers"), &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_pack_paths_from_dir(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("gtpack") {
            out.push(path);
            continue;
        }
        if path.is_dir() {
            if path.join("pack.yaml").exists() || path.join("manifest.cbor").exists() {
                out.push(path);
            } else {
                collect_pack_paths_from_dir(&path, out)?;
            }
        }
    }
    Ok(())
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

fn provider_id_from_pack_path(pack_path: &Path) -> String {
    pack_path
        .file_stem()
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "provider".to_string())
}

fn infer_bundle_root_from_pack_path(pack_path: &Path) -> Option<PathBuf> {
    let mut current = if pack_path.is_dir() {
        Some(pack_path)
    } else {
        pack_path.parent()
    };
    while let Some(path) = current {
        if path.file_name().and_then(|value| value.to_str()) == Some("packs") {
            return path.parent().map(Path::to_path_buf);
        }
        if path.join("bundle.yaml").exists() {
            return Some(path.to_path_buf());
        }
        current = path.parent();
    }
    None
}

fn load_secret_requirements_from_pack(pack_path: &Path) -> Result<Vec<PackSecretRequirement>> {
    if pack_path.is_dir() {
        return load_secret_requirements_from_dir(pack_path);
    }
    if !is_probably_zip(pack_path)? {
        return load_secret_requirements_from_tar(pack_path);
    }
    load_secret_requirements_from_zip(pack_path)
}

fn is_probably_zip(path: &Path) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut magic = [0_u8; 4];
    let read = file.read(&mut magic)?;
    Ok(read == magic.len() && magic == [0x50, 0x4b, 0x03, 0x04])
}

fn is_probably_tar(path: &Path) -> Result<bool> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(257))?;
    let mut magic = [0_u8; 5];
    let read = file.read(&mut magic)?;
    Ok(read == magic.len() && magic == *b"ustar")
}

fn load_secret_requirements_from_dir(pack_path: &Path) -> Result<Vec<PackSecretRequirement>> {
    let mut requirements = Vec::new();
    for asset in SECRET_ASSET_PATHS {
        let path = pack_path.join(asset);
        if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            requirements.extend(parse_requirements(&contents, &path)?);
        }
    }
    let setup_yaml = pack_path.join("assets/setup.yaml");
    if setup_yaml.exists() {
        let contents = std::fs::read_to_string(&setup_yaml)?;
        requirements.extend(parse_setup_secret_requirements(&contents, &setup_yaml)?);
    }
    Ok(dedup_requirements(requirements))
}

fn load_secret_requirements_from_zip(pack_path: &Path) -> Result<Vec<PackSecretRequirement>> {
    let file = File::open(pack_path)?;
    let mut archive = match ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(_) => return Ok(Vec::new()),
    };
    let mut requirements = Vec::new();
    for asset in SECRET_ASSET_PATHS {
        match archive.by_name(asset) {
            Ok(mut entry) => {
                let mut contents = String::new();
                entry.read_to_string(&mut contents)?;
                requirements.extend(parse_requirements(&contents, Path::new(asset))?);
            }
            Err(ZipError::FileNotFound) => continue,
            Err(err) => return Err(DeployerError::Other(err.to_string())),
        }
    }
    if let Ok(mut entry) = archive.by_name("assets/setup.yaml") {
        let mut contents = String::new();
        entry.read_to_string(&mut contents)?;
        requirements.extend(parse_setup_secret_requirements(
            &contents,
            Path::new("assets/setup.yaml"),
        )?);
    }
    Ok(dedup_requirements(requirements))
}

fn load_secret_requirements_from_tar(pack_path: &Path) -> Result<Vec<PackSecretRequirement>> {
    if !is_probably_tar(pack_path)? {
        return Ok(Vec::new());
    }
    let file = File::open(pack_path)?;
    let mut archive = tar::Archive::new(file);
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(_) => return Ok(Vec::new()),
    };
    let mut requirements = Vec::new();
    for entry in entries {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = match entry.path() {
            Ok(path) => path.into_owned(),
            Err(_) => continue,
        };
        let Some(path_str) = path.to_str() else {
            continue;
        };
        if SECRET_ASSET_PATHS.contains(&path_str) {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            requirements.extend(parse_requirements(&contents, &path)?);
        } else if path_str == "assets/setup.yaml" {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            requirements.extend(parse_setup_secret_requirements(&contents, &path)?);
        }
    }
    Ok(dedup_requirements(requirements))
}

fn parse_requirements(contents: &str, path: &Path) -> Result<Vec<PackSecretRequirement>> {
    serde_json::from_str(contents).map_err(|err| {
        DeployerError::Config(format!(
            "parse secret requirements from {}: {err}",
            path.display()
        ))
    })
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct PackSecretRequirement {
    key: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default = "default_required")]
    required: bool,
    #[serde(default)]
    default_value: Option<String>,
    #[serde(default)]
    generated: Option<AssetGeneratedSecret>,
}

/// The `generated` block of a pack `secret-requirements.json` entry — the
/// deployer's own reader for the shared generation model (Option A: parsers
/// stay per-repo). Optional fields take the same asset-path defaults
/// greentic-start applies (length 32, `base64url`, team scope) so a pack mints
/// identically wherever it's read; [`AssetGeneratedSecret::to_requirement`]
/// lifts it into the canonical [`GeneratedSecretRequirement`].
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct AssetGeneratedSecret {
    policy: Option<String>,
    length: Option<usize>,
    encoding: Option<String>,
    scope: Option<AssetGeneratedSecretScope>,
    #[serde(default)]
    regenerate_if_present: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct AssetGeneratedSecretScope {
    level: Option<String>,
    team: Option<String>,
}

impl AssetGeneratedSecret {
    fn to_requirement(&self) -> GeneratedSecretRequirement {
        GeneratedSecretRequirement {
            policy: self.policy.clone().unwrap_or_else(|| "random".to_string()),
            length: self.length.unwrap_or(32),
            encoding: self
                .encoding
                .clone()
                .unwrap_or_else(|| "base64url".to_string()),
            scope: GeneratedSecretScope {
                level: self
                    .scope
                    .as_ref()
                    .and_then(|scope| scope.level.clone())
                    .unwrap_or_else(|| "team".to_string()),
                team: self.scope.as_ref().and_then(|scope| scope.team.clone()),
            },
            regenerate_if_present: self.regenerate_if_present.unwrap_or(false),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SetupSpec {
    #[serde(default)]
    questions: Vec<SetupQuestion>,
}

#[derive(Debug, Deserialize)]
struct SetupQuestion {
    name: String,
    #[serde(default)]
    secret_key: Option<String>,
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    secret: bool,
    #[serde(default)]
    required: bool,
}

fn parse_setup_secret_requirements(
    contents: &str,
    path: &Path,
) -> Result<Vec<PackSecretRequirement>> {
    let setup: SetupSpec = serde_yaml_bw::from_str(contents).map_err(|err| {
        DeployerError::Config(format!(
            "parse setup secrets from {}: {err}",
            path.display()
        ))
    })?;
    Ok(setup
        .questions
        .into_iter()
        .filter(|question| question.secret)
        .map(|question| PackSecretRequirement {
            key: question.secret_key.unwrap_or(question.name),
            aliases: Vec::new(),
            required: question.required,
            default_value: question.default,
            generated: None,
        })
        .collect())
}

fn dedup_requirements(requirements: Vec<PackSecretRequirement>) -> Vec<PackSecretRequirement> {
    let mut by_key = BTreeMap::new();
    for requirement in requirements {
        let key = canonical_secret_name(&requirement.key);
        by_key
            .entry(key)
            .and_modify(|existing: &mut PackSecretRequirement| {
                existing.required |= requirement.required;
                if existing.default_value.is_none() {
                    existing.default_value = requirement.default_value.clone();
                }
                if existing.aliases.is_empty() {
                    existing.aliases = requirement.aliases.clone();
                }
                if existing.generated.is_none() {
                    existing.generated = requirement.generated.clone();
                }
            })
            .or_insert(requirement);
    }
    by_key.into_values().collect()
}

// Parse a whole-string `${VAR}` placeholder and return `VAR`.
// `greentic-setup` persists unresolved env-var references in the dev secrets
// store when a non-interactive run cannot prompt. Without expansion here those
// placeholders would propagate to the cloud secrets store verbatim and break
// providers that try to use the value (e.g. state-redis treating `${REDIS_URL}`
// as a connection string).
fn extract_env_placeholder(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let inner = trimmed.strip_prefix("${")?.strip_suffix('}')?;
    if inner.is_empty() || inner.contains(|c: char| c.is_whitespace() || c == '$' || c == '{') {
        return None;
    }
    Some(inner.to_string())
}

/// Whether `value` (the value resolved for `uri`) is a placeholder
/// `greentic-start` auto-seeds into the dev store for un-provisioned secrets
/// (`secrets_setup::placeholder_text_for_uri`): `ollama-placeholder` for
/// `api_key`-shaped URIs, `placeholder for <uri>` for everything else. These
/// are NOT real credentials — promoting one to a cloud secret manager would
/// both ship a non-working value AND clobber any real value an operator
/// pre-seeded there, so the cloud-apply resolver treats them as unresolved.
///
/// Both forms are matched **exactly**, never by prefix: `ollama-placeholder`
/// is a globally-unique sentinel, and `placeholder for <uri>` is compared
/// against *this* candidate's `uri` so an arbitrary operator value that merely
/// begins with `placeholder for ` is not misclassified as unresolved.
///
/// NOTE: the marker strings are duplicated from `greentic-start`
/// (`secrets_setup.rs`) and must stay in sync. A shared sentinel in the
/// foundation crate is the deeper fix (tracked with the secrets-lib scaffold
/// follow-up), out of scope for this surgical change.
fn is_placeholder_secret_value(value: &str, uri: &str) -> bool {
    let trimmed = value.trim();
    trimmed == "ollama-placeholder"
        || trimmed
            .strip_prefix("placeholder for ")
            .is_some_and(|rest| rest == uri)
}

fn default_required() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::MessagingEndpointId;

    #[test]
    fn extract_env_placeholder_matches_whole_string_dollar_brace_form() {
        assert_eq!(
            extract_env_placeholder("${REDIS_URL}").as_deref(),
            Some("REDIS_URL")
        );
        assert_eq!(
            extract_env_placeholder("${OPENAI_API_KEY}").as_deref(),
            Some("OPENAI_API_KEY")
        );
        assert_eq!(
            extract_env_placeholder("  ${PUBLIC_BASE_URL}  ").as_deref(),
            Some("PUBLIC_BASE_URL"),
            "surrounding whitespace is allowed"
        );
    }

    #[test]
    fn extract_env_placeholder_rejects_partial_or_malformed_patterns() {
        assert_eq!(extract_env_placeholder("redis://host:6379/0"), None);
        assert_eq!(extract_env_placeholder("prefix-${VAR}"), None);
        assert_eq!(extract_env_placeholder("${VAR}-suffix"), None);
        assert_eq!(extract_env_placeholder("${}"), None);
        assert_eq!(extract_env_placeholder("${VAR WITH SPACE}"), None);
        assert_eq!(extract_env_placeholder("${NESTED${INNER}}"), None);
    }

    #[test]
    fn canonical_env_key_matches_start_runtime_shape() {
        assert_eq!(
            canonical_secret_store_key("secrets://dev/demo/_/openai/api_key").as_deref(),
            Some("GREENTIC_SECRET__DEV__DEMO_____OPENAI__API_KEY")
        );
    }

    #[test]
    fn cloud_secret_name_is_stable_and_normalized() {
        assert_eq!(
            cloud_secret_name(
                "greentic/dev/demo/_",
                "messaging-telegram",
                "TELEGRAM_BOT_TOKEN"
            ),
            "greentic/dev/demo/_/messaging_telegram/telegram_bot_token"
        );
    }

    #[test]
    fn requirement_uri_preserves_pack_provider_id_hyphens() {
        let dir = tempfile::tempdir().unwrap();
        let pack_dir = dir.path().join("packs/messaging-webchat-gui/assets");
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(
            pack_dir.join("secret-requirements.json"),
            r#"[{"key":"jwt_signing_key","required":true}]"#,
        )
        .unwrap();

        let ctx = RuntimeSecretContext {
            bundle_root: dir.path().to_path_buf(),
            pack_paths: vec![dir.path().join("packs/messaging-webchat-gui")],
            environment: "dev".into(),
            tenant: "demo".into(),
            team: None,
            extra_dev_store_roots: Vec::new(),
        };

        let requirements = collect_requirements(&ctx).unwrap();
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].provider_id, "messaging-webchat-gui");
        assert_eq!(
            requirements[0].uri,
            "secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key"
        );
        assert_eq!(
            cloud_secret_name(
                "greentic/dev/demo/_",
                &requirements[0].provider_id,
                &requirements[0].key
            ),
            "greentic/dev/demo/_/messaging_webchat_gui/jwt_signing_key"
        );
    }

    #[test]
    fn bundle_secret_requirements_reads_packs_dir_scoped_to_tenant() {
        // Mirrors the env-manifest wizard: a built bundle workspace with a
        // provider pack under `packs/` whose `secret-requirements.json`
        // declares one key. The wizard derives exactly the manifest secret
        // path the apply engine later writes.
        let dir = tempfile::tempdir().unwrap();
        let pack_dir = dir.path().join("packs/messaging-telegram");
        std::fs::create_dir_all(pack_dir.join("assets")).unwrap();
        // `pack.yaml` marks the directory as a pack so `discover_bundle_pack_paths`
        // picks it up (real bundles ship `.gtpack` archives; a marked dir is the
        // lighter-weight equivalent for the test).
        std::fs::write(pack_dir.join("pack.yaml"), "id: messaging-telegram\n").unwrap();
        std::fs::write(
            pack_dir.join("assets/secret-requirements.json"),
            r#"[{"key":"TELEGRAM_BOT_TOKEN","required":true}]"#,
        )
        .unwrap();

        let reqs = bundle_secret_requirements(dir.path(), "local", "legal").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0].uri,
            "secrets://local/legal/_/messaging-telegram/telegram_bot_token"
        );
        // …and the inverse strips the env prefix back to the manifest path.
        assert_eq!(
            manifest_secret_path(&reqs[0].uri, "local").as_deref(),
            Some("legal/_/messaging-telegram/telegram_bot_token")
        );
    }

    #[test]
    fn bundle_secret_requirements_empty_when_unbuilt() {
        // No `packs/` dir (bundle not built yet) → no requirements, no error.
        let dir = tempfile::tempdir().unwrap();
        let reqs = bundle_secret_requirements(dir.path(), "local", "legal").unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn manifest_secret_path_rejects_foreign_env_or_scheme() {
        assert_eq!(
            manifest_secret_path("secrets://prod/legal/_/p/tok", "local"),
            None,
            "different env is not stripped"
        );
        assert_eq!(
            manifest_secret_path("https://example.com/x", "local"),
            None,
            "non-secrets scheme is rejected"
        );
    }

    #[test]
    fn flat_secret_name_limits_length_with_digest() {
        let name = flat_cloud_secret_name(
            "greentic/dev/demo/default",
            "very-long-provider-name",
            "THIS_IS_A_VERY_LONG_SECRET_NAME",
            40,
        );
        assert!(name.len() <= 40);
        assert!(name.starts_with("greentic-dev-demo-default"));
    }

    #[test]
    fn infers_bundle_root_from_pack_path_under_packs_dir() {
        let path = Path::new("/tmp/demo-bundle/packs/app.gtpack");
        assert_eq!(
            infer_bundle_root_from_pack_path(path).as_deref(),
            Some(Path::new("/tmp/demo-bundle"))
        );
    }

    #[test]
    fn skips_non_zip_gtpack_when_scanning_secret_requirements() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("aws.gtpack");
        std::fs::write(&pack, b"not a zip").unwrap();
        let reqs = load_secret_requirements_from_pack(&pack).unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn reads_secret_requirements_from_tar_gtpack() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("provider.gtpack");
        let file = File::create(&pack).unwrap();
        let mut builder = tar::Builder::new(file);
        let contents = br#"[{"key":"API_TOKEN","required":true}]"#;
        let mut header = tar::Header::new_gnu();
        header.set_path("assets/secret-requirements.json").unwrap();
        header.set_size(contents.len() as u64);
        header.set_cksum();
        builder
            .append(&header, contents.as_slice())
            .expect("append tar entry");
        builder.finish().unwrap();

        let reqs = load_secret_requirements_from_pack(&pack).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].key, "API_TOKEN");
    }

    #[test]
    fn reads_secret_requirements_from_setup_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("pack");
        std::fs::create_dir_all(pack.join("assets")).unwrap();
        std::fs::write(
            pack.join("assets/setup.yaml"),
            r#"
questions:
  - name: api_key
    secret: true
    required: true
  - name: display_name
    secret: false
"#,
        )
        .unwrap();

        let reqs = load_secret_requirements_from_pack(&pack).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].key, "api_key");
        assert!(reqs[0].required);
    }

    #[test]
    fn discovers_provider_pack_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("providers/messaging")).unwrap();
        std::fs::write(
            dir.path()
                .join("providers/messaging/messaging-webchat-gui.gtpack"),
            b"",
        )
        .unwrap();

        let paths = discover_bundle_pack_paths(dir.path()).unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].ends_with("messaging-webchat-gui.gtpack"));
    }

    #[tokio::test]
    async fn resolve_runtime_secrets_no_longer_falls_back_to_setup_answers() {
        // Pre-B12a, `setup-answers.json` was a secondary source when the dev
        // store missed. After B12a, the dev store is the only source — a stale
        // plaintext value at the legacy sink must NOT resolve.
        let dir = tempfile::tempdir().unwrap();
        let answers_dir = dir.path().join("state/config/demo-pack");
        std::fs::create_dir_all(&answers_dir).unwrap();
        std::fs::write(
            answers_dir.join("setup-answers.json"),
            r#"{"api_key":"STALE-PLAINTEXT-MUST-NOT-LEAK"}"#,
        )
        .unwrap();
        let ctx = RuntimeSecretContext {
            bundle_root: dir.path().to_path_buf(),
            pack_paths: Vec::new(),
            environment: "dev".into(),
            tenant: "demo".into(),
            team: None,
            extra_dev_store_roots: Vec::new(),
        };
        let requirement = RuntimeSecretRequirement {
            uri: canonical_secret_uri("dev", "demo", None, "demo_pack", "api_key"),
            provider_id: "demo_pack".into(),
            key: "api_key".into(),
            required: true,
            default_value: None,
            aliases: Vec::new(),
            generated: None,
            source: dir.path().join("packs/demo-pack.gtpack"),
        };

        let resolution = resolve_runtime_secrets(&ctx, &[requirement]).await;
        assert!(
            resolution.resolved.is_empty(),
            "no source means no resolution"
        );
        assert_eq!(resolution.missing.len(), 1);
        assert!(
            !resolution.missing[0]
                .checked_sources
                .iter()
                .any(|s| s.contains("setup-answers")),
            "setup-answers must not appear in checked_sources after B12a",
        );
    }

    fn build_skips_unresolved_optional_fixture(
        bundle_root: &Path,
    ) -> (PathBuf, std::path::PathBuf) {
        let packs_dir = bundle_root.join("packs");
        let config_dir = bundle_root.join("state/config/demo-app");
        std::fs::create_dir_all(packs_dir.join("demo-app/assets")).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            packs_dir.join("demo-app/assets/setup.yaml"),
            r#"
questions:
  - name: api_key
    secret: true
    required: false
  - name: oauth_client_secret
    secret: true
    required: false
  - name: jwt_signing_key
    secret: true
    required: true
"#,
        )
        .unwrap();
        // A stale plaintext in setup-answers.json MUST NOT make api_key
        // appear in env_map — the setup-answers fallback is gone (B12a).
        std::fs::write(
            config_dir.join("setup-answers.json"),
            r#"{"api_key":"STALE-PLAINTEXT-MUST-NOT-LEAK"}"#,
        )
        .unwrap();
        (packs_dir.clone(), packs_dir.join("demo-app"))
    }

    fn deployer_config_for_fixture(bundle_root: &Path, pack_path: PathBuf) -> DeployerConfig {
        DeployerConfig {
            capability: DeployerCapability::Apply,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "demo".into(),
            environment: "dev".into(),
            pack_path: Some(pack_path),
            bundle_root: Some(bundle_root.to_path_buf()),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: None,
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: true,
            output: crate::config::OutputFormat::Json,
            greentic: greentic_config::ConfigResolver::new()
                .load()
                .unwrap()
                .config,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: Some("file:///tmp/demo.gtbundle".into()),
            bundle_digest: Some(
                "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".into(),
            ),
            repo_registry_base: None,
            store_registry_base: None,
        }
    }

    #[test]
    fn runtime_secret_env_map_skips_unresolved_optional_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_root = dir.path();
        let (_packs_dir, pack_path) = build_skips_unresolved_optional_fixture(bundle_root);
        let config = deployer_config_for_fixture(bundle_root, pack_path);

        let env_map = runtime_secret_env_map_for_cloud(&config).unwrap();
        // Required secret is always included.
        assert!(env_map.contains_key("secrets://dev/demo/_/demo-app/jwt_signing_key"));
        // Optionals with no source in env or DevStore are skipped — the
        // stale plaintext in setup-answers.json must not contribute.
        assert!(!env_map.contains_key("secrets://dev/demo/_/demo-app/api_key"));
        assert!(!env_map.contains_key("secrets://dev/demo/_/demo-app/oauth_client_secret"));
        assert!(!env_map.contains_key("oauth_client_secret"));
    }

    fn seed_devstore_api_key(bundle_root: &Path) {
        use greentic_secrets_lib::{DevStore, SecretFormat};
        let store_path = bundle_root.join(".greentic/state/dev/.dev.secrets.env");
        std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        let store = DevStore::with_path(&store_path).unwrap();
        // Seed via an isolated current-thread runtime — no ambient runtime
        // required, matching how the production sync path reaches the store.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                store
                    .put(
                        "secrets://dev/demo/_/demo-app/api_key",
                        SecretFormat::Text,
                        b"from-dev-store",
                    )
                    .await
                    .unwrap();
            });
    }

    fn assert_devstore_optional_in_env_map(env_map: &BTreeMap<String, String>) {
        assert!(
            env_map.contains_key("secrets://dev/demo/_/demo-app/api_key"),
            "optional secret with DevStore value MUST appear in env_map: {env_map:?}",
        );
        assert!(env_map.contains_key("secrets://dev/demo/_/demo-app/jwt_signing_key"));
        // Other optional with no source stays skipped.
        assert!(!env_map.contains_key("secrets://dev/demo/_/demo-app/oauth_client_secret"));
    }

    #[test]
    fn runtime_secret_env_map_includes_optional_secrets_with_devstore_value() {
        // Codex F1 regression: an optional secret backed only by the dev
        // secrets store (no env var) MUST appear in the cloud env_map so
        // Terraform can wire it through to the runtime.
        let dir = tempfile::tempdir().unwrap();
        let bundle_root = dir.path();
        let (_packs_dir, pack_path) = build_skips_unresolved_optional_fixture(bundle_root);
        seed_devstore_api_key(bundle_root);

        let config = deployer_config_for_fixture(bundle_root, pack_path);
        let env_map = runtime_secret_env_map_for_cloud(&config).unwrap();
        assert_devstore_optional_in_env_map(&env_map);
    }

    // xhigh review C1 regression: the production cloud-deploy path runs
    // `runtime_secret_env_map_for_cloud` from *inside* a current-thread tokio
    // runtime (run_backend_operation builds `Builder::new_current_thread()`).
    // The previous `block_in_place` bridge panicked there. This test
    // reproduces that exact reentry shape and must not panic.
    #[test]
    fn runtime_secret_env_map_callable_from_within_current_thread_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_root = dir.path();
        let (_packs_dir, pack_path) = build_skips_unresolved_optional_fixture(bundle_root);
        seed_devstore_api_key(bundle_root);
        let config = deployer_config_for_fixture(bundle_root, pack_path);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let env_map = rt
            .block_on(async { runtime_secret_env_map_for_cloud(&config) })
            .unwrap();
        assert_devstore_optional_in_env_map(&env_map);
    }

    #[test]
    fn secret_value_debug_is_redacted() {
        let value = SecretValue("super-secret".to_string());
        assert_eq!(format!("{value:?}"), "<redacted>");
    }

    #[tokio::test]
    async fn resolve_runtime_secrets_honors_alias_uris() {
        // A value seeded only under an alias URI must still satisfy the
        // requirement (mirrors greentic-start's alias handling).
        let dir = tempfile::tempdir().unwrap();
        let bundle_root = dir.path();
        let store_path = bundle_root.join(".greentic/state/dev/.dev.secrets.env");
        std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        let alias_uri = canonical_secret_uri("dev", "demo", None, "demo_pack", "legacy_jwt_key");
        {
            let store = DevStore::with_path(&store_path).unwrap();
            store
                .put(
                    &alias_uri,
                    greentic_secrets_lib::SecretFormat::Text,
                    b"aliased-value",
                )
                .await
                .unwrap();
        }

        let ctx = RuntimeSecretContext {
            bundle_root: bundle_root.to_path_buf(),
            pack_paths: Vec::new(),
            environment: "dev".into(),
            tenant: "demo".into(),
            team: None,
            extra_dev_store_roots: Vec::new(),
        };
        let requirement = RuntimeSecretRequirement {
            uri: canonical_secret_uri("dev", "demo", None, "demo_pack", "jwt_signing_key"),
            provider_id: "demo_pack".into(),
            key: "jwt_signing_key".into(),
            required: true,
            default_value: None,
            aliases: vec!["legacy_jwt_key".into()],
            generated: None,
            source: bundle_root.join("packs/demo-pack.gtpack"),
        };

        let resolution = resolve_runtime_secrets(&ctx, &[requirement]).await;
        assert!(resolution.missing.is_empty(), "alias value must resolve");
        assert_eq!(resolution.resolved.len(), 1);
        assert_eq!(resolution.resolved[0].value.expose(), "aliased-value");
    }

    #[test]
    fn collect_requirements_parses_generated_and_aliases() {
        // The deployer parses the pack's `generated`/`aliases` metadata into the
        // shared `greentic-secrets` model so it is aware which secrets are
        // system-minted (Option A: reader stays here, model is shared).
        let dir = tempfile::tempdir().unwrap();
        let pack_dir = dir.path().join("packs/messaging-webex/assets");
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(
            pack_dir.join("secret-requirements.json"),
            r#"[{"key":"webex_webhook_secret","aliases":["WEBEX_WEBHOOK_SECRET"],"required":true,"generated":{"policy":"random","length":20,"encoding":"raw_text","scope":{"level":"tenant","team":"_"}}}]"#,
        )
        .unwrap();

        let ctx = RuntimeSecretContext {
            bundle_root: dir.path().to_path_buf(),
            pack_paths: vec![dir.path().join("packs/messaging-webex")],
            environment: "dev".into(),
            tenant: "demo".into(),
            team: None,
            extra_dev_store_roots: Vec::new(),
        };
        let reqs = collect_requirements(&ctx).unwrap();
        assert_eq!(reqs.len(), 1);
        let req = &reqs[0];
        assert_eq!(req.key, "webex_webhook_secret");
        // Aliases are canonicalized to match the store-key derivation.
        assert_eq!(req.aliases, vec!["webex_webhook_secret".to_string()]);
        let generated = req.generated.as_ref().expect("generated policy parsed");
        assert_eq!(generated.policy, "random");
        assert_eq!(generated.length, 20);
        assert_eq!(generated.encoding, "raw_text");
        assert_eq!(generated.scope.level, "tenant");
        assert_eq!(generated.scope.team.as_deref(), Some("_"));
    }

    #[tokio::test]
    async fn generated_secret_resolves_from_its_declared_team_scope() {
        // A generated secret explicitly scoped to a real team is minted by the
        // runtime under that team (`generated_scope_team`), not the context
        // team (`_`). The deployer must derive the SAME team for both the
        // primary URI and the alias candidate URIs, or it searches `_` and
        // misses the value — the cloud-promotion gap this consolidation closes.
        let dir = tempfile::tempdir().unwrap();
        let bundle_root = dir.path();
        let pack_dir = bundle_root.join("packs/messaging-webex/assets");
        std::fs::create_dir_all(&pack_dir).unwrap();
        std::fs::write(
            pack_dir.join("secret-requirements.json"),
            r#"[{"key":"webex_webhook_secret","aliases":["legacy_webhook"],"required":true,"generated":{"policy":"random","length":20,"encoding":"raw_text","scope":{"level":"team","team":"legal"}}}]"#,
        )
        .unwrap();

        let ctx = RuntimeSecretContext {
            bundle_root: bundle_root.to_path_buf(),
            pack_paths: vec![bundle_root.join("packs/messaging-webex")],
            environment: "dev".into(),
            tenant: "demo".into(),
            team: None,
            extra_dev_store_roots: Vec::new(),
        };
        let reqs = collect_requirements(&ctx).unwrap();
        assert_eq!(reqs.len(), 1);
        // Primary URI is scoped to the declared team `legal`, not `_`.
        assert!(
            reqs[0].uri.starts_with("secrets://dev/demo/legal/"),
            "generated secret must be team-scoped, got {}",
            reqs[0].uri,
        );

        // Seed the value under the *alias* at the same team scope; resolution
        // must find it via the team-scoped alias candidate URI.
        let alias_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("legal"),
            &reqs[0].provider_id,
            "legacy_webhook",
        );
        let store_path = bundle_root.join(".greentic/state/dev/.dev.secrets.env");
        std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        {
            let store = DevStore::with_path(&store_path).unwrap();
            store
                .put(
                    &alias_uri,
                    greentic_secrets_lib::SecretFormat::Text,
                    b"team-scoped-value",
                )
                .await
                .unwrap();
        }

        let resolution = resolve_runtime_secrets(&ctx, &reqs).await;
        assert!(
            resolution.missing.is_empty(),
            "team-scoped alias value must resolve: {:?}",
            resolution.missing,
        );
        assert_eq!(resolution.resolved.len(), 1);
        assert_eq!(resolution.resolved[0].value.expose(), "team-scoped-value");
    }

    /// A required, operator-supplied-shaped requirement — the common test shape
    /// (no default, no aliases, not generated).
    fn req(uri: &str, provider_id: &str, key: &str) -> RuntimeSecretRequirement {
        RuntimeSecretRequirement {
            uri: uri.into(),
            provider_id: provider_id.into(),
            key: key.into(),
            required: true,
            default_value: None,
            aliases: Vec::new(),
            generated: None,
            source: PathBuf::from("environment.json"),
        }
    }

    async fn seed_dev_store_value(bundle_root: &Path, uri: &str, value: &[u8]) {
        use greentic_secrets_lib::{DevStore, SecretFormat};
        let store_path = bundle_root.join(".greentic/state/dev/.dev.secrets.env");
        std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        let store = DevStore::with_path(&store_path).unwrap();
        store.put(uri, SecretFormat::Text, value).await.unwrap();
    }

    fn ctx_for(bundle_root: &Path, environment: &str, tenant: &str) -> RuntimeSecretContext {
        RuntimeSecretContext {
            bundle_root: bundle_root.to_path_buf(),
            pack_paths: Vec::new(),
            environment: environment.into(),
            tenant: tenant.into(),
            team: None,
            extra_dev_store_roots: Vec::new(),
        }
    }

    #[test]
    fn is_placeholder_secret_value_matches_only_exact_start_markers() {
        let uri = "secrets://dev/demo/_/openai/api_key";
        // `ollama-placeholder` is a global sentinel (URI-independent), trimmed.
        assert!(is_placeholder_secret_value("ollama-placeholder", uri));
        assert!(is_placeholder_secret_value("  ollama-placeholder  ", uri));
        // `placeholder for <uri>` matches ONLY for its own URI.
        assert!(is_placeholder_secret_value(
            "placeholder for secrets://dev/demo/_/openai/api_key",
            uri
        ));
        assert!(
            !is_placeholder_secret_value("placeholder for secrets://dev/demo/_/other/key", uri),
            "the templated marker must not match a different URI"
        );
        // Genuine credentials (incl. a real value that merely *starts with*
        // `placeholder for `) and the unexpanded ${VAR} form must NOT match.
        assert!(!is_placeholder_secret_value(
            "placeholder for my passphrase",
            uri
        ));
        assert!(!is_placeholder_secret_value("sk-realkey-123", uri));
        assert!(!is_placeholder_secret_value("", uri));
        assert!(!is_placeholder_secret_value("${OPENAI_API_KEY}", uri));
        assert!(!is_placeholder_secret_value("ollama", uri));
    }

    #[tokio::test]
    async fn resolve_treats_start_placeholder_as_unresolved_required_is_missing() {
        // A required secret whose only dev-store value is a greentic-start
        // placeholder must NOT resolve: the deploy fails loudly (the secret
        // lands in `missing`) instead of promoting `ollama-placeholder` to the
        // cloud secret manager.
        let dir = tempfile::tempdir().unwrap();
        let uri = "secrets://dev/demo/_/openai/api_key";
        seed_dev_store_value(dir.path(), uri, b"ollama-placeholder").await;

        let ctx = ctx_for(dir.path(), "dev", "demo");
        let resolution = resolve_runtime_secrets(&ctx, &[req(uri, "openai", "api_key")]).await;

        assert!(
            resolution.resolved.is_empty(),
            "a placeholder must not resolve"
        );
        assert_eq!(resolution.missing.len(), 1);
        assert_eq!(resolution.missing[0].requirement.uri, uri);
        assert!(
            resolution.missing[0]
                .checked_sources
                .iter()
                .any(|s| s.contains("auto-seeded placeholder")),
            "the ignored placeholder source must be recorded for the operator: {:?}",
            resolution.missing[0].checked_sources,
        );
    }

    #[tokio::test]
    async fn resolve_skips_optional_placeholder_so_cloud_value_survives() {
        // An OPTIONAL secret backed only by a placeholder is dropped (neither
        // resolved nor missing), so it is never promoted — a value an operator
        // pre-seeded directly in the cloud secret manager is left intact.
        let dir = tempfile::tempdir().unwrap();
        let uri = "secrets://dev/demo/_/openai/api_key";
        seed_dev_store_value(dir.path(), uri, b"ollama-placeholder").await;

        let ctx = ctx_for(dir.path(), "dev", "demo");
        let mut requirement = req(uri, "openai", "api_key");
        requirement.required = false;
        let resolution = resolve_runtime_secrets(&ctx, &[requirement]).await;

        assert!(resolution.resolved.is_empty());
        assert!(
            resolution.missing.is_empty(),
            "an optional placeholder is skipped, not reported missing"
        );
    }

    #[tokio::test]
    async fn resolve_ignores_uri_scoped_placeholder_for_marker() {
        // The `placeholder for <uri>` marker (start's non-api_key form) seeded
        // under its own URI is treated as unresolved.
        let dir = tempfile::tempdir().unwrap();
        let uri = "secrets://dev/demo/_/webhook/token";
        seed_dev_store_value(
            dir.path(),
            uri,
            b"placeholder for secrets://dev/demo/_/webhook/token",
        )
        .await;

        let ctx = ctx_for(dir.path(), "dev", "demo");
        let resolution = resolve_runtime_secrets(&ctx, &[req(uri, "webhook", "token")]).await;

        assert!(resolution.resolved.is_empty());
        assert_eq!(resolution.missing.len(), 1);
    }

    #[tokio::test]
    async fn resolve_keeps_real_value_that_merely_starts_with_placeholder_for() {
        // Codex F2 regression: a genuine secret value beginning with
        // "placeholder for " — but NOT equal to the exact `placeholder for
        // <uri>` marker — must still resolve. The matcher is exact, not a
        // prefix, so real operator bytes are never misclassified.
        let dir = tempfile::tempdir().unwrap();
        let uri = "secrets://dev/demo/_/app/passphrase";
        let real = b"placeholder for the vault, rotated monthly";
        seed_dev_store_value(dir.path(), uri, real).await;

        let ctx = ctx_for(dir.path(), "dev", "demo");
        let resolution = resolve_runtime_secrets(&ctx, &[req(uri, "app", "passphrase")]).await;

        assert!(resolution.missing.is_empty());
        assert_eq!(resolution.resolved.len(), 1);
        assert_eq!(
            resolution.resolved[0].value.expose(),
            "placeholder for the vault, rotated monthly"
        );
    }

    #[tokio::test]
    async fn resolve_still_accepts_a_real_value_after_placeholder_guard() {
        // Regression: the guard must not over-match a genuine credential.
        let dir = tempfile::tempdir().unwrap();
        let uri = "secrets://dev/demo/_/openai/api_key";
        seed_dev_store_value(dir.path(), uri, b"sk-realkey-123").await;

        let ctx = ctx_for(dir.path(), "dev", "demo");
        let resolution = resolve_runtime_secrets(&ctx, &[req(uri, "openai", "api_key")]).await;

        assert!(resolution.missing.is_empty());
        assert_eq!(resolution.resolved.len(), 1);
        assert_eq!(resolution.resolved[0].value.expose(), "sk-realkey-123");
    }

    fn env_with_webhook_endpoint(
        env_id: &str,
        eid: MessagingEndpointId,
        with_ref: bool,
    ) -> Environment {
        use chrono::Utc;
        use greentic_deploy_spec::{
            EnvironmentHostConfig, MessagingEndpoint, SchemaVersion, SecretRef,
        };
        let eid_lower = eid.to_string().to_lowercase();
        let webhook_secret_ref = with_ref.then(|| {
            SecretRef::try_new(format!(
                "secret://{env_id}/default/_/messaging-{eid_lower}/webhook_secret"
            ))
            .unwrap()
        });
        let endpoint = MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: EnvId::try_from(env_id).unwrap(),
            endpoint_id: eid,
            provider_id: "tg-legal".into(),
            provider_type: "telegram".into(),
            display_name: "Legal Bot".into(),
            secret_refs: Vec::new(),
            webhook_secret_ref,
            linked_bundles: Vec::new(),
            welcome_flow: None,
            generation: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            updated_by: "operator://test".into(),
        };
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: EnvId::try_from(env_id).unwrap(),
            name: env_id.into(),
            host_config: EnvironmentHostConfig::new(EnvId::try_from(env_id).unwrap()),
            packs: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            messaging_endpoints: vec![endpoint],
            extensions: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    #[test]
    fn endpoint_webhook_requirement_matches_runtime_read_uri() {
        let eid = MessagingEndpointId::new();
        let eid_lower = eid.to_string().to_lowercase();
        let env = env_with_webhook_endpoint("prod", eid, true);

        let reqs = collect_endpoint_webhook_requirements(&env).unwrap();
        assert_eq!(reqs.len(), 1);
        let req = &reqs[0];
        // Deploy==runtime alignment: the URI the deployer promotes under MUST be
        // the exact `secrets://…` URI greentic-start derives from the endpoint's
        // webhook_secret_ref (tenant `default`, team `_`, lowercased eid). Drift
        // here means the runtime can't find the secret in the cloud manager.
        assert_eq!(
            req.uri,
            format!("secrets://prod/default/_/messaging-{eid_lower}/webhook_secret")
        );
        assert_eq!(req.provider_id, format!("messaging-{eid_lower}"));
        assert_eq!(req.key, "webhook_secret");
        assert!(req.required);
        assert!(req.generated.is_none());
    }

    #[test]
    fn endpoint_without_webhook_ref_yields_no_requirement() {
        let env = env_with_webhook_endpoint("prod", MessagingEndpointId::new(), false);
        assert!(
            collect_endpoint_webhook_requirements(&env)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn dev_store_paths_includes_extra_env_roots_deduped() {
        let bundle = PathBuf::from("/bundle");
        let env_dir = PathBuf::from("/env");
        let paths = dev_store_paths(&bundle, std::slice::from_ref(&env_dir));
        assert!(paths.contains(&bundle.join(".greentic/dev/.dev.secrets.env")));
        assert!(paths.contains(&bundle.join(".greentic/state/dev/.dev.secrets.env")));
        assert!(paths.contains(&env_dir.join(".greentic/dev/.dev.secrets.env")));
        assert!(paths.contains(&env_dir.join(".greentic/state/dev/.dev.secrets.env")));

        // bundle_root == env_dir must not duplicate entries.
        let deduped = dev_store_paths(&bundle, std::slice::from_ref(&bundle));
        let unique: BTreeSet<_> = deduped.iter().cloned().collect();
        assert_eq!(deduped.len(), unique.len());
    }

    #[test]
    fn cloud_remote_name_for_webhook_is_endpoint_scoped() {
        let req = req(
            "secrets://prod/default/_/messaging-abc/webhook_secret",
            "messaging-abc",
            WEBHOOK_SECRET_KEY,
        );
        let prefix = default_cloud_secret_prefix("prod", "acme", None);
        // `cloud_secret_name` canonicalizes the provider/key segments (hyphen →
        // underscore). This is the internal cloud-SM resource name; the runtime
        // still reads by the raw `secrets://…messaging-abc…` URI (the env-map key).
        assert_eq!(
            cloud_remote_name(Provider::Aws, &prefix, &req).unwrap(),
            "greentic/prod/acme/_/messaging_abc/webhook_secret"
        );
        // Distinct endpoints → distinct cloud names (no cross-endpoint collision).
        let mut req2 = req.clone();
        req2.provider_id = "messaging-xyz".into();
        assert_ne!(
            cloud_remote_name(Provider::Aws, &prefix, &req),
            cloud_remote_name(Provider::Aws, &prefix, &req2)
        );
    }

    #[tokio::test]
    async fn resolve_finds_webhook_value_in_env_dir_dev_store() {
        // The webhook value lives in the env dev-store (where `op messaging add`
        // writes), NOT the bundle-root dev-store the pack-scan path reads.
        // resolve_runtime_secrets must consult the extra env root.
        let bundle = tempfile::tempdir().unwrap();
        let env_dir = tempfile::tempdir().unwrap();
        let uri = "secrets://prod/default/_/messaging-abc/webhook_secret";
        let store_path = env_dir.path().join(".greentic/dev/.dev.secrets.env");
        std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        {
            let store = DevStore::with_path(&store_path).unwrap();
            store
                .put(uri, greentic_secrets_lib::SecretFormat::Text, b"wh-value")
                .await
                .unwrap();
        }

        let ctx = RuntimeSecretContext {
            bundle_root: bundle.path().to_path_buf(),
            pack_paths: Vec::new(),
            environment: "prod".into(),
            tenant: "demo".into(),
            team: None,
            extra_dev_store_roots: vec![env_dir.path().to_path_buf()],
        };
        let requirement = req(uri, "messaging-abc", WEBHOOK_SECRET_KEY);
        let resolution = resolve_runtime_secrets(&ctx, std::slice::from_ref(&requirement)).await;
        assert!(resolution.missing.is_empty(), "{:?}", resolution.missing);
        assert_eq!(resolution.resolved.len(), 1);
        assert_eq!(resolution.resolved[0].value.expose(), "wh-value");
    }

    #[tokio::test]
    async fn resolve_misses_webhook_value_without_env_root() {
        // Same value present only in the env dev-store, but no extra env root →
        // the bundle-root-only search misses it. This is exactly the gap the
        // env-root wiring closes.
        let bundle = tempfile::tempdir().unwrap();
        let env_dir = tempfile::tempdir().unwrap();
        let uri = "secrets://prod/default/_/messaging-abc/webhook_secret";
        let store_path = env_dir.path().join(".greentic/dev/.dev.secrets.env");
        std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        {
            let store = DevStore::with_path(&store_path).unwrap();
            store
                .put(uri, greentic_secrets_lib::SecretFormat::Text, b"wh-value")
                .await
                .unwrap();
        }
        let ctx = RuntimeSecretContext {
            bundle_root: bundle.path().to_path_buf(),
            pack_paths: Vec::new(),
            environment: "prod".into(),
            tenant: "demo".into(),
            team: None,
            extra_dev_store_roots: Vec::new(),
        };
        let requirement = req(uri, "messaging-abc", WEBHOOK_SECRET_KEY);
        let resolution = resolve_runtime_secrets(&ctx, std::slice::from_ref(&requirement)).await;
        assert_eq!(resolution.missing.len(), 1);
    }

    #[test]
    fn load_environment_from_store_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env_id = EnvId::try_from("prod").unwrap();
        assert!(
            load_environment_from_store(&store, &env_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn load_environment_from_store_fails_closed_on_corrupt_env() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env_id = EnvId::try_from("prod").unwrap();
        let env_path = dir.path().join("prod/environment.json");
        std::fs::create_dir_all(env_path.parent().unwrap()).unwrap();
        std::fs::write(&env_path, b"{ not valid json").unwrap();
        assert!(load_environment_from_store(&store, &env_id).is_err());
    }

    #[test]
    fn build_cloud_env_map_pack_wins_on_uri_collision() {
        let uri = "secrets://prod/default/_/messaging-abc/webhook_secret".to_string();
        let pack = req(&uri, "packprov", "api_key");
        let ep_collide = req(&uri, "messaging-abc", WEBHOOK_SECRET_KEY);
        let ep_other = req(
            "secrets://prod/default/_/messaging-xyz/webhook_secret",
            "messaging-xyz",
            WEBHOOK_SECRET_KEY,
        );
        let resolved: BTreeSet<String> = [
            uri.clone(),
            "secrets://prod/default/_/messaging-xyz/webhook_secret".to_string(),
        ]
        .into_iter()
        .collect();
        let prefix = default_cloud_secret_prefix("prod", "acme", None);
        let map = build_cloud_env_map(
            Provider::Aws,
            &prefix,
            std::slice::from_ref(&pack),
            &[ep_collide, ep_other],
            &resolved,
        );
        // Collision URI keeps the PACK remote name (built from packprov/api_key),
        // not the endpoint's.
        assert_eq!(
            map.get(&uri).unwrap(),
            &cloud_remote_name(Provider::Aws, &prefix, &pack).unwrap()
        );
        assert!(map.contains_key("secrets://prod/default/_/messaging-xyz/webhook_secret"));
    }
}
