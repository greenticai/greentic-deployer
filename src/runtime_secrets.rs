use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use greentic_secrets_lib::{DevStore, SecretsStore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zip::{ZipArchive, result::ZipError};

use crate::config::{DeployerConfig, Provider};
use crate::contract::DeployerCapability;
use crate::error::{DeployerError, Result};

const DEV_SECRETS_PATH_ENV: &str = "GREENTIC_DEV_SECRETS_PATH";
const TEAM_DEFAULT: &str = "_";
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
    pub source: PathBuf,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn expose(&self) -> &str {
        &self.0
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
    let Some(bundle_root) = config
        .bundle_root
        .clone()
        .or_else(|| infer_bundle_root_from_pack_path(&config.pack_path))
    else {
        return Ok(None);
    };

    let mut pack_paths = vec![config.pack_path.clone()];
    if let Some(provider_pack) = config.provider_pack.as_ref() {
        pack_paths.push(provider_pack.clone());
    }
    pack_paths.extend(discover_bundle_pack_paths(&bundle_root)?);
    pack_paths = dedup_paths(pack_paths);

    let ctx = RuntimeSecretContext {
        bundle_root,
        pack_paths,
        environment: config.environment.clone(),
        tenant: config.tenant.clone(),
        team: None,
    };
    let requirements = collect_requirements(&ctx)?;
    if requirements.is_empty() {
        return Ok(None);
    }

    let resolution = resolve_runtime_secrets(&ctx, &requirements).await;
    if !resolution.missing.is_empty() {
        return Err(DeployerError::Config(format_missing_runtime_secrets(
            &resolution.missing,
        )));
    }
    Ok(Some(resolution))
}

pub fn default_cloud_secret_prefix(environment: &str, tenant: &str, team: Option<&str>) -> String {
    let team = canonical_team(team);
    format!("greentic/{environment}/{tenant}/{team}")
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
            let uri = canonical_secret_uri(
                &ctx.environment,
                &ctx.tenant,
                ctx.team.as_deref(),
                &provider_id,
                &key,
            );
            by_uri
                .entry(uri.clone())
                .or_insert(RuntimeSecretRequirement {
                    uri,
                    provider_id: provider_id.clone(),
                    key,
                    required: req.required,
                    source: pack_path.clone(),
                });
        }
    }
    Ok(by_uri.into_values().collect())
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
    let Some(bundle_root) = config
        .bundle_root
        .clone()
        .or_else(|| infer_bundle_root_from_pack_path(&config.pack_path))
    else {
        return Ok(BTreeMap::new());
    };

    let mut pack_paths = vec![config.pack_path.clone()];
    if let Some(provider_pack) = config.provider_pack.as_ref() {
        pack_paths.push(provider_pack.clone());
    }
    pack_paths.extend(discover_bundle_pack_paths(&bundle_root)?);
    pack_paths = dedup_paths(pack_paths);

    let ctx = RuntimeSecretContext {
        bundle_root,
        pack_paths,
        environment: config.environment.clone(),
        tenant: config.tenant.clone(),
        team: None,
    };
    let prefix = default_cloud_secret_prefix(&config.environment, &config.tenant, None);
    let requirements = collect_requirements(&ctx)?;

    // Unify env-map generation with the resolution that the cloud-secret
    // promotion path uses. `resolve_runtime_secrets` consults env vars AND
    // every dev secrets store on disk, so optional secrets backed only by
    // the DevStore are included in the env_map (Codex review F1: previously
    // the env-only filter silently skipped DevStore-backed optionals while
    // the AWS/GCP/Azure apply paths still promoted them, producing
    // runtime auth failures because Terraform was never given the URI).
    let resolution = block_on_async_resolution(&ctx, &requirements);
    let resolved_uris: BTreeSet<String> = resolution
        .resolved
        .into_iter()
        .map(|r| r.requirement.uri)
        .collect();

    let mut env_map = BTreeMap::new();
    for requirement in requirements {
        if !requirement.required && !resolved_uris.contains(&requirement.uri) {
            continue;
        }
        let remote_name = match config.provider {
            Provider::Aws => cloud_secret_name(&prefix, &requirement.provider_id, &requirement.key),
            Provider::Azure => {
                flat_cloud_secret_name(&prefix, &requirement.provider_id, &requirement.key, 127)
            }
            Provider::Gcp => {
                flat_cloud_secret_name(&prefix, &requirement.provider_id, &requirement.key, 255)
            }
            _ => continue,
        };
        env_map.insert(requirement.uri, remote_name);
    }
    Ok(env_map)
}

/// Run `resolve_runtime_secrets` from inside a sync context. The deployer's
/// call chain (`apply::run` → … → `runtime_secret_env_map_for_cloud`) starts
/// async at the top, then hops through several sync helpers before reaching
/// this function. `block_in_place` + `Handle::current().block_on` keeps the
/// async tree intact without spawning a nested runtime (which would panic
/// inside an existing one). When no runtime is current (e.g. unit tests
/// constructed without `#[tokio::test]`), fall back to a fresh
/// single-threaded runtime so the function is callable from any context.
fn block_on_async_resolution(
    ctx: &RuntimeSecretContext,
    requirements: &[RuntimeSecretRequirement],
) -> RuntimeSecretResolution {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| {
            handle.block_on(resolve_runtime_secrets(ctx, requirements))
        }),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create ephemeral tokio runtime for runtime-secret resolution")
            .block_on(resolve_runtime_secrets(ctx, requirements)),
    }
}

pub async fn resolve_runtime_secrets(
    ctx: &RuntimeSecretContext,
    requirements: &[RuntimeSecretRequirement],
) -> RuntimeSecretResolution {
    let store_paths = dev_store_paths(&ctx.bundle_root);
    let mut resolved = Vec::new();
    let mut missing = Vec::new();

    for requirement in requirements {
        let mut checked_sources = Vec::new();
        if let Some(env_key) = canonical_secret_store_key(&requirement.uri) {
            checked_sources.push(format!("env {env_key}"));
            if let Ok(value) = env::var(&env_key)
                && !value.is_empty()
            {
                resolved.push(ResolvedRuntimeSecret {
                    requirement: requirement.clone(),
                    value: SecretValue(value),
                    source: SecretValueSource::Env { key: env_key },
                });
                continue;
            }
        }

        let mut found = None;
        for path in &store_paths {
            checked_sources.push(path.display().to_string());
            if !path.exists() {
                continue;
            }
            if let Ok(store) = DevStore::with_path(path)
                && let Ok(bytes) = store.get(&requirement.uri).await
                && let Ok(value) = String::from_utf8(bytes)
                && !value.is_empty()
            {
                // `gtc setup --non-interactive` writes raw `${VAR}` placeholders
                // into the dev secrets store. Expand them here against the
                // process env so the promoted cloud secret carries the actual
                // value, not the placeholder string. If the env var is unset,
                // treat the dev-store entry as unresolved and mark the
                // requirement missing.
                if let Some(env_key) = extract_env_placeholder(&value) {
                    checked_sources.push(format!("env ${{{env_key}}} (from dev store)"));
                    match env::var(&env_key) {
                        Ok(resolved) if !resolved.is_empty() => {
                            found = Some((path.clone(), resolved));
                            break;
                        }
                        _ => continue,
                    }
                }
                found = Some((path.clone(), value));
                break;
            }
        }

        if let Some((path, value)) = found {
            resolved.push(ResolvedRuntimeSecret {
                requirement: requirement.clone(),
                value: SecretValue(value),
                source: SecretValueSource::DevStore { path },
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

pub fn canonical_secret_uri(
    env: &str,
    tenant: &str,
    team: Option<&str>,
    provider: &str,
    key: &str,
) -> String {
    format!(
        "secrets://{}/{}/{}/{}/{}",
        env,
        tenant,
        canonical_team(team),
        provider,
        canonical_secret_name(key)
    )
}

pub fn canonical_secret_store_key(uri: &str) -> Option<String> {
    let trimmed = uri.strip_prefix("secrets://")?;
    let segments: Vec<&str> = trimmed.split('/').collect();
    if segments.len() != 5 {
        return None;
    }
    let mut parts = vec!["GREENTIC_SECRET".to_string()];
    parts.extend(segments.into_iter().map(normalize_store_segment));
    Some(parts.join("__"))
}

pub fn canonical_secret_name(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let mut prev_underscore = false;

    for ch in raw.chars() {
        let Some(normalized) = normalize_secret_char(ch) else {
            continue;
        };
        if normalized == '_' {
            if prev_underscore {
                continue;
            }
            prev_underscore = true;
        } else {
            prev_underscore = false;
        }
        result.push(normalized);
    }

    let trimmed = result.trim_matches('_');
    if trimmed.is_empty() {
        "secret".to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_secret_char(ch: char) -> Option<char> {
    match ch {
        'A'..='Z' => Some(ch.to_ascii_lowercase()),
        'a'..='z' | '0'..='9' | '_' => Some(ch),
        '-' | '.' | ' ' | '/' => Some('_'),
        _ => None,
    }
}

fn normalize_store_segment(segment: &str) -> String {
    segment
        .chars()
        .map(|ch| match ch {
            'A'..='Z' | '0'..='9' => ch,
            'a'..='z' => ch.to_ascii_uppercase(),
            '_' => '_',
            _ => '_',
        })
        .collect()
}

fn canonical_team(team: Option<&str>) -> &str {
    match team
        .map(str::trim)
        .filter(|team| !team.is_empty() && !team.eq_ignore_ascii_case("default"))
    {
        Some(team) => team,
        None => TEAM_DEFAULT,
    }
}

fn dev_store_paths(bundle_root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = env::var_os(DEV_SECRETS_PATH_ENV) {
        paths.push(PathBuf::from(path));
    }
    paths.push(bundle_root.join(".greentic/dev/.dev.secrets.env"));
    paths.push(bundle_root.join(".greentic/state/dev/.dev.secrets.env"));

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
    #[serde(default = "default_required")]
    required: bool,
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
            required: question.required,
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

fn default_required() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let requirement = RuntimeSecretRequirement {
            uri: canonical_secret_uri("dev", "demo", None, "demo_pack", "api_key"),
            provider_id: "demo_pack".into(),
            key: "api_key".into(),
            required: true,
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
            pack_path,
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
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_secret_env_map_includes_optional_secrets_with_devstore_value() {
        // Codex F1 regression: an optional secret backed only by the dev
        // secrets store (no env var) MUST appear in the cloud env_map so
        // Terraform can wire it through to the runtime. Pre-fix, the env-only
        // filter silently skipped these, leaving the workload with no
        // configured URI even though `resolve_runtime_secrets` (used by the
        // promotion path) found and uploaded the value.
        use greentic_secrets_lib::{DevStore, SecretFormat};

        let dir = tempfile::tempdir().unwrap();
        let bundle_root = dir.path();
        let (_packs_dir, pack_path) = build_skips_unresolved_optional_fixture(bundle_root);

        // Seed the DevStore with a value for the optional `api_key`.
        let store_path = bundle_root.join(".greentic/state/dev/.dev.secrets.env");
        std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        let store = DevStore::with_path(&store_path).unwrap();
        store
            .put(
                "secrets://dev/demo/_/demo-app/api_key",
                SecretFormat::Text,
                b"from-dev-store",
            )
            .await
            .unwrap();

        let config = deployer_config_for_fixture(bundle_root, pack_path);
        let env_map =
            tokio::task::spawn_blocking(move || runtime_secret_env_map_for_cloud(&config))
                .await
                .unwrap()
                .unwrap();

        assert!(
            env_map.contains_key("secrets://dev/demo/_/demo-app/api_key"),
            "optional secret with DevStore value MUST appear in env_map: {env_map:?}",
        );
        assert!(env_map.contains_key("secrets://dev/demo/_/demo-app/jwt_signing_key"));
        // Other optional with no source stays skipped.
        assert!(!env_map.contains_key("secrets://dev/demo/_/demo-app/oauth_client_secret"));
    }

    #[test]
    fn secret_value_debug_is_redacted() {
        let value = SecretValue("super-secret".to_string());
        assert_eq!(format!("{value:?}"), "<redacted>");
    }
}
