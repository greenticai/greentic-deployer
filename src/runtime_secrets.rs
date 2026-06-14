use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use greentic_secrets_lib::{DevStore, SecretsStore};
use greentic_types::{ExtensionInline, decode_pack_manifest};
use rand::RngExt as _;
use serde::Deserialize;
use serde_cbor::value::Value as CborValue;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use zip::{ZipArchive, result::ZipError};

use crate::config::{DeployerConfig, Provider};
use crate::contract::DeployerCapability;
use crate::error::{DeployerError, Result};

const DEV_SECRETS_PATH_ENV: &str = "GREENTIC_DEV_SECRETS_PATH";
const TEAM_DEFAULT: &str = "_";
const EXT_GENERATED_SECRETS_V1: &str = "greentic.generated-secrets.v1";
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
    pub generated: Option<GeneratedSecretRequirement>,
    pub source: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedSecretRequirement {
    pub policy: String,
    pub length: usize,
    pub encoding: String,
    pub scope: GeneratedSecretScope,
    pub regenerate_if_present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedSecretScope {
    pub level: String,
    pub team: Option<String>,
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
    SetupAnswers { path: PathBuf },
    SetupDefault,
    Generated,
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

    let pack_paths = pack_paths_for_cloud_apply(config, &bundle_root)?;

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
                requirement_team(req.generated.as_ref(), ctx.team.as_deref()),
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
                    default_value: req.default_value,
                    generated: req.generated,
                    source: pack_path.clone(),
                });
        }
    }
    Ok(by_uri.into_values().collect())
}

fn pack_paths_for_cloud_apply(config: &DeployerConfig, bundle_root: &Path) -> Result<Vec<PathBuf>> {
    let mut pack_paths = vec![config.pack_path.clone()];
    if let Some(provider_pack) = config.provider_pack.as_ref() {
        pack_paths.push(provider_pack.clone());
    }
    pack_paths.extend(
        discover_bundle_pack_paths(bundle_root)?
            .into_iter()
            .filter(|path| include_pack_for_cloud_provider(config.provider, bundle_root, path)),
    );
    Ok(dedup_paths(pack_paths))
}

fn include_pack_for_cloud_provider(
    provider: Provider,
    bundle_root: &Path,
    pack_path: &Path,
) -> bool {
    let Ok(relative) = pack_path.strip_prefix(bundle_root) else {
        return true;
    };
    let mut components = relative.components();
    let Some(std::path::Component::Normal(first)) = components.next() else {
        return true;
    };
    let Some(std::path::Component::Normal(second)) = components.next() else {
        return true;
    };
    if first != "providers" || second != "secrets" {
        return true;
    }
    let Some(active_stem) = active_secrets_provider_pack_stem(provider) else {
        return false;
    };
    provider_id_from_pack_path(pack_path) == active_stem
}

fn active_secrets_provider_pack_stem(provider: Provider) -> Option<&'static str> {
    match provider {
        Provider::Aws => Some("aws-sm"),
        Provider::Gcp => Some("gcp-sm"),
        Provider::Azure => Some("azure-kv"),
        _ => None,
    }
}

pub fn runtime_secret_env_map_for_cloud(
    _config: &DeployerConfig,
) -> Result<BTreeMap<String, String>> {
    // Cloud runtimes now receive `state/config/platform/secrets-provider.json`.
    // Runtime secrets are still resolved and promoted before apply, but they
    // must not be exposed as `GREENTIC_SECRET__...` environment variables.
    Ok(BTreeMap::new())
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
                // into the dev secrets store too — not just into setup-answers.
                // Expand them here against the process env so the promoted
                // cloud secret carries the actual value, not the placeholder
                // string. If the env var is unset, treat the dev-store entry
                // as unresolved and fall back to setup-answers (where the same
                // expansion runs as a second chance) before marking missing.
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
        } else if let Some((path, value)) =
            resolve_from_setup_answers(&ctx.bundle_root, requirement, &mut checked_sources)
        {
            resolved.push(ResolvedRuntimeSecret {
                requirement: requirement.clone(),
                value: SecretValue(value),
                source: SecretValueSource::SetupAnswers { path },
            });
        } else if let Some(value) = requirement
            .default_value
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            checked_sources.push("assets/setup.yaml default".to_string());
            resolved.push(ResolvedRuntimeSecret {
                requirement: requirement.clone(),
                value: SecretValue(value.clone()),
                source: SecretValueSource::SetupDefault,
            });
        } else if let Some(generated) = &requirement.generated {
            checked_sources.push("generated secret metadata".to_string());
            match generated_secret_value(generated) {
                Ok(value) => resolved.push(ResolvedRuntimeSecret {
                    requirement: requirement.clone(),
                    value: SecretValue(value),
                    source: SecretValueSource::Generated,
                }),
                Err(err) if requirement.required => {
                    checked_sources.push(format!("generation failed: {err}"));
                    tracing::warn!(
                        secret_uri = %requirement.uri,
                        secret_key = %requirement.key,
                        "required runtime secret could not be generated"
                    );
                    missing.push(MissingRuntimeSecret {
                        requirement: requirement.clone(),
                        checked_sources,
                    });
                }
                Err(_) => {}
            }
        } else if requirement.required {
            tracing::warn!(
                secret_uri = %requirement.uri,
                secret_key = %requirement.key,
                checked_sources = ?checked_sources,
                "required runtime secret is not available"
            );
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

fn requirement_team<'a>(
    generated: Option<&'a GeneratedSecretRequirement>,
    default_team: Option<&'a str>,
) -> Option<&'a str> {
    let Some(generated) = generated else {
        return default_team;
    };
    if generated.scope.level.eq_ignore_ascii_case("tenant")
        || generated.scope.team.as_deref() == Some("_")
    {
        return None;
    }
    generated.scope.team.as_deref().or(default_team)
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

fn config_id_from_pack_path(pack_path: &Path) -> Option<String> {
    pack_path
        .file_stem()
        .and_then(|value| value.to_str())
        .map(ToOwned::to_owned)
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
    let mut requirements = load_generated_requirements_from_dir(pack_path)?;
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
    let mut requirements = load_generated_requirements_from_zip(&mut archive)?;
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
        } else if path_str == "manifest.cbor" {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            requirements.extend(load_generated_requirements_from_manifest_cbor_bytes(
                &bytes,
            )?);
        } else if path_str == "pack.manifest.json" {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            requirements.extend(load_generated_requirements_from_manifest_json_str(
                &contents,
            )?);
        }
    }
    Ok(dedup_requirements(requirements))
}

fn parse_requirements(contents: &str, path: &Path) -> Result<Vec<PackSecretRequirement>> {
    let path_display = path.display().to_string();
    let requirements: Vec<AssetSecretRequirement> =
        serde_json::from_str(contents).map_err(|err| {
            DeployerError::Config(format!(
                "parse secret requirements from {path_display}: {err}"
            ))
        })?;
    Ok(requirements
        .into_iter()
        .filter_map(asset_requirement_to_pack_requirement)
        .collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PackSecretRequirement {
    key: String,
    required: bool,
    default_value: Option<String>,
    generated: Option<GeneratedSecretRequirement>,
}

#[derive(Debug, Deserialize)]
struct AssetSecretRequirement {
    key: Option<String>,
    name: Option<String>,
    #[serde(default = "default_required")]
    required: bool,
    #[serde(default)]
    default_value: Option<String>,
    #[serde(default)]
    generated: Option<AssetGeneratedSecret>,
}

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

#[derive(Debug, Deserialize)]
struct GeneratedSecretsExtension {
    #[serde(default)]
    secrets: Vec<GeneratedSecretEntry>,
}

#[derive(Debug, Deserialize)]
struct GeneratedSecretEntry {
    key: String,
    #[serde(default = "default_required")]
    required: bool,
    policy: Option<String>,
    length: Option<usize>,
    encoding: Option<String>,
    scope: Option<AssetGeneratedSecretScope>,
    #[serde(default)]
    regenerate_if_present: Option<bool>,
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
    let path_display = path.display().to_string();
    let setup: SetupSpec = serde_yaml_bw::from_str(contents).map_err(|err| {
        DeployerError::Config(format!("parse setup secrets from {path_display}: {err}"))
    })?;
    Ok(setup
        .questions
        .into_iter()
        .filter(|question| question.secret)
        .map(|question| PackSecretRequirement {
            key: question.secret_key.unwrap_or(question.name),
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
                if existing.generated.is_none() {
                    existing.generated = requirement.generated.clone();
                }
            })
            .or_insert(requirement);
    }
    by_key.into_values().collect()
}

fn asset_requirement_to_pack_requirement(
    req: AssetSecretRequirement,
) -> Option<PackSecretRequirement> {
    let key = req.key.or(req.name)?;
    Some(PackSecretRequirement {
        key,
        required: req.required,
        default_value: req.default_value,
        generated: req.generated.map(|generated| GeneratedSecretRequirement {
            policy: generated.policy.unwrap_or_else(|| "random".to_string()),
            length: generated.length.unwrap_or(32),
            encoding: generated
                .encoding
                .unwrap_or_else(|| "base64url".to_string()),
            scope: GeneratedSecretScope {
                level: generated
                    .scope
                    .as_ref()
                    .and_then(|scope| scope.level.clone())
                    .unwrap_or_else(|| "team".to_string()),
                team: generated.scope.and_then(|scope| scope.team),
            },
            regenerate_if_present: generated.regenerate_if_present.unwrap_or(false),
        }),
    })
}

fn load_generated_requirements_from_dir(pack_path: &Path) -> Result<Vec<PackSecretRequirement>> {
    let manifest_cbor = pack_path.join("manifest.cbor");
    if manifest_cbor.exists() {
        let bytes = std::fs::read(&manifest_cbor)?;
        let requirements = load_generated_requirements_from_manifest_cbor_bytes(&bytes)?;
        if !requirements.is_empty() {
            return Ok(requirements);
        }
    }
    let manifest_json = pack_path.join("pack.manifest.json");
    if manifest_json.exists() {
        let contents = std::fs::read_to_string(&manifest_json)?;
        return load_generated_requirements_from_manifest_json_str(&contents);
    }
    Ok(Vec::new())
}

fn load_generated_requirements_from_zip<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<Vec<PackSecretRequirement>> {
    match archive.by_name("manifest.cbor") {
        Ok(mut entry) => {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let requirements = load_generated_requirements_from_manifest_cbor_bytes(&bytes)?;
            if !requirements.is_empty() {
                return Ok(requirements);
            }
        }
        Err(ZipError::FileNotFound) => {}
        Err(err) => return Err(DeployerError::Other(err.to_string())),
    }
    match archive.by_name("pack.manifest.json") {
        Ok(mut entry) => {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            load_generated_requirements_from_manifest_json_str(&contents)
        }
        Err(ZipError::FileNotFound) => Ok(Vec::new()),
        Err(err) => Err(DeployerError::Other(err.to_string())),
    }
}

fn load_generated_requirements_from_manifest_cbor_bytes(
    bytes: &[u8],
) -> Result<Vec<PackSecretRequirement>> {
    if let Ok(manifest) = decode_pack_manifest(bytes) {
        let Some(value) = manifest
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.get(EXT_GENERATED_SECRETS_V1))
            .and_then(|extension| extension.inline.as_ref())
        else {
            return Ok(Vec::new());
        };
        let ExtensionInline::Other(value) = value else {
            return Ok(Vec::new());
        };
        return parse_generated_secrets_extension(value.clone());
    }

    let Ok(value) = serde_cbor::from_slice::<CborValue>(bytes) else {
        return Ok(Vec::new());
    };
    let Some(inline) = cbor_generated_extension_inline(&value) else {
        return Ok(Vec::new());
    };
    let json = cbor_to_json(inline)?;
    parse_generated_secrets_extension(json)
}

fn load_generated_requirements_from_manifest_json_str(
    contents: &str,
) -> Result<Vec<PackSecretRequirement>> {
    let manifest: serde_json::Value = serde_json::from_str(contents).map_err(|err| {
        DeployerError::Config(format!("parse pack.manifest.json generated secrets: {err}"))
    })?;
    let Some(value) = manifest
        .get("extensions")
        .and_then(|extensions| extensions.get(EXT_GENERATED_SECRETS_V1))
        .and_then(|extension| extension.get("inline"))
    else {
        return Ok(Vec::new());
    };
    parse_generated_secrets_extension(value.clone())
}

fn parse_generated_secrets_extension(
    value: serde_json::Value,
) -> Result<Vec<PackSecretRequirement>> {
    let extension: GeneratedSecretsExtension = serde_json::from_value(value).map_err(|err| {
        DeployerError::Config(format!("parse generated secrets extension: {err}"))
    })?;
    Ok(extension
        .secrets
        .into_iter()
        .filter(|secret| secret.required)
        .map(|secret| PackSecretRequirement {
            key: secret.key,
            required: true,
            default_value: None,
            generated: Some(GeneratedSecretRequirement {
                policy: secret.policy.unwrap_or_else(|| "random".to_string()),
                length: secret.length.unwrap_or(20),
                encoding: secret.encoding.unwrap_or_else(|| "raw_text".to_string()),
                scope: GeneratedSecretScope {
                    level: secret
                        .scope
                        .as_ref()
                        .and_then(|scope| scope.level.clone())
                        .unwrap_or_else(|| "tenant".to_string()),
                    team: secret.scope.and_then(|scope| scope.team),
                },
                regenerate_if_present: secret.regenerate_if_present.unwrap_or(false),
            }),
        })
        .collect())
}

fn cbor_generated_extension_inline(value: &CborValue) -> Option<&CborValue> {
    let CborValue::Map(map) = value else {
        return None;
    };
    let extensions = cbor_map_get(map, "extensions")?;
    let CborValue::Map(extensions) = extensions else {
        return None;
    };
    let extension = cbor_map_get(extensions, EXT_GENERATED_SECRETS_V1)?;
    let CborValue::Map(extension) = extension else {
        return None;
    };
    cbor_map_get(extension, "inline")
}

fn cbor_map_get<'a>(map: &'a BTreeMap<CborValue, CborValue>, key: &str) -> Option<&'a CborValue> {
    map.iter().find_map(|(candidate, value)| match candidate {
        CborValue::Text(text) if text == key => Some(value),
        _ => None,
    })
}

fn cbor_to_json(value: &CborValue) -> Result<serde_json::Value> {
    match value {
        CborValue::Null => Ok(serde_json::Value::Null),
        CborValue::Bool(value) => Ok(serde_json::Value::Bool(*value)),
        CborValue::Integer(value) => Ok(serde_json::Value::Number(
            serde_json::Number::from_i128(*value).ok_or_else(|| {
                DeployerError::Config("generated secrets integer is out of range".to_string())
            })?,
        )),
        CborValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| DeployerError::Config("generated secrets float is invalid".to_string())),
        CborValue::Bytes(_) => Err(DeployerError::Config(
            "generated secrets extension cannot contain bytes".to_string(),
        )),
        CborValue::Text(value) => Ok(serde_json::Value::String(value.clone())),
        CborValue::Array(values) => values
            .iter()
            .map(cbor_to_json)
            .collect::<Result<Vec<_>>>()
            .map(serde_json::Value::Array),
        CborValue::Map(map) => {
            let mut object = serde_json::Map::new();
            for (key, value) in map {
                let CborValue::Text(key) = key else {
                    return Err(DeployerError::Config(
                        "generated secrets extension object key must be a string".to_string(),
                    ));
                };
                object.insert(key.clone(), cbor_to_json(value)?);
            }
            Ok(serde_json::Value::Object(object))
        }
        _ => Err(DeployerError::Config(
            "generated secrets extension contains unsupported CBOR value".to_string(),
        )),
    }
}

fn generated_secret_value(generated: &GeneratedSecretRequirement) -> Result<String> {
    if !generated.policy.eq_ignore_ascii_case("random") {
        return Err(DeployerError::Config(format!(
            "unsupported generated secret policy `{}`",
            generated.policy
        )));
    }
    let length = generated.length.max(1);
    match generated.encoding.as_str() {
        "raw_text" => Ok(random_ascii(length)),
        "base64url" => {
            let mut bytes = vec![0u8; length];
            rand::rng().fill(&mut bytes[..]);
            Ok(URL_SAFE_NO_PAD.encode(bytes))
        }
        "hex" => {
            let mut bytes = vec![0u8; length];
            rand::rng().fill(&mut bytes[..]);
            Ok(hex::encode(bytes))
        }
        other => Err(DeployerError::Config(format!(
            "unsupported generated secret encoding `{other}`"
        ))),
    }
}

fn random_ascii(length: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let mut bytes = vec![0u8; length];
    rand::rng().fill(&mut bytes[..]);
    bytes
        .into_iter()
        .map(|byte| ALPHABET[usize::from(byte) % ALPHABET.len()] as char)
        .collect()
}

fn resolve_from_setup_answers(
    bundle_root: &Path,
    requirement: &RuntimeSecretRequirement,
    checked_sources: &mut Vec<String>,
) -> Option<(PathBuf, String)> {
    for config_id in setup_answer_config_id_candidates(&requirement.source) {
        let path = bundle_root
            .join("state/config")
            .join(config_id)
            .join("setup-answers.json");
        checked_sources.push(path.display().to_string());
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(_) => continue,
        };
        let answers = match serde_json::from_str::<BTreeMap<String, JsonValue>>(&contents) {
            Ok(answers) => answers,
            Err(_) => continue,
        };
        for (key, value) in answers {
            if canonical_secret_name(&key) != requirement.key {
                continue;
            }
            if let Some(value) = value.as_str()
                && !value.is_empty()
            {
                if let Some(env_key) = extract_env_placeholder(value) {
                    checked_sources.push(format!("env ${{{env_key}}} (from setup-answers)"));
                    return match env::var(&env_key) {
                        Ok(resolved) if !resolved.is_empty() => Some((path, resolved)),
                        _ => None,
                    };
                }
                return Some((path, value.to_string()));
            }
        }
    }
    None
}

fn setup_answer_config_id_candidates(pack_path: &Path) -> Vec<String> {
    let Some(config_id) = config_id_from_pack_path(pack_path) else {
        return Vec::new();
    };
    let mut candidates = vec![config_id.clone()];
    if let Some((base, _)) = config_id.split_once("-gtpack-sha-")
        && !base.is_empty()
    {
        candidates.push(base.to_string());
    }
    candidates
}

// Parse a whole-string `${VAR}` placeholder and return `VAR`.
// `greentic-setup` persists unresolved env-var references in setup-answers.json
// when a non-interactive run cannot prompt. Without expansion here, those
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
    fn setup_answer_config_id_candidates_include_gtpack_sha_base_alias() {
        let candidates = setup_answer_config_id_candidates(Path::new(
            "/tmp/packs/deep-research-demo-gtpack-sha-abc123.gtpack",
        ));
        assert_eq!(
            candidates,
            vec![
                "deep-research-demo-gtpack-sha-abc123".to_string(),
                "deep-research-demo".to_string(),
            ]
        );
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
    fn collect_requirements_discovers_generated_secret_from_manifest_cbor_extension() {
        use greentic_types::{
            ExtensionInline, ExtensionRef, PackId, PackKind, PackManifest, PackSignatures,
            encode_pack_manifest,
        };
        use semver::Version;
        use serde_json::json;
        use std::io::Write;
        use zip::write::FileOptions;

        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("packs/messaging-webchat-gui.gtpack");
        std::fs::create_dir_all(pack.parent().unwrap()).unwrap();
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "greentic.generated-secrets.v1".to_string(),
            ExtensionRef {
                kind: "greentic.generated-secrets.v1".to_string(),
                version: "1".to_string(),
                digest: None,
                location: None,
                inline: Some(ExtensionInline::Other(json!({
                    "secrets": [{
                        "key": "jwt_signing_key",
                        "aliases": ["JWT_SIGNING_KEY"],
                        "required": true,
                        "policy": "random",
                        "length": 20,
                        "encoding": "raw_text",
                        "scope": {"level": "tenant", "team": "_"},
                        "regenerate_if_present": false
                    }]
                }))),
            },
        );
        let manifest = PackManifest {
            schema_version: "1".to_string(),
            pack_id: PackId::new("messaging-webchat-gui").unwrap(),
            name: None,
            version: Version::parse("0.0.0").unwrap(),
            kind: PackKind::Provider,
            publisher: "test".to_string(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: Some(extensions),
        };
        let file = File::create(&pack).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())
            .unwrap();
        zip.write_all(&encode_pack_manifest(&manifest).unwrap())
            .unwrap();
        zip.finish().unwrap();

        let ctx = RuntimeSecretContext {
            bundle_root: dir.path().to_path_buf(),
            pack_paths: vec![pack],
            environment: "dev".into(),
            tenant: "demo".into(),
            team: Some("default".into()),
        };

        let requirements = collect_requirements(&ctx).unwrap();
        assert_eq!(requirements.len(), 1);
        assert_eq!(
            requirements[0].uri,
            "secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key"
        );
        assert_eq!(requirements[0].key, "jwt_signing_key");
        assert!(requirements[0].generated.is_some());
    }

    #[test]
    fn collect_requirements_discovers_generated_secret_from_pack_manifest_json_extension() {
        use std::io::Write;
        use zip::write::FileOptions;

        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("packs/messaging-webchat-gui.gtpack");
        std::fs::create_dir_all(pack.parent().unwrap()).unwrap();
        let file = File::create(&pack).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("pack.manifest.json", FileOptions::<()>::default())
            .unwrap();
        zip.write_all(
            br#"{
                "extensions": {
                    "greentic.generated-secrets.v1": {
                        "inline": {
                            "secrets": [{
                                "key": "jwt_signing_key",
                                "policy": "random",
                                "length": 20,
                                "encoding": "raw_text",
                                "scope": {"level": "tenant", "team": "_"}
                            }]
                        }
                    }
                }
            }"#,
        )
        .unwrap();
        zip.finish().unwrap();

        let ctx = RuntimeSecretContext {
            bundle_root: dir.path().to_path_buf(),
            pack_paths: vec![pack],
            environment: "dev".into(),
            tenant: "demo".into(),
            team: Some("default".into()),
        };

        let requirements = collect_requirements(&ctx).unwrap();
        assert_eq!(requirements.len(), 1);
        assert_eq!(
            requirements[0].uri,
            "secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key"
        );
        assert!(requirements[0].generated.is_some());
    }

    #[test]
    fn runtime_secret_env_map_omits_generated_secret_env_aliases_for_cloud_binding() {
        use greentic_types::{
            ExtensionInline, ExtensionRef, PackId, PackKind, PackManifest, PackSignatures,
            encode_pack_manifest,
        };
        use semver::Version;
        use serde_json::json;
        use std::io::Write;
        use zip::write::FileOptions;

        let dir = tempfile::tempdir().unwrap();
        let bundle_root = dir.path();
        let pack = bundle_root.join("packs/messaging-webchat-gui.gtpack");
        std::fs::create_dir_all(pack.parent().unwrap()).unwrap();
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "greentic.generated-secrets.v1".to_string(),
            ExtensionRef {
                kind: "greentic.generated-secrets.v1".to_string(),
                version: "1".to_string(),
                digest: None,
                location: None,
                inline: Some(ExtensionInline::Other(json!({
                    "secrets": [{
                        "key": "jwt_signing_key",
                        "policy": "random",
                        "length": 20,
                        "encoding": "raw_text",
                        "scope": {"level": "tenant", "team": "_"}
                    }]
                }))),
            },
        );
        let manifest = PackManifest {
            schema_version: "1".to_string(),
            pack_id: PackId::new("messaging-webchat-gui").unwrap(),
            name: None,
            version: Version::parse("0.0.0").unwrap(),
            kind: PackKind::Provider,
            publisher: "test".to_string(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: Some(extensions),
        };
        let file = File::create(&pack).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())
            .unwrap();
        zip.write_all(&encode_pack_manifest(&manifest).unwrap())
            .unwrap();
        zip.finish().unwrap();

        let config = DeployerConfig {
            capability: DeployerCapability::Apply,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "demo".into(),
            environment: "dev".into(),
            pack_path: pack.clone(),
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
        };

        let env_map = runtime_secret_env_map_for_cloud(&config).unwrap();
        assert!(env_map.is_empty());
    }

    #[tokio::test]
    async fn cloud_apply_resolution_generates_generated_secret_without_setup_answer() {
        let dir = tempfile::tempdir().unwrap();
        let pack = dir.path().join("packs/messaging-webchat-gui");
        std::fs::create_dir_all(pack.join("assets")).unwrap();
        std::fs::write(
            pack.join("assets/secret-requirements.json"),
            r#"[{
                "key":"jwt_signing_key",
                "required":true,
                "generated":{
                    "policy":"random",
                    "length":20,
                    "encoding":"raw_text",
                    "scope":{"level":"tenant","team":"_"},
                    "regenerate_if_present":false
                }
            }]"#,
        )
        .unwrap();

        let ctx = RuntimeSecretContext {
            bundle_root: dir.path().to_path_buf(),
            pack_paths: vec![pack],
            environment: "dev".into(),
            tenant: "demo".into(),
            team: Some("default".into()),
        };
        let requirements = collect_requirements(&ctx).unwrap();
        let resolution = resolve_runtime_secrets(&ctx, &requirements).await;

        assert!(resolution.missing.is_empty());
        assert_eq!(resolution.resolved.len(), 1);
        assert_eq!(resolution.resolved[0].value.expose().len(), 20);
        assert!(matches!(
            resolution.resolved[0].source,
            SecretValueSource::Generated
        ));
    }

    #[test]
    fn generated_secret_value_supports_start_encodings() {
        let raw = generated_secret_value(&GeneratedSecretRequirement {
            policy: "random".into(),
            length: 20,
            encoding: "raw_text".into(),
            scope: GeneratedSecretScope {
                level: "tenant".into(),
                team: Some("_".into()),
            },
            regenerate_if_present: false,
        })
        .unwrap();
        assert_eq!(raw.len(), 20);

        let b64 = generated_secret_value(&GeneratedSecretRequirement {
            policy: "random".into(),
            length: 20,
            encoding: "base64url".into(),
            scope: GeneratedSecretScope {
                level: "tenant".into(),
                team: Some("_".into()),
            },
            regenerate_if_present: false,
        })
        .unwrap();
        assert!(!b64.contains('+'));
        assert!(!b64.contains('/'));
        assert!(!b64.contains('='));

        let hex = generated_secret_value(&GeneratedSecretRequirement {
            policy: "random".into(),
            length: 20,
            encoding: "hex".into(),
            scope: GeneratedSecretScope {
                level: "tenant".into(),
                team: Some("_".into()),
            },
            regenerate_if_present: false,
        })
        .unwrap();
        assert_eq!(hex.len(), 40);
        assert!(hex.chars().all(|ch| ch.is_ascii_hexdigit()));
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
    async fn cloud_apply_resolution_filters_secrets_provider_packs_by_target() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_root = dir.path();
        let app_pack = bundle_root.join("packs/greentic-main-website");
        std::fs::create_dir_all(&app_pack).unwrap();
        std::fs::write(app_pack.join("pack.yaml"), "id: greentic-main-website\n").unwrap();

        let aws_provider = bundle_root.join("providers/secrets/aws-sm");
        std::fs::create_dir_all(aws_provider.join("assets")).unwrap();
        std::fs::write(
            aws_provider.join("pack.yaml"),
            "id: greentic.secrets.aws-sm\n",
        )
        .unwrap();
        std::fs::write(
            aws_provider.join("assets/secret-requirements.json"),
            r#"[{
                "key":"aws_runtime_probe",
                "required":true,
                "generated":{
                    "policy":"random",
                    "length":20,
                    "encoding":"raw_text",
                    "scope":{"level":"tenant","team":"_"}
                }
            }]"#,
        )
        .unwrap();

        for (provider_dir, key) in [
            ("gcp-sm", "gcp_project_credentials"),
            ("azure-kv", "azure_key_vault_credentials"),
        ] {
            let inactive_provider = bundle_root.join("providers/secrets").join(provider_dir);
            std::fs::create_dir_all(inactive_provider.join("assets")).unwrap();
            std::fs::write(
                inactive_provider.join("pack.yaml"),
                format!("id: greentic.secrets.{provider_dir}\n"),
            )
            .unwrap();
            std::fs::write(
                inactive_provider.join("assets/secret-requirements.json"),
                format!(r#"[{{"key":"{key}","required":true}}]"#),
            )
            .unwrap();
        }

        let config = DeployerConfig {
            capability: DeployerCapability::Apply,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "demo".into(),
            environment: "dev".into(),
            pack_path: app_pack,
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
        };

        let resolution = resolve_for_cloud_apply(&config)
            .await
            .expect("resolve AWS cloud runtime secrets")
            .expect("runtime secrets should be present");
        let resolved_uris = resolution
            .resolved
            .iter()
            .map(|secret| secret.requirement.uri.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            resolved_uris,
            vec!["secrets://dev/demo/_/aws-sm/aws_runtime_probe"]
        );
        assert!(resolution.missing.is_empty());
    }

    #[tokio::test]
    async fn resolves_secret_values_from_setup_answers() {
        let dir = tempfile::tempdir().unwrap();
        let answers_dir = dir.path().join("state/config/demo-pack");
        std::fs::create_dir_all(&answers_dir).unwrap();
        std::fs::write(
            answers_dir.join("setup-answers.json"),
            r#"{"api_key":"secret-value"}"#,
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
            default_value: None,
            generated: None,
            source: dir.path().join("packs/demo-pack.gtpack"),
        };

        let resolution = resolve_runtime_secrets(&ctx, &[requirement]).await;
        assert!(resolution.missing.is_empty());
        assert_eq!(resolution.resolved.len(), 1);
        assert_eq!(resolution.resolved[0].value.expose(), "secret-value");
        assert!(matches!(
            resolution.resolved[0].source,
            SecretValueSource::SetupAnswers { .. }
        ));
    }

    #[test]
    fn runtime_secret_env_map_omits_explicit_secret_env_aliases_for_cloud_binding() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_root = dir.path();
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
        std::fs::write(
            config_dir.join("setup-answers.json"),
            r#"{"api_key":"secret-value"}"#,
        )
        .unwrap();

        let config = DeployerConfig {
            capability: DeployerCapability::Apply,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "demo".into(),
            environment: "dev".into(),
            pack_path: packs_dir.join("demo-app"),
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
        };

        let env_map = runtime_secret_env_map_for_cloud(&config).unwrap();
        assert!(env_map.is_empty());
    }

    #[test]
    fn runtime_secret_env_map_omits_optional_setup_secret_default_for_cloud_binding() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_root = dir.path();
        let packs_dir = bundle_root.join("packs");
        std::fs::create_dir_all(packs_dir.join("deep-research-demo/assets")).unwrap();
        std::fs::write(
            packs_dir.join("deep-research-demo/assets/setup.yaml"),
            r#"
questions:
  - name: api_key_secret
    secret_key: api_key_secret
    secret: true
    required: false
    default: ollama-placeholder
"#,
        )
        .unwrap();

        let config = DeployerConfig {
            capability: DeployerCapability::Apply,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "demo".into(),
            environment: "dev".into(),
            pack_path: packs_dir.join("deep-research-demo"),
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
        };

        let env_map = runtime_secret_env_map_for_cloud(&config).unwrap();
        assert!(env_map.is_empty());
    }

    #[test]
    fn secret_value_debug_is_redacted() {
        let value = SecretValue("super-secret".to_string());
        assert_eq!(format!("{value:?}"), "<redacted>");
    }
}
