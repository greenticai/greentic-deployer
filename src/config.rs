use std::fs;
use std::path::PathBuf;

use greentic_config::{ConfigFileFormat, ConfigLayer, ConfigResolver, ProvenanceMap};
use greentic_config_types::{GreenticConfig, PathsConfig, TelemetryConfig};
use greentic_types::ConnectionKind;
use greentic_types::pack::PackRef;
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::adapter::{AdapterFamily, MultiTargetKind, UnifiedTargetSelection};
use crate::contract::DeployerCapability;
use crate::error::{DeployerError, Result};

/// Supported deployment targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provider {
    Local,
    Aws,
    Azure,
    Gcp,
    K8s,
    Generic,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Local => "local",
            Provider::Aws => "aws",
            Provider::Azure => "azure",
            Provider::Gcp => "gcp",
            Provider::K8s => "k8s",
            Provider::Generic => "generic",
        }
    }

    /// The provider-oriented flow must stay outside the dedicated single-vm adapter path.
    pub fn adapter_family(&self) -> AdapterFamily {
        AdapterFamily::MultiTarget
    }

    pub fn unified_target(&self) -> UnifiedTargetSelection {
        UnifiedTargetSelection::MultiTarget(MultiTargetKind::from(*self))
    }
}

/// Output format for plan rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Yaml,
}

/// Library-facing request used to resolve deployer configuration.
#[derive(Debug, Clone)]
pub struct DeployerRequest {
    pub capability: DeployerCapability,
    pub provider: Provider,
    pub strategy: String,
    pub tenant: String,
    pub environment: Option<String>,
    pub pack_path: PathBuf,
    pub bundle_source: Option<String>,
    pub bundle_digest: Option<String>,
    pub providers_dir: PathBuf,
    pub packs_dir: PathBuf,
    pub provider_pack: Option<PathBuf>,
    pub pack_id: Option<String>,
    pub pack_version: Option<String>,
    pub pack_digest: Option<String>,
    pub distributor_url: Option<String>,
    pub distributor_token: Option<String>,
    pub preview: bool,
    pub dry_run: bool,
    pub execute_local: bool,
    pub output: OutputFormat,
    pub config_path: Option<PathBuf>,
    pub allow_remote_in_offline: bool,
    pub deploy_pack_id_override: Option<String>,
    pub deploy_flow_id_override: Option<String>,
}

impl DeployerRequest {
    pub fn new(
        capability: DeployerCapability,
        provider: Provider,
        tenant: impl Into<String>,
        pack_path: PathBuf,
    ) -> Self {
        Self {
            capability,
            provider,
            strategy: "iac-only".into(),
            tenant: tenant.into(),
            environment: None,
            pack_path,
            bundle_source: None,
            bundle_digest: None,
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: None,
            pack_id: None,
            pack_version: None,
            pack_digest: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: OutputFormat::Text,
            config_path: None,
            allow_remote_in_offline: false,
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
        }
    }
}

/// Complete configuration used by the deployer runtime.
#[derive(Debug, Clone)]
pub struct DeployerConfig {
    pub capability: DeployerCapability,
    pub provider: Provider,
    pub strategy: String,
    pub tenant: String,
    pub environment: String,
    pub pack_path: PathBuf,
    pub bundle_source: Option<String>,
    pub bundle_digest: Option<String>,
    pub providers_dir: PathBuf,
    pub packs_dir: PathBuf,
    pub provider_pack: Option<PathBuf>,
    pub pack_ref: Option<PackRef>,
    pub distributor_url: Option<String>,
    pub distributor_token: Option<String>,
    pub preview: bool,
    pub dry_run: bool,
    pub execute_local: bool,
    pub output: OutputFormat,
    pub greentic: GreenticConfig,
    pub provenance: ProvenanceMap,
    pub config_warnings: Vec<String>,
    pub deploy_pack_id_override: Option<String>,
    pub deploy_flow_id_override: Option<String>,
}

impl DeployerConfig {
    pub fn resolve(request: DeployerRequest) -> Result<Self> {
        let mut resolver = ConfigResolver::new();
        if let Some(layer) = load_explicit_config(request.config_path.as_ref())? {
            resolver = resolver.with_cli_overrides(layer);
        }
        let resolved = resolver
            .load()
            .map_err(|err| DeployerError::Config(err.to_string()))?;
        let greentic = resolved.config;

        if !request.pack_path.exists() && request.pack_id.is_none() {
            return Err(DeployerError::Config(format!(
                "pack path {} does not exist (and no pack_id provided)",
                request.pack_path.display()
            )));
        }

        let environment = env_id_to_string(
            request
                .environment
                .clone()
                .or_else(|| Some(greentic.environment.env_id.to_string())),
        );

        let pack_ref = build_pack_ref(
            request.pack_id.as_deref(),
            request.pack_version.as_deref(),
            request.pack_digest.as_deref(),
        )?;

        validate_offline_policy(
            greentic.environment.connection.as_ref(),
            &pack_ref,
            request.distributor_url.as_deref(),
            request.allow_remote_in_offline,
        )?;

        if request.deploy_pack_id_override.is_some() ^ request.deploy_flow_id_override.is_some() {
            return Err(DeployerError::Config(
                "deploy_pack_id_override and deploy_flow_id_override must be set together"
                    .to_string(),
            ));
        }

        Ok(Self {
            capability: request.capability,
            provider: request.provider,
            strategy: request.strategy,
            tenant: request.tenant,
            environment,
            pack_path: request.pack_path,
            bundle_source: request.bundle_source,
            bundle_digest: request.bundle_digest,
            providers_dir: request.providers_dir,
            packs_dir: request.packs_dir,
            provider_pack: request.provider_pack,
            pack_ref,
            distributor_url: request.distributor_url,
            distributor_token: request.distributor_token,
            preview: request.preview,
            dry_run: request.dry_run,
            execute_local: request.execute_local,
            output: request.output,
            greentic,
            provenance: resolved.provenance,
            config_warnings: resolved.warnings,
            deploy_pack_id_override: request.deploy_pack_id_override,
            deploy_flow_id_override: request.deploy_flow_id_override,
        })
    }

    pub fn deploy_base(&self) -> PathBuf {
        self.greentic.paths.state_dir.join("deploy")
    }

    pub fn runtime_base(&self) -> PathBuf {
        self.greentic.paths.state_dir.join("runtime")
    }

    pub fn output_scope_key(&self) -> String {
        scope_key_for_path(&self.pack_path)
    }

    pub fn provider_output_dir(&self) -> PathBuf {
        self.deploy_base()
            .join(self.provider.as_str())
            .join(&self.tenant)
            .join(&self.environment)
            .join(self.output_scope_key())
    }

    pub fn runtime_output_dir(&self) -> PathBuf {
        self.runtime_base()
            .join(&self.tenant)
            .join(&self.environment)
            .join(self.output_scope_key())
    }

    pub fn telemetry_config(&self) -> &TelemetryConfig {
        &self.greentic.telemetry
    }

    pub fn paths(&self) -> &PathsConfig {
        &self.greentic.paths
    }
}

fn scope_key_for_path(path: &std::path::Path) -> String {
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string();
    let mut scoped = String::with_capacity(canonical.len());
    for ch in canonical.chars() {
        if ch.is_ascii_alphanumeric() {
            scoped.push(ch.to_ascii_lowercase());
        } else {
            scoped.push('-');
        }
    }
    while scoped.contains("--") {
        scoped = scoped.replace("--", "-");
    }
    scoped.trim_matches('-').to_string()
}

fn load_explicit_config(path: Option<&PathBuf>) -> Result<Option<ConfigLayer>> {
    let Some(path) = path else {
        return Ok(None);
    };

    let contents = fs::read_to_string(path).map_err(|err| {
        DeployerError::Config(format!(
            "failed to read config file {}: {err}",
            path.display()
        ))
    })?;

    let format = match path.extension().and_then(|s| s.to_str()) {
        Some("json") => ConfigFileFormat::Json,
        _ => ConfigFileFormat::Toml,
    };

    let layer = match format {
        ConfigFileFormat::Toml => toml::from_str::<ConfigLayer>(&contents)
            .map_err(|err| format!("toml parse error: {err}")),
        ConfigFileFormat::Json => serde_json::from_str::<ConfigLayer>(&contents)
            .map_err(|err| format!("json parse error: {err}")),
    }
    .map_err(|err| {
        DeployerError::Config(format!("invalid config file {}: {err}", path.display()))
    })?;

    Ok(Some(layer))
}

fn build_pack_ref(
    pack_id: Option<&str>,
    pack_version: Option<&str>,
    pack_digest: Option<&str>,
) -> Result<Option<PackRef>> {
    let Some(pack_id) = pack_id else {
        return Ok(None);
    };
    let version_str = pack_version.ok_or_else(|| {
        DeployerError::Config("when using pack_id you must set pack_version".into())
    })?;
    let digest = pack_digest.ok_or_else(|| {
        DeployerError::Config("when using pack_id you must set pack_digest".into())
    })?;
    let version = Version::parse(version_str).map_err(|err| {
        DeployerError::Config(format!("invalid pack version '{}': {}", version_str, err))
    })?;
    Ok(Some(PackRef::new(
        pack_id.to_string(),
        version,
        digest.to_string(),
    )))
}

fn env_id_to_string(env_id: Option<String>) -> String {
    env_id.unwrap_or_else(|| "dev".to_string())
}

fn validate_offline_policy(
    connection: Option<&ConnectionKind>,
    pack_ref: &Option<PackRef>,
    distributor_url: Option<&str>,
    allow_remote_in_offline: bool,
) -> Result<()> {
    if matches!(connection, Some(ConnectionKind::Offline))
        && !allow_remote_in_offline
        && (pack_ref.is_some() || distributor_url.is_some())
    {
        return Err(DeployerError::OfflineDisallowed(
            "connection is Offline but remote pack/distributor requested; set allow_remote_in_offline to override".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn provider_targets_stay_on_multi_target_adapter_family() {
        for provider in [
            Provider::Local,
            Provider::Aws,
            Provider::Azure,
            Provider::Gcp,
            Provider::K8s,
            Provider::Generic,
        ] {
            assert_eq!(provider.adapter_family(), AdapterFamily::MultiTarget);
            assert!(matches!(
                provider.unified_target(),
                UnifiedTargetSelection::MultiTarget(_)
            ));
        }
    }

    fn base_request() -> DeployerRequest {
        DeployerRequest::new(
            DeployerCapability::Plan,
            Provider::Aws,
            "acme",
            PathBuf::from("examples/acme-pack"),
        )
    }

    fn write_config(dir: &Path) -> PathBuf {
        let cfg = r#"
[environment]
env_id = "prod"
connection = "offline"

[paths]
greentic_root = "."
state_dir = ".greentic/state"
cache_dir = ".greentic/cache"
logs_dir = ".greentic/logs"

[telemetry]
enabled = false

[network]
tls_mode = "system"

[secrets]
kind = "none"
"#;
        let path = dir.join("config.toml");
        fs::write(&path, cfg).expect("write config");
        path
    }

    #[test]
    fn defaults_to_dev_environment_when_missing() {
        let config = DeployerConfig::resolve(base_request()).expect("config builds");
        assert_eq!(config.environment, "dev");
    }

    #[test]
    fn accepts_explicit_environment_field() {
        let mut request = base_request();
        request.environment = Some("prod".into());
        let config = DeployerConfig::resolve(request).expect("config builds");
        assert_eq!(config.environment, "prod");
    }

    #[test]
    fn rejects_pack_id_without_version_or_digest() {
        let mut request = base_request();
        request.pack_id = Some("dev.greentic.sample".into());
        let err = DeployerConfig::resolve(request).unwrap_err();
        assert!(
            format!("{err}").contains("pack_version"),
            "expected version requirement error, got {err}"
        );
    }

    #[test]
    fn builds_pack_ref_when_provided() {
        let mut request = base_request();
        request.pack_id = Some("dev.greentic.sample".into());
        request.pack_version = Some("0.1.0".into());
        request.pack_digest = Some("sha256:deadbeef".into());
        let config = DeployerConfig::resolve(request).expect("config builds");
        let pack_ref = config.pack_ref.expect("pack_ref present");
        assert_eq!(pack_ref.oci_url, "dev.greentic.sample");
        assert_eq!(pack_ref.version.to_string(), "0.1.0");
        assert_eq!(pack_ref.digest, "sha256:deadbeef");
    }

    #[test]
    fn explicit_config_file_overrides_default_env() {
        let dir = tempdir().unwrap();
        let cfg_path = write_config(dir.path());

        let mut request = base_request();
        request.config_path = Some(cfg_path);
        let config = DeployerConfig::resolve(request).expect("config builds");
        assert_eq!(config.greentic.environment.env_id.to_string(), "prod");
    }

    #[test]
    fn offline_connection_blocks_remote_pack_without_override() {
        let dir = tempdir().unwrap();
        let cfg_path = write_config(dir.path());

        let mut request = base_request();
        request.pack_path = dir.path().to_path_buf();
        request.pack_id = Some("dev.greentic.sample".into());
        request.pack_version = Some("0.1.0".into());
        request.pack_digest = Some("sha256:deadbeef".into());
        request.distributor_url = Some("https://distributor.greentic.ai".into());
        request.config_path = Some(cfg_path);

        let err = DeployerConfig::resolve(request).unwrap_err();
        assert!(
            format!("{err}").contains("Offline"),
            "expected offline validation error, got {err}"
        );
    }

    #[test]
    fn provider_output_dir_is_scoped_by_pack_path() {
        let dir = tempdir().unwrap();
        let first_pack = dir.path().join("bundle-a").join("packs").join("app.gtpack");
        let second_pack = dir.path().join("bundle-b").join("packs").join("app.gtpack");
        fs::create_dir_all(first_pack.parent().unwrap()).expect("create first pack dir");
        fs::create_dir_all(second_pack.parent().unwrap()).expect("create second pack dir");
        fs::write(&first_pack, "").expect("write first pack");
        fs::write(&second_pack, "").expect("write second pack");

        let mut first_request = base_request();
        first_request.pack_path = first_pack;
        let first_config = DeployerConfig::resolve(first_request).expect("first config");

        let mut second_request = base_request();
        second_request.pack_path = second_pack;
        let second_config = DeployerConfig::resolve(second_request).expect("second config");

        assert_ne!(
            first_config.provider_output_dir(),
            second_config.provider_output_dir()
        );
        assert_ne!(
            first_config.runtime_output_dir(),
            second_config.runtime_output_dir()
        );
    }
}
