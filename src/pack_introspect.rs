use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use greentic_config_types::{NetworkConfig, TlsMode};
use greentic_distributor_client::PackId;
use greentic_distributor_client::source::DistributorSource;
use greentic_types::ConnectionKind;
use greentic_types::cbor::decode_pack_manifest;
use greentic_types::component::ComponentManifest;
use greentic_types::deployment::{
    ChannelPlan, DeploymentPlan, MessagingPlan, RunnerPlan, TelemetryPlan,
};
use greentic_types::flow::FlowKind;
use greentic_types::pack::PackRef;
use greentic_types::pack_manifest::{PackFlowEntry, PackKind, PackManifest};
use greentic_types::secrets::{SecretRequirement, SecretScope};
use semver::Version;
use serde_json::{Value as JsonValue, json};
use tar::Archive;
use zip::result::ZipError;

use crate::config::DeployerConfig;
use crate::error::{DeployerError, Result};
use crate::path_safety::normalize_under_root;
use crate::plan::{
    ComponentRole, DeploymentHints, DeploymentProfile, InferenceNotes, InfraPlan, PlanContext,
    PlannedComponent, Target, assemble_plan,
};

/// Load a pack manifest from raw .gtpack bytes.
///
/// CBOR must be decoded exclusively via `greentic_types::decode_pack_manifest`.
pub fn load_pack_manifest_from_bytes(bytes: &[u8]) -> Result<PackManifest> {
    decode_pack_manifest(bytes).map_err(DeployerError::ManifestDecode)
}

/// Build a plan context from the provided pack.
pub fn build_plan(config: &DeployerConfig) -> Result<PlanContext> {
    let cwd = std::env::current_dir()?;
    let mut source = if let Some(pack_ref) = &config.pack_ref {
        let source = resolve_distributor_source(config)?;
        PackSource::from_registry(pack_ref.clone(), source)?
    } else {
        let safe_path = if config.pack_path.is_absolute() {
            let canon = config.pack_path.canonicalize()?;
            if !canon.starts_with(&cwd) {
                return Err(DeployerError::Pack(format!(
                    "absolute pack path escapes root {}: {}",
                    cwd.display(),
                    canon.display()
                )));
            }
            canon
        } else {
            normalize_under_root(&cwd, &config.pack_path)
                .map_err(|err| DeployerError::Pack(err.to_string()))?
        };
        PackSource::open(&safe_path)?
    };
    build_plan_with_source(&mut source, config)
}

/// Build a plan using an explicitly provided pack source (e.g., registry).
pub fn build_plan_with_source(
    source: &mut PackSource,
    config: &DeployerConfig,
) -> Result<PlanContext> {
    let manifest = source.read_manifest()?;
    let deployment = build_deployment_hints(config);
    let base = plan_from_pack_kind(&manifest, config);
    let external_components: Vec<String> = external_facing_components(&manifest)
        .into_iter()
        .map(|c| c.id.to_string())
        .collect();
    let components = infer_component_profiles(&manifest, &deployment);
    Ok(assemble_plan(
        base,
        config,
        deployment,
        external_components,
        components,
    ))
}

/// Preferred pack sources.
#[allow(dead_code)]
pub enum PackSource {
    GtpackPath(PathBuf),
    Dir(PathBuf),
    Registry {
        reference: PackRef,
        source: Arc<dyn DistributorSource>,
    },
}

impl PackSource {
    fn open(path: &Path) -> Result<Self> {
        if path.is_dir() {
            Ok(Self::Dir(path.to_path_buf()))
        } else {
            Ok(Self::GtpackPath(path.to_path_buf()))
        }
    }

    #[allow(dead_code)]
    pub fn from_registry(reference: PackRef, source: Arc<dyn DistributorSource>) -> Result<Self> {
        Ok(Self::Registry { reference, source })
    }

    fn read_manifest(&mut self) -> Result<PackManifest> {
        match self {
            PackSource::GtpackPath(path) => read_manifest_from_gtpack(path),
            PackSource::Dir(path) => read_manifest_from_directory(path),
            PackSource::Registry {
                source, reference, ..
            } => read_manifest_from_registry(source.as_ref(), reference),
        }
    }
}

fn read_manifest_from_tar(path: &Path) -> Result<PackManifest> {
    let file = File::open(path)?;
    let mut archive = Archive::new(file);
    let mut manifest_bytes = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == Path::new("manifest.cbor") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            manifest_bytes = Some(buf);
            break;
        }
    }

    let bytes = manifest_bytes.ok_or_else(|| {
        DeployerError::Pack(format!(
            "manifest.cbor missing in pack archive {}",
            path.display()
        ))
    })?;

    load_pack_manifest_from_bytes(&bytes)
}

fn read_manifest_from_zip(path: &Path) -> Result<PackManifest> {
    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| {
        DeployerError::Pack(format!("failed to open zip pack {}: {err}", path.display()))
    })?;
    let mut entry = archive.by_name("manifest.cbor").map_err(|err| match err {
        ZipError::FileNotFound => DeployerError::Pack(format!(
            "manifest.cbor missing in pack archive {}",
            path.display()
        )),
        other => DeployerError::Pack(format!(
            "failed to read manifest.cbor in {}: {other}",
            path.display()
        )),
    })?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    load_pack_manifest_from_bytes(&bytes)
}

/// Read a manifest directly from a `.gtpack` archive on disk.
pub fn read_manifest_from_gtpack(path: &Path) -> Result<PackManifest> {
    match read_manifest_from_tar(path) {
        Ok(manifest) => Ok(manifest),
        Err(DeployerError::Io(err)) if err.kind() == std::io::ErrorKind::InvalidData => {
            read_manifest_from_zip(path)
        }
        Err(DeployerError::Io(err)) if err.kind() == std::io::ErrorKind::Other => {
            read_manifest_from_zip(path)
        }
        Err(err) => Err(err),
    }
}

/// Read an arbitrary entry from a `.gtpack` archive.
pub fn read_entry_from_gtpack(path: &Path, entry_path: &Path) -> Result<Vec<u8>> {
    match read_entry_from_tar_gtpack(path, entry_path) {
        Ok(bytes) => Ok(bytes),
        Err(DeployerError::Io(err)) if err.kind() == std::io::ErrorKind::InvalidData => {
            read_entry_from_zip_gtpack(path, entry_path)
        }
        Err(DeployerError::Io(err)) if err.kind() == std::io::ErrorKind::Other => {
            read_entry_from_zip_gtpack(path, entry_path)
        }
        Err(err) => Err(err),
    }
}

fn read_entry_from_tar_gtpack(path: &Path, entry_path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut archive = Archive::new(file);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == entry_path {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            return Ok(buf);
        }
    }
    Err(DeployerError::Pack(format!(
        "entry {} not found in {}",
        entry_path.display(),
        path.display()
    )))
}

fn read_entry_from_zip_gtpack(path: &Path, entry_path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| {
        DeployerError::Pack(format!("failed to open zip pack {}: {err}", path.display()))
    })?;
    let mut entry = archive
        .by_name(&entry_path.to_string_lossy())
        .map_err(|err| match err {
            ZipError::FileNotFound => DeployerError::Pack(format!(
                "entry {} not found in {}",
                entry_path.display(),
                path.display()
            )),
            other => DeployerError::Pack(format!(
                "failed to read entry {} in {}: {other}",
                entry_path.display(),
                path.display()
            )),
        })?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

fn resolve_distributor_source(config: &DeployerConfig) -> Result<Arc<dyn DistributorSource>> {
    if let Some(source) = DISTRIBUTOR_SOURCE.get().cloned() {
        return Ok(source);
    }

    build_http_distributor_source(config).map_err(|err| {
        if matches!(err, DeployerError::Config(_) | DeployerError::OfflineDisallowed(_)) {
            err
        } else {
            DeployerError::Config(format!(
                "no distributor source registered; either register one programmatically or set distributor_url ({err})"
            ))
        }
    })
}

static DISTRIBUTOR_SOURCE: once_cell::sync::OnceCell<Arc<dyn DistributorSource>> =
    once_cell::sync::OnceCell::new();

/// Register a distributor source for registry-based pack resolution.
pub fn set_distributor_source(source: Arc<dyn DistributorSource>) {
    let _ = DISTRIBUTOR_SOURCE.set(source);
}

fn build_http_distributor_source(config: &DeployerConfig) -> Result<Arc<dyn DistributorSource>> {
    let base_url = config
        .distributor_url
        .as_deref()
        .ok_or_else(|| DeployerError::Config("set distributor_url when using pack_id".into()))?;

    if matches!(
        config.greentic.environment.connection,
        Some(ConnectionKind::Offline)
    ) {
        return Err(DeployerError::OfflineDisallowed(
            "connection is Offline but distributor URL was requested".into(),
        ));
    }

    let client = build_http_client(&config.greentic.network, base_url)?;
    Ok(Arc::new(HttpPackSource::new(
        client,
        base_url.to_string(),
        config.distributor_token.clone(),
    )))
}

struct HttpPackSource {
    client: reqwest::blocking::Client,
    base_url: String,
    token: Option<String>,
    retries: usize,
}

impl HttpPackSource {
    fn new(client: reqwest::blocking::Client, base_url: String, token: Option<String>) -> Self {
        Self {
            client,
            base_url,
            token,
            retries: 3,
        }
    }
}

fn build_http_client(network: &NetworkConfig, base_url: &str) -> Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder();

    if let Some(proxy_url) = &network.proxy_url {
        let proxy = reqwest::Proxy::all(proxy_url).map_err(|err| {
            DeployerError::Config(format!("invalid proxy URL {proxy_url}: {err}"))
        })?;
        builder = builder.proxy(proxy);
    }

    builder = match network.tls_mode {
        TlsMode::Disabled => {
            if base_url.starts_with("https://") {
                return Err(DeployerError::Config(
                    "network.tls_mode=disabled is not allowed for https distributor_url; use http or enable TLS"
                        .into(),
                ));
            }
            builder
        }
        TlsMode::System | TlsMode::Strict => builder,
    };

    if let Some(connect_ms) = network.connect_timeout_ms {
        builder = builder.connect_timeout(Duration::from_millis(connect_ms));
    }
    if let Some(read_ms) = network.read_timeout_ms {
        builder = builder.timeout(Duration::from_millis(read_ms));
    }

    builder.build().map_err(|err| {
        DeployerError::Config(format!(
            "failed to build HTTP client for distributor: {err}"
        ))
    })
}

impl DistributorSource for HttpPackSource {
    fn fetch_pack(
        &self,
        pack_id: &PackId,
        version: &Version,
    ) -> std::result::Result<Vec<u8>, greentic_distributor_client::error::DistributorError> {
        let url = format!("{}/distributor-api/pack", self.base_url);
        let payload = serde_json::json!({
            "pack_id": pack_id.as_str(),
            "version": version.to_string(),
        });
        let mut last_err = None;
        for _ in 0..self.retries {
            let mut request = self.client.post(url.clone()).json(&payload);
            if let Some(token) = &self.token {
                request = request.bearer_auth(token);
            }
            match request.send() {
                Ok(response) if response.status().is_success() => {
                    let bytes = response
                        .bytes()
                        .map_err(|err| {
                            greentic_distributor_client::error::DistributorError::Other(
                                err.to_string(),
                            )
                        })?
                        .to_vec();
                    return Ok(bytes);
                }
                Ok(response) if response.status() == reqwest::StatusCode::NOT_FOUND => {
                    return Err(greentic_distributor_client::error::DistributorError::NotFound);
                }
                Ok(response)
                    if response.status() == reqwest::StatusCode::UNAUTHORIZED
                        || response.status() == reqwest::StatusCode::FORBIDDEN =>
                {
                    return Err(
                        greentic_distributor_client::error::DistributorError::PermissionDenied,
                    );
                }
                Ok(response) => {
                    last_err = Some(format!("http status {}", response.status()));
                }
                Err(err) => {
                    last_err = Some(err.to_string());
                }
            }
        }

        Err(greentic_distributor_client::error::DistributorError::Other(
            last_err.unwrap_or_else(|| "failed to fetch pack".into()),
        ))
    }

    fn fetch_component(
        &self,
        _component_id: &greentic_distributor_client::ComponentId,
        _version: &Version,
    ) -> std::result::Result<Vec<u8>, greentic_distributor_client::error::DistributorError> {
        Err(greentic_distributor_client::error::DistributorError::NotFound)
    }
}

pub fn read_manifest_from_directory(root: &Path) -> Result<PackManifest> {
    let cbor = normalize_under_root(root, Path::new("manifest.cbor"))
        .map_err(|err| DeployerError::Pack(err.to_string()))?;
    if !cbor.exists() {
        return Err(DeployerError::Pack(format!(
            "manifest.cbor missing in {}",
            root.display()
        )));
    }
    let bytes = fs::read(cbor)?;
    load_pack_manifest_from_bytes(&bytes)
}

fn read_manifest_from_registry(
    source: &dyn DistributorSource,
    reference: &PackRef,
) -> Result<PackManifest> {
    let pack_id = reference.oci_url.parse::<PackId>().map_err(|err| {
        DeployerError::Config(format!("invalid pack id '{}': {err}", reference.oci_url))
    })?;
    let bytes = source.fetch_pack(&pack_id, &reference.version)?;
    load_pack_manifest_from_bytes(&bytes)
}

fn build_deployment_hints(config: &DeployerConfig) -> DeploymentHints {
    let target: Target = config.provider.into();
    DeploymentHints {
        target,
        provider: config.provider.as_str().to_string(),
        strategy: config.strategy.clone(),
    }
}

fn plan_from_pack_kind(manifest: &PackManifest, config: &DeployerConfig) -> DeploymentPlan {
    match manifest.kind {
        PackKind::Application => plan_application(manifest, config),
        PackKind::Provider => plan_provider(manifest, config),
        PackKind::Infrastructure => plan_infrastructure(manifest, config),
        PackKind::Library => plan_library(manifest, config),
    }
}

fn plan_application(manifest: &PackManifest, config: &DeployerConfig) -> DeploymentPlan {
    infer_base_deployment_plan(manifest, config)
}

fn plan_provider(manifest: &PackManifest, config: &DeployerConfig) -> DeploymentPlan {
    let mut plan = infer_base_deployment_plan(manifest, config);
    // Providers shouldn't expose channels directly; keep runners/secrets but drop channels.
    plan.channels.clear();
    plan
}

fn plan_infrastructure(manifest: &PackManifest, config: &DeployerConfig) -> DeploymentPlan {
    let mut plan = infer_base_deployment_plan(manifest, config);
    // Infra packs generally lack messaging entrypoints.
    plan.channels.clear();
    plan.messaging = None;
    plan
}

fn plan_library(manifest: &PackManifest, config: &DeployerConfig) -> DeploymentPlan {
    // Libraries are not deployed directly; surface metadata without runners/channels.
    DeploymentPlan {
        pack_id: manifest.pack_id.to_string(),
        pack_version: manifest.version.clone(),
        tenant: config.tenant.clone(),
        environment: config.environment.clone(),
        runners: Vec::new(),
        messaging: None,
        channels: Vec::new(),
        secrets: collect_secret_requirements(manifest, config),
        oauth: Vec::new(),
        telemetry: None,
        extra: JsonValue::Null,
    }
}

fn infer_base_deployment_plan(manifest: &PackManifest, config: &DeployerConfig) -> DeploymentPlan {
    let runners = build_runner_plan(manifest);
    let channels = build_channel_plan(manifest);
    let secrets = collect_secret_requirements(manifest, config);
    let messaging = messaging_plan_if_needed(manifest, &channels);
    let telemetry = Some(TelemetryPlan {
        required: true,
        suggested_endpoint: None,
        extra: JsonValue::Null,
    });

    DeploymentPlan {
        pack_id: manifest.pack_id.to_string(),
        pack_version: manifest.version.clone(),
        tenant: config.tenant.clone(),
        environment: config.environment.clone(),
        runners,
        messaging,
        channels,
        secrets,
        oauth: Vec::new(),
        telemetry,
        extra: JsonValue::Null,
    }
}

fn messaging_plan_if_needed(
    manifest: &PackManifest,
    channels: &[ChannelPlan],
) -> Option<MessagingPlan> {
    if messaging_flows(manifest).next().is_none() && channels.is_empty() {
        return None;
    }

    Some(MessagingPlan {
        logical_cluster: "nats-default".to_string(),
        subjects: Vec::new(),
        extra: JsonValue::Null,
    })
}

fn build_runner_plan(manifest: &PackManifest) -> Vec<RunnerPlan> {
    components_for_deployment(manifest)
        .into_iter()
        .map(|component| {
            let resources = &component.resources;
            let replicas = if resources.average_latency_ms.unwrap_or(0) < 50 {
                2
            } else {
                1
            };
            RunnerPlan {
                name: component.id.to_string(),
                replicas,
                capabilities: json!({
                    "cpu_millis": resources.cpu_millis,
                    "memory_mb": resources.memory_mb,
                    "average_latency_ms": resources.average_latency_ms,
                }),
            }
        })
        .collect()
}

fn build_channel_plan(manifest: &PackManifest) -> Vec<ChannelPlan> {
    let mut channels = Vec::new();

    for entry in messaging_flows(manifest) {
        let entrypoints: Vec<String> = if entry.flow.entrypoints.is_empty() {
            vec!["default".to_string()]
        } else {
            entry.flow.entrypoints.keys().cloned().collect()
        };

        for name in entrypoints {
            channels.push(ChannelPlan {
                name: name.clone(),
                flow_id: entry.id.to_string(),
                kind: "messaging".to_string(),
                config: JsonValue::Null,
            });
        }
    }

    for entry in http_flows(manifest) {
        let entrypoints: Vec<String> = if entry.flow.entrypoints.is_empty() {
            vec!["default".to_string()]
        } else {
            entry.flow.entrypoints.keys().cloned().collect()
        };

        for name in entrypoints {
            channels.push(ChannelPlan {
                name: name.clone(),
                flow_id: entry.id.to_string(),
                kind: "http".to_string(),
                config: JsonValue::Null,
            });
        }
    }

    channels
}

fn collect_secret_requirements(
    manifest: &PackManifest,
    config: &DeployerConfig,
) -> Vec<SecretRequirement> {
    let mut secrets = Vec::new();
    for component in components_for_deployment(manifest) {
        if let Some(spec) = component.capabilities.host.secrets.as_ref() {
            for requirement in &spec.required {
                let mut requirement = requirement.clone();
                if requirement.scope.is_none() {
                    requirement.scope = Some(SecretScope {
                        env: config.environment.clone(),
                        tenant: config.tenant.clone(),
                        team: None,
                    });
                }

                if secrets.iter().any(|entry: &SecretRequirement| {
                    entry.key == requirement.key && entry.scope == requirement.scope
                }) {
                    continue;
                }
                secrets.push(requirement);
            }
        }
    }
    secrets
}

/// Components that should be deployed (currently all declared components).
pub fn components_for_deployment(manifest: &PackManifest) -> Vec<&ComponentManifest> {
    manifest.components.iter().collect()
}

/// Components that are external-facing (messaging/http/event ingress).
pub fn external_facing_components(manifest: &PackManifest) -> Vec<&ComponentManifest> {
    manifest
        .components
        .iter()
        .filter(|component| {
            let host_caps = &component.capabilities.host;
            host_caps
                .messaging
                .as_ref()
                .map(|m| m.inbound)
                .unwrap_or(false)
                || host_caps
                    .events
                    .as_ref()
                    .map(|e| e.inbound)
                    .unwrap_or(false)
                || host_caps
                    .http
                    .as_ref()
                    .map(|http| http.server)
                    .unwrap_or(false)
        })
        .collect()
}

/// Iterator over messaging flows embedded in the pack.
pub fn messaging_flows<'a>(
    manifest: &'a PackManifest,
) -> impl Iterator<Item = &'a PackFlowEntry> + 'a {
    manifest
        .flows
        .iter()
        .filter(|entry| entry.kind == FlowKind::Messaging)
}

/// Iterator over HTTP flows embedded in the pack.
pub fn http_flows<'a>(manifest: &'a PackManifest) -> impl Iterator<Item = &'a PackFlowEntry> + 'a {
    manifest
        .flows
        .iter()
        .filter(|entry| entry.kind == FlowKind::Http)
}

/// Iterator over component configuration flows.
pub fn config_flows<'a>(
    manifest: &'a PackManifest,
) -> impl Iterator<Item = &'a PackFlowEntry> + 'a {
    manifest
        .flows
        .iter()
        .filter(|entry| entry.kind == FlowKind::ComponentConfig)
}

fn infer_component_profiles(
    manifest: &PackManifest,
    deployment: &DeploymentHints,
) -> Vec<PlannedComponent> {
    let mut planned = Vec::new();
    for component in &manifest.components {
        let role = infer_component_role(component);
        let (profile, inference) = infer_profile(component, &role);
        let infra = map_profile_to_infra(&deployment.target, &profile);
        planned.push(PlannedComponent {
            id: component.id.to_string(),
            role,
            profile,
            target: deployment.target.clone(),
            infra,
            inference,
        });
    }

    planned.sort_by(|a, b| a.id.cmp(&b.id));
    planned
}

fn infer_component_role(component: &ComponentManifest) -> ComponentRole {
    let host_caps = &component.capabilities.host;
    if host_caps
        .messaging
        .as_ref()
        .map(|caps| caps.inbound)
        .unwrap_or(false)
    {
        return ComponentRole::MessagingAdapter;
    }
    if host_caps
        .events
        .as_ref()
        .map(|caps| caps.inbound)
        .unwrap_or(false)
    {
        return ComponentRole::EventProvider;
    }
    if host_caps
        .events
        .as_ref()
        .map(|caps| caps.outbound)
        .unwrap_or(false)
    {
        return ComponentRole::EventBridge;
    }
    ComponentRole::Worker
}

fn infer_profile(
    component: &ComponentManifest,
    role: &ComponentRole,
) -> (DeploymentProfile, Option<InferenceNotes>) {
    if let Some(default) = component.profiles.default.as_deref()
        && let Some(profile) = parse_profile(default)
    {
        return (
            profile,
            Some(InferenceNotes {
                source: "default profile from component manifest".to_string(),
                warnings: Vec::new(),
            }),
        );
    }

    let host_caps = &component.capabilities.host;
    if host_caps
        .http
        .as_ref()
        .map(|caps| caps.server)
        .unwrap_or(false)
    {
        return (
            DeploymentProfile::HttpEndpoint,
            Some(InferenceNotes {
                source: "inferred from http.server capability".to_string(),
                warnings: Vec::new(),
            }),
        );
    }
    if host_caps
        .messaging
        .as_ref()
        .map(|caps| caps.inbound || caps.outbound)
        .unwrap_or(false)
    {
        return (
            DeploymentProfile::LongLivedService,
            Some(InferenceNotes {
                source: "inferred from messaging capability".to_string(),
                warnings: Vec::new(),
            }),
        );
    }
    if host_caps
        .events
        .as_ref()
        .map(|caps| caps.inbound || caps.outbound)
        .unwrap_or(false)
    {
        return (
            DeploymentProfile::ScheduledSource,
            Some(InferenceNotes {
                source: "inferred from events capability".to_string(),
                warnings: Vec::new(),
            }),
        );
    }

    let (profile, warning) = default_profile(role);
    let warnings = if warning {
        vec![format!(
            "component {} (role={}) defaulted to {:?}",
            component.id,
            role_label(role),
            profile
        )]
    } else {
        Vec::new()
    };

    (
        profile,
        Some(InferenceNotes {
            source: "fallback profile inference".to_string(),
            warnings,
        }),
    )
}

fn role_label(role: &ComponentRole) -> &'static str {
    match role {
        ComponentRole::EventProvider => "event_provider",
        ComponentRole::EventBridge => "event_bridge",
        ComponentRole::MessagingAdapter => "messaging_adapter",
        ComponentRole::Worker => "worker",
        ComponentRole::Other => "component",
    }
}

fn default_profile(role: &ComponentRole) -> (DeploymentProfile, bool) {
    match role {
        ComponentRole::Worker => (DeploymentProfile::OneShotJob, false),
        ComponentRole::EventProvider | ComponentRole::EventBridge => {
            (DeploymentProfile::LongLivedService, true)
        }
        ComponentRole::MessagingAdapter => (DeploymentProfile::LongLivedService, true),
        ComponentRole::Other => (DeploymentProfile::LongLivedService, true),
    }
}

fn parse_profile(value: &str) -> Option<DeploymentProfile> {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "longlivedservice" | "long_lived_service" => Some(DeploymentProfile::LongLivedService),
        "httpendpoint" | "http_endpoint" => Some(DeploymentProfile::HttpEndpoint),
        "queueconsumer" | "queue_consumer" => Some(DeploymentProfile::QueueConsumer),
        "scheduledsource" | "scheduled_source" => Some(DeploymentProfile::ScheduledSource),
        "oneshotjob" | "one_shot_job" | "one_shot" => Some(DeploymentProfile::OneShotJob),
        _ => None,
    }
}

fn map_profile_to_infra(target: &Target, profile: &DeploymentProfile) -> InfraPlan {
    let (summary, resources) = match (target, profile) {
        (Target::Local, DeploymentProfile::HttpEndpoint) => (
            "local gateway + handler".to_string(),
            vec!["local-gateway".into(), "runner-handler".into()],
        ),
        (Target::Aws, DeploymentProfile::HttpEndpoint) => (
            "api-gateway + lambda".to_string(),
            vec!["api-gateway".into(), "lambda".into()],
        ),
        (Target::Azure, DeploymentProfile::HttpEndpoint) => (
            "function app (http trigger)".to_string(),
            vec!["function-app".into()],
        ),
        (Target::Gcp, DeploymentProfile::HttpEndpoint) => {
            ("cloud run (http)".to_string(), vec!["cloud-run".into()])
        }
        (Target::K8s, DeploymentProfile::HttpEndpoint) => (
            "ingress + service + deployment".to_string(),
            vec!["ingress".into(), "service".into(), "deployment".into()],
        ),
        (Target::Local, DeploymentProfile::LongLivedService) => (
            "runner-managed long-lived process".to_string(),
            vec!["local-runner".into()],
        ),
        (Target::Aws, DeploymentProfile::LongLivedService) => (
            "ecs/eks service".to_string(),
            vec!["container-service".into()],
        ),
        (Target::Azure, DeploymentProfile::LongLivedService) => (
            "container apps / app service".to_string(),
            vec!["container-app".into()],
        ),
        (Target::Gcp, DeploymentProfile::LongLivedService) => (
            "cloud run (always on)".to_string(),
            vec!["cloud-run".into()],
        ),
        (Target::K8s, DeploymentProfile::LongLivedService) => (
            "deployment + service".to_string(),
            vec!["deployment".into(), "service".into()],
        ),
        (Target::Local, DeploymentProfile::QueueConsumer) => (
            "local queue worker".to_string(),
            vec!["local-queue-worker".into()],
        ),
        (Target::Aws, DeploymentProfile::QueueConsumer) => (
            "sqs/event source + lambda".to_string(),
            vec!["sqs".into(), "lambda".into()],
        ),
        (Target::Azure, DeploymentProfile::QueueConsumer) => (
            "service bus queue trigger".to_string(),
            vec!["service-bus".into(), "function".into()],
        ),
        (Target::Gcp, DeploymentProfile::QueueConsumer) => (
            "pubsub subscriber".to_string(),
            vec!["pubsub".into(), "subscriber".into()],
        ),
        (Target::K8s, DeploymentProfile::QueueConsumer) => (
            "deployment + queue consumer".to_string(),
            vec!["deployment".into()],
        ),
        (Target::Local, DeploymentProfile::ScheduledSource) => (
            "local scheduler + runner invocation".to_string(),
            vec!["scheduler".into(), "runner".into()],
        ),
        (Target::Aws, DeploymentProfile::ScheduledSource) => (
            "eventbridge schedule + lambda".to_string(),
            vec!["eventbridge".into(), "lambda".into()],
        ),
        (Target::Azure, DeploymentProfile::ScheduledSource) => (
            "timer-triggered function".to_string(),
            vec!["function-app".into()],
        ),
        (Target::Gcp, DeploymentProfile::ScheduledSource) => (
            "cloud scheduler + run/function".to_string(),
            vec!["cloud-scheduler".into(), "cloud-run".into()],
        ),
        (Target::K8s, DeploymentProfile::ScheduledSource) => {
            ("cronjob".to_string(), vec!["cronjob".into()])
        }
        (Target::Local, DeploymentProfile::OneShotJob) => {
            ("runner one-shot job".to_string(), vec!["runner".into()])
        }
        (Target::Aws, DeploymentProfile::OneShotJob) => {
            ("lambda invocation".to_string(), vec!["lambda".into()])
        }
        (Target::Azure, DeploymentProfile::OneShotJob) => (
            "container apps job / function".to_string(),
            vec!["container-app-job".into()],
        ),
        (Target::Gcp, DeploymentProfile::OneShotJob) => {
            ("cloud run job".to_string(), vec!["cloud-run-job".into()])
        }
        (Target::K8s, DeploymentProfile::OneShotJob) => ("job".to_string(), vec!["job".into()]),
    };

    InfraPlan {
        target: target.clone(),
        profile: profile.clone(),
        summary,
        resources,
        notes: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeployerConfig, OutputFormat, Provider};
    use crate::contract::DeployerCapability;
    use greentic_types::cbor::encode_pack_manifest;
    use greentic_types::component::{ComponentCapabilities, ComponentProfiles, HostCapabilities};
    use greentic_types::flow::{
        ComponentRef, Flow, FlowMetadata, InputMapping, Node, OutputMapping,
    };
    use greentic_types::pack_manifest::PackDependency;
    use greentic_types::{ComponentId, FlowId, NodeId, PackId, SemverReq};
    use indexmap::IndexMap;
    use semver::Version;
    use std::env;
    use std::io::Write;
    use std::str::FromStr;
    use tar::Builder;

    fn sample_component(id: &str, inbound_messaging: bool) -> ComponentManifest {
        let host_caps = HostCapabilities {
            messaging: Some(greentic_types::component::MessagingCapabilities {
                inbound: inbound_messaging,
                outbound: true,
            }),
            ..Default::default()
        };
        ComponentManifest {
            id: ComponentId::from_str(id).unwrap(),
            version: Version::new(0, 1, 0),
            supports: vec![FlowKind::Messaging, FlowKind::Http],
            world: "greentic:test/world".to_string(),
            profiles: ComponentProfiles {
                default: Some("long_lived_service".to_string()),
                supported: vec!["long_lived_service".to_string()],
            },
            capabilities: ComponentCapabilities {
                host: host_caps,
                ..Default::default()
            },
            configurators: None,
            operations: Vec::new(),
            config_schema: None,
            resources: Default::default(),
            dev_flows: Default::default(),
        }
    }

    fn sample_flow(id: &str, kind: FlowKind, component: &ComponentManifest) -> PackFlowEntry {
        let mut nodes: IndexMap<NodeId, Node, greentic_types::flow::FlowHasher> =
            IndexMap::default();
        nodes.insert(
            NodeId::from_str("start").unwrap(),
            Node {
                id: NodeId::from_str("start").unwrap(),
                component: ComponentRef {
                    id: component.id.clone(),
                    pack_alias: None,
                    operation: None,
                },
                input: InputMapping {
                    mapping: JsonValue::Null,
                },
                output: OutputMapping {
                    mapping: JsonValue::Null,
                },
                routing: greentic_types::flow::Routing::End,
                telemetry: Default::default(),
            },
        );

        let mut entrypoints = std::collections::BTreeMap::new();
        entrypoints.insert("default".to_string(), JsonValue::Null);

        let flow = Flow {
            schema_version: "flowir-v1".to_string(),
            id: FlowId::from_str(id).unwrap(),
            kind,
            entrypoints,
            nodes,
            metadata: FlowMetadata::default(),
        };

        PackFlowEntry {
            id: flow.id.clone(),
            kind,
            flow,
            tags: vec![format!("{kind:?}")],
            entrypoints: vec!["default".to_string()],
        }
    }

    fn sample_manifest() -> PackManifest {
        let messaging_component = sample_component("dev.greentic.chat", true);
        let http_component = sample_component("dev.greentic.http", false);

        let flows = vec![
            sample_flow("chat_flow", FlowKind::Messaging, &messaging_component),
            sample_flow("http_flow", FlowKind::Http, &http_component),
            sample_flow(
                "config_flow",
                FlowKind::ComponentConfig,
                &messaging_component,
            ),
        ];

        PackManifest {
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::from_str("dev.greentic.sample").unwrap(),
            name: None,
            version: Version::new(0, 1, 0),
            kind: PackKind::Application,
            publisher: "greentic".to_string(),
            secret_requirements: Vec::new(),
            components: vec![messaging_component, http_component],
            flows,
            dependencies: vec![PackDependency {
                alias: "common".to_string(),
                pack_id: PackId::from_str("dev.greentic.common").unwrap(),
                version_req: SemverReq::parse("*").unwrap(),
                required_capabilities: vec![],
            }],
            capabilities: Vec::new(),
            signatures: Default::default(),
            bootstrap: None,
            extensions: None,
        }
    }

    #[test]
    fn manifest_round_trip_from_tar_and_dir() {
        let manifest = sample_manifest();
        let encoded = encode_pack_manifest(&manifest).expect("encode manifest");

        let mut builder = Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(encoded.len() as u64);
        header.set_cksum();
        header.set_mode(0o644);
        builder
            .append_data(&mut header, "manifest.cbor", encoded.as_slice())
            .expect("append manifest");
        let dummy = b"wasm";
        let mut comp_header = tar::Header::new_gnu();
        comp_header.set_size(dummy.len() as u64);
        comp_header.set_cksum();
        comp_header.set_mode(0o644);
        builder
            .append_data(
                &mut comp_header,
                "components/dev.greentic.chat.wasm",
                dummy.as_slice(),
            )
            .expect("append component");
        let tar_bytes = builder.into_inner().expect("tar bytes");

        let from_bytes = load_pack_manifest_from_bytes(&encode_pack_manifest(&manifest).unwrap())
            .expect("decode manifest");
        assert_eq!(from_bytes.pack_id, manifest.pack_id);

        let base = env::current_dir().expect("cwd").join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let manifest_path = dir.path().join("manifest.cbor");
        fs::write(&manifest_path, &encoded).expect("write manifest");
        fs::create_dir(dir.path().join("components")).expect("mkdir components");
        fs::write(
            dir.path().join("components/dev.greentic.chat.wasm"),
            b"wasm",
        )
        .expect("write component");

        let mut tar_file = tempfile::NamedTempFile::new().expect("temp tar");
        tar_file.write_all(&tar_bytes).expect("write tar");

        let decoded_tar = {
            let mut source = PackSource::open(tar_file.path()).expect("open tar source");
            source.read_manifest().expect("read tar manifest")
        };
        assert_eq!(decoded_tar.pack_id, manifest.pack_id);
        let decoded_dir = {
            let mut source = PackSource::open(dir.path()).expect("open dir source");
            source.read_manifest().expect("read dir manifest")
        };
        assert_eq!(decoded_dir.pack_id, manifest.pack_id);
    }

    #[test]
    fn helpers_filter_flows_and_components() {
        let manifest = sample_manifest();
        let messaging: Vec<_> = messaging_flows(&manifest).collect();
        let http: Vec<_> = http_flows(&manifest).collect();
        let config: Vec<_> = config_flows(&manifest).collect();

        assert_eq!(messaging.len(), 1);
        assert_eq!(http.len(), 1);
        assert_eq!(config.len(), 1);

        let components = components_for_deployment(&manifest);
        assert_eq!(components.len(), 2);
        let external = external_facing_components(&manifest);
        assert_eq!(external.len(), 1);
        assert_eq!(
            external[0].id,
            ComponentId::from_str("dev.greentic.chat").unwrap()
        );
    }

    #[test]
    fn runner_plan_respects_resource_hints() {
        let mut manifest = sample_manifest();
        // Set resource hints to drive replicas > 1.
        if let Some(component) = manifest
            .components
            .iter_mut()
            .find(|c| c.id == ComponentId::from_str("dev.greentic.chat").unwrap())
        {
            component.resources.cpu_millis = Some(256);
            component.resources.memory_mb = Some(512);
            component.resources.average_latency_ms = Some(10);
        }
        let runners = build_runner_plan(&manifest);
        let chat = runners
            .iter()
            .find(|r| r.name == "dev.greentic.chat")
            .expect("runner present");
        assert!(
            chat.replicas >= 2,
            "low-latency components scale up replicas"
        );
        assert_eq!(
            chat.capabilities.get("cpu_millis").and_then(|v| v.as_u64()),
            Some(256)
        );
        assert_eq!(
            chat.capabilities.get("memory_mb").and_then(|v| v.as_u64()),
            Some(512)
        );
    }

    #[test]
    fn library_pack_skips_runners_and_channels() {
        let mut manifest = sample_manifest();
        manifest.kind = PackKind::Library;
        let config = default_config(PathBuf::from("."));
        let plan = plan_from_pack_kind(&manifest, &config);
        assert!(plan.runners.is_empty());
        assert!(plan.channels.is_empty());
        assert_eq!(plan.pack_id, manifest.pack_id.to_string());
    }

    #[test]
    fn provider_plan_drops_channels_but_keeps_runners() {
        let mut manifest = sample_manifest();
        manifest.kind = PackKind::Provider;
        let config = default_config(PathBuf::from("."));
        let plan = plan_from_pack_kind(&manifest, &config);
        assert!(
            plan.channels.is_empty(),
            "provider packs should not expose channels"
        );
        assert!(!plan.runners.is_empty(), "provider packs keep runners");
    }

    #[test]
    fn infrastructure_plan_has_no_messaging() {
        let mut manifest = sample_manifest();
        manifest.kind = PackKind::Infrastructure;
        let config = default_config(PathBuf::from("."));
        let plan = plan_from_pack_kind(&manifest, &config);
        assert!(plan.messaging.is_none(), "infra packs drop messaging plan");
    }

    struct MemorySource {
        bytes: Vec<u8>,
    }

    impl DistributorSource for MemorySource {
        fn fetch_pack(
            &self,
            _pack_id: &PackId,
            _version: &Version,
        ) -> std::result::Result<Vec<u8>, greentic_distributor_client::error::DistributorError>
        {
            Ok(self.bytes.clone())
        }

        fn fetch_component(
            &self,
            _component_id: &greentic_distributor_client::ComponentId,
            _version: &Version,
        ) -> std::result::Result<Vec<u8>, greentic_distributor_client::error::DistributorError>
        {
            Err(greentic_distributor_client::error::DistributorError::NotFound)
        }
    }

    #[test]
    fn registry_source_can_load_manifest() {
        let manifest = sample_manifest();
        let encoded = encode_pack_manifest(&manifest).expect("encode manifest");
        let source = MemorySource { bytes: encoded };
        let pack_id = PackId::try_from("dev.greentic.sample").unwrap();
        let reference = PackRef::new(
            pack_id.to_string(),
            Version::new(0, 1, 0),
            "sha256:deadbeef",
        );
        let decoded = read_manifest_from_registry(&source, &reference).expect("registry decode");
        assert_eq!(decoded.pack_id, manifest.pack_id);
    }

    #[test]
    fn build_plan_uses_registry_when_pack_ref_set() {
        let manifest = sample_manifest();
        let encoded = encode_pack_manifest(&manifest).expect("encode manifest");
        let source = MemorySource { bytes: encoded };
        set_distributor_source(Arc::new(source));

        let config = registry_config();

        let plan = build_plan(&config).expect("plan builds via registry");
        assert_eq!(plan.plan.pack_id, manifest.pack_id.to_string());
    }

    fn registry_config() -> DeployerConfig {
        DeployerConfig {
            capability: DeployerCapability::Plan,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path: PathBuf::from("unused.gtpack"),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: None,
            pack_ref: Some(PackRef::new(
                "dev.greentic.sample",
                Version::new(0, 1, 0),
                "sha256:deadbeef",
            )),
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: OutputFormat::Text,
            greentic: greentic_config::ConfigResolver::new()
                .load()
                .expect("load default config")
                .config,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: None,
            bundle_digest: None,
            repo_registry_base: None,
            store_registry_base: None,
        }
    }

    fn default_config(pack_path: PathBuf) -> DeployerConfig {
        DeployerConfig {
            capability: DeployerCapability::Plan,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path,
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: None,
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: OutputFormat::Text,
            greentic: greentic_config::ConfigResolver::new()
                .load()
                .expect("load default config")
                .config,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: None,
            bundle_digest: None,
            repo_registry_base: None,
            store_registry_base: None,
        }
    }
}
