//! Opt-in native Linux host deployment. Requests never grant host access.
//!
//! The legacy single-VM entrypoints remain unchanged. This format requires a
//! separately provisioned, root-owned policy and staged local artifacts.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use greentic_types::deployment::host::{
    HostArchitecture, HostDeviceAccess, HostNetworkMode, HostPortBind, HostPortProtocol,
    HostRequirements, HostRequirementsVersion,
};
use serde::{Deserialize, Serialize};

use crate::error::{DeployerError, Result};
use crate::single_vm::{SingleVmPlanOutput, build_single_vm_host_base, render_single_vm_plan};
use crate::spec::{DeploymentSpecV1, LinuxArch};

const MAX_CONFIG_BYTES: u64 = 65_536;

mod transaction;
pub use transaction::{HostApplyReport, apply};

/// Explicit host envelope; ordinary v1 single-VM specs still reject ARM64.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSingleVmSpec {
    pub schema_version: HostRequirementsVersion,
    pub deployment: DeploymentSpecV1,
    pub host: HostRequirements,
}

/// Operator configuration, provisioned independently of packs and extensions.
/// Equality with the complete approved spec prevents a pack from reusing an
/// allowlisted device for a different image or replacing approved mounts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDeploymentPolicy {
    pub schema_version: HostRequirementsVersion,
    pub approved: HostSingleVmSpec,
    pub workload_uid: u32,
    pub workload_gid: u32,
    /// Operator-approved persistent-data compatibility contract. Changes need a
    /// separate migration workflow; service rollback never downgrades it.
    pub storage_contract: String,
    /// SHA-256 of the staged bundle, independent of its pathname.
    pub bundle_sha256: String,
    /// Local health-client identity; private key never enters a plan or bundle.
    pub health_client_certificate: PathBuf,
    pub health_client_key: PathBuf,
}

/// Facts captured locally, not supplied by a pack or a serialized plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NativeHostEvidence {
    os: String,
    architecture: String,
    image_id: String,
    bundle_sha256: String,
    paths: Vec<NativePathEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct NativePathEvidence {
    requested: PathBuf,
    resolved: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// Read-only preview. Cannot be deserialized and used as an authorization.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatedHostPlan {
    output: SingleVmPlanOutput,
    evidence: NativeHostEvidence,
    workload_uid: u32,
    workload_gid: u32,
}

fn denied(message: impl Into<String>) -> DeployerError {
    DeployerError::Config(format!("host deployment: {}", message.into()))
}

impl HostSingleVmSpec {
    pub fn from_path(path: &Path) -> Result<Self> {
        let bytes = read_bounded(path)?;
        let spec: Self = serde_yaml_bw::from_slice(&bytes)
            .map_err(|err| denied(format!("invalid host specification: {err}")))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        self.deployment.validate_for_host()?;
        self.host
            .validate()
            .map_err(|err| denied(format!("invalid host requirements: {err:?}")))?;
        if self.host.sockets.iter().any(|s| {
            s.source != "/run/dbus/system_bus_socket" || s.target != "/run/dbus/system_bus_socket"
        }) {
            return Err(denied(
                "this host adapter supports only the explicitly approved system D-Bus socket; engine/control sockets are unsupported",
            ));
        }
        let d = &self.deployment.spec;
        if d.runtime.admin.bind != "127.0.0.1:8433" {
            return Err(denied(
                "host mode requires the explicit IPv4 loopback admin binding",
            ));
        }
        let name = &self.deployment.metadata.name;
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || name.ends_with('-')
            || name.contains("--")
        {
            return Err(denied(
                "host deployment names must use canonical lowercase letters, digits and single hyphens",
            ));
        }
        let arch = match d.runtime.arch {
            LinuxArch::X86_64 => HostArchitecture::X86_64,
            LinuxArch::Aarch64 => HostArchitecture::Aarch64,
        };
        if self.host.architecture != arch {
            return Err(denied("host and runtime architectures disagree"));
        }
        // The existing runtime's admin readiness endpoint requires reachable
        // loopback mTLS. No-network workloads need a different supported probe.
        if self.host.network == HostNetworkMode::None {
            return Err(denied(
                "network=none is not supported by the single-VM mTLS health probe",
            ));
        }
        if self.host.health.port != 8433
            || self.host.health.path != d.health.readiness_path
            || u64::from(self.host.health.startup_timeout_seconds)
                != d.health.startup_timeout_seconds
        {
            return Err(denied(
                "host readiness must match the runtime's loopback mTLS endpoint",
            ));
        }
        if !self.host.ports.iter().any(|p| {
            p.host_port == 8433
                && p.workload_port == 8433
                && p.protocol == HostPortProtocol::Tcp
                && p.bind == HostPortBind::Loopback
        }) {
            return Err(denied("declare the loopback TCP admin port 8433"));
        }
        if self.host.ports.iter().any(|p| {
            p.workload_port == 8433
                && (p.host_port != 8433
                    || p.bind != HostPortBind::Loopback
                    || p.protocol != HostPortProtocol::Tcp)
        }) {
            return Err(denied(
                "the admin endpoint must never be published beyond loopback",
            ));
        }
        if d.service.user != "root" || d.service.group != "root" {
            return Err(denied(
                "Docker/systemd supervision requires the root host service identity; the workload remains non-root",
            ));
        }
        let image = &d.runtime.image;
        let Some(digest) = image
            .rsplit_once("@sha256:")
            .map(|(_, digest)| digest)
            .or_else(|| image.strip_prefix("sha256:"))
        else {
            return Err(denied("runtime image must be pinned by sha256 digest"));
        };
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(denied("runtime image digest must contain 64 hex digits"));
        }
        if local_bundle_path(&d.bundle.source).is_none() {
            return Err(denied("stage the bundle locally before host planning"));
        }
        let reserved = [
            local_bundle_path(&d.bundle.source).unwrap().to_owned(),
            d.runtime.admin.mtls.ca_file.clone(),
            d.runtime.admin.mtls.cert_file.clone(),
            d.runtime.admin.mtls.key_file.clone(),
            PathBuf::from("/mnt/greentic/bundles").join(&self.deployment.metadata.name),
        ];
        for target in self
            .host
            .devices
            .iter()
            .map(|m| &m.target)
            .chain(self.host.sockets.iter().map(|m| &m.target))
            .chain(self.host.mounts.iter().map(|m| &m.target))
        {
            let target = Path::new(target);
            if reserved
                .iter()
                .any(|p| p.starts_with(target) || target.starts_with(p))
            {
                return Err(denied(
                    "host mappings must not shadow staged bundle or mTLS credential paths",
                ));
            }
        }
        // Base renderer already mounts these four directories. Requiring exact
        // declarations avoids implicit persistence or additional access.
        let storage = [
            &d.storage.state_dir,
            &d.storage.cache_dir,
            &d.storage.log_dir,
            &d.storage.temp_dir,
        ];
        if storage.iter().enumerate().any(|(i, p)| {
            storage
                .iter()
                .skip(i + 1)
                .any(|q| p.starts_with(q) || q.starts_with(p))
        }) {
            return Err(denied("runtime storage directories must not overlap"));
        }
        for path in storage {
            if !self.host.mounts.iter().any(|m| {
                Path::new(&m.source) == path && Path::new(&m.target) == path && !m.read_only
            }) {
                return Err(denied(
                    "every runtime storage directory requires an explicit writable identity mapping",
                ));
            }
        }
        Ok(())
    }
}

fn local_bundle_path(source: &str) -> Option<&Path> {
    source
        .strip_prefix("file://")
        .or_else(|| source.starts_with('/').then_some(source))
        .map(Path::new)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(denied("configuration or credential file exceeds 64 KiB"));
    }
    Ok(bytes)
}

impl HostDeploymentPolicy {
    pub fn from_path(path: &Path) -> Result<Self> {
        verify_root_owned_path(path)?;
        let policy: Self = serde_json::from_slice(&read_bounded(path)?)?;
        policy.approve(&policy.approved)?;
        Ok(policy)
    }

    fn approve(&self, spec: &HostSingleVmSpec) -> Result<()> {
        spec.validate()?;
        if &self.approved != spec {
            return Err(denied(
                "request differs from the operator-approved deployment",
            ));
        }
        if self.workload_uid == 0 || self.workload_gid == 0 {
            return Err(denied("workload UID and GID must be nonzero"));
        }
        if self.bundle_sha256.len() != 64
            || !self
                .bundle_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(denied(
                "policy bundle_sha256 must contain 64 lowercase hex digits",
            ));
        }
        if self.storage_contract.is_empty()
            || self.storage_contract.len() > 128
            || !self
                .storage_contract
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(denied(
                "storage contract must be a bounded literal identifier",
            ));
        }
        if spec.host.mounts.iter().any(|m| {
            !m.read_only && (m.owner_uid != self.workload_uid || m.owner_gid != self.workload_gid)
        }) {
            return Err(denied(
                "writable mounts must be owned by the workload UID/GID",
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn verify_root_owned_path(path: &Path) -> Result<()> {
    verify_root_owned_entry(path, false)
}

#[cfg(unix)]
fn verify_root_owned_entry(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(denied(
            "operator policy/credential path must be absolute and free of symlinks",
        ));
    }
    for entry in path.ancestors() {
        let meta = fs::symlink_metadata(entry)?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(denied(
                "operator policy/credential and ancestors must be root-owned and not group/world writable",
            ));
        }
    }
    let meta = fs::metadata(path)?;
    if (directory && !meta.is_dir()) || (!directory && !meta.is_file()) {
        return Err(denied("operator policy/credential must be a regular file"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_root_owned_path(_path: &Path) -> Result<()> {
    Err(denied("native Linux host policy is unavailable on this OS"))
}

/// Plan and preview deliberately use the same fresh native preflight as apply.
pub fn plan(spec_path: &Path, policy_path: &Path) -> Result<ValidatedHostPlan> {
    let spec = HostSingleVmSpec::from_path(spec_path)?;
    let policy = HostDeploymentPolicy::from_path(policy_path)?;
    prepare(&spec, &policy)
}

fn prepare(spec: &HostSingleVmSpec, policy: &HostDeploymentPolicy) -> Result<ValidatedHostPlan> {
    policy.approve(spec)?;
    let evidence = probe_native(spec, policy)?;
    transaction::validate_health_identity(spec, policy)?;
    let base = build_single_vm_host_base(&spec.deployment)?;
    let mut output = render_single_vm_plan(&base);
    let flags = render_host_flags(spec, policy, &evidence)?;
    let unit = &mut output.files[0].contents;
    if unit.matches("  -p 127.0.0.1:8433:8433 \\\n").count() != 1
        || unit.matches("  --read-only \\\n").count() != 1
        || unit.matches("/usr/bin/docker run ").count() != 1
        || unit.matches("/usr/bin/docker stop ").count() != 1
    {
        return Err(denied(
            "base renderer changed; host restrictions cannot be applied safely",
        ));
    }
    // Replace the legacy implicit port with the fully declared mappings.
    *unit = unit.replace("  -p 127.0.0.1:8433:8433 \\\n", "");
    *unit = unit.replacen(
        "  --read-only \\\n",
        &format!("  --read-only \\\n{flags}"),
        1,
    );
    *unit = unit.replace(
        "/usr/bin/docker ",
        "/usr/bin/docker --host unix:///var/run/docker.sock ",
    );
    if spec.host.network == HostNetworkMode::Bridge {
        // Host publication stays on 127.0.0.1. The runtime must listen on the
        // container interface so Docker's isolated bridge can forward to it.
        for line in ["GREENTIC_ADMIN_BIND", "GREENTIC_ADMIN_LISTEN"] {
            let old = format!("{line}={}\n", spec.deployment.spec.runtime.admin.bind);
            output.files[1].contents = output.files[1]
                .contents
                .replace(&old, &format!("{line}=0.0.0.0:8433\n"));
        }
    }
    let plan = ValidatedHostPlan {
        output,
        evidence,
        workload_uid: policy.workload_uid,
        workload_gid: policy.workload_gid,
    };
    transaction::validate_preview(&plan, policy)?;
    Ok(plan)
}

fn docker_output(args: &[&str]) -> Result<String> {
    // Fixed local daemon: environment contexts cannot redirect verified local
    // paths to a remote Docker host.
    let mut command = Command::new("/usr/bin/docker");
    command
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_HOST")
        .args(["--host", "unix:///var/run/docker.sock"])
        .args(args);
    let output = transaction::command_output(command, std::time::Duration::from_secs(10))?;
    if !output.status.success() {
        return Err(denied(
            "local Docker inspection failed; stage required images before deployment",
        ));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| denied("invalid Docker inspection output"))
}

#[cfg(unix)]
fn observe_path(path: &Path, symlink_allowed: bool) -> Result<(NativePathEvidence, fs::Metadata)> {
    use std::os::unix::fs::MetadataExt;
    let resolved = fs::canonicalize(path)?;
    if !symlink_allowed && resolved != path {
        return Err(denied(
            "persistent and credential paths must not traverse symlinks",
        ));
    }
    // Only a leaf character-device alias may be resolved. Unprivileged users
    // must not be able to swap a mapped path's parents between probe and start.
    for candidate in [path, resolved.as_path()] {
        verify_root_owned_entry(
            candidate
                .parent()
                .ok_or_else(|| denied("missing host path parent"))?,
            true,
        )?;
    }
    let meta = fs::metadata(&resolved)?;
    Ok((
        NativePathEvidence {
            requested: path.to_owned(),
            resolved,
            device: meta.dev(),
            inode: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
        },
        meta,
    ))
}

#[cfg(unix)]
fn probe_native(
    spec: &HostSingleVmSpec,
    policy: &HostDeploymentPolicy,
) -> Result<NativeHostEvidence> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let (arch, docker_arch) = match spec.host.architecture {
        HostArchitecture::Aarch64 => ("aarch64", "arm64"),
        HostArchitecture::X86_64 => ("x86_64", "amd64"),
    };
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != arch {
        return Err(denied(format!("requires native Linux/{arch}")));
    }
    let image_platform = docker_output(&[
        "image",
        "inspect",
        &spec.deployment.spec.runtime.image,
        "--format",
        "{{.Os}}/{{.Architecture}}",
    ])?;
    if image_platform != format!("linux/{docker_arch}") {
        return Err(denied(
            "staged image architecture does not match the native host",
        ));
    }
    let image_id = docker_output(&[
        "image",
        "inspect",
        &spec.deployment.spec.runtime.image,
        "--format",
        "{{.Id}}",
    ])?;
    let mut paths = Vec::new();
    let mut observe = |path: &Path, symlink_allowed: bool| -> Result<fs::Metadata> {
        let (evidence, meta) = observe_path(path, symlink_allowed)?;
        paths.push(evidence);
        Ok(meta)
    };
    for device in &spec.host.devices {
        let meta = observe(Path::new(&device.source), true)?;
        let required = if device.access == HostDeviceAccess::Read {
            0o040
        } else {
            0o060
        };
        if !meta.file_type().is_char_device()
            || meta.gid() == 0
            || meta.mode() & required != required
        {
            return Err(denied(
                "requested device is missing or is not a character device",
            ));
        }
    }
    for socket in &spec.host.sockets {
        if !observe(Path::new(&socket.source), false)?
            .file_type()
            .is_socket()
        {
            return Err(denied(
                "requested socket is missing or is not a Unix socket",
            ));
        }
    }
    for mount in &spec.host.mounts {
        let meta = observe(Path::new(&mount.source), false)?;
        let shift = if meta.uid() == policy.workload_uid {
            6
        } else if meta.gid() == policy.workload_gid {
            3
        } else {
            0
        };
        let required = if mount.read_only { 5 } else { 7 };
        if !meta.is_dir()
            || meta.uid() != mount.owner_uid
            || meta.gid() != mount.owner_gid
            || meta.mode() & 0o022 != 0
            || (meta.mode() >> shift) & required != required
        {
            return Err(denied(
                "persistent mount must be an existing directory with the declared owner and protected permissions",
            ));
        }
    }
    let d = &spec.deployment.spec;
    let bundle =
        local_bundle_path(&d.bundle.source).ok_or_else(|| denied("local bundle required"))?;
    for path in [
        bundle,
        &d.runtime.admin.mtls.ca_file,
        &d.runtime.admin.mtls.cert_file,
    ] {
        let meta = observe(path, false)?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || meta.mode() & 0o004 == 0
        {
            return Err(denied(
                "staged bundle and public mTLS certificates must be protected root-owned regular files readable by the workload",
            ));
        }
    }
    let bundle_sha256 = hash_bundle(bundle)?;
    if bundle_sha256 != policy.bundle_sha256 {
        return Err(denied(
            "staged bundle digest differs from the operator-approved artifact",
        ));
    }
    let key = observe(&d.runtime.admin.mtls.key_file, false)?;
    if !key.is_file()
        || key.uid() != 0
        || key.gid() != policy.workload_gid
        || key.mode() & 0o037 != 0
        || key.mode() & 0o040 == 0
    {
        return Err(denied(
            "server private key must be root-owned, readable by the workload group and inaccessible to others",
        ));
    }
    let bundle_mount = build_single_vm_host_base(&spec.deployment)?
        .bundle
        .mount_path;
    let mount = observe(&bundle_mount, false)?;
    if !mount.is_dir()
        || mount.uid() != 0
        || mount.mode() & 0o022 != 0
        || mount.mode() & 0o005 != 0o005
    {
        return Err(denied(
            "provision a protected root-owned bundle mount directory before planning",
        ));
    }
    verify_root_owned_path(&policy.health_client_certificate)?;
    verify_root_owned_path(&policy.health_client_key)?;
    if fs::metadata(&policy.health_client_key)?.mode() & 0o077 != 0 {
        return Err(denied(
            "health-client private key must be accessible only to root",
        ));
    }
    Ok(NativeHostEvidence {
        os: "linux".into(),
        architecture: arch.into(),
        image_id,
        bundle_sha256,
        paths,
    })
}

fn hash_bundle(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    const LIMIT: u64 = 512 * 1024 * 1024;
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > LIMIT {
        return Err(denied("staged bundle exceeds 512 MiB"));
    }
    let mut reader = file.take(LIMIT + 1);
    let mut hash = Sha256::new();
    let mut total = 0;
    let mut buffer = [0u8; 8192];
    loop {
        let size = reader.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        total += size as u64;
        if total > LIMIT {
            return Err(denied("staged bundle grew beyond its size bound"));
        }
        hash.update(&buffer[..size]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(not(unix))]
fn probe_native(
    _spec: &HostSingleVmSpec,
    _policy: &HostDeploymentPolicy,
) -> Result<NativeHostEvidence> {
    Err(denied(
        "native Linux host deployment is unavailable on this OS",
    ))
}

fn render_host_flags(
    spec: &HostSingleVmSpec,
    policy: &HostDeploymentPolicy,
    facts: &NativeHostEvidence,
) -> Result<String> {
    let mut args = vec![
        format!("--user {}:{}", policy.workload_uid, policy.workload_gid),
        "--cap-drop ALL".into(),
        "--security-opt no-new-privileges:true".into(),
        "--pull never".into(),
        format!(
            "--platform linux/{}",
            match spec.host.architecture {
                HostArchitecture::Aarch64 => "arm64",
                HostArchitecture::X86_64 => "amd64",
            }
        ),
        format!(
            "--network {}",
            match spec.host.network {
                HostNetworkMode::Bridge => "bridge",
                HostNetworkMode::Host => "host",
                HostNetworkMode::None => return Err(denied("unsupported network mode")),
            }
        ),
    ];
    let storage = &spec.deployment.spec.storage;
    for device in &spec.host.devices {
        let resolved = facts
            .paths
            .iter()
            .find(|p| p.requested == Path::new(&device.source))
            .ok_or_else(|| denied("missing native device evidence"))?;
        let path = resolved
            .resolved
            .to_str()
            .ok_or_else(|| denied("non-UTF8 device path"))?;
        // Canonical device paths also pass the shared exact-path validator.
        let mut checked = spec.host.clone();
        checked
            .devices
            .iter_mut()
            .find(|d| d.source == device.source)
            .unwrap()
            .source = path.into();
        checked
            .validate()
            .map_err(|_| denied("unsafe resolved device path"))?;
        args.push(format!(
            "--device {}:{}:{}",
            path,
            device.target,
            match device.access {
                HostDeviceAccess::Read => "r",
                HostDeviceAccess::ReadWrite => "rw",
            }
        ));
        args.push(format!("--group-add {}", resolved.gid));
    }
    for socket in &spec.host.sockets {
        args.push(format!(
            "--mount type=bind,source={},target={}",
            socket.source, socket.target
        ));
    }
    for mount in &spec.host.mounts {
        if [
            &storage.state_dir,
            &storage.cache_dir,
            &storage.log_dir,
            &storage.temp_dir,
        ]
        .iter()
        .any(|p| **p == Path::new(&mount.source))
        {
            continue;
        }
        args.push(format!(
            "--mount type=bind,source={},target={}{}",
            mount.source,
            mount.target,
            if mount.read_only { ",readonly" } else { "" }
        ));
    }
    if spec.host.network == HostNetworkMode::Bridge {
        for port in &spec.host.ports {
            args.push(format!(
                "--publish {}:{}:{}/{}",
                match port.bind {
                    HostPortBind::Loopback => "127.0.0.1",
                    HostPortBind::AllInterfaces => "0.0.0.0",
                },
                port.host_port,
                port.workload_port,
                match port.protocol {
                    HostPortProtocol::Tcp => "tcp",
                    HostPortProtocol::Udp => "udp",
                }
            ));
        }
    }
    Ok(args
        .into_iter()
        .map(|arg| format!("  {arg} \\\n"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_types::deployment::host::*;

    pub(super) fn fixture() -> (HostSingleVmSpec, HostDeploymentPolicy) {
        let mut deployment =
            DeploymentSpecV1::from_yaml_str(include_str!("../examples/single-vm.deployment.yaml"))
                .unwrap();
        deployment.spec.runtime.arch = LinuxArch::Aarch64;
        deployment.spec.runtime.image =
            format!("registry.example/runtime@sha256:{}", "a".repeat(64));
        deployment.spec.service.user = "root".into();
        deployment.spec.service.group = "root".into();
        let storage = &deployment.spec.storage;
        let mounts = [
            &storage.state_dir,
            &storage.cache_dir,
            &storage.log_dir,
            &storage.temp_dir,
        ]
        .into_iter()
        .map(|p| HostPersistentMount {
            source: p.display().to_string(),
            target: p.display().to_string(),
            read_only: false,
            owner_uid: 1000,
            owner_gid: 1000,
        })
        .collect();
        let spec = HostSingleVmSpec {
            schema_version: HostRequirementsVersion::V1,
            deployment,
            host: HostRequirements {
                schema_version: HostRequirementsVersion::V1,
                os: HostOperatingSystem::Linux,
                architecture: HostArchitecture::Aarch64,
                network: HostNetworkMode::Bridge,
                devices: vec![],
                sockets: vec![],
                mounts,
                ports: vec![HostPort {
                    host_port: 8433,
                    workload_port: 8433,
                    protocol: HostPortProtocol::Tcp,
                    bind: HostPortBind::Loopback,
                }],
                health: HostHealthRequirement {
                    port: 8433,
                    path: "/ready".into(),
                    startup_timeout_seconds: 120,
                },
            },
        };
        let policy = HostDeploymentPolicy {
            schema_version: HostRequirementsVersion::V1,
            approved: spec.clone(),
            workload_uid: 1000,
            workload_gid: 1000,
            storage_contract: "simulator-v1".into(),
            bundle_sha256: "b".repeat(64),
            health_client_certificate: "/etc/greentic/health-client.crt".into(),
            health_client_key: "/etc/greentic/health-client.key".into(),
        };
        (spec, policy)
    }

    pub(super) fn facts() -> NativeHostEvidence {
        NativeHostEvidence {
            os: "linux".into(),
            architecture: "aarch64".into(),
            image_id: "fixture-image".into(),
            bundle_sha256: "b".repeat(64),
            paths: vec![],
        }
    }

    #[test]
    fn arm64_is_opt_in_and_policy_is_bound_to_the_complete_request() {
        let (spec, policy) = fixture();
        spec.validate().unwrap();
        assert!(spec.deployment.validate().is_err());
        policy.approve(&spec).unwrap();
        let mut changed = spec.clone();
        changed.deployment.spec.runtime.image =
            format!("registry.example/other@sha256:{}", "b".repeat(64));
        assert!(policy.approve(&changed).is_err());
        changed = spec.clone();
        changed.host.network = HostNetworkMode::Host;
        assert!(policy.approve(&changed).is_err());
        let mut root = policy.clone();
        root.workload_uid = 0;
        assert!(root.approve(&spec).is_err());
        root = policy.clone();
        root.workload_gid = 0;
        assert!(root.approve(&spec).is_err());
        root = policy;
        root.workload_uid = 2000;
        assert!(root.approve(&spec).is_err());
    }

    #[test]
    fn unsupported_or_contradictory_host_requests_fail_closed() {
        let (spec, _) = fixture();
        for mutate in [
            |s: &mut HostSingleVmSpec| s.host.architecture = HostArchitecture::X86_64,
            |s: &mut HostSingleVmSpec| s.host.network = HostNetworkMode::None,
            |s: &mut HostSingleVmSpec| s.host.ports[0].bind = HostPortBind::AllInterfaces,
            |s: &mut HostSingleVmSpec| s.host.mounts.clear(),
            |s: &mut HostSingleVmSpec| {
                s.deployment.spec.bundle.source = "https://example.org/bundle".into()
            },
            |s: &mut HostSingleVmSpec| {
                s.deployment.spec.runtime.image = "registry.example/runtime:latest".into()
            },
            |s: &mut HostSingleVmSpec| s.host.health.path = "/different".into(),
            |s: &mut HostSingleVmSpec| s.deployment.metadata.name = "prod_blue".into(),
        ] {
            let mut changed = spec.clone();
            mutate(&mut changed);
            assert!(changed.validate().is_err());
        }
        let mut value = serde_json::to_value(&spec).unwrap();
        value["host"]["privileged"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HostSingleVmSpec>(value).is_err());
    }

    #[test]
    fn rendered_flags_are_bounded_and_never_grant_device_node_creation() {
        let (mut spec, mut policy) = fixture();
        spec.host.devices.push(HostDeviceMapping {
            source: "/dev/serial/by-id/coordinator".into(),
            target: "/dev/zigbee".into(),
            access: HostDeviceAccess::ReadWrite,
        });
        spec.host.sockets.push(HostSocketMapping {
            source: "/run/dbus/system_bus_socket".into(),
            target: "/run/dbus/system_bus_socket".into(),
        });
        policy.approved = spec.clone();
        let mut native = facts();
        native.paths.push(NativePathEvidence {
            requested: "/dev/serial/by-id/coordinator".into(),
            resolved: "/dev/ttyUSB0".into(),
            device: 1,
            inode: 2,
            uid: 0,
            gid: 20,
            mode: 0o660,
        });
        let flags = render_host_flags(&spec, &policy, &native).unwrap();
        for expected in [
            "--user 1000:1000",
            "--cap-drop ALL",
            "--security-opt no-new-privileges:true",
            "--pull never",
            "--platform linux/arm64",
            "--device /dev/ttyUSB0:/dev/zigbee:rw",
            "--group-add 20",
            "--publish 127.0.0.1:8433:8433/tcp",
        ] {
            assert!(flags.contains(expected), "{expected}");
        }
        assert!(!flags.contains("rwm"));
        assert!(!flags.contains("--privileged"));
        native.paths[0].resolved = "/dev/ttyUSB0 --privileged".into();
        assert!(render_host_flags(&spec, &policy, &native).is_err());
    }

    #[test]
    fn foreign_native_architecture_is_rejected_before_docker_or_filesystem_access() {
        let (mut spec, mut policy) = fixture();
        if std::env::consts::ARCH == "aarch64" {
            spec.deployment.spec.runtime.arch = LinuxArch::X86_64;
            spec.host.architecture = HostArchitecture::X86_64;
        }
        policy.approved = spec.clone();
        assert!(
            prepare(&spec, &policy)
                .unwrap_err()
                .to_string()
                .contains("native Linux")
        );
    }

    #[test]
    fn oversized_input_and_untrusted_policy_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spec.json");
        fs::write(&path, vec![b' '; MAX_CONFIG_BYTES as usize + 1]).unwrap();
        assert!(
            HostSingleVmSpec::from_path(&path)
                .unwrap_err()
                .to_string()
                .contains("64 KiB")
        );
        fs::write(&path, serde_json::to_vec(&fixture().1).unwrap()).unwrap();
        assert!(HostDeploymentPolicy::from_path(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn missing_hardware_and_unprotected_mapping_ancestors_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-coordinator");
        assert!(
            matches!(observe_path(&missing, true), Err(DeployerError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound)
        );
        let file = dir.path().join("not-a-device");
        fs::write(&file, "untrusted").unwrap();
        assert!(observe_path(&fs::canonicalize(&file).unwrap(), false).is_err());
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&file, &alias).unwrap();
        assert!(observe_path(&alias, false).is_err());
    }
}
