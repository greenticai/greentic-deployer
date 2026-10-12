//! Durable service transaction. Persistent workload directories are never
//! deleted, restored from a service backup, or recursively changed here.

use super::*;
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use crate::environment::atomic_write_bytes;
use crate::single_vm::SingleVmPlannedFile;

const JOURNAL_LIMIT: u64 = 512 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct HostApplyReport {
    service: String,
    storage_contract: String,
    healthy: bool,
    recovered_interrupted_apply: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedFile {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    mode: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: HostRequirementsVersion,
    service: String,
    files: Vec<SavedFile>,
    enabled: bool,
    active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    schema_version: HostRequirementsVersion,
    storage_contract: String,
    image_id: String,
}

trait ServiceControl {
    fn enabled(&mut self, service: &str) -> Result<bool>;
    fn active(&mut self, service: &str) -> Result<bool>;
    fn run(&mut self, action: &str, service: Option<&str>) -> Result<()>;
    fn healthy(&mut self) -> Result<()>;
    fn pre_launch(&mut self) -> Result<()>;
}

struct NativeService {
    client: reqwest::blocking::Client,
    health_url: String,
    deadline: Duration,
    launch_check: Option<(
        HostSingleVmSpec,
        HostDeploymentPolicy,
        PathBuf,
        NativeHostEvidence,
    )>,
}

pub(super) fn command_output(mut command: Command, timeout: Duration) -> Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map_err(Into::into);
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(denied("native service command timed out"));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn systemctl(action: &str, service: Option<&str>) -> Result<Output> {
    let mut command = Command::new("/usr/bin/systemctl");
    command.arg(action);
    if let Some(service) = service {
        command.arg(service);
    }
    command_output(command, Duration::from_secs(30))
}

impl ServiceControl for NativeService {
    fn pre_launch(&mut self) -> Result<()> {
        let (spec, policy, path, previous) = self
            .launch_check
            .as_ref()
            .ok_or_else(|| denied("missing launch preflight"))?;
        let current = HostDeploymentPolicy::from_path(path)?;
        if &current != policy || &probe_native(spec, &current)? != previous {
            return Err(denied(
                "operator policy, artifacts or native mappings changed since planning",
            ));
        }
        Ok(())
    }
    fn enabled(&mut self, service: &str) -> Result<bool> {
        let output = systemctl("is-enabled", Some(service))?;
        match String::from_utf8_lossy(&output.stdout).trim() {
            "enabled" => Ok(true),
            "disabled" | "not-found" => Ok(false),
            _ => Err(denied(
                "unsupported existing service enablement state (masked/static/indirect or query failure)",
            )),
        }
    }

    fn active(&mut self, service: &str) -> Result<bool> {
        let output = systemctl("is-active", Some(service))?;
        match String::from_utf8_lossy(&output.stdout).trim() {
            "active" => Ok(true),
            "inactive" | "failed" | "unknown" => Ok(false),
            _ => Err(denied(
                "service is transitioning or its state could not be inspected",
            )),
        }
    }

    fn run(&mut self, action: &str, service: Option<&str>) -> Result<()> {
        if !systemctl(action, service)?.status.success() {
            return Err(denied(format!("systemctl {action} failed")));
        }
        Ok(())
    }

    fn healthy(&mut self) -> Result<()> {
        let start = Instant::now();
        while start.elapsed() < self.deadline {
            let remaining = self.deadline.saturating_sub(start.elapsed());
            if self
                .client
                .get(&self.health_url)
                .timeout(remaining.min(Duration::from_secs(2)))
                .send()
                .is_ok_and(|r| r.status().is_success())
            {
                return Ok(());
            }
            std::thread::sleep(
                Duration::from_millis(100).min(self.deadline.saturating_sub(start.elapsed())),
            );
        }
        Err(denied("runtime failed its bounded mTLS readiness probe"))
    }
}

impl NativeService {
    fn new(spec: &HostSingleVmSpec, policy: &HostDeploymentPolicy) -> Result<Self> {
        let ca = reqwest::Certificate::from_pem(&read_bounded(
            &spec.deployment.spec.runtime.admin.mtls.ca_file,
        )?)
        .map_err(|_| denied("invalid health CA certificate"))?;
        let mut identity = read_bounded(&policy.health_client_certificate)?;
        identity.push(b'\n');
        identity.extend(read_bounded(&policy.health_client_key)?);
        let identity = reqwest::Identity::from_pem(&identity)
            .map_err(|_| denied("invalid health-client identity"))?;
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_certs_only([ca])
            .identity(identity)
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| denied("could not initialize local mTLS health client"))?;
        Ok(Self {
            client,
            health_url: format!("https://127.0.0.1:8433{}", spec.host.health.path),
            deadline: Duration::from_secs(u64::from(spec.host.health.startup_timeout_seconds)),
            launch_check: None,
        })
    }
}

pub(super) fn validate_health_identity(
    spec: &HostSingleVmSpec,
    policy: &HostDeploymentPolicy,
) -> Result<()> {
    NativeService::new(spec, policy).map(|_| ())
}

#[cfg(unix)]
fn protected_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.exists() {
        let parent = path
            .parent()
            .ok_or_else(|| denied("invalid protected directory"))?;
        verify_root_owned_entry(parent, true)?;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        if let Err(err) = builder.create(path)
            && err.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(err.into());
        }
    }
    verify_root_owned_entry(path, true)
}

#[cfg(unix)]
fn save_file(path: &Path) -> Result<SavedFile> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(denied("service transaction refuses non-regular files"));
            }
            Ok(SavedFile {
                path: path.to_owned(),
                bytes: Some(read_bounded(path)?),
                mode: meta.mode() & 0o777,
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(SavedFile {
            path: path.to_owned(),
            bytes: None,
            mode: 0o600,
        }),
        Err(err) => Err(err.into()),
    }
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_write_bytes(path, bytes)
        .map_err(|err| denied(format!("atomic service write failed: {err}")))
}

fn remove_durable(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => fs::File::open(path.parent().ok_or_else(|| denied("missing parent"))?)?
            .sync_all()
            .map_err(Into::into),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(unix)]
fn restore(journal: &Journal, service: &mut impl ServiceControl) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Stop first. If this fails, leave the journal and refuse to rewrite a live
    // service underneath an unknown process. A later invocation can recover.
    let unit_exists = journal
        .files
        .iter()
        .any(|f| f.path.extension().is_some_and(|e| e == "service") && f.path.exists());
    if journal.active || unit_exists {
        service.run("stop", Some(&journal.service))?;
    }
    if !journal.enabled && unit_exists {
        service.run("disable", Some(&journal.service))?;
    }
    for saved in &journal.files {
        if let Some(bytes) = &saved.bytes {
            write(&saved.path, bytes)?;
            fs::set_permissions(&saved.path, fs::Permissions::from_mode(saved.mode))?;
            fs::File::open(&saved.path)?.sync_all()?;
        } else {
            remove_durable(&saved.path)?;
        }
    }
    service.run("daemon-reload", None)?;
    if journal.enabled {
        service.run("enable", Some(&journal.service))?;
    }
    if journal.active {
        service.run("restart", Some(&journal.service))?;
    }
    Ok(())
}

fn read_journal(path: &Path) -> Result<Journal> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(JOURNAL_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > JOURNAL_LIMIT {
        return Err(denied("service journal exceeds size bound"));
    }
    serde_json::from_slice(&bytes).map_err(Into::into)
}

#[cfg(unix)]
pub(super) fn validate_preview(
    plan: &ValidatedHostPlan,
    policy: &HostDeploymentPolicy,
) -> Result<()> {
    let root = Path::new("/var/lib/greentic-deployer");
    let name = &plan.output.service_unit_name;
    let state = root.join(format!("{name}.installed.json"));
    let pending = root.join(format!("{name}.pending.json"));
    if root.exists() {
        verify_root_owned_entry(root, true)?;
    }
    if state.exists() {
        verify_root_owned_path(&state)?;
    }
    if pending.exists() {
        verify_root_owned_path(&pending)?;
        let journal = read_journal(&pending)?;
        let expected = plan
            .output
            .files
            .iter()
            .map(|f| &f.path)
            .chain(std::iter::once(&state));
        if journal.service != *name || journal.files.iter().map(|f| &f.path).ne(expected) {
            return Err(denied(
                "pending recovery journal does not match this deployment",
            ));
        }
    }
    validate_storage_contract(plan, policy, &state, pending.exists())
}

#[cfg(not(unix))]
pub(super) fn validate_preview(
    _plan: &ValidatedHostPlan,
    _policy: &HostDeploymentPolicy,
) -> Result<()> {
    Err(denied("native Linux preview is unavailable on this OS"))
}

fn validate_storage_contract(
    plan: &ValidatedHostPlan,
    policy: &HostDeploymentPolicy,
    state: &Path,
    recovery_pending: bool,
) -> Result<()> {
    if state.exists() {
        let installed: Installed = serde_json::from_slice(&read_bounded(state)?)?;
        if installed.storage_contract != policy.storage_contract {
            return Err(denied(
                "storage contract change requires an explicit compatible migration; service rollback cannot downgrade data",
            ));
        }
    } else if !recovery_pending
        && plan.output.files.iter().any(|f| {
            f.kind == crate::single_vm::SingleVmPlannedFileKind::SystemdUnit && f.path.exists()
        })
    {
        return Err(denied(
            "existing unmanaged service has no storage compatibility record; explicit migration is required",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn execute_transaction(
    plan: &ValidatedHostPlan,
    policy: &HostDeploymentPolicy,
    root: &Path,
    service: &mut impl ServiceControl,
) -> Result<HostApplyReport> {
    let name = &plan.output.service_unit_name;
    let state_path = root.join(format!("{name}.installed.json"));
    let journal_path = root.join(format!("{name}.pending.json"));
    let mut expected: Vec<PathBuf> = plan.output.files.iter().map(|f| f.path.clone()).collect();
    expected.push(state_path.clone());
    let mut recovered = false;
    if journal_path.exists() {
        let journal = read_journal(&journal_path)?;
        if journal.service != *name || journal.files.iter().map(|f| &f.path).ne(expected.iter()) {
            return Err(denied(
                "service recovery journal does not match the protected transaction paths",
            ));
        }
        if journal.files.iter().any(|f| {
            f.mode & !0o755 != 0
                || f.bytes
                    .as_ref()
                    .is_some_and(|b| b.len() as u64 > MAX_CONFIG_BYTES)
        }) {
            return Err(denied("invalid protected service backup"));
        }
        restore(&journal, service)?;
        remove_durable(&journal_path)?;
        recovered = true;
    }
    validate_storage_contract(plan, policy, &state_path, false)?;
    let saved = expected
        .iter()
        .map(|p| save_file(p))
        .collect::<Result<Vec<_>>>()?;
    let journal = Journal {
        schema_version: HostRequirementsVersion::V1,
        service: name.clone(),
        files: saved,
        enabled: service.enabled(name)?,
        active: service.active(name)?,
    };
    let bytes = serde_json::to_vec(&journal)?;
    if bytes.len() as u64 > JOURNAL_LIMIT {
        return Err(denied("service backup exceeds journal limit"));
    }
    write(&journal_path, &bytes)?;
    let applied = (|| -> Result<()> {
        for SingleVmPlannedFile { path, contents, .. } in &plan.output.files {
            write(path, contents.as_bytes())?;
        }
        service.run("daemon-reload", None)?;
        service.run("enable", Some(name))?;
        service.pre_launch()?;
        service.run("restart", Some(name))?;
        service.healthy()?;
        let installed = Installed {
            schema_version: HostRequirementsVersion::V1,
            storage_contract: policy.storage_contract.clone(),
            image_id: plan.evidence.image_id.clone(),
        };
        write(&state_path, &serde_json::to_vec(&installed)?)?;
        remove_durable(&journal_path)?;
        Ok(())
    })();
    if let Err(err) = applied {
        if !journal_path.exists() {
            write(&journal_path, &bytes)?;
        }
        if let Err(rollback) = restore(&journal, service) {
            return Err(denied(format!(
                "apply failed ({err}); recovery incomplete ({rollback}); protected journal retained"
            )));
        }
        remove_durable(&journal_path)?;
        return Err(denied(format!(
            "apply failed ({err}); previous service files/state restored; workload data retained"
        )));
    }
    Ok(HostApplyReport {
        service: name.clone(),
        storage_contract: policy.storage_contract.clone(),
        healthy: true,
        recovered_interrupted_apply: recovered,
    })
}

/// Fresh policy and native preflight, exclusive service lock, durable journal,
/// bounded mTLS readiness, and service-only rollback. Never pulls an image.
#[cfg(unix)]
pub fn apply(spec_path: &Path, policy_path: &Path) -> Result<HostApplyReport> {
    use std::os::unix::fs::OpenOptionsExt;
    if std::env::consts::OS != "linux" || !rustix::process::geteuid().is_root() {
        return Err(denied(
            "native apply requires the Linux root supervisor; workloads run as the policy's non-root UID/GID",
        ));
    }
    let spec = HostSingleVmSpec::from_path(spec_path)?;
    let policy = HostDeploymentPolicy::from_path(policy_path)?;
    policy.approve(&spec)?;
    // Prepare before creating any supervisor state. Recheck after locking too.
    prepare(&spec, &policy)?;
    let root = Path::new("/var/lib/greentic-deployer");
    protected_directory(root)?;
    let name = build_single_vm_host_base(&spec.deployment)?.service_name;
    let lock_path = root.join(format!("{name}.lock"));
    if lock_path.exists() {
        verify_root_owned_path(&lock_path)?;
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&lock_path)?;
    lock.try_lock()
        .map_err(|_| denied("another deployment transaction holds the service lock"))?;
    let policy = HostDeploymentPolicy::from_path(policy_path)?;
    let plan = prepare(&spec, &policy)?;
    for file in &plan.output.files {
        protected_directory(
            file.path
                .parent()
                .ok_or_else(|| denied("missing service file parent"))?,
        )?;
        if file.path.exists() {
            verify_root_owned_path(&file.path)?;
        }
    }
    // The supervisor directory is root-only. Existing state/journals must not
    // be links or writable files supplied by the workload.
    for suffix in ["installed.json", "pending.json"] {
        let path = root.join(format!("{}.{}", plan.output.service_unit_name, suffix));
        if path.exists() {
            verify_root_owned_path(&path)?;
        }
    }
    let mut service = NativeService::new(&spec, &policy)?;
    service.launch_check = Some((
        spec,
        policy.clone(),
        policy_path.to_owned(),
        plan.evidence.clone(),
    ));
    let report = execute_transaction(&plan, &policy, root, &mut service)?;
    drop(lock);
    Ok(report)
}

#[cfg(not(unix))]
pub fn apply(_spec_path: &Path, _policy_path: &Path) -> Result<HostApplyReport> {
    Err(denied("native Linux apply is unavailable on this OS"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::single_vm::SingleVmPlannedFileKind;

    #[derive(Default)]
    struct MockService {
        calls: Vec<String>,
        fail_restart_once: bool,
        fail_health: bool,
        fail_stop: bool,
        fail_preflight: bool,
    }

    impl ServiceControl for MockService {
        fn pre_launch(&mut self) -> Result<()> {
            self.calls.push("preflight".into());
            if self.fail_preflight {
                return Err(denied("injected changed policy or native mapping"));
            }
            Ok(())
        }
        fn enabled(&mut self, _service: &str) -> Result<bool> {
            Ok(true)
        }
        fn active(&mut self, _service: &str) -> Result<bool> {
            Ok(true)
        }
        fn run(&mut self, action: &str, _service: Option<&str>) -> Result<()> {
            self.calls.push(action.into());
            if action == "restart" && self.fail_restart_once {
                self.fail_restart_once = false;
                return Err(denied("injected restart failure"));
            }
            if action == "stop" && self.fail_stop {
                return Err(denied("injected stop failure"));
            }
            Ok(())
        }
        fn healthy(&mut self) -> Result<()> {
            self.calls.push("health".into());
            if self.fail_health {
                Err(denied("injected health failure"))
            } else {
                Ok(())
            }
        }
    }

    fn fixture(root: &Path) -> (ValidatedHostPlan, HostDeploymentPolicy) {
        let (spec, policy) = super::super::tests::fixture();
        let base = build_single_vm_host_base(&spec.deployment).unwrap();
        let mut output = render_single_vm_plan(&base);
        output.files = vec![
            SingleVmPlannedFile {
                path: root.join("test.service"),
                kind: SingleVmPlannedFileKind::SystemdUnit,
                contents: "new unit".into(),
            },
            SingleVmPlannedFile {
                path: root.join("test.env"),
                kind: SingleVmPlannedFileKind::EnvironmentFile,
                contents: "new env".into(),
            },
        ];
        fs::write(&output.files[0].path, "old unit").unwrap();
        let installed = Installed {
            schema_version: HostRequirementsVersion::V1,
            storage_contract: policy.storage_contract.clone(),
            image_id: "previous-fixture-image".into(),
        };
        fs::write(
            root.join(format!("{}.installed.json", output.service_unit_name)),
            serde_json::to_vec(&installed).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("persistent.sqlite"),
            "persistent data must survive",
        )
        .unwrap();
        (
            ValidatedHostPlan {
                output,
                evidence: super::super::tests::facts(),
                workload_uid: 1000,
                workload_gid: 1000,
            },
            policy,
        )
    }

    fn pending_path(root: &Path, plan: &ValidatedHostPlan) -> PathBuf {
        root.join(format!("{}.pending.json", plan.output.service_unit_name))
    }

    #[test]
    fn mock_success_commits_only_after_health_and_refuses_storage_downgrade() {
        let dir = tempfile::tempdir().unwrap();
        let (plan, mut policy) = fixture(dir.path());
        let mut service = MockService::default();
        let report = execute_transaction(&plan, &policy, dir.path(), &mut service).unwrap();
        assert!(report.healthy);
        assert!(!report.recovered_interrupted_apply);
        assert_eq!(
            service.calls,
            ["daemon-reload", "enable", "preflight", "restart", "health"]
        );
        assert!(!pending_path(dir.path(), &plan).exists());
        let state = dir
            .path()
            .join(format!("{}.installed.json", plan.output.service_unit_name));
        let installed: Installed = serde_json::from_slice(&fs::read(state).unwrap()).unwrap();
        assert_eq!(installed.storage_contract, "simulator-v1");
        policy.storage_contract = "incompatible-v0".into();
        service.calls.clear();
        assert!(
            execute_transaction(&plan, &policy, dir.path(), &mut service)
                .unwrap_err()
                .to_string()
                .contains("migration")
        );
        assert!(service.calls.is_empty());
        assert_eq!(
            fs::read_to_string(dir.path().join("persistent.sqlite")).unwrap(),
            "persistent data must survive"
        );
    }

    #[test]
    fn startup_and_health_failures_restore_service_files_without_touching_data() {
        for health in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (plan, policy) = fixture(dir.path());
            let mut service = MockService {
                fail_restart_once: !health,
                fail_health: health,
                ..Default::default()
            };
            let err = execute_transaction(&plan, &policy, dir.path(), &mut service).unwrap_err();
            assert!(err.to_string().contains("restored"));
            assert_eq!(
                fs::read_to_string(&plan.output.files[0].path).unwrap(),
                "old unit"
            );
            assert!(!plan.output.files[1].path.exists());
            assert!(!pending_path(dir.path(), &plan).exists());
            assert_eq!(
                fs::read_to_string(dir.path().join("persistent.sqlite")).unwrap(),
                "persistent data must survive"
            );
            assert!(service.calls.iter().any(|c| c == "stop"));
        }
    }

    #[test]
    fn changed_preflight_restores_previous_service_without_launching_update() {
        let dir = tempfile::tempdir().unwrap();
        let (plan, policy) = fixture(dir.path());
        let mut service = MockService {
            fail_preflight: true,
            ..Default::default()
        };
        let err = execute_transaction(&plan, &policy, dir.path(), &mut service).unwrap_err();
        assert!(err.to_string().contains("restored"));
        assert_eq!(service.calls.iter().filter(|c| *c == "restart").count(), 1);
        assert!(!service.calls.iter().any(|c| c == "health"));
        let stopped = service.calls.iter().position(|c| c == "stop").unwrap();
        let restarted = service.calls.iter().position(|c| c == "restart").unwrap();
        assert!(stopped < restarted, "only the restored service can restart");
        assert_eq!(
            fs::read_to_string(&plan.output.files[0].path).unwrap(),
            "old unit"
        );
        assert!(!pending_path(dir.path(), &plan).exists());
    }

    #[test]
    fn incomplete_rollback_retains_journal_then_recovers_on_next_apply() {
        let dir = tempfile::tempdir().unwrap();
        let (plan, policy) = fixture(dir.path());
        let mut failing = MockService {
            fail_health: true,
            fail_stop: true,
            ..Default::default()
        };
        let err = execute_transaction(&plan, &policy, dir.path(), &mut failing).unwrap_err();
        assert!(err.to_string().contains("recovery incomplete"));
        assert!(pending_path(dir.path(), &plan).exists());
        let mut recovered = MockService::default();
        let report = execute_transaction(&plan, &policy, dir.path(), &mut recovered).unwrap();
        assert!(report.recovered_interrupted_apply);
        assert_eq!(recovered.calls[0], "stop");
        assert!(!pending_path(dir.path(), &plan).exists());
        assert_eq!(
            fs::read_to_string(dir.path().join("persistent.sqlite")).unwrap(),
            "persistent data must survive"
        );
    }

    #[test]
    fn journal_cannot_redirect_restore_to_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        let (plan, policy) = fixture(dir.path());
        let journal = Journal {
            schema_version: HostRequirementsVersion::V1,
            service: plan.output.service_unit_name.clone(),
            enabled: true,
            active: true,
            files: vec![SavedFile {
                path: dir.path().join("persistent.sqlite"),
                bytes: Some(b"corruption".to_vec()),
                mode: 0o600,
            }],
        };
        write(
            &pending_path(dir.path(), &plan),
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        let mut service = MockService::default();
        assert!(execute_transaction(&plan, &policy, dir.path(), &mut service).is_err());
        assert!(service.calls.is_empty());
        assert_eq!(
            fs::read_to_string(dir.path().join("persistent.sqlite")).unwrap(),
            "persistent data must survive"
        );
    }
}
