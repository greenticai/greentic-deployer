use std::process::Command;

fn example_spec_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("single-vm.deployment.yaml")
}

fn writable_spec_path() -> std::path::PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.keep();
    let spec = root.join("single-vm.deployment.yaml");
    std::fs::write(
        &spec,
        format!(
            r#"apiVersion: greentic.ai/v1alpha1
kind: Deployment
metadata:
  name: acme-prod
spec:
  target: single-vm
  bundle:
    source: file://{bundle}
    format: squashfs
  runtime:
    image: ghcr.io/greenticai/greentic-runtime:0.1.0
    arch: x86_64
    admin:
      bind: 127.0.0.1:8433
      mtls:
        caFile: {ca}
        certFile: {cert}
        keyFile: {key}
  storage:
    stateDir: {state}
    cacheDir: {cache}
    logDir: {log}
    tempDir: {tmp}
  service:
    manager: systemd
    user: greentic
    group: greentic
  health:
    readinessPath: /ready
    livenessPath: /health
    startupTimeoutSeconds: 120
  rollout:
    strategy: recreate
"#,
            bundle = root.join("bundle.squashfs").display(),
            ca = root.join("admin").join("ca.crt").display(),
            cert = root.join("admin").join("client.crt").display(),
            key = root.join("admin").join("client.key").display(),
            state = root.join("state").display(),
            cache = root.join("cache").display(),
            log = root.join("log").display(),
            tmp = root.join("tmp").display(),
        ),
    )
    .expect("write spec");
    spec
}

#[test]
fn single_vm_plan_cli_renders_json_output() {
    let spec = example_spec_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "single-vm",
            "plan",
            "--spec",
            spec.to_str().expect("spec path"),
            "--output",
            "json",
        ])
        .output()
        .expect("run greentic-deployer");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"service_unit_name\": \"acme-prod-greentic-runtime.service\""));
    assert!(stdout.contains("\"bind\": \"127.0.0.1:8433\""));
    assert!(stdout.contains("\"mount_path\": \"/mnt/greentic/bundles/acme-prod\""));
}

#[test]
fn single_vm_apply_cli_renders_text_output() {
    let spec = writable_spec_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "single-vm",
            "apply",
            "--spec",
            spec.to_str().expect("spec path"),
            "--output",
            "text",
        ])
        .output()
        .expect("run greentic-deployer");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("apply report:"));
    assert!(stdout.contains("directories created:"));
    assert!(stdout.contains("state"));
    assert!(!stdout.trim_start().starts_with('{'));
}

#[test]
fn single_vm_destroy_cli_renders_text_output() {
    let spec = writable_spec_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "single-vm",
            "destroy",
            "--spec",
            spec.to_str().expect("spec path"),
            "--output",
            "text",
        ])
        .output()
        .expect("run greentic-deployer");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("destroy report:"));
    assert!(stdout.contains("files removed:"));
    assert!(stdout.contains("commands run:"));
    assert!(!stdout.trim_start().starts_with('{'));
}

#[test]
fn single_vm_status_cli_reports_not_installed_for_fresh_spec() {
    let spec = writable_spec_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "single-vm",
            "status",
            "--spec",
            spec.to_str().expect("spec path"),
            "--output",
            "json",
        ])
        .output()
        .expect("run greentic-deployer");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"status\": \"not_installed\""));
    assert!(stdout.contains("\"state_exists\": false"));
}

#[test]
fn single_vm_plan_cli_rejects_non_x86_64_arch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = dir.path().join("single-vm-aarch64.yaml");
    std::fs::write(
        &spec,
        r#"apiVersion: greentic.ai/v1alpha1
kind: Deployment
metadata:
  name: acme-prod
spec:
  target: single-vm
  bundle:
    source: file:///opt/greentic/bundles/acme.squashfs
    format: squashfs
  runtime:
    image: ghcr.io/greenticai/greentic-runtime:0.1.0
    arch: aarch64
    admin:
      bind: 127.0.0.1:8433
      mtls:
        caFile: /etc/greentic/admin/ca.crt
        certFile: /etc/greentic/admin/client.crt
        keyFile: /etc/greentic/admin/client.key
  storage:
    stateDir: /var/lib/greentic/state
    cacheDir: /var/lib/greentic/cache
    logDir: /var/log/greentic
    tempDir: /var/lib/greentic/tmp
  service:
    manager: systemd
    user: greentic
    group: greentic
  health:
    readinessPath: /ready
    livenessPath: /health
    startupTimeoutSeconds: 120
  rollout:
    strategy: recreate
"#,
    )
    .expect("write spec");

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "single-vm",
            "plan",
            "--spec",
            spec.to_str().expect("spec path"),
        ])
        .output()
        .expect("run greentic-deployer");

    assert!(!output.status.success(), "command unexpectedly succeeded");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("runtime.arch must be x86_64"));
}
