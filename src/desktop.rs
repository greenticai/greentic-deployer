//! Desktop deploy backend: docker-compose and podman local deploys.
//!
//! Pure command construction + thin execution. Integrates with the deploy
//! extension flow (`src/ext/`) via the `desktop` backend id.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopConfig {
    pub image: Option<String>,
    pub compose_file: Option<PathBuf>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub deployment_name: String,
    #[serde(default = "default_project_dir")]
    pub project_dir: PathBuf,
}

fn default_project_dir() -> PathBuf {
    std::env::temp_dir().join("greentic-desktop")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeKind {
    DockerCompose,
    Podman,
}

impl RuntimeKind {
    pub fn cmd_name(&self) -> &'static str {
        match self {
            Self::DockerCompose => "docker",
            Self::Podman => "podman",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopPlan {
    pub runtime: RuntimeKind,
    pub deployment_name: String,
    pub compose_file: PathBuf,
    pub project_dir: PathBuf,
}

/// Pure transform: config → plan. No IO.
pub fn plan(runtime: RuntimeKind, config: &DesktopConfig) -> Result<DesktopPlan> {
    let compose_file = config
        .compose_file
        .clone()
        .unwrap_or_else(|| config.project_dir.join("docker-compose.yml"));
    Ok(DesktopPlan {
        runtime,
        deployment_name: config.deployment_name.clone(),
        compose_file,
        project_dir: config.project_dir.clone(),
    })
}

pub fn build_up_command(plan: &DesktopPlan) -> Command {
    // Accepted risk: runtime is a closed enum that resolves only to docker or podman, and no shell is used.
    // foxguard: ignore[rs/no-command-injection]
    let mut cmd = Command::new(plan.runtime.cmd_name());
    match plan.runtime {
        RuntimeKind::DockerCompose => {
            cmd.arg("compose")
                .arg("-p")
                .arg(&plan.deployment_name)
                .arg("-f")
                .arg(&plan.compose_file)
                .arg("up")
                .arg("-d");
        }
        RuntimeKind::Podman => {
            cmd.arg("play").arg("kube").arg(&plan.compose_file);
        }
    }
    cmd.current_dir(&plan.project_dir);
    cmd
}

pub fn build_down_command(plan: &DesktopPlan) -> Command {
    // Accepted risk: runtime is a closed enum that resolves only to docker or podman, and no shell is used.
    // foxguard: ignore[rs/no-command-injection]
    let mut cmd = Command::new(plan.runtime.cmd_name());
    match plan.runtime {
        RuntimeKind::DockerCompose => {
            cmd.arg("compose")
                .arg("-p")
                .arg(&plan.deployment_name)
                .arg("-f")
                .arg(&plan.compose_file)
                .arg("down");
        }
        RuntimeKind::Podman => {
            cmd.arg("pod").arg("stop").arg(&plan.deployment_name);
        }
    }
    cmd
}

pub fn build_status_command(plan: &DesktopPlan) -> Command {
    // Accepted risk: runtime is a closed enum that resolves only to docker or podman, and no shell is used.
    // foxguard: ignore[rs/no-command-injection]
    let mut cmd = Command::new(plan.runtime.cmd_name());
    match plan.runtime {
        RuntimeKind::DockerCompose => {
            cmd.arg("compose")
                .arg("-p")
                .arg(&plan.deployment_name)
                .arg("ps")
                .arg("--format")
                .arg("json");
        }
        RuntimeKind::Podman => {
            cmd.arg("pod")
                .arg("ps")
                .arg("--format")
                .arg("json")
                .arg("--filter")
                .arg(format!("name={}", plan.deployment_name));
        }
    }
    cmd
}

pub fn apply(plan: &DesktopPlan) -> Result<()> {
    let status = build_up_command(plan)
        .status()
        .with_context(|| format!("spawn {}", plan.runtime.cmd_name()))?;
    if !status.success() {
        anyhow::bail!(
            "{} up exited with status {}",
            plan.runtime.cmd_name(),
            status
        );
    }
    Ok(())
}

pub fn destroy(plan: &DesktopPlan) -> Result<()> {
    let status = build_down_command(plan)
        .status()
        .with_context(|| format!("spawn {}", plan.runtime.cmd_name()))?;
    if !status.success() {
        anyhow::bail!(
            "{} down exited with status {}",
            plan.runtime.cmd_name(),
            status
        );
    }
    Ok(())
}

pub fn preflight_check(runtime: RuntimeKind) -> Result<()> {
    // Accepted risk: runtime is a closed enum that resolves only to docker or podman, and no shell is used.
    // foxguard: ignore[rs/no-command-injection]
    let mut cmd = Command::new(runtime.cmd_name());
    cmd.arg("--version");
    let out = cmd
        .output()
        .with_context(|| format!("'{}' not found in PATH", runtime.cmd_name()))?;
    if !out.status.success() {
        anyhow::bail!("'{} --version' returned non-zero", runtime.cmd_name());
    }
    Ok(())
}

/// Abstraction for command execution so tests can stub.
pub trait CommandRunner: Send + Sync {
    fn run(&self, cmd: &mut Command) -> anyhow::Result<std::process::ExitStatus>;
}

/// Production runner: invokes `Command::status()`.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, cmd: &mut Command) -> anyhow::Result<std::process::ExitStatus> {
        let program = cmd.get_program().to_string_lossy().to_string();
        cmd.status().with_context(|| format!("spawn {program}"))
    }
}

/// Map extension-contributed handler string → `RuntimeKind`.
pub fn runtime_from_handler(handler: Option<&str>) -> Result<RuntimeKind> {
    match handler {
        Some("docker-compose") => Ok(RuntimeKind::DockerCompose),
        Some("podman") => Ok(RuntimeKind::Podman),
        Some(other) => Err(anyhow::anyhow!(
            "unsupported desktop handler: '{other}' (expected 'docker-compose' or 'podman')"
        )),
        None => Err(anyhow::anyhow!(
            "missing handler for desktop backend (expected 'docker-compose' or 'podman')"
        )),
    }
}

/// Extension-driven apply: parse JSON config, dispatch to real runner.
pub fn apply_from_ext(handler: Option<&str>, config_json: &str, creds_json: &str) -> Result<()> {
    apply_from_ext_with_runner(handler, config_json, creds_json, &RealCommandRunner)
}

/// Extension-driven destroy: parse JSON config, dispatch to real runner.
pub fn destroy_from_ext(handler: Option<&str>, config_json: &str, creds_json: &str) -> Result<()> {
    destroy_from_ext_with_runner(handler, config_json, creds_json, &RealCommandRunner)
}

/// Test-friendly apply: accepts an injected runner.
pub fn apply_from_ext_with_runner(
    handler: Option<&str>,
    config_json: &str,
    _creds_json: &str,
    runner: &dyn CommandRunner,
) -> Result<()> {
    let config: DesktopConfig =
        serde_json::from_str(config_json).context("parse desktop config JSON")?;
    let runtime = runtime_from_handler(handler)?;
    let plan_result = plan(runtime, &config)?;
    let program_name = plan_result.runtime.cmd_name();
    let mut cmd = build_up_command(&plan_result);
    let status = runner.run(&mut cmd)?;
    if !status.success() {
        anyhow::bail!("{} up exited with status {}", program_name, status);
    }
    Ok(())
}

/// Test-friendly destroy: accepts an injected runner.
pub fn destroy_from_ext_with_runner(
    handler: Option<&str>,
    config_json: &str,
    _creds_json: &str,
    runner: &dyn CommandRunner,
) -> Result<()> {
    let config: DesktopConfig =
        serde_json::from_str(config_json).context("parse desktop config JSON")?;
    let runtime = runtime_from_handler(handler)?;
    let plan_result = plan(runtime, &config)?;
    let program_name = plan_result.runtime.cmd_name();
    let mut cmd = build_down_command(&plan_result);
    let status = runner.run(&mut cmd)?;
    if !status.success() {
        anyhow::bail!("{} down exited with status {}", program_name, status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> DesktopConfig {
        DesktopConfig {
            image: Some("nginx:stable".into()),
            compose_file: Some(PathBuf::from("/tmp/compose.yml")),
            ports: vec!["8080:80".into()],
            env: vec![],
            deployment_name: "my-app".into(),
            project_dir: PathBuf::from("/tmp/proj"),
        }
    }

    #[test]
    fn plan_echoes_compose_file_and_name() {
        let p = plan(RuntimeKind::DockerCompose, &sample_config()).unwrap();
        assert_eq!(p.deployment_name, "my-app");
        assert_eq!(p.compose_file, PathBuf::from("/tmp/compose.yml"));
        assert_eq!(p.runtime, RuntimeKind::DockerCompose);
    }

    #[test]
    fn plan_defaults_compose_file_to_project_dir() {
        let mut cfg = sample_config();
        cfg.compose_file = None;
        let p = plan(RuntimeKind::Podman, &cfg).unwrap();
        assert_eq!(
            p.compose_file,
            PathBuf::from("/tmp/proj/docker-compose.yml")
        );
    }

    #[test]
    fn up_command_docker_compose_args() {
        let p = plan(RuntimeKind::DockerCompose, &sample_config()).unwrap();
        let cmd = build_up_command(&p);
        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            args,
            vec![
                "compose",
                "-p",
                "my-app",
                "-f",
                "/tmp/compose.yml",
                "up",
                "-d"
            ]
        );
        assert_eq!(cmd.get_program(), "docker");
    }

    #[test]
    fn up_command_podman_args() {
        let p = plan(RuntimeKind::Podman, &sample_config()).unwrap();
        let cmd = build_up_command(&p);
        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        assert_eq!(args, vec!["play", "kube", "/tmp/compose.yml"]);
        assert_eq!(cmd.get_program(), "podman");
    }

    #[test]
    fn down_command_docker_compose_args() {
        let p = plan(RuntimeKind::DockerCompose, &sample_config()).unwrap();
        let cmd = build_down_command(&p);
        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            args,
            vec!["compose", "-p", "my-app", "-f", "/tmp/compose.yml", "down"]
        );
    }

    #[test]
    fn status_command_docker_compose_args() {
        let p = plan(RuntimeKind::DockerCompose, &sample_config()).unwrap();
        let cmd = build_status_command(&p);
        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            args,
            vec!["compose", "-p", "my-app", "ps", "--format", "json"]
        );
    }

    #[test]
    fn runtime_from_handler_maps_known_handlers() {
        assert_eq!(
            runtime_from_handler(Some("docker-compose")).unwrap(),
            RuntimeKind::DockerCompose
        );
        assert_eq!(
            runtime_from_handler(Some("podman")).unwrap(),
            RuntimeKind::Podman
        );
    }

    #[test]
    fn runtime_from_handler_rejects_unknown() {
        let err = runtime_from_handler(Some("kubernetes")).unwrap_err();
        assert!(format!("{err}").contains("kubernetes"));
    }

    #[test]
    fn runtime_from_handler_rejects_missing() {
        let err = runtime_from_handler(None).unwrap_err();
        assert!(format!("{err}").contains("missing handler"));
    }

    #[derive(Default)]
    struct RecordingRunner {
        captured: std::sync::Mutex<Vec<Vec<String>>>,
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, cmd: &mut Command) -> anyhow::Result<std::process::ExitStatus> {
            let argv: Vec<String> =
                std::iter::once(cmd.get_program().to_string_lossy().to_string())
                    .chain(cmd.get_args().map(|a| a.to_string_lossy().to_string()))
                    .collect();
            self.captured.lock().unwrap().push(argv);
            Ok(fake_exit_success())
        }
    }

    fn fake_exit_success() -> std::process::ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(0)
        }
        #[cfg(not(unix))]
        {
            use std::os::windows::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(0)
        }
    }

    fn sample_config_json() -> String {
        r#"{
            "image": "nginx:stable",
            "composeFile": "/tmp/compose.yml",
            "ports": ["8080:80"],
            "env": [],
            "deploymentName": "my-app",
            "projectDir": "/tmp/proj"
        }"#
        .to_string()
    }

    #[test]
    fn apply_from_ext_with_runner_invokes_up_command() {
        let runner = RecordingRunner::default();
        apply_from_ext_with_runner(Some("docker-compose"), &sample_config_json(), "{}", &runner)
            .expect("apply ok");
        let captured = runner.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let argv = &captured[0];
        assert_eq!(argv[0], "docker");
        assert!(argv.contains(&"up".to_string()));
        assert!(argv.contains(&"my-app".to_string()));
    }

    #[test]
    fn destroy_from_ext_with_runner_invokes_down_command() {
        let runner = RecordingRunner::default();
        destroy_from_ext_with_runner(Some("docker-compose"), &sample_config_json(), "{}", &runner)
            .expect("destroy ok");
        let captured = runner.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].contains(&"down".to_string()));
    }

    #[test]
    fn apply_from_ext_rejects_invalid_json() {
        let runner = RecordingRunner::default();
        let err = apply_from_ext_with_runner(Some("docker-compose"), "not json", "{}", &runner)
            .unwrap_err();
        assert!(format!("{err}").contains("parse"));
    }

    #[test]
    fn apply_from_ext_rejects_unknown_handler() {
        let runner = RecordingRunner::default();
        let err =
            apply_from_ext_with_runner(Some("kubernetes"), &sample_config_json(), "{}", &runner)
                .unwrap_err();
        assert!(format!("{err}").contains("kubernetes"));
    }

    #[test]
    fn apply_from_ext_propagates_nonzero_exit() {
        struct FailingRunner;
        impl CommandRunner for FailingRunner {
            fn run(&self, _cmd: &mut Command) -> anyhow::Result<std::process::ExitStatus> {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    Ok(std::process::ExitStatus::from_raw(1 << 8))
                }
                #[cfg(not(unix))]
                {
                    use std::os::windows::process::ExitStatusExt;
                    Ok(std::process::ExitStatus::from_raw(1))
                }
            }
        }
        let err = apply_from_ext_with_runner(
            Some("docker-compose"),
            &sample_config_json(),
            "{}",
            &FailingRunner,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("exited"));
    }
}
