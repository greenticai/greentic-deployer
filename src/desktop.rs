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
}
