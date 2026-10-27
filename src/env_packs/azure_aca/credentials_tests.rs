use std::path::Path;

use greentic_deploy_spec::{EnvId, EnvironmentHostConfig};

use super::*;
use crate::credentials::ZeroizedAdmin;

#[derive(Debug)]
struct Scripted {
    env: Result<(), String>,
    perms: Result<Vec<Permission>, String>,
}

#[async_trait]
impl AzureValidatorClient for Scripted {
    async fn check_environment(&self) -> Result<(), String> {
        self.env.clone()
    }
    async fn effective_permissions(&self) -> Result<Vec<Permission>, String> {
        self.perms.clone()
    }
}

fn run(c: &AzureAcaDeployerCredentials) -> RequirementsReport {
    let id = EnvId::try_from("local").unwrap();
    let cfg = EnvironmentHostConfig::new(id.clone());
    c.validate(&ValidationContext { env_id: &id, env_root: Path::new("."), host_config: &cfg })
}

fn all_granted() -> Vec<Permission> {
    vec![Permission { actions: REQUIRED_ACTIONS.iter().map(|s| s.to_string()).collect(), not_actions: vec![] }]
}

#[test]
fn a_fully_granted_identity_passes_via_the_fake_client_only() {
    let c = AzureAcaDeployerCredentials::with_client(Arc::new(Scripted { env: Ok(()), perms: Ok(all_granted()) }));
    let r = run(&c);
    assert!(r.passed(), "{:?}", r.missing());
    assert_eq!(r.checks.len(), c.required_capabilities().len());
}

#[test]
fn missing_actions_are_reported_exactly() {
    let perms = vec![Permission { actions: vec!["Microsoft.App/containerApps/read".into()], not_actions: vec![] }];
    let c = AzureAcaDeployerCredentials::with_client(Arc::new(Scripted { env: Ok(()), perms: Ok(perms) }));
    let r = run(&c);
    assert!(!r.passed());
    let missing = r.missing();
    assert_eq!(missing.len(), REQUIRED_ACTIONS.len() - 1);
    assert!(!missing.contains(&"azure-aca.rbac.Microsoft.App/containerApps/read".to_string()));
}

#[test]
fn an_unreachable_environment_fails_token_and_environment_and_skips_rbac() {
    let c = AzureAcaDeployerCredentials::with_client(Arc::new(Scripted { env: Err("401 unauthorized".into()), perms: Ok(all_granted()) }));
    let r = run(&c);
    assert!(!r.passed());
    assert!(r.checks.iter().all(|c| matches!(c.status, CapabilityStatus::Fail { .. })));
}

#[test]
fn without_a_client_and_without_credentials_every_capability_fails_closed() {
    let r = run(&AzureAcaDeployerCredentials::default());
    assert!(!r.passed());
}

#[test]
fn bootstrap_is_render_only_and_binds_nothing() {
    let id = EnvId::try_from("local").unwrap();
    let admin = ZeroizedAdmin::new("", String::new());
    let out = AzureAcaDeployerCredentials::default()
        .bootstrap(&BootstrapInput { env_id: &id, env_root: Path::new("."), admin: &admin })
        .unwrap();
    assert!(out.bound_credentials_ref.is_none() && out.bound_secret_material.is_none());
    assert_eq!(out.rules_pack.entries.len(), 3);
}
