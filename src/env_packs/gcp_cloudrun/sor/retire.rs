//! Retiring SoR units the manifest no longer declares: delete the service and
//! its secret, only when THIS environment owns them, and never one a declared
//! unit still uses (a `secret_prefix` change retires the old ledger entry,
//! whose service is the very service just brought up).

use super::spec::sor_service_ref;
use super::target::SorServiceTarget;
use super::up::service_holder;
use crate::env_packs::deployer::DeployerError;
use crate::env_packs::gcp_cloudrun::deploy_target::CloudRunTarget;
use crate::env_packs::gcp_cloudrun::deployer::{
    SecretOwnership, env_owner_stamp, provider, secret_ownership,
};
use crate::environment::sor_units::CloudRunSorPlacement;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SorRetireOutcome {
    pub deleted_services: Vec<String>,
    pub deleted_secrets: Vec<String>,
    pub notes: Vec<String>,
}

pub async fn retire(
    secrets: &dyn CloudRunTarget,
    services: &dyn SorServiceTarget,
    env_id: &str,
    retired: &[CloudRunSorPlacement],
    keep: &[CloudRunSorPlacement],
) -> Result<SorRetireOutcome, DeployerError> {
    let owner = env_owner_stamp(env_id);
    let mut out = SorRetireOutcome::default();
    for place in retired {
        let service = sor_service_ref(place);
        let service_in_use = keep.iter().any(|k| {
            k.project == place.project && k.region == place.region && k.service == place.service
        });
        if !service_in_use {
            match services.get_sor_service(&service).await.map_err(provider)? {
                None => {}
                Some(live) if live.owner.as_deref() == Some(owner.as_str()) => {
                    services
                        .delete_sor_service(&service)
                        .await
                        .map_err(provider)?;
                    out.deleted_services.push(service.name.clone());
                }
                Some(live) => out.notes.push(format!(
                    "Cloud Run service `{}` was left in place: it {}, and this is environment \
                     `{owner}`",
                    service.name,
                    service_holder(live.owner.as_deref())
                )),
            }
        }
        let secret_in_use = keep
            .iter()
            .any(|k| k.project == place.project && k.secret == place.secret);
        if secret_in_use {
            continue;
        }
        match secret_ownership(secrets, &place.secret, env_id).await? {
            SecretOwnership::Absent => {}
            SecretOwnership::Ours => {
                secrets
                    .delete_secret(&place.secret)
                    .await
                    .map_err(provider)?;
                out.deleted_secrets.push(place.secret.clone());
            }
            SecretOwnership::Legacy | SecretOwnership::Conflict { .. } => {
                out.notes.push(format!(
                    "Secret Manager secret `{}` was left in place: this environment does not \
                     own it",
                    place.secret
                ));
            }
        }
    }
    Ok(out)
}
