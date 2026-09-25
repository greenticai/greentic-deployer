//! A System-of-Record unit declared in an env manifest (`sor_units`), and the
//! two env-dir sidecars that record it.
//!
//! Deliberately NOT a field of `greentic_deploy_spec::Environment`: that
//! struct is published and constructed by struct literal in greentic-start
//! and greentic-designer, so a new public field breaks their builds the moment
//! a floating dev-lane range picks up this crate. `sor-units.json` holds what
//! `op env apply` was last asked to declare; `sor-units.applied.json` is the
//! reconcile-owned ledger of what may exist on the cluster, which is what
//! lets reconcile prune a unit the manifest no longer names.

use greentic_deploy_spec::EnvId;
use serde::{Deserialize, Serialize};

/// Schema id of `<env_dir>/sor-units.json`.
pub const SOR_UNITS_V1: &str = "greentic.sor-units.v1";
/// Schema id of `<env_dir>/sor-units.applied.json`.
pub const SOR_LEDGER_V1: &str = "greentic.sor-units-applied.v1";

/// One SoR unit, exactly the `sor_units[]` shape of the env manifest
/// (contract C2). Every `*_ref` is a store rel-path
/// (`<tenant>/<team>/<pack>/<name>`), never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SorUnit {
    pub unit_id: String,
    /// Capability-URI pack segment; names the route document.
    pub sor: String,
    /// `oci://…@sha256:<hex>` — the sorx container pulls it at boot.
    pub pack_ref: String,
    /// sorx image, pinned by the designer.
    pub image: String,
    /// Must equal the answers' `tenant.tenant_id`; becomes the route
    /// document's `tenant`.
    pub tenant_id: String,
    pub answers_ref: String,
    pub postgres_url_ref: String,
    /// Optional extra trusted CA (PEM). `null` and absent both mean none.
    #[serde(default)]
    pub postgres_ca_ref: Option<String>,
    pub shared_secret_ref: String,
}

impl SorUnit {
    /// Every store ref this unit reads, in a fixed order (answers,
    /// postgres_url, optional postgres_ca, shared_secret).
    pub fn input_refs(&self) -> Vec<&str> {
        let mut refs = vec![self.answers_ref.as_str(), self.postgres_url_ref.as_str()];
        if let Some(ca) = &self.postgres_ca_ref {
            refs.push(ca.as_str());
        }
        refs.push(self.shared_secret_ref.as_str());
        refs
    }
}

/// One entry of the applied ledger: a unit reconcile may have created, and
/// where. `namespace` is recorded because a teardown must address the
/// namespace the objects were applied in, not the one the answers name now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedSorUnit {
    pub unit_id: String,
    pub sor: String,
    pub namespace: String,
}

/// `<env_dir>/sor-units.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SorUnitsDoc {
    pub schema: String,
    pub environment_id: EnvId,
    pub units: Vec<SorUnit>,
}

/// `<env_dir>/sor-units.applied.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SorLedgerDoc {
    pub schema: String,
    pub environment_id: EnvId,
    pub units: Vec<AppliedSorUnit>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::{EnvironmentStore as _, LocalFsStore};
    use greentic_deploy_spec::EnvId;

    pub(crate) fn landlord() -> SorUnit {
        SorUnit {
            unit_id: "landlord".into(),
            sor: "landlord-tenant-sor".into(),
            pack_ref: format!(
                "oci://reg.example/greentic/sor-landlord:t1@sha256:{}",
                "a".repeat(64)
            ),
            image: "ghcr.io/greenticai/greentic-sorx:0.2.36114419551".into(),
            tenant_id: "acme".into(),
            answers_ref: "default/_/sor-landlord/answers".into(),
            postgres_url_ref: "default/_/sor-landlord/postgres_url".into(),
            postgres_ca_ref: None,
            shared_secret_ref: "default/_/sor-landlord/shared_secret".into(),
        }
    }

    #[test]
    fn input_refs_list_every_ref_and_the_optional_ca_only_when_set() {
        let mut unit = landlord();
        assert_eq!(
            unit.input_refs(),
            vec![
                "default/_/sor-landlord/answers",
                "default/_/sor-landlord/postgres_url",
                "default/_/sor-landlord/shared_secret",
            ]
        );
        unit.postgres_ca_ref = Some("default/_/sor-landlord/postgres_ca".into());
        assert_eq!(unit.input_refs().len(), 4);
        assert_eq!(unit.input_refs()[2], "default/_/sor-landlord/postgres_ca");
    }

    #[test]
    fn the_sidecars_round_trip_and_an_absent_file_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store
            .save(&crate::cli::tests_common::make_env("local"))
            .unwrap();
        let env_id = EnvId::try_from("local").unwrap();

        assert!(store.load_sor_units(&env_id).unwrap().is_empty());
        assert!(store.load_sor_ledger(&env_id).unwrap().is_empty());

        let applied = AppliedSorUnit {
            unit_id: "landlord".into(),
            sor: "landlord-tenant-sor".into(),
            namespace: "gtc-local".into(),
        };
        store
            .transact(&env_id, |locked| {
                locked.save_sor_units(&[landlord()])?;
                locked.save_sor_ledger(std::slice::from_ref(&applied))
            })
            .unwrap();

        assert_eq!(store.load_sor_units(&env_id).unwrap(), vec![landlord()]);
        assert_eq!(store.load_sor_ledger(&env_id).unwrap(), vec![applied]);
        let raw: serde_json::Value = serde_json::from_slice(
            &std::fs::read(store.env_dir(&env_id).unwrap().join("sor-units.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(raw["schema"], SOR_UNITS_V1);
        assert_eq!(raw["environment_id"], "local");
    }
}
