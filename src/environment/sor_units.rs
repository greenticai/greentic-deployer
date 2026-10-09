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

/// Which deployer lane a SoR unit was deployed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SorLane {
    K8s,
    CloudRun,
}

impl SorLane {
    /// The deployer env-pack that owns (and alone can retire) this lane's units.
    pub fn deployer(self) -> &'static str {
        match self {
            Self::K8s => "greentic.deployer.k8s",
            Self::CloudRun => "greentic.deployer.gcp-cloudrun",
        }
    }
}

/// Where a Cloud Run SoR unit was deployed. Recorded, never re-derived, for
/// the reason `namespace` is: `project`, `region` and `secret_prefix` are
/// answers an operator can edit between deploys, and a retirement must address
/// the objects that EXIST, not the ones the answers name now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudRunSorPlacement {
    /// `gtc-sor-<unit_id>`.
    pub service: String,
    /// `<secret_prefix>-sor-<unit_id>`: the owner-stamped Secret Manager
    /// secret whose versions carry the unit's inputs.
    pub secret: String,
    pub project: String,
    pub region: String,
}

impl CloudRunSorPlacement {
    pub fn for_unit(project: &str, region: &str, secret_prefix: &str, unit_id: &str) -> Self {
        Self {
            service: crate::env_packs::k8s::manifests::sor::sor_object_name(unit_id),
            secret: format!("{secret_prefix}-sor-{unit_id}"),
            project: project.to_string(),
            region: region.to_string(),
        }
    }
}

/// One entry of the applied ledger: a unit a SoR phase may have created, and
/// where. Exactly one placement is set: `namespace` (k8s) or `cloud_run`.
///
/// `namespace` is skipped when empty and `cloud_run` when absent, so a k8s
/// entry serializes byte-for-byte as 3C wrote it and every 3C ledger still
/// parses. A pre-3E deployer refuses a Cloud Run entry outright
/// (`deny_unknown_fields`), which is the safe direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedSorUnit {
    pub unit_id: String,
    pub sor: String,
    /// k8s: the namespace the objects were applied in. Empty on Cloud Run.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    /// Cloud Run: where the service and its secret live. Absent on k8s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_run: Option<CloudRunSorPlacement>,
    /// Store rel-paths of the inputs this unit was deployed with (never a
    /// value). Recorded so that once the unit is retired, or one of its
    /// `*_ref`s re-pointed, the OLD inputs are still kept out of the seed that
    /// ships into routers and workers, and are deleted from the store. A
    /// ledger written before this field reads as empty.
    #[serde(default)]
    pub input_refs: Vec<String>,
}

impl AppliedSorUnit {
    /// The lane this entry belongs to; an entry naming both placements or
    /// neither is corrupt and names the unit.
    pub fn lane(&self) -> Result<SorLane, String> {
        match (self.namespace.is_empty(), &self.cloud_run) {
            (false, None) => Ok(SorLane::K8s),
            (true, Some(_)) => Ok(SorLane::CloudRun),
            (false, Some(_)) => Err(format!(
                "the SoR ledger entry for unit `{}` records both a namespace and a Cloud Run \
                 placement",
                self.unit_id
            )),
            (true, None) => Err(format!(
                "the SoR ledger entry for unit `{}` records neither a namespace nor a Cloud Run \
                 placement",
                self.unit_id
            )),
        }
    }

    /// The same unit at the same place, whatever inputs it was recorded with.
    pub fn same_unit(&self, other: &Self) -> bool {
        self.sor == other.sor && self.same_place(other)
    }

    /// The same unit's objects: id and placement (a changed `sor` keeps them).
    pub fn same_place(&self, other: &Self) -> bool {
        self.unit_id == other.unit_id
            && self.namespace == other.namespace
            && self.cloud_run == other.cloud_run
    }
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
    use serde_json::json;

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
            cloud_run: None,
            input_refs: landlord()
                .input_refs()
                .into_iter()
                .map(str::to_string)
                .collect(),
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

    /// A ledger written before `input_refs` existed still loads, with no refs.
    #[test]
    fn a_ledger_without_input_refs_still_deserialises() {
        let old = serde_json::json!({
            "schema": SOR_LEDGER_V1,
            "environment_id": "local",
            "units": [{"unit_id": "landlord", "sor": "landlord-tenant-sor", "namespace": "gtc-local"}],
        });
        let doc: SorLedgerDoc = serde_json::from_value(old).expect("old ledger loads");
        assert_eq!(doc.units.len(), 1);
        assert!(doc.units[0].input_refs.is_empty());
    }

    fn cloud_run_entry() -> AppliedSorUnit {
        AppliedSorUnit {
            unit_id: "landlord".into(),
            sor: "landlord-tenant-sor".into(),
            namespace: String::new(),
            cloud_run: Some(CloudRunSorPlacement::for_unit(
                "proj",
                "europe-west1",
                "gtc-local",
                "landlord",
            )),
            input_refs: vec!["default/_/sor-landlord/answers".into()],
        }
    }

    #[test]
    fn a_k8s_entry_serializes_exactly_as_3c_wrote_it() {
        let entry = AppliedSorUnit {
            unit_id: "landlord".into(),
            sor: "landlord-tenant-sor".into(),
            namespace: "gtc-local".into(),
            cloud_run: None,
            input_refs: vec!["default/_/sor-landlord/answers".into()],
        };
        assert_eq!(
            serde_json::to_value(&entry).unwrap(),
            json!({
                "unit_id": "landlord",
                "sor": "landlord-tenant-sor",
                "namespace": "gtc-local",
                "input_refs": ["default/_/sor-landlord/answers"],
            })
        );
        let written_by_3c: AppliedSorUnit = serde_json::from_value(json!({
            "unit_id": "landlord", "sor": "landlord-tenant-sor", "namespace": "gtc-local",
        }))
        .unwrap();
        assert_eq!(written_by_3c.lane(), Ok(SorLane::K8s));
        assert!(written_by_3c.cloud_run.is_none());
    }

    #[test]
    fn a_cloud_run_entry_records_where_it_was_deployed_and_no_namespace() {
        let entry = cloud_run_entry();
        let value = serde_json::to_value(&entry).unwrap();
        assert_eq!(
            value["cloud_run"],
            json!({
                "service": "gtc-sor-landlord",
                "secret": "gtc-local-sor-landlord",
                "project": "proj",
                "region": "europe-west1",
            })
        );
        assert!(value.get("namespace").is_none(), "{value}");
        let back: AppliedSorUnit = serde_json::from_value(value).unwrap();
        assert_eq!(back, entry);
        assert_eq!(back.lane(), Ok(SorLane::CloudRun));
    }

    #[test]
    fn an_entry_with_both_or_neither_placement_is_refused_naming_the_unit() {
        let mut both = cloud_run_entry();
        both.namespace = "gtc-local".into();
        assert!(both.lane().unwrap_err().contains("`landlord`"));
        let mut neither = cloud_run_entry();
        neither.cloud_run = None;
        assert!(neither.lane().unwrap_err().contains("`landlord`"));
    }

    #[test]
    fn same_unit_and_same_place_compare_the_cloud_run_placement() {
        let a = cloud_run_entry();
        let mut moved = a.clone();
        if let Some(p) = moved.cloud_run.as_mut() {
            p.region = "us-central1".into();
        }
        assert!(!a.same_unit(&moved));
        assert!(!a.same_place(&moved));

        let mut more_inputs = a.clone();
        more_inputs
            .input_refs
            .push("default/_/sor-landlord/postgres_url".into());
        assert!(a.same_unit(&more_inputs), "inputs are not identity");

        let mut renamed = a.clone();
        renamed.sor = "other-sor".into();
        assert!(!a.same_unit(&renamed));
        assert!(
            a.same_place(&renamed),
            "a unit that only changed its `sor` keeps its objects"
        );
    }
}
