use chrono::Utc;
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, CustomerId, DeploymentId, EnvId, PartyId,
    RevenueShareEntry, RevisionId, RouteBinding, SchemaVersion, SpecError, TenantSelector,
    TrafficSplit, TrafficSplitEntry,
};
use std::path::PathBuf;
use std::str::FromStr;

fn split(weights: &[u32]) -> TrafficSplit {
    TrafficSplit {
        schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
        env_id: EnvId::from_str("local").unwrap(),
        deployment_id: DeploymentId::new(),
        bundle_id: "customer.support".into(),
        generation: 1,
        entries: weights
            .iter()
            .map(|&w| TrafficSplitEntry {
                revision_id: RevisionId::new(),
                weight_bps: w,
            })
            .collect(),
        updated_at: Utc::now(),
        updated_by: "operator://test".into(),
        idempotency_key: "01JTKW5B4W4Q5Y1CQW93F7S5VH".into(),
        authorization_ref: PathBuf::from("audit/test.json"),
        previous_split_ref: None,
    }
}

#[test]
fn traffic_split_accepts_sum_10000() {
    assert!(split(&[10_000]).validate().is_ok());
    assert!(split(&[9_900, 100]).validate().is_ok());
    assert!(split(&[5_000, 4_000, 1_000]).validate().is_ok());
}

#[test]
fn traffic_split_rejects_undersum() {
    let err = split(&[9_999]).validate().unwrap_err();
    assert_eq!(err, SpecError::BasisPointsSum { sum: 9_999 });
}

#[test]
fn traffic_split_rejects_oversum() {
    let err = split(&[5_001, 5_000]).validate().unwrap_err();
    assert_eq!(err, SpecError::BasisPointsSum { sum: 10_001 });
}

fn deployment(shares: &[u32]) -> BundleDeployment {
    BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id: DeploymentId::new(),
        env_id: EnvId::from_str("local").unwrap(),
        bundle_id: "customer.support".into(),
        customer_id: CustomerId::new("local-dev"),
        status: BundleDeploymentStatus::Active,
        current_revisions: vec![],
        route_binding: RouteBinding {
            hosts: vec!["example.com".into()],
            path_prefixes: vec!["/".into()],
            tenant_selector: TenantSelector {
                tenant: "acme".into(),
                team: "support".into(),
            },
        },
        revenue_share: shares
            .iter()
            .enumerate()
            .map(|(i, &bps)| RevenueShareEntry {
                party_id: PartyId::new(format!("party-{i}")),
                basis_points: bps,
            })
            .collect(),
        revenue_policy_ref: PathBuf::from("billing/v1.json.sig"),
        usage: None,
        created_at: Utc::now(),
        authorization_ref: PathBuf::from("audit/test.json"),
    }
}

#[test]
fn revenue_share_accepts_sum_10000() {
    assert!(deployment(&[10_000]).validate().is_ok());
    assert!(deployment(&[3_000, 7_000]).validate().is_ok());
}

#[test]
fn revenue_share_rejects_wrong_sum() {
    let err = deployment(&[1_000, 2_000]).validate().unwrap_err();
    assert_eq!(err, SpecError::BasisPointsSum { sum: 3_000 });
}
