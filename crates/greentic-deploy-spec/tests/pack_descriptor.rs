use greentic_deploy_spec::{PackDescriptor, PackDescriptorParseError};

#[test]
fn parses_canonical_descriptor() {
    let d = PackDescriptor::try_new("greentic.deployer.k8s@1.0.0").unwrap();
    assert_eq!(d.path(), "greentic.deployer.k8s");
    assert_eq!(d.version().to_string(), "1.0.0");
    assert_eq!(d.as_str(), "greentic.deployer.k8s@1.0.0");
}

#[test]
fn parses_three_part_path() {
    let d = PackDescriptor::try_new("greentic.secrets.dev-store@0.5.12").unwrap();
    assert_eq!(d.path(), "greentic.secrets.dev-store");
    assert_eq!(d.version().to_string(), "0.5.12");
}

#[test]
fn rejects_missing_version() {
    let err = PackDescriptor::try_new("greentic.deployer.k8s").unwrap_err();
    assert_eq!(err, PackDescriptorParseError::MissingVersion);
}

#[test]
fn rejects_empty_path() {
    let err = PackDescriptor::try_new("@1.0.0").unwrap_err();
    assert_eq!(err, PackDescriptorParseError::EmptyPath);
}

#[test]
fn rejects_path_without_dot() {
    let err = PackDescriptor::try_new("deployer@1.0.0").unwrap_err();
    assert_eq!(err, PackDescriptorParseError::PathMissingDot);
}

#[test]
fn rejects_uppercase_path() {
    let err = PackDescriptor::try_new("greentic.Deployer.k8s@1.0.0").unwrap_err();
    assert_eq!(err, PackDescriptorParseError::InvalidPathChar('D'));
}

#[test]
fn rejects_multiple_at() {
    let err = PackDescriptor::try_new("a.b@1.0.0@extra").unwrap_err();
    assert!(matches!(err, PackDescriptorParseError::InvalidSemver(_)));
}

#[test]
fn rejects_invalid_semver() {
    let err = PackDescriptor::try_new("a.b@not-a-version").unwrap_err();
    assert!(matches!(err, PackDescriptorParseError::InvalidSemver(_)));
}

#[test]
fn round_trips_through_json() {
    let d = PackDescriptor::try_new("greentic.telemetry.stdout@0.5.0").unwrap();
    let json = serde_json::to_string(&d).unwrap();
    assert_eq!(json, "\"greentic.telemetry.stdout@0.5.0\"");
    let back: PackDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}
