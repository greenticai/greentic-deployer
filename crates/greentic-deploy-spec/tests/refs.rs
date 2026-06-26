use greentic_deploy_spec::{RuntimeRef, RuntimeRefParseError, SecretRef, SecretRefParseError};

#[test]
fn secret_ref_accepts_valid_uri() {
    let r = SecretRef::try_new("secret://prod-eu/customer.support/telegram/bot_token").unwrap();
    assert_eq!(
        r.as_str(),
        "secret://prod-eu/customer.support/telegram/bot_token"
    );
}

#[test]
fn secret_ref_rejects_other_scheme() {
    let err = SecretRef::try_new("file:///etc/keys").unwrap_err();
    assert_eq!(err, SecretRefParseError::MissingScheme);
}

#[test]
fn secret_ref_rejects_empty_path() {
    let err = SecretRef::try_new("secret://").unwrap_err();
    assert_eq!(err, SecretRefParseError::EmptyPath);
}

#[test]
fn runtime_ref_accepts_valid_uri() {
    let r = RuntimeRef::try_new("runtime://prod-eu/discovered/alb_dns").unwrap();
    assert_eq!(r.as_str(), "runtime://prod-eu/discovered/alb_dns");
}

#[test]
fn runtime_ref_rejects_other_scheme() {
    let err = RuntimeRef::try_new("https://example.com").unwrap_err();
    assert_eq!(err, RuntimeRefParseError::MissingScheme);
}

#[test]
fn refs_round_trip_through_json() {
    let r = SecretRef::try_new("secret://local/env-packs/secrets/key").unwrap();
    let j = serde_json::to_string(&r).unwrap();
    let back: SecretRef = serde_json::from_str(&j).unwrap();
    assert_eq!(back, r);
}
