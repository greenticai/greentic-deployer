//! Manifest-shape rules for `sor_units` (contract C2, amendments 3, 4, 8).

use std::collections::BTreeSet;

use crate::cli::OpError;
use crate::env_packs::k8s::manifests::is_dns1123_label;
use crate::environment::sor_units::SorUnit;

/// `gtc-sor-` (8) + 55 = 63, the DNS-1123 label limit of the object names.
const MAX_UNIT_ID_LEN: usize = 55;

/// Store categories a SoR input may never live in: their names are stored
/// verbatim or under a different env segment, and `sorla` is where the route
/// documents themselves are written.
const RESERVED_CATEGORIES: &[&str] = &["mcp", "a2a", "sorla", "llm"];

pub(crate) fn validate_sor_units(units: &[SorUnit]) -> Result<(), OpError> {
    let mut ids = BTreeSet::new();
    let mut sors = BTreeSet::new();
    for unit in units {
        let id = unit.unit_id.as_str();
        if !is_dns1123_label(id) || id.len() > MAX_UNIT_ID_LEN {
            return Err(invalid(format!(
                "sor_units: unit_id `{id}` must be a DNS-1123 label of at most {MAX_UNIT_ID_LEN} \
                 characters (it names the Kubernetes objects `gtc-sor-<unit_id>`)"
            )));
        }
        if !ids.insert(id) {
            return Err(invalid(format!("sor_units: duplicate unit_id `{id}`")));
        }
        validate_sor_key(id, &unit.sor)?;
        if !sors.insert(unit.sor.as_str()) {
            return Err(invalid(format!(
                "sor_units: duplicate sor `{}` (one SoR has one route document per environment)",
                unit.sor
            )));
        }
        validate_pack_ref(id, &unit.pack_ref)?;
        validate_image(id, &unit.image)?;
        if unit.tenant_id.trim().is_empty() {
            return Err(invalid(format!(
                "sor_units `{id}`: tenant_id must not be empty"
            )));
        }
        validate_ref(id, "answers_ref", &unit.answers_ref, "answers")?;
        validate_ref(
            id,
            "postgres_url_ref",
            &unit.postgres_url_ref,
            "postgres_url",
        )?;
        if let Some(ca) = &unit.postgres_ca_ref {
            validate_ref(id, "postgres_ca_ref", ca, "postgres_ca")?;
        }
        validate_ref(
            id,
            "shared_secret_ref",
            &unit.shared_secret_ref,
            "shared_secret",
        )?;
    }
    Ok(())
}

fn invalid(msg: String) -> OpError {
    OpError::InvalidArgument(msg)
}

/// The `<sor>` of `default/_/sorla/<sor>`: stored verbatim (3B), so it must
/// stay one path segment and match what the designer mints.
fn validate_sor_key(id: &str, sor: &str) -> Result<(), OpError> {
    let ok = sor
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && sor
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "sor_units `{id}`: sor `{sor}` must be lowercase a-z, 0-9, `-`, `.` or `_`, \
             starting with a letter or digit"
        )))
    }
}

/// `oci://<registry>/<repo>[:<tag>]@sha256:<64 lowercase hex>` (amendment 4).
fn validate_pack_ref(id: &str, pack_ref: &str) -> Result<(), OpError> {
    let refuse = || {
        invalid(format!(
            "sor_units `{id}`: pack_ref must be `oci://<registry>/<repo>@sha256:<64 hex>` \
             (digest-pinned); got `{pack_ref}`"
        ))
    };
    let rest = pack_ref.strip_prefix("oci://").ok_or_else(refuse)?;
    let (name, digest) = rest.rsplit_once("@sha256:").ok_or_else(refuse)?;
    let hex_ok = digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if name.is_empty() || !name.contains('/') || !hex_ok {
        return Err(refuse());
    }
    Ok(())
}

/// Same character set `K8sParams::from_answers` accepts for `runtime_image`.
fn validate_image(id: &str, image: &str) -> Result<(), OpError> {
    let ok = !image.is_empty()
        && image
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-_/:@".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "sor_units `{id}`: image `{image}` contains invalid characters"
        )))
    }
}

/// A four-segment dev-store path whose name segment is this field's own
/// canonical name, outside the verbatim categories.
fn validate_ref(id: &str, field: &str, rel: &str, expected_name: &str) -> Result<(), OpError> {
    crate::cli::secrets::validate_dev_store_secret_path(rel)
        .map_err(|e| invalid(format!("sor_units `{id}`: {field}: {e}")))?;
    let segments: Vec<&str> = rel.split('/').collect();
    if RESERVED_CATEGORIES.contains(&segments[2]) {
        return Err(invalid(format!(
            "sor_units `{id}`: {field} `{rel}` may not live in the store category `{}`",
            segments[2]
        )));
    }
    if segments[3] != expected_name {
        return Err(invalid(format!(
            "sor_units `{id}`: {field} `{rel}` must end in `{expected_name}`"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::sor_units::SorUnit;

    fn unit() -> SorUnit {
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

    fn refused(units: &[SorUnit]) -> String {
        match validate_sor_units(units) {
            Err(OpError::InvalidArgument(msg)) => msg,
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn a_well_formed_unit_passes() {
        validate_sor_units(&[unit()]).expect("valid");
    }

    #[test]
    fn duplicate_unit_ids_and_duplicate_sors_are_refused() {
        let mut other = unit();
        other.sor = "other-sor".into();
        assert!(refused(&[unit(), other]).contains("duplicate unit_id `landlord`"));
        let mut other = unit();
        other.unit_id = "landlord-2".into();
        assert!(refused(&[unit(), other]).contains("duplicate sor `landlord-tenant-sor`"));
    }

    #[test]
    fn a_unit_id_must_be_a_dns_label_short_enough_for_its_object_names() {
        let mut u = unit();
        u.unit_id = "Landlord".into();
        assert!(refused(&[u]).contains("unit_id `Landlord`"));
        let mut u = unit();
        u.unit_id = "a".repeat(56);
        assert!(refused(&[u]).contains("at most 55"));
        let mut u = unit();
        u.unit_id = "a".repeat(55);
        validate_sor_units(&[u]).expect("55 characters fits `gtc-sor-<id>` in 63");
    }

    #[test]
    fn pack_ref_must_be_an_oci_reference_pinned_by_digest() {
        for bad in [
            "reg.example/greentic/sor:t1".to_string(),
            "oci://reg.example/greentic/sor:t1".to_string(),
            "oci://reg.example/greentic/sor@sha256:abc".to_string(),
            format!("oci://reg.example/greentic/sor@sha256:{}", "A".repeat(64)),
            format!("oci://@sha256:{}", "a".repeat(64)),
        ] {
            let mut u = unit();
            u.pack_ref = bad.clone();
            assert!(refused(&[u]).contains("pack_ref"), "{bad} must be refused");
        }
    }

    #[test]
    fn each_ref_is_a_four_segment_store_path_with_its_own_canonical_name() {
        let mut u = unit();
        u.answers_ref = "default/_/sor/landlord/answers".into();
        assert!(refused(&[u]).contains("answers_ref"));
        let mut u = unit();
        u.postgres_url_ref = "default/_/sor-landlord/answers".into();
        assert!(refused(&[u]).contains("must end in `postgres_url`"));
        let mut u = unit();
        u.postgres_ca_ref = Some("default/_/sor-landlord/postgres_url".into());
        assert!(refused(&[u]).contains("must end in `postgres_ca`"));
        let mut u = unit();
        u.shared_secret_ref = "default/_/sorla/shared_secret".into();
        assert!(refused(&[u]).contains("category `sorla`"));
    }

    #[test]
    fn sor_image_and_tenant_are_checked() {
        let mut u = unit();
        u.sor = "landlord/tenant".into();
        assert!(refused(&[u]).contains("sor `landlord/tenant`"));
        let mut u = unit();
        u.image = "ghcr.io/Greentic/sorx:x".into();
        assert!(refused(&[u]).contains("image"));
        let mut u = unit();
        u.tenant_id = "  ".into();
        assert!(refused(&[u]).contains("tenant_id"));
    }
}
