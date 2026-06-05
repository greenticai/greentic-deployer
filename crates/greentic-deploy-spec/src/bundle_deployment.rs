//! `greentic.bundle-deployment.v1` (`§5.4`).
//!
//! The usage-level anchor (P6). One per `(env_id, bundle_id, customer_id)`.

use crate::error::SpecError;
use crate::ids::{BundleId, CustomerId, DeploymentId, PartyId, RevisionId};
use crate::version::SchemaVersion;
use chrono::{DateTime, Utc};
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

const BASIS_POINTS_TOTAL: u32 = 10_000;

/// Caps on [`BundleDeployment::config_overrides`] — applied in [`BundleDeployment::validate`].
///
/// `environment.json` is loaded into memory at every operator verb (warm,
/// traffic set, etc.) and serialized in audit events; an unbounded
/// per-deployment config payload would amplify both. Single-pack/single-key
/// overrides like `{"messaging-telegram": {"api_base_url": "..."}}` are
/// hundreds of bytes; the caps below give ~3 orders of magnitude of
/// headroom without admitting a "store the whole pack config here" misuse
/// that belongs in Phase C's `pack-config.v1.non_secret` channel.
pub const MAX_CONFIG_OVERRIDE_PACKS: usize = 32;
pub const MAX_CONFIG_OVERRIDE_KEYS_PER_PACK: usize = 64;
pub const MAX_CONFIG_OVERRIDE_BYTES: usize = 16 * 1024;

/// Shared `§5.4` revenue-share invariant: every entry's basis points must be
/// `<= 10,000` and the sum across entries must equal exactly `10,000`.
///
/// The sum widens into `u64` and rejects any per-entry value above 10,000 so a
/// crafted document like `[u32::MAX, 10001]` cannot wrap to exactly 10,000 in
/// release builds. Shared by [`BundleDeployment::validate`] and the versioned
/// [`RevenuePolicyDocument`](crate::revenue_policy::RevenuePolicyDocument).
pub(crate) fn validate_revenue_share_total(
    revenue_share: &[RevenueShareEntry],
) -> Result<(), SpecError> {
    let mut sum: u64 = 0;
    for entry in revenue_share {
        if entry.basis_points > BASIS_POINTS_TOTAL {
            return Err(SpecError::BasisPointsEntryTooLarge {
                value: entry.basis_points,
            });
        }
        sum += u64::from(entry.basis_points);
    }
    if sum != u64::from(BASIS_POINTS_TOTAL) {
        return Err(SpecError::BasisPointsSum { sum });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BundleDeploymentStatus {
    Active,
    Paused,
    Archived,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantSelector {
    pub tenant: String,
    pub team: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteBinding {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    pub tenant_selector: TenantSelector,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenueShareEntry {
    pub party_id: PartyId,
    pub basis_points: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageMeter {
    pub meter_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleDeployment {
    pub schema: SchemaVersion,
    pub deployment_id: DeploymentId,
    pub env_id: EnvId,
    pub bundle_id: BundleId,
    pub customer_id: CustomerId,
    pub status: BundleDeploymentStatus,
    /// Subset of `Environment.revisions` for this deployment.
    #[serde(default)]
    pub current_revisions: Vec<RevisionId>,
    pub route_binding: RouteBinding,
    pub revenue_share: Vec<RevenueShareEntry>,
    /// Path to the signed, versioned policy document.
    pub revenue_policy_ref: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageMeter>,
    pub created_at: DateTime<Utc>,
    pub authorization_ref: PathBuf,
    /// Per-pack non-secret runtime config overrides applied at the egress
    /// boundary (D.4). Outer key is the pack id (matches the on-disk
    /// `<bundle>/packs/<pack_id>.gtpack` slug and the `pack_id` carried on
    /// synthesized HTTP routes); inner key is the provider config field
    /// (`api_base_url`, `default_chat_id`, …). Values flow through
    /// `messaging_egress::build_send_payload` → `SendPayloadInV1.config`
    /// → the WASM provider's `load_config(input.get("config"))` path.
    ///
    /// Secrets MUST NOT land here — they go through `SecretsManager` via
    /// the `secrets://<env>/<tenant>/<team>/<pack>/<key>` URI scheme
    /// resolved by the `secrets-store` host import (B12a). The non-secret/
    /// secret split is the producer's responsibility (deployer CLI rejects
    /// secret-marked keys); validation here is the structural cap only.
    ///
    /// Caps: see [`MAX_CONFIG_OVERRIDE_PACKS`],
    /// [`MAX_CONFIG_OVERRIDE_KEYS_PER_PACK`],
    /// [`MAX_CONFIG_OVERRIDE_BYTES`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config_overrides: BTreeMap<String, BTreeMap<String, Value>>,
}

impl BundleDeployment {
    pub fn schema_str() -> &'static str {
        SchemaVersion::BUNDLE_DEPLOYMENT_V1
    }

    /// `§5.4`: schema discriminator equals `greentic.bundle-deployment.v1`
    /// and the sum of revenue-share basis points MUST equal 10,000.
    ///
    /// Sum widens into `u64` and rejects any per-entry value above 10,000 so a
    /// crafted document like `[u32::MAX, 10001]` cannot wrap to exactly 10,000
    /// in release builds.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.schema.as_str() != SchemaVersion::BUNDLE_DEPLOYMENT_V1 {
            return Err(SpecError::SchemaMismatch {
                expected: SchemaVersion::BUNDLE_DEPLOYMENT_V1,
                actual: self.schema.as_str().to_string(),
            });
        }
        validate_revenue_share_total(&self.revenue_share)?;
        validate_config_overrides(&self.config_overrides)
    }
}

/// Structural validation for `config_overrides`. Caps the pack count, the
/// per-pack key count, and the total serialized size — and rejects empty
/// pack ids / empty config keys (both would break downstream lookup keyed
/// on those strings).
///
/// The byte cap is computed on a canonical JSON serialization so
/// pack/key/value reshuffling doesn't bypass it.
pub(crate) fn validate_config_overrides(
    overrides: &BTreeMap<String, BTreeMap<String, Value>>,
) -> Result<(), SpecError> {
    if overrides.len() > MAX_CONFIG_OVERRIDE_PACKS {
        return Err(SpecError::ConfigOverridesTooManyPacks {
            count: overrides.len(),
            max: MAX_CONFIG_OVERRIDE_PACKS,
        });
    }
    for (pack_id, fields) in overrides {
        if pack_id.is_empty() {
            return Err(SpecError::ConfigOverrideEmptyPackId);
        }
        if fields.len() > MAX_CONFIG_OVERRIDE_KEYS_PER_PACK {
            return Err(SpecError::ConfigOverridesTooManyKeysForPack {
                pack_id: pack_id.clone(),
                count: fields.len(),
                max: MAX_CONFIG_OVERRIDE_KEYS_PER_PACK,
            });
        }
        for key in fields.keys() {
            if key.is_empty() {
                return Err(SpecError::ConfigOverrideEmptyKey {
                    pack_id: pack_id.clone(),
                });
            }
        }
    }
    let serialized_len = serde_json::to_vec(overrides)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    if serialized_len > MAX_CONFIG_OVERRIDE_BYTES {
        return Err(SpecError::ConfigOverridesTooLarge {
            bytes: serialized_len,
            max: MAX_CONFIG_OVERRIDE_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod config_overrides_tests {
    use super::*;
    use serde_json::json;

    fn ok(packs: &[(&str, &[(&str, Value)])]) -> Result<(), SpecError> {
        let mut overrides = BTreeMap::new();
        for (pack_id, fields) in packs {
            let mut field_map = BTreeMap::new();
            for (k, v) in *fields {
                field_map.insert((*k).to_string(), v.clone());
            }
            overrides.insert((*pack_id).to_string(), field_map);
        }
        validate_config_overrides(&overrides)
    }

    #[test]
    fn empty_overrides_pass() {
        assert!(ok(&[]).is_ok());
    }

    #[test]
    fn single_pack_single_key_passes() {
        assert!(
            ok(&[(
                "messaging-telegram",
                &[("api_base_url", json!("https://staging.example.com"))],
            )])
            .is_ok()
        );
    }

    #[test]
    fn empty_pack_id_rejected() {
        let err = ok(&[("", &[("api_base_url", json!("x"))])]).unwrap_err();
        assert_eq!(err, SpecError::ConfigOverrideEmptyPackId);
    }

    #[test]
    fn empty_config_key_rejected() {
        let err = ok(&[("messaging-telegram", &[("", json!("x"))])]).unwrap_err();
        assert_eq!(
            err,
            SpecError::ConfigOverrideEmptyKey {
                pack_id: "messaging-telegram".to_string(),
            }
        );
    }

    #[test]
    fn too_many_packs_rejected() {
        let mut overrides = BTreeMap::new();
        for i in 0..=MAX_CONFIG_OVERRIDE_PACKS {
            let mut fields = BTreeMap::new();
            fields.insert("k".to_string(), json!("v"));
            overrides.insert(format!("pack-{i}"), fields);
        }
        let err = validate_config_overrides(&overrides).unwrap_err();
        assert_eq!(
            err,
            SpecError::ConfigOverridesTooManyPacks {
                count: MAX_CONFIG_OVERRIDE_PACKS + 1,
                max: MAX_CONFIG_OVERRIDE_PACKS,
            }
        );
    }

    #[test]
    fn too_many_keys_per_pack_rejected() {
        let mut fields = BTreeMap::new();
        for i in 0..=MAX_CONFIG_OVERRIDE_KEYS_PER_PACK {
            fields.insert(format!("k-{i}"), json!("v"));
        }
        let mut overrides = BTreeMap::new();
        overrides.insert("messaging-telegram".to_string(), fields);
        let err = validate_config_overrides(&overrides).unwrap_err();
        assert_eq!(
            err,
            SpecError::ConfigOverridesTooManyKeysForPack {
                pack_id: "messaging-telegram".to_string(),
                count: MAX_CONFIG_OVERRIDE_KEYS_PER_PACK + 1,
                max: MAX_CONFIG_OVERRIDE_KEYS_PER_PACK,
            }
        );
    }

    /// A value crafted to push the serialized representation past
    /// `MAX_CONFIG_OVERRIDE_BYTES` even though the pack + key counts
    /// pass. Catches the "fewer big values bypass the cap" attack.
    #[test]
    fn oversized_total_serialized_rejected() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "blob".to_string(),
            json!("x".repeat(MAX_CONFIG_OVERRIDE_BYTES)),
        );
        let mut overrides = BTreeMap::new();
        overrides.insert("p".to_string(), fields);
        let err = validate_config_overrides(&overrides).unwrap_err();
        match err {
            SpecError::ConfigOverridesTooLarge { bytes, max } => {
                assert!(bytes > max, "must report bytes={bytes} > max={max}");
                assert_eq!(max, MAX_CONFIG_OVERRIDE_BYTES);
            }
            other => panic!("expected ConfigOverridesTooLarge, got {other:?}"),
        }
    }
}
