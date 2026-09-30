//! Per-bundle / per-revision runtime pins (unified update L2).
//!
//! A manifest entry may pin the greentic-start image (`sha256:<hex>`) a
//! revision runs. The "effective runtime" is the only identity the deployer
//! compares: the pin when present, else the environment answer.

use greentic_deploy_spec::{CapabilitySlot, Environment, PackDescriptor};

use crate::cli::OpError;
use crate::cli::env_manifest::EnvManifest;
use crate::env_packs::EnvPackRegistry;
use crate::env_packs::deployer::Capability;

/// `pinned.or(answer)` — a pin wins over the deployer binding's answer.
///
/// Applied to BOTH sides of every comparison (a staged revision's own
/// `runtime_image_digest`, and a manifest entry's pin), so a revision staged
/// before pins existed (`None`) keeps matching an unpinned entry — and an entry
/// pinned to the answer — for as long as the answer is unchanged.
pub(super) fn effective_runtime<'a>(
    pinned: Option<&'a str>,
    answer: Option<&'a str>,
) -> Option<&'a str> {
    pinned.or(answer)
}

/// Refuse a manifest that pins a runtime (bundle- or revision-level) when the
/// deployer bound after this apply cannot honour one.
///
/// An adapter without `runtime_pin` (k8s, local-process) runs the environment's
/// runtime answer for every revision: it would stage the pin onto the store
/// revision and then ignore it, so the store would claim a runtime nothing
/// runs. The deployer is the manifest's deployer pack when it declares one,
/// else the env's existing binding, else a fresh env's default local deployer.
pub(super) fn refuse_unpinnable_runtime(
    manifest: &EnvManifest,
    env: Option<&Environment>,
) -> Result<(), OpError> {
    let pinned = manifest.bundles.iter().any(|b| {
        b.runtime_image_digest.is_some()
            || b.revisions
                .iter()
                .flatten()
                .any(|r| r.runtime_image_digest.is_some())
    });
    if !pinned {
        return Ok(());
    }
    let descriptor = deployer_after_apply(manifest, env)?;
    let registry = EnvPackRegistry::with_builtins();
    let deployer = crate::cli::env_drain::deployer_of(&registry, &descriptor)?;
    deployer
        .capabilities()
        .require(descriptor.path(), Capability::RuntimePin)
        .map_err(|missing| {
            OpError::InvalidArgument(format!(
                "manifest pins a runtime_image_digest, but {missing}: that adapter runs the \
                 environment's runtime answer for every revision. Drop the pin, or bind a \
                 deployer that declares the `runtime_pin` capability"
            ))
        })
}

fn deployer_after_apply(
    manifest: &EnvManifest,
    env: Option<&Environment>,
) -> Result<PackDescriptor, OpError> {
    if let Some(mp) = manifest
        .packs
        .iter()
        .find(|mp| mp.slot == CapabilitySlot::Deployer)
    {
        return PackDescriptor::try_new(&mp.kind).map_err(|e| {
            OpError::InvalidArgument(format!("packs[] deployer kind `{}`: {e}", mp.kind))
        });
    }
    if let Some(binding) = env.and_then(|e| e.pack_for_slot(CapabilitySlot::Deployer)) {
        return Ok(binding.kind.clone());
    }
    PackDescriptor::try_new(crate::defaults::LOCAL_DEPLOYER_PACK)
        .map_err(|e| OpError::InvalidArgument(format!("default deployer kind: {e}")))
}

/// A runtime pin is `sha256:` followed by 64 lowercase hex characters.
pub(in crate::cli) fn validate_runtime_pin(
    location: &str,
    value: Option<&str>,
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let ok = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{location}: runtime_image_digest `{value}` must be `sha256:` followed by 64 \
             lowercase hex characters"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn a_pin_wins_over_the_answer() {
        assert_eq!(effective_runtime(Some(B), Some(A)), Some(B));
    }

    #[test]
    fn an_unpinned_revision_runs_the_answer() {
        assert_eq!(effective_runtime(None, Some(A)), Some(A));
        assert_eq!(effective_runtime(None, None), None);
    }

    #[test]
    fn only_a_lowercase_sha256_is_a_pin() {
        assert!(validate_runtime_pin("bundles[0]", Some(A)).is_ok());
        assert!(validate_runtime_pin("bundles[0]", None).is_ok());
        assert!(validate_runtime_pin("bundles[0]", Some("sha256:ABC")).is_err());
        assert!(validate_runtime_pin("bundles[0]", Some("develop")).is_err());
    }
}
