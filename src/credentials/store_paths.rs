//! Canonical dev-store paths at which a deployer env-pack's
//! [`bootstrap`](super::DeployerCredentials::bootstrap) lands the bound
//! credential material it minted.
//!
//! **This module owns the W1/W2 orphan invariant. Other sites link here rather
//! than restate it.**
//!
//! ## The invariant
//!
//! `credentials::bootstrap` writes the minted material (**W1**) *before* it
//! persists `credentials_ref` (**W2**). That order is deliberate — a failed save
//! must leave bootstrap re-runnable rather than point the env at a credential
//! whose material isn't there — but it means a crash between the two orphans
//! material that nothing names. A denylist keyed on `credentials_ref` therefore
//! cannot see it, and the next runtime seed would copy the deployer's own
//! credential into the workload, where the shared dev master key decrypts it.
//!
//! So: **bound credential material may only ever land somewhere the runtime-seed
//! denylist can strip it.** Two mechanisms hold that up, and neither subsumes the
//! other:
//!
//! * **Write-time** — [`landing_is_covered`], enforced by `run_bootstrap` before
//!   anything is written or persisted. Catches a handler that mints at a path
//!   nothing here covers.
//! * **Seed-time** — `cli::env::staging_excluded_uris` strips
//!   [`BOUND_CREDENTIAL_STORE_PATHS`] unconditionally. Catches the orphan itself,
//!   which by definition appears *after* the write-time check already passed.
//!
//! ## Why the paths live here
//!
//! 1. **Single source of truth.** The minting handlers build their
//!    `bound_credentials_ref` from these constants and the denylist excludes
//!    them, so the writer and the denylist provably cannot drift.
//! 2. **Feature independence.** A dev-store outlives the binary that wrote it.
//!    An AWS-capable build can land material at [`AWS_DEPLOYER_SESSION`] and
//!    crash; a later build compiled *without* `creds-aws` must still strip that
//!    material from any seed it stages. Gating the denylist on the SDK features
//!    of the *current* binary would reintroduce the leak, so the list is
//!    unconditional and additive: paths are only ever added, never removed.

/// Where the K8s bootstrap's `--bind` path lands the minted ServiceAccount
/// bearer. Aliased as `env_packs::k8s::bootstrap::DEPLOYER_TOKEN_STORE_PATH`.
pub(crate) const K8S_DEPLOYER_TOKEN: &str = "default/_/k8s-deployer/deployer_token";

/// Where the AWS bootstrap lands the assumed STS session. Aliased as
/// `env_packs::aws::credentials::DEPLOYER_SESSION_STORE_PATH`.
pub(crate) const AWS_DEPLOYER_SESSION: &str = "default/_/aws-deployer/deployer_session";

/// Every store-relative path at which a built-in deployer bootstrap has ever
/// landed bound credential material, `secret://<env>/<path>`-relative.
///
/// **Control-plane namespace.** Reserved for the deployer's own credentials;
/// runtime material must not be written here, and everything listed is stripped
/// from every staged runtime seed unconditionally (module doc).
///
/// **Adding a deployer env-pack that mints bind material?** Its landing path MUST
/// be added here, or its bootstrap fails closed. Only env-packs whose `bootstrap`
/// returns `bound_credentials_ref: Some(_)` need an entry.
pub(crate) const BOUND_CREDENTIAL_STORE_PATHS: &[&str] =
    &[K8S_DEPLOYER_TOKEN, AWS_DEPLOYER_SESSION];

/// `<tenant>/<team>/<pack>/<name>@<version>` → `<tenant>/<team>/<pack>/<name>`.
///
/// Only the final segment may carry a version (`SecretUri` parses `@` there).
/// The dev-store's exclusion filter matches by this versionless identity, so
/// every reservation/denylist comparison must normalize first — otherwise
/// `…/deployer_token@1`, which names the very same key, slips through.
pub(crate) fn versionless_rel_path(rel_path: &str) -> String {
    match rel_path.rsplit_once('/') {
        Some((head, last)) => match last.split_once('@') {
            Some((name, _version)) => format!("{head}/{name}"),
            None => rel_path.to_string(),
        },
        None => rel_path.to_string(),
    }
}

/// Whether `rel_path` names the deployer's own bound-credential namespace,
/// compared by canonical versionless identity.
pub(crate) fn is_reserved_rel_path(rel_path: &str) -> bool {
    BOUND_CREDENTIAL_STORE_PATHS.contains(&versionless_rel_path(rel_path).as_str())
}

/// Check that bound credential material may be written at `bound_ref` — the
/// write-time half of the module's invariant.
///
/// Checked against the ACTUAL destination rather than the handler's claim about
/// it: a handler that declares a covered path while returning a rogue or
/// cross-environment ref must not pass. All three conditions are load-bearing:
///
/// * the ref parses (a ref no exclusion can match is itself a refusal reason),
/// * it is scoped to the env being written (a cross-env ref lands a key in this
///   env's store that this env's exclusion would never name),
/// * its versionless path equals the declaration AND is covered by
///   [`BOUND_CREDENTIAL_STORE_PATHS`].
///
/// `Err` carries the resolved landing site (`<env>:<rel>`, `None` if the ref did
/// not parse) so the caller can report what would have happened.
pub(crate) fn landing_is_covered(
    bound_ref: &greentic_deploy_spec::SecretRef,
    env_id: &greentic_deploy_spec::EnvId,
    declared: Option<&str>,
) -> Result<(), Option<String>> {
    // Resolved through the same canonicalization the writer uses
    // (`to_store_uri` re-canonicalizes the team), so this compares what will
    // really be on disk.
    let landing = bound_ref
        .to_store_uri()
        .ok()
        .and_then(|uri| split_store_uri(&uri.to_string()).map(|(env, rel)| (env.to_string(), rel)));
    match (&landing, declared) {
        (Some((ref_env, rel)), Some(path))
            if ref_env == env_id.as_str()
                && rel == path
                && BOUND_CREDENTIAL_STORE_PATHS.contains(&path) =>
        {
            Ok(())
        }
        _ => Err(landing.map(|(env, rel)| format!("{env}:{rel}"))),
    }
}

/// Split a canonical store URI `secret(s)://<env>/<rel>` into its env and its
/// versionless store-relative path. `None` when the URI has no env + tail.
pub(crate) fn split_store_uri(store_uri: &str) -> Option<(&str, String)> {
    let (_scheme, rest) = store_uri.split_once("://")?;
    let (env, rel) = rest.split_once('/')?;
    if env.is_empty() || rel.is_empty() {
        return None;
    }
    Some((env, versionless_rel_path(rel)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versionless_rel_path_normalizes_only_the_final_segment() {
        let base = "default/_/k8s-deployer/deployer_token";
        assert_eq!(versionless_rel_path(base), base);
        assert_eq!(versionless_rel_path(&format!("{base}@1")), base);
        assert_eq!(versionless_rel_path(&format!("{base}@v2")), base);
        // Trailing `@` — an empty version still names the same key.
        assert_eq!(versionless_rel_path(&format!("{base}@")), base);
        // Only the FIRST `@` splits, so a version containing `@` cannot smuggle
        // the name back in.
        assert_eq!(versionless_rel_path(&format!("{base}@1@2")), base);
        // An `@` in a non-final segment is not a version.
        assert_eq!(
            versionless_rel_path("default/_/k8s@x/token"),
            "default/_/k8s@x/token"
        );
        // Degenerate inputs must not panic.
        assert_eq!(versionless_rel_path("nolash"), "nolash");
        assert_eq!(versionless_rel_path(""), "");
    }

    #[test]
    fn split_store_uri_extracts_env_and_versionless_rel() {
        assert_eq!(
            split_store_uri("secrets://local/default/_/k8s-deployer/deployer_token@3"),
            Some(("local", "default/_/k8s-deployer/deployer_token".to_string()))
        );
        assert_eq!(
            split_store_uri("secret://prod/a/b/c/d"),
            Some(("prod", "a/b/c/d".to_string()))
        );
        for bad in [
            "",
            "nonsense",
            "secrets://",
            "secrets://env",
            "secrets:///rel",
        ] {
            assert!(split_store_uri(bad).is_none(), "`{bad}` must not parse");
        }
    }

    /// Conformance guard: walk the *registry* — not a hard-coded pair — and
    /// require that every deployer env-pack which declares a credential landing
    /// path has that path in the denylist. A new minting handler that forgets to
    /// register its path fails here rather than silently leaking an orphaned
    /// credential into a workload seed.
    ///
    /// Registry-driven on purpose: asserting on the two built-in constants would
    /// be tautological (they are aliases of the entries below) and would pass
    /// for a third handler that never registered its path at all.
    #[test]
    fn every_declared_handler_landing_path_is_in_the_denylist() {
        use crate::env_packs::registry::EnvPackRegistry;
        use greentic_deploy_spec::CapabilitySlot;

        let registry = EnvPackRegistry::with_builtins();
        let mut declared = 0;
        for handler in registry.handlers() {
            if handler.slot() != CapabilitySlot::Deployer {
                continue;
            }
            let Some(creds) = handler.deployer_credentials() else {
                continue;
            };
            let Some(path) = creds.bound_credential_store_path() else {
                continue; // render-only / local — mints nothing to orphan
            };
            declared += 1;
            assert!(
                BOUND_CREDENTIAL_STORE_PATHS.contains(&path),
                "deployer env-pack `{}` lands bound credential material at `{path}`, \
                 but that path is not in BOUND_CREDENTIAL_STORE_PATHS — a crashed \
                 bootstrap would orphan a credential the runtime-seed denylist misses. \
                 Add it to credentials::store_paths.",
                handler.descriptor_path()
            );
        }
        assert!(
            declared > 0,
            "sanity: at least the k8s deployer must declare a landing path — a zero \
             count would make this guard vacuous"
        );
    }

    /// The denylist must not depend on which provider SDK features this binary
    /// compiled: a dev-store written by a fuller build outlives it.
    ///
    /// Note this assertion can only *bite* when compiled without `creds-aws`
    /// (`cargo test --lib --no-default-features`); a cfg-gated entry looks
    /// identical under the default feature set. CI builds that configuration but
    /// does not test it, so the real guard against regression is that
    /// [`BOUND_CREDENTIAL_STORE_PATHS`] is a plain unconditional const — keep it
    /// that way.
    #[test]
    fn denylist_is_feature_independent() {
        assert!(
            BOUND_CREDENTIAL_STORE_PATHS.contains(&AWS_DEPLOYER_SESSION),
            "the AWS path must be excluded even in a build without `creds-aws` — \
             an AWS-capable build can have orphaned material there"
        );
        assert!(BOUND_CREDENTIAL_STORE_PATHS.contains(&K8S_DEPLOYER_TOKEN));
    }

    /// Entries must be canonical four-segment store-relative paths, so
    /// `secret://<env>/<path>` parses as a store-aligned ref.
    #[test]
    fn paths_are_canonical_four_segment_store_relative() {
        for path in BOUND_CREDENTIAL_STORE_PATHS {
            assert_eq!(
                path.split('/').count(),
                4,
                "`{path}` must be <tenant>/<team>/<category>/<name>"
            );
            assert!(!path.starts_with('/'), "`{path}` must be store-relative");
        }
    }
}
