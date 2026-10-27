//! Deterministic Azure resource names for one Greentic deployment / revision.

use greentic_deploy_spec::{DeploymentId, RevisionId};
use sha2::{Digest, Sha256};

/// Container App name limit (`NEEDS_LIVE`, see the decision record).
pub(crate) const APP_NAME_MAX: usize = 32;
/// Revision suffix limit documented by Microsoft Learn.
pub(crate) const SUFFIX_MAX: usize = 64;

/// Name of the Container App serving one deployment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AppName(String);

impl AppName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AppName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Revision suffix (`r` + lowercased Greentic revision id).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RevisionSuffix(String);

impl RevisionSuffix {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

fn fold(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars().flat_map(char::to_lowercase) {
        let c = if c.is_ascii_alphanumeric() { c } else { '-' };
        if c == '-' && out.ends_with('-') {
            continue;
        }
        out.push(c);
    }
    out
}

/// `prefix` + `body` folded into `[a-z0-9-]`, at most `max` long. When it has to
/// be cut, a 6-hex hash of the ORIGINAL input keeps two long names apart.
pub(crate) fn fit_name(prefix: &str, body: &str, max: usize) -> String {
    let full = fold(&format!("{prefix}{body}"));
    let full = full.trim_matches('-').to_string();
    if full.len() <= max {
        return full;
    }
    let digest = hex::encode(&Sha256::digest(format!("{prefix}{body}").as_bytes())[..3]);
    let keep = max.saturating_sub(digest.len() + 1);
    let head = full[..keep].trim_end_matches('-');
    format!("{head}-{digest}")
}

pub(crate) fn app_name(deployment_id: &DeploymentId) -> AppName {
    AppName(fit_name("gtc-", &deployment_id.0.to_string(), APP_NAME_MAX))
}

pub(crate) fn revision_suffix(revision_id: &RevisionId) -> RevisionSuffix {
    let mut s = fit_name("r", &revision_id.0.to_string(), SUFFIX_MAX);
    // The prefix is always a letter, so the start rule holds; `--` is folded away.
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    RevisionSuffix(s)
}

/// ACA revision name: `<app>--<suffix>`.
pub(crate) fn revision_name(app: &AppName, suffix: &RevisionSuffix) -> String {
    format!("{}--{}", app.0, suffix.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    #[test]
    fn app_name_is_stable_and_within_limit() {
        let d = DeploymentId(Ulid::from(7_u128));
        let a = app_name(&d);
        assert_eq!(a, app_name(&d));
        assert!(a.as_str().len() <= APP_NAME_MAX, "{a}");
        assert!(a.as_str().starts_with("gtc-"));
        assert!(!a.as_str().ends_with('-'));
    }

    #[test]
    fn two_long_names_never_collide_after_truncation() {
        let a = fit_name("gtc-", &"x".repeat(60), 32);
        let b = fit_name("gtc-", &format!("{}y", "x".repeat(60)), 32);
        assert_ne!(a, b);
        assert!(a.len() <= 32 && b.len() <= 32);
        assert!(!a.ends_with('-') && !b.ends_with('-'));
    }

    #[test]
    fn suffix_starts_with_a_letter_and_has_no_double_dash() {
        let s = revision_suffix(&RevisionId(Ulid::from(0x10_u128)));
        assert!(s.as_str().starts_with('r'));
        assert!(!s.as_str().contains("--"));
        assert!(s.as_str().len() <= SUFFIX_MAX);
        let name = revision_name(&app_name(&DeploymentId(Ulid::from(1_u128))), &s);
        assert_eq!(name.matches("--").count(), 1);
    }
}
