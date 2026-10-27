//! The ARM actions the deployer needs, and a wildcard-aware matcher over an
//! identity's effective permissions.
//!
//! Every action the real target calls appears in [`REAL_ACA_TARGET_RBAC_ACTIONS`],
//! in the validator's [`REQUIRED_ACTIONS`] and in the rendered custom role; tests
//! tie the three together.

/// Actions the ARM REST client issues (control plane only). Tied to the validator
/// set by a test; the rendered role is built from [`REQUIRED_ACTIONS`].
#[cfg(test)]
pub(crate) const REAL_ACA_TARGET_RBAC_ACTIONS: &[&str] = &[
    "Microsoft.App/containerApps/read",
    "Microsoft.App/containerApps/write",
    "Microsoft.App/containerApps/delete",
    "Microsoft.App/containerApps/listSecrets/action",
    "Microsoft.App/containerApps/revisions/read",
    "Microsoft.App/containerApps/revisions/deactivate/action",
    "Microsoft.App/managedEnvironments/read",
    // Creating an app inside an environment needs `join` on the environment.
    "Microsoft.App/managedEnvironments/join/action",
    // Long-running operation polling.
    "Microsoft.App/locations/containerappOperationStatuses/read",
];

/// Actions the validator checks: the target's plus the preflight's own read, and
/// revision activate / restart (operators recover stuck revisions with them).
pub(crate) const REQUIRED_ACTIONS: &[&str] = &[
    "Microsoft.App/containerApps/read",
    "Microsoft.App/containerApps/write",
    "Microsoft.App/containerApps/delete",
    "Microsoft.App/containerApps/listSecrets/action",
    "Microsoft.App/containerApps/revisions/read",
    "Microsoft.App/containerApps/revisions/deactivate/action",
    "Microsoft.App/containerApps/revisions/activate/action",
    "Microsoft.App/containerApps/revisions/restart/action",
    "Microsoft.App/managedEnvironments/read",
    "Microsoft.App/managedEnvironments/join/action",
    "Microsoft.App/locations/containerappOperationStatuses/read",
    "Microsoft.Authorization/permissions/read",
];

/// One entry of `GET .../providers/Microsoft.Authorization/permissions`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permission {
    pub actions: Vec<String>,
    pub not_actions: Vec<String>,
}

/// Case-insensitive match of `pattern` (which may contain `*`) against `action`.
pub(crate) fn pattern_matches(pattern: &str, action: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let a = action.to_ascii_lowercase();
    let parts: Vec<&str> = p.split('*').collect();
    if parts.len() == 1 {
        return p == a;
    }
    let mut rest = a.as_str();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(pos) => rest = &rest[pos + part.len()..],
                None => return false,
            }
        }
    }
    true
}

/// Allowed when some permission lists a matching action and none of THAT
/// permission's `notActions` matches (Azure evaluates them per entry).
pub(crate) fn action_allowed(perms: &[Permission], action: &str) -> bool {
    perms.iter().any(|p| {
        p.actions.iter().any(|a| pattern_matches(a, action))
            && !p.not_actions.iter().any(|n| pattern_matches(n, action))
    })
}

/// Required actions the identity lacks, in `REQUIRED_ACTIONS` order.
#[cfg(test)]
pub(crate) fn missing_actions(perms: &[Permission]) -> Vec<&'static str> {
    REQUIRED_ACTIONS
        .iter()
        .copied()
        .filter(|a| !action_allowed(perms, a))
        .collect()
}

/// True when the grant is a blanket wildcard (`*` or `Microsoft.App/*`): it works,
/// but is broader than the least-privilege role the bootstrap renders.
pub(crate) fn is_broad(perms: &[Permission]) -> bool {
    perms
        .iter()
        .flat_map(|p| p.actions.iter())
        .any(|a| a == "*" || a.eq_ignore_ascii_case("Microsoft.App/*"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perm(actions: &[&str], not: &[&str]) -> Permission {
        Permission {
            actions: actions.iter().map(|s| s.to_string()).collect(),
            not_actions: not.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn wildcard_matching_and_notactions() {
        assert!(pattern_matches("*", "Microsoft.App/containerApps/read"));
        assert!(pattern_matches(
            "Microsoft.App/*/read",
            "microsoft.app/containerApps/read"
        ));
        assert!(pattern_matches(
            "Microsoft.App/containerApps/*",
            "Microsoft.App/containerApps/listSecrets/action"
        ));
        assert!(!pattern_matches(
            "Microsoft.App/containerApps/read",
            "Microsoft.App/containerApps/write"
        ));
        assert!(!pattern_matches(
            "Microsoft.Web/*",
            "Microsoft.App/containerApps/read"
        ));
        let p = [perm(&["*"], &["Microsoft.App/containerApps/delete"])];
        assert!(action_allowed(&p, "Microsoft.App/containerApps/read"));
        assert!(!action_allowed(&p, "Microsoft.App/containerApps/delete"));
        // A notAction in one entry does not strip another entry's grant.
        let two = [
            p[0].clone(),
            perm(&["Microsoft.App/containerApps/delete"], &[]),
        ];
        assert!(action_allowed(&two, "Microsoft.App/containerApps/delete"));
    }

    #[test]
    fn missing_actions_are_reported_exactly_in_order() {
        let have = [perm(
            &[
                "Microsoft.App/containerApps/read",
                "Microsoft.App/containerApps/write",
            ],
            &[],
        )];
        let missing = missing_actions(&have);
        assert_eq!(missing.len(), REQUIRED_ACTIONS.len() - 2);
        assert_eq!(missing[0], "Microsoft.App/containerApps/delete");
        assert!(missing_actions(&[perm(&["*"], &[])]).is_empty());
    }

    #[test]
    fn a_contributor_wildcard_is_accepted_but_flagged_broad() {
        let p = [perm(&["*"], &["Microsoft.Authorization/*/Delete"])];
        assert!(missing_actions(&p).is_empty());
        assert!(is_broad(&p));
        assert!(!is_broad(&[perm(
            &["Microsoft.App/containerApps/read"],
            &[]
        )]));
    }

    #[test]
    fn the_target_actions_are_a_subset_of_the_validator_set() {
        for a in REAL_ACA_TARGET_RBAC_ACTIONS {
            assert!(
                REQUIRED_ACTIONS.contains(a),
                "{a} missing from REQUIRED_ACTIONS"
            );
        }
    }
}
