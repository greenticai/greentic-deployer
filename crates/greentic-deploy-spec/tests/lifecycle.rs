use greentic_deploy_spec::{RevisionLifecycle, is_valid_transition};

#[test]
fn matrix_allows_documented_transitions() {
    use RevisionLifecycle::*;
    let allowed = [
        (Inactive, Staged),
        (Inactive, Failed),
        (Staged, Warming),
        (Staged, Failed),
        (Staged, Archived),
        (Warming, Ready),
        (Warming, Failed),
        (Warming, Archived),
        (Ready, Draining),
        (Ready, Failed),
        (Ready, Archived),
        (Draining, Inactive),
        (Failed, Staged),
        (Failed, Archived),
    ];
    for (from, to) in allowed {
        assert!(
            is_valid_transition(from, to),
            "expected {from:?} → {to:?} to be allowed",
        );
    }
}

#[test]
fn matrix_denies_all_other_transitions() {
    use RevisionLifecycle::*;
    let states = [Inactive, Staged, Warming, Ready, Draining, Failed, Archived];
    let allowed_set: std::collections::HashSet<_> = [
        (Inactive, Staged),
        (Inactive, Failed),
        (Staged, Warming),
        (Staged, Failed),
        (Staged, Archived),
        (Warming, Ready),
        (Warming, Failed),
        (Warming, Archived),
        (Ready, Draining),
        (Ready, Failed),
        (Ready, Archived),
        (Draining, Inactive),
        (Failed, Staged),
        (Failed, Archived),
    ]
    .into_iter()
    .collect();

    for &from in &states {
        for &to in &states {
            let want = allowed_set.contains(&(from, to));
            assert_eq!(
                is_valid_transition(from, to),
                want,
                "transition {from:?} → {to:?} mismatch",
            );
        }
    }
}

#[test]
fn archived_is_terminal() {
    use RevisionLifecycle::*;
    for to in [Inactive, Staged, Warming, Ready, Draining, Failed, Archived] {
        assert!(
            !is_valid_transition(Archived, to),
            "archived should not transition to {to:?}",
        );
    }
}

#[test]
fn no_self_transitions() {
    use RevisionLifecycle::*;
    for s in [Inactive, Staged, Warming, Ready, Draining, Failed, Archived] {
        assert!(
            !is_valid_transition(s, s),
            "self-transition should not be allowed for {s:?}",
        );
    }
}
