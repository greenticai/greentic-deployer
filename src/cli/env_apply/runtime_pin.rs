//! Per-bundle / per-revision runtime pins (unified update L2).
//!
//! A manifest entry may pin the greentic-start image (`sha256:<hex>`) a
//! revision runs. The "effective runtime" is the only identity the deployer
//! compares: the pin when present, else the environment answer.

/// `pinned.or(answer)` — a pin wins over the deployer binding's answer.
// Consumed by the convergence/reuse comparison (DP3).
#[allow(dead_code)]
pub(super) fn effective_runtime<'a>(
    pinned: Option<&'a str>,
    answer: Option<&'a str>,
) -> Option<&'a str> {
    pinned.or(answer)
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
