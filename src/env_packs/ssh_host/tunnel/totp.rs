//! RFC 6238 time-based one-time passwords, computed on the deployer.
//!
//! HMAC-SHA1, 6 digits, 30 second step: what Cisco, Duo-less RADIUS and every
//! authenticator app use by default. The seed is the customer's (base32, as the
//! enrolment page prints it) and reaches us only as a `0600` file; it is held in
//! zeroizing memory and never logged, never in argv.

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

pub const STEP_SECS: u64 = 30;
pub const DIGITS: u32 = 6;

/// Earliest plausible "now": 2025-01-01T00:00:00Z. A clock before it is a clock
/// that was never set (VM without NTP, epoch 0).
pub const CLOCK_FLOOR_UNIX: u64 = 1_735_689_600;
/// Latest plausible "now": 2100-01-01T00:00:00Z.
pub const CLOCK_CEILING_UNIX: u64 = 4_102_444_800;

/// Decode an RFC 4648 base32 seed. Case, spaces, `-` and `=` padding are ignored.
pub fn decode_base32(text: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let (mut buffer, mut bits) = (0u32, 0u32);
    let mut seen = 0usize;
    for c in text.chars() {
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            ' ' | '-' | '=' => continue,
            _ => return Err("the TOTP seed is not base32 (A-Z and 2-7)"),
        };
        seen += 1;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if seen < 16 {
        return Err("the TOTP seed is too short (a real seed is at least 16 base32 characters)");
    }
    Ok(out)
}

fn padded(block: &[u8], pad: u8) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(block.iter().map(|b| b ^ pad).collect::<Vec<u8>>())
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK: usize = 64;
    let mut block = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        let digest = Sha1::digest(key);
        let digest: &[u8] = digest.as_ref();
        block[..digest.len()].copy_from_slice(digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha1::new();
    inner.update(padded(&block[..], 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let inner: &[u8] = inner.as_ref();
    let mut outer = Sha1::new();
    outer.update(padded(&block[..], 0x5c));
    outer.update(inner);
    let outer = outer.finalize();
    let outer: &[u8] = outer.as_ref();
    let mut mac = [0u8; 20];
    mac.copy_from_slice(outer);
    mac
}

/// The 6-digit code for `secret` at `unix_time`.
pub fn code(secret: &[u8], unix_time: u64) -> Zeroizing<String> {
    let counter = (unix_time / STEP_SECS).to_be_bytes();
    let mac = hmac_sha1(secret, &counter);
    let offset = usize::from(mac[19] & 0x0f);
    let truncated = u32::from_be_bytes([
        mac[offset] & 0x7f,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    Zeroizing::new(format!(
        "{:0width$}",
        truncated % 10u32.pow(DIGITS),
        width = DIGITS as usize
    ))
}

/// `Some(reason)` when the host clock is so far off that no code can be right.
/// This catches an unset clock, not a few seconds of skew (that needs a time
/// reference the deployer does not have offline).
pub fn clock_problem(now_unix: u64) -> Option<String> {
    if now_unix < CLOCK_FLOOR_UNIX {
        Some("the host clock is set before 2025, so a one-time code would be rejected".into())
    } else if now_unix > CLOCK_CEILING_UNIX {
        Some(
            "the host clock is set past the year 2100, so a one-time code would be rejected".into(),
        )
    } else {
        None
    }
}

/// Seconds to wait so the code is not computed in the last 3 seconds of its
/// step, where it can expire while the login is in flight.
pub fn wait_for_fresh_step(now_unix: u64) -> u64 {
    let into_step = now_unix % STEP_SECS;
    if into_step >= STEP_SECS - 3 {
        STEP_SECS - into_step
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA1 seed "12345678901234567890"; the RFC lists 8
    /// digits, the last 6 are the 6-digit code.
    #[test]
    fn matches_the_rfc_6238_vectors() {
        let seed = b"12345678901234567890";
        for (time, expected) in [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(&*code(seed, time), expected, "t={time}");
        }
    }

    #[test]
    fn decodes_base32_seeds_the_way_authenticator_apps_print_them() {
        // "12345678901234567890" in base32.
        let seed = decode_base32("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(seed.as_slice(), b"12345678901234567890");
        assert_eq!(
            decode_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====")
                .unwrap()
                .as_slice(),
            b"12345678901234567890"
        );
    }

    #[test]
    fn refuses_a_seed_that_is_not_base32_or_is_too_short() {
        assert!(decode_base32("not base32 !!!!!!!!!!!!").is_err());
        assert!(decode_base32("GEZDGNBV").is_err());
    }

    #[test]
    fn long_keys_are_hashed_first() {
        let key = [0xaa_u8; 80];
        // Self-consistency: a key over the block size must not panic and must differ
        // from its truncation.
        assert_ne!(code(&key, 59), code(&key[..64], 59));
    }

    #[test]
    fn an_unset_or_absurd_clock_is_refused_and_a_late_second_waits() {
        assert!(clock_problem(0).is_some());
        assert!(clock_problem(1_800_000_000).is_none());
        assert!(clock_problem(5_000_000_000).is_some());
        assert_eq!(wait_for_fresh_step(1_800_000_000), 0);
        assert_eq!(wait_for_fresh_step(1_800_000_028), 2);
        assert_eq!(wait_for_fresh_step(1_800_000_029), 1);
    }
}
