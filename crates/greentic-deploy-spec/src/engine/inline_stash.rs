//! One-step rollback stash: a previous-state JSON snapshot encoded inline
//! as a base64 token under the `inline://` sentinel prefix (Phase D
//! PR-4.2c — promoted from the deployer CLI's duplicated copies in
//! `cli::env_packs` / `cli::traffic` now that the pure traffic transforms
//! live in this crate and both backends must read/write the same tokens).
//!
//! The scheme is intentionally minimal — one step of rollback, no history
//! sidecar file (which would need its own backup/lock contract). The token
//! rides in `previous_split_ref` / `previous_binding_ref` `PathBuf` fields,
//! so it must stay path-safe: URL-safe base64, no padding.

use serde_json::Value;
use std::path::{Path, PathBuf};

/// Sentinel prefix discriminating an inline snapshot token from a real
/// filesystem path in `previous_*_ref` fields.
pub const PREV_PREFIX: &str = "inline://";

/// Stash a JSON snapshot inline so a rollback verb can restore it without a
/// sidecar history file.
pub fn stash_inline(snapshot: Value) -> PathBuf {
    let mut encoded = String::from(PREV_PREFIX);
    let raw = serde_json::to_string(&snapshot).expect("Value re-serialises");
    encoded.push_str(&base64_encode(raw.as_bytes()));
    PathBuf::from(encoded)
}

/// Decode an inline snapshot token back into its JSON value. Returns `None`
/// when the ref is not an `inline://` token or the payload is malformed.
pub fn load_inline(prev_ref: &Path) -> Option<Value> {
    let token = prev_ref.to_str()?;
    let encoded = token.strip_prefix(PREV_PREFIX)?;
    let bytes = base64_decode(encoded)?;
    let raw = std::str::from_utf8(&bytes).ok()?;
    serde_json::from_str(raw).ok()
}

// Minimal URL-safe base64 (no padding). Hand-rolled to keep the spec crate's
// dep tree clean — `base64` is not a dependency, and pulling it in for an
// encoding used only by this one short path is the wrong trade.

fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = val(bytes[i])?;
        let b1 = val(*bytes.get(i + 1)?)?;
        let b2 = bytes.get(i + 2).copied().and_then(val);
        let b3 = bytes.get(i + 3).copied().and_then(val);
        let triple = ((b0 as u32) << 18)
            | ((b1 as u32) << 12)
            | ((b2.unwrap_or(0) as u32) << 6)
            | (b3.unwrap_or(0) as u32);
        out.push(((triple >> 16) & 0xFF) as u8);
        if b2.is_some() {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if b3.is_some() {
            out.push((triple & 0xFF) as u8);
        }
        i += 4;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn base64_round_trips_all_remainder_lengths() {
        for case in [
            b"".as_slice(),
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"\x00\xff\x80\x7f",
        ] {
            let encoded = base64_encode(case);
            let decoded = base64_decode(&encoded).expect("decode");
            assert_eq!(decoded, case, "round-trip failed for {case:?}");
        }
    }

    #[test]
    fn base64_decode_rejects_invalid_chars_and_lone_byte() {
        assert_eq!(base64_decode("a!"), None);
        assert_eq!(base64_decode("a"), None, "1 leftover sextet is malformed");
    }

    #[test]
    fn stash_and_load_round_trip_json() {
        let snapshot = json!({"generation": 3, "entries": [{"weight_bps": 10_000}]});
        let token = stash_inline(snapshot.clone());
        assert!(token.to_string_lossy().starts_with(PREV_PREFIX));
        assert_eq!(load_inline(&token), Some(snapshot));
    }

    #[test]
    fn load_inline_rejects_non_token_paths() {
        assert_eq!(load_inline(Path::new("splits/previous.json")), None);
        assert_eq!(load_inline(Path::new("inline://%%not-base64%%")), None);
    }
}
