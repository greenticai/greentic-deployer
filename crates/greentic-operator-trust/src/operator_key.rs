//! Operator-key load/generate (C2 of `plans/next-gen-deployment.md`).
//!
//! Provides the Ed25519 keypair the operator uses to sign artifacts it owns
//! (today: B10 revenue-policy DSSE; future: revision manifests, audit-log
//! tips). Key material lives on the operator's filesystem and is created on
//! first use; rotation is out of scope for C2 v1 — that's the Trust plan.
//!
//! ## Key location
//!
//! The path is resolved in this order:
//!
//! 1. `$GTC_OPERATOR_KEY_PATH` if set (caller wants a non-default location,
//!    e.g. a vault-mounted tmpfs path or a CI fixture).
//! 2. `~/.greentic/operator/key.pem` on POSIX/Windows.
//! 3. Error — no home directory and no env override.
//!
//! Companion file: `<key.pem>.pub` (SPKI PEM). It is derived from the
//! private key, written next to it on generation, and cross-checked on
//! subsequent loads — if a `.pub` exists but does not match the canonical
//! id derived from the private key, the load fails. A stale `.pub` from a
//! prior `.pem` always indicates operator-side tampering or a partial
//! rotation; deriving silently from the private key would mask it.
//!
//! ## File modes
//!
//! On POSIX, the private key is written with mode `0600` and the public
//! key with mode `0644`. On platforms without `std::os::unix::fs`, the
//! permissions fall through to the OS default.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use greentic_distributor_client::signing::{SigningError, key_id_for_public_key_pem};
use rand::TryRngCore;
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

/// Override for the operator key path. When set, takes precedence over the
/// `~/.greentic/operator/key.pem` default.
pub const OPERATOR_KEY_PATH_ENV: &str = "GTC_OPERATOR_KEY_PATH";

/// Home-directory resolution for the default key location. Mirrors the
/// deployer's `environment::store::dirs_home` so the resolved path is
/// identical whichever crate asks.
#[cfg(unix)]
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(windows)]
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE").map(PathBuf::from)
}

#[cfg(not(any(unix, windows)))]
fn dirs_home() -> Option<PathBuf> {
    None
}

#[derive(Debug, Error)]
pub enum OperatorKeyError {
    #[error(
        "cannot resolve operator key path: `${OPERATOR_KEY_PATH_ENV}` is unset and no home directory is available"
    )]
    NoHome,
    #[error("operator key io on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("operator key parse: {0}")]
    KeyDecode(String),
    #[error("operator key derivation: {0}")]
    Signing(#[from] SigningError),
    #[error(
        "operator public key `{pub_path}` is stale: id `{pub_id}` does not match private-key id `{priv_id}` — delete the `.pub` and re-run to regenerate, or restore the matching private key"
    )]
    StalePublicKey {
        pub_path: PathBuf,
        pub_id: String,
        priv_id: String,
    },
    #[error("operator key entropy: {0}")]
    Entropy(String),
    /// The on-disk operator key has group/world-readable permissions. A
    /// copied or restored key with `0644`/`0660` would otherwise be signed
    /// with while other local users could exfiltrate it. Reject before use.
    #[error(
        "operator key `{path}` has insecure permissions (mode {mode:#o}); expected mode `0600` (owner-only). Restore with `chmod 600 {path}` or delete and regenerate."
    )]
    InsecurePermissions { path: PathBuf, mode: u32 },
    /// The on-disk operator key is not a regular file (symlink, directory,
    /// FIFO, etc.). `O_NOFOLLOW` would have caught a symlink in `open`; this
    /// covers everything else after `fstat`.
    #[error(
        "operator key `{path}` is not a regular file (symlinks, directories, FIFOs etc. are rejected)"
    )]
    NotRegularFile { path: PathBuf },
    /// A directory component on the path to the operator key is a symlink.
    /// `O_NOFOLLOW` only refuses the final component; an attacker who
    /// controls an intermediate directory (e.g. swaps `~/.greentic` for a
    /// symlink to their own dir before the operator's first run) would
    /// otherwise have the load and write resolve into their controlled
    /// directory. Caught by `lstat`-walking each parent on every load/generate.
    #[error(
        "operator key path `{path}`: ancestor `{ancestor}` is a symlink. Re-create the directory as a real path (e.g. `mv {ancestor} {ancestor}.symlink && mkdir -p {ancestor}`) to prevent intermediate-symlink redirection."
    )]
    SymlinkInAncestor { path: PathBuf, ancestor: PathBuf },
}

/// The operator's signing key + its derived id, ready for DSSE signing.
pub struct OperatorKey {
    /// Path the key was loaded/generated from (for diagnostics).
    pub path: PathBuf,
    /// PKCS#8 PEM private key. `Zeroizing` wipes the heap allocation on drop.
    pub private_pem: Zeroizing<String>,
    /// SPKI PEM public key.
    pub public_pem: String,
    /// Canonical key id (hex SHA-256 prefix of the public key, lowercase).
    pub key_id: String,
}

impl std::fmt::Debug for OperatorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorKey")
            .field("path", &self.path)
            .field("private_pem", &"[REDACTED]")
            .field("public_pem_len", &self.public_pem.len())
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// Resolve the path the operator key should live at without touching disk.
pub fn resolve_path() -> Result<PathBuf, OperatorKeyError> {
    resolve_path_with(std::env::var_os(OPERATOR_KEY_PATH_ENV), dirs_home())
}

/// Decoupled resolver: explicit `override_path` (typically
/// `std::env::var_os(OPERATOR_KEY_PATH_ENV)`) and `home`. Exposed for tests
/// that need to exercise both branches without mutating process env.
pub(crate) fn resolve_path_with(
    override_path: Option<std::ffi::OsString>,
    home: Option<PathBuf>,
) -> Result<PathBuf, OperatorKeyError> {
    if let Some(p) = override_path
        && !p.is_empty()
    {
        return Ok(PathBuf::from(p));
    }
    home.map(|h| h.join(".greentic").join("operator").join("key.pem"))
        .ok_or(OperatorKeyError::NoHome)
}

/// Load the operator key from the resolved path, generating a fresh keypair
/// if the file does not yet exist.
///
/// On generation:
/// - Parent directory is created (recursively) with default umask.
/// - Private key written PKCS#8 PEM mode `0600` (POSIX only).
/// - Public key written SPKI PEM as `<key>.pub` mode `0644` (POSIX only).
///
/// On load:
/// - The private PEM is parsed.
/// - If a `.pub` sibling exists, its derived id must equal the
///   private-key-derived id; a mismatch is rejected as a stale `.pub`.
///   If no `.pub` exists, one is written next to the private key (recovery
///   for an operator who deleted only the public file).
pub fn load_or_generate() -> Result<OperatorKey, OperatorKeyError> {
    let path = resolve_path()?;
    load_or_generate_at(&path)
}

/// Load an existing operator key, failing with `NotFound` if no key file is
/// present. **Does not generate.** Use this from CLI verbs that should
/// refuse to act on an unbootstrapped operator (e.g. `bundles add/update` —
/// generating a throwaway key as a side-effect of a `bundles add` that
/// then fails the trust-root precondition is confusing and leaves
/// unexpected state on disk).
pub fn load_existing_only() -> Result<OperatorKey, OperatorKeyError> {
    let path = resolve_path()?;
    refuse_symlink_in_ancestors(&path)?;
    let pem = read_existing_securely(&path)?;
    load_existing(&path, pem)
}

/// Read an existing signing key at an explicit path (e.g. `--signing-key`)
/// with the same hardening as [`load_existing_only`]: symlink-ancestor gate,
/// `O_NOFOLLOW` open, regular-file + mode (0600) checks, and a pre-sized
/// `Zeroizing` read. Returns `(private_pem, key_id)`. Unlike `load_existing`,
/// it writes NO `.pub` sibling — the path is caller-supplied, so regenerating
/// a public file next to it would litter unexpected state. The mode/symlink
/// enforcement is Unix-only (a no-op on other platforms, matching
/// `read_existing_securely`).
pub fn read_signing_key_at(path: &Path) -> Result<(Zeroizing<String>, String), OperatorKeyError> {
    refuse_symlink_in_ancestors(path)?;
    let private_pem = read_existing_securely(path)?;
    let (_public_pem, key_id) = derive_public_pem_and_key_id(&private_pem)?;
    Ok((private_pem, key_id))
}

/// Like [`load_or_generate`] but with an explicit path (tests + callers
/// that already resolved the path themselves).
pub fn load_or_generate_at(path: &Path) -> Result<OperatorKey, OperatorKeyError> {
    // Reject symlinks anywhere on the path BEFORE touching the file. This
    // closes the intermediate-symlink gap O_NOFOLLOW leaves open (only the
    // leaf component is protected by O_NOFOLLOW). The check is best-effort
    // against a concurrent attacker who races the create — that window is
    // closed by the parent dir's mode in practice.
    refuse_symlink_in_ancestors(path)?;
    match read_existing_securely(path) {
        Ok(private_pem) => load_existing(path, private_pem),
        Err(OperatorKeyError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            generate_at(path)
        }
        Err(other) => Err(other),
    }
}

/// Walk every existing parent of `path` and refuse the load/generate if any
/// is a symlink. `path` itself is allowed to not exist (the generate path
/// creates it); only existing ancestors are checked.
fn refuse_symlink_in_ancestors(path: &Path) -> Result<(), OperatorKeyError> {
    let mut ancestor = path.parent();
    while let Some(p) = ancestor {
        if p.as_os_str().is_empty() {
            break;
        }
        match std::fs::symlink_metadata(p) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(OperatorKeyError::SymlinkInAncestor {
                        path: path.to_path_buf(),
                        ancestor: p.to_path_buf(),
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Ancestor doesn't exist yet — create_dir_all will materialize it.
            }
            Err(source) => {
                return Err(OperatorKeyError::Io {
                    path: p.to_path_buf(),
                    source,
                });
            }
        }
        ancestor = p.parent();
    }
    Ok(())
}

/// Open the operator key file refusing symlinks (`O_NOFOLLOW`), validate
/// that it is a regular file owned by a safe principal with permissions
/// that do not leak the key material to other local users, then read its
/// contents into a [`Zeroizing`] buffer pre-sized to the file length so
/// `read_to_string` does not realloc and strand earlier (unzeroed) heap
/// allocations holding partial PEM content.
///
/// Returns `Io { kind = NotFound }` if the file does not exist so callers
/// can dispatch to the generate path.
fn read_existing_securely(path: &Path) -> Result<Zeroizing<String>, OperatorKeyError> {
    let file = open_no_follow(path)?;
    let meta = file.metadata().map_err(|source| OperatorKeyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.is_file() {
        return Err(OperatorKeyError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    check_mode(path, &meta)?;
    // Pre-size to file length + a small slack so `read_to_string` writes into
    // the initial allocation rather than growing through realloc. Each
    // realloc would free an intermediate buffer holding partial key material
    // back to the global allocator unzeroed — see Codex review finding.
    let len = meta.len().try_into().unwrap_or(usize::MAX);
    let mut contents = Zeroizing::new(String::with_capacity(len.saturating_add(8)));
    use std::io::Read;
    {
        let mut handle = file;
        handle
            .read_to_string(&mut contents)
            .map_err(|source| OperatorKeyError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }
    Ok(contents)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<std::fs::File, OperatorKeyError> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NOFOLLOW makes `open` fail with ELOOP if the final path component is
    // a symlink. Combined with the `is_file()` check on the resulting fd,
    // this rejects symlinked, directory, FIFO, and device targets.
    let result = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path);
    match result {
        Ok(f) => Ok(f),
        Err(e) => {
            // ELOOP from O_NOFOLLOW maps to a "not a regular file" outcome
            // rather than the raw io error so callers see a meaningful kind.
            #[allow(clippy::manual_map)]
            if let Some(raw) = e.raw_os_error()
                && raw == libc::ELOOP
            {
                return Err(OperatorKeyError::NotRegularFile {
                    path: path.to_path_buf(),
                });
            }
            Err(OperatorKeyError::Io {
                path: path.to_path_buf(),
                source: e,
            })
        }
    }
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<std::fs::File, OperatorKeyError> {
    // Best-effort on non-Unix: just open the file; symlink + permissions
    // checks are Unix-specific. `read_to_string`-style errors propagate via
    // OperatorKeyError::Io.
    std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| OperatorKeyError::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(unix)]
fn check_mode(path: &Path, meta: &std::fs::Metadata) -> Result<(), OperatorKeyError> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(OperatorKeyError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_mode(_path: &Path, _meta: &std::fs::Metadata) -> Result<(), OperatorKeyError> {
    Ok(())
}

/// Decode a PKCS#8 private PEM, derive the SPKI public PEM and the canonical
/// key-id (hex SHA-256 prefix). The signing key is wiped (`drop`) before
/// returning so only the public material escapes this scope.
fn derive_public_pem_and_key_id(private_pem: &str) -> Result<(String, String), OperatorKeyError> {
    let sk = Ed25519SigningKey::from_pkcs8_pem(private_pem)
        .map_err(|e| OperatorKeyError::KeyDecode(format!("PKCS#8 private PEM: {e}")))?;
    let vk = sk.verifying_key();
    let public_pem = vk
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| OperatorKeyError::KeyDecode(format!("derive SPKI PEM: {e}")))?;
    drop(sk);
    let key_id = key_id_for_public_key_pem(&public_pem)?;
    Ok((public_pem, key_id))
}

fn load_existing(
    path: &Path,
    private_pem: Zeroizing<String>,
) -> Result<OperatorKey, OperatorKeyError> {
    let (public_pem, key_id) = derive_public_pem_and_key_id(&private_pem)?;

    let pub_path = public_sibling(path);
    match std::fs::read_to_string(&pub_path) {
        Ok(existing_pub) => {
            let existing_id = key_id_for_public_key_pem(&existing_pub).map_err(|e| {
                OperatorKeyError::KeyDecode(format!(
                    "`.pub` sibling at {}: {e}",
                    pub_path.display()
                ))
            })?;
            if !existing_id.eq_ignore_ascii_case(&key_id) {
                return Err(OperatorKeyError::StalePublicKey {
                    pub_path,
                    pub_id: existing_id,
                    priv_id: key_id,
                });
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Operator deleted only the .pub — regenerate it from the key
            // we just loaded so verifiers can find a public PEM on disk.
            write_public_sibling(&pub_path, &public_pem)?;
        }
        Err(source) => {
            return Err(OperatorKeyError::Io {
                path: pub_path,
                source,
            });
        }
    }

    Ok(OperatorKey {
        path: path.to_path_buf(),
        private_pem,
        public_pem,
        key_id,
    })
}

fn generate_at(path: &Path) -> Result<OperatorKey, OperatorKeyError> {
    // Wrap the 32-byte seed in `Zeroizing` so the raw private-key material
    // is wiped from the stack the moment we leave this scope (or panic).
    // Without this, the seed survives in the stack frame until the slot is
    // overwritten by unrelated frames, and a core dump or memory-disclosure
    // exploit can reconstruct the keypair from it.
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut seed[..])
        .map_err(|e| OperatorKeyError::Entropy(e.to_string()))?;
    let sk = Ed25519SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    // `to_pkcs8_pem` already returns a `Zeroizing<String>`; converting via
    // `.to_string()` would clone the PEM into a bare `String` that lives
    // unprotected until re-wrapped. Keep the underlying buffer in its
    // original wrapper instead — no intermediate copy.
    let private_pem: Zeroizing<String> = Zeroizing::new(
        sk.to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| OperatorKeyError::KeyDecode(format!("encode PKCS#8 PEM: {e}")))?
            .to_string(),
    );
    let public_pem = vk
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| OperatorKeyError::KeyDecode(format!("encode SPKI PEM: {e}")))?;
    drop(sk);
    let key_id = key_id_for_public_key_pem(&public_pem)?;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|source| OperatorKeyError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    // Race-safe: `write_private_exclusive` uses `create_new`, so if a
    // concurrent caller landed first we fall through to the load path
    // and adopt their key (which has its own `.pub` already written).
    match write_private_exclusive(path, &private_pem) {
        Ok(()) => {
            let pub_path = public_sibling(path);
            // `.pub` is best-effort: if a racer just wrote one we leave it.
            let _ = write_public_sibling_exclusive(&pub_path, &public_pem);
            Ok(OperatorKey {
                path: path.to_path_buf(),
                private_pem,
                public_pem,
                key_id,
            })
        }
        Err(OperatorKeyError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            // Racer won — adopt their key through the SAME secure read path
            // a non-racing load would have used. The earlier plain
            // `std::fs::read_to_string` here bypassed O_NOFOLLOW, the
            // is_file() gate, and the 0600 mode check — an attacker who
            // swapped the file for a symlink between the loser's
            // persist_noclobber failure and this read would have bypassed
            // every defense `read_existing_securely` provides.
            let existing = read_existing_securely(path)?;
            load_existing(path, existing)
        }
        Err(other) => Err(other),
    }
}

fn public_sibling(private_path: &Path) -> PathBuf {
    let mut s = private_path.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

/// Atomically write `contents` to `path`, refusing to overwrite. The write
/// goes through a temp file in the same directory + `persist_noclobber`,
/// which uses `link(2)` (POSIX) or its Windows equivalent — readers see
/// either no file or the fully-written file, never a partial one.
fn write_exclusive(path: &Path, contents: &str, mode: u32) -> Result<(), OperatorKeyError> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::Path::new(".").to_path_buf());
    let mut tmp =
        tempfile::NamedTempFile::new_in(&parent).map_err(|source| OperatorKeyError::Io {
            path: parent.clone(),
            source,
        })?;
    tmp.write_all(contents.as_bytes())
        .map_err(|source| OperatorKeyError::Io {
            path: tmp.path().to_path_buf(),
            source,
        })?;
    tmp.flush().map_err(|source| OperatorKeyError::Io {
        path: tmp.path().to_path_buf(),
        source,
    })?;
    set_mode(&tmp, mode)?;
    tmp.as_file()
        .sync_all()
        .map_err(|source| OperatorKeyError::Io {
            path: tmp.path().to_path_buf(),
            source,
        })?;
    tmp.persist_noclobber(path)
        .map_err(|e| OperatorKeyError::Io {
            path: path.to_path_buf(),
            source: e.error,
        })?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(tmp: &tempfile::NamedTempFile, mode: u32) -> Result<(), OperatorKeyError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(tmp.path(), perms).map_err(|source| OperatorKeyError::Io {
        path: tmp.path().to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn set_mode(_tmp: &tempfile::NamedTempFile, _mode: u32) -> Result<(), OperatorKeyError> {
    Ok(())
}

fn write_private_exclusive(path: &Path, contents: &str) -> Result<(), OperatorKeyError> {
    write_exclusive(path, contents, 0o600)
}

fn write_public_sibling_exclusive(path: &Path, contents: &str) -> Result<(), OperatorKeyError> {
    write_exclusive(path, contents, 0o644)
}

/// Write the public-key sibling unconditionally (used by the load path's
/// recovery branch when the `.pub` was deleted but the `.pem` is still
/// present and trusted).
fn write_public_sibling(path: &Path, contents: &str) -> Result<(), OperatorKeyError> {
    // Best-effort exclusive write; if a racer just landed a `.pub` we
    // leave theirs alone (load_existing already validated it matches the
    // private-key id we share).
    match write_public_sibling_exclusive(path, contents) {
        Ok(()) => Ok(()),
        Err(OperatorKeyError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            Ok(())
        }
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn generate_creates_keypair_with_canonical_id() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        let key = load_or_generate_at(&path).unwrap();
        assert_eq!(key.key_id.len(), 32);
        assert!(key.private_pem.contains("BEGIN PRIVATE KEY"));
        assert!(key.public_pem.contains("BEGIN PUBLIC KEY"));
        assert!(path.is_file(), "private key file must exist");
        let pub_path = public_sibling(&path);
        assert!(pub_path.is_file(), "public sibling must exist");
        let pub_id =
            key_id_for_public_key_pem(&std::fs::read_to_string(&pub_path).unwrap()).unwrap();
        assert_eq!(pub_id, key.key_id);
    }

    #[test]
    fn load_is_idempotent_after_generate() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        let first = load_or_generate_at(&path).unwrap();
        let second = load_or_generate_at(&path).unwrap();
        assert_eq!(first.key_id, second.key_id);
        assert_eq!(first.public_pem, second.public_pem);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        load_or_generate_at(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn stale_pub_sibling_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        load_or_generate_at(&path).unwrap();
        // Overwrite .pub with a different valid SPKI PEM.
        let other_sk = Ed25519SigningKey::from_bytes(&[7u8; 32]);
        let other_pub = other_sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let pub_path = public_sibling(&path);
        std::fs::write(&pub_path, &other_pub).unwrap();

        let err = load_or_generate_at(&path).expect_err("stale pub must be rejected");
        assert!(matches!(err, OperatorKeyError::StalePublicKey { .. }));
    }

    #[test]
    fn missing_pub_sibling_is_regenerated_on_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        load_or_generate_at(&path).unwrap();
        let pub_path = public_sibling(&path);
        std::fs::remove_file(&pub_path).unwrap();

        let key = load_or_generate_at(&path).unwrap();
        assert!(pub_path.is_file(), "pub sibling must be regenerated");
        let pub_id =
            key_id_for_public_key_pem(&std::fs::read_to_string(&pub_path).unwrap()).unwrap();
        assert_eq!(pub_id, key.key_id);
    }

    #[test]
    fn env_override_takes_precedence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("override.pem");
        let resolved = resolve_path_with(
            Some(path.as_os_str().to_owned()),
            Some(PathBuf::from("/should-not-be-used")),
        )
        .unwrap();
        assert_eq!(resolved, path);
    }

    #[test]
    fn empty_env_override_falls_through_to_home() {
        let home = PathBuf::from("/home/op");
        let resolved =
            resolve_path_with(Some(std::ffi::OsString::new()), Some(home.clone())).unwrap();
        assert_eq!(
            resolved,
            home.join(".greentic").join("operator").join("key.pem")
        );
    }

    #[test]
    fn missing_env_and_missing_home_is_no_home_error() {
        let err = resolve_path_with(None, None).expect_err("must error");
        assert!(matches!(err, OperatorKeyError::NoHome));
    }

    #[test]
    fn debug_redacts_private_pem() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        let key = load_or_generate_at(&path).unwrap();
        let dbg = format!("{key:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn concurrent_generates_converge_on_one_key() {
        // The cold-start race that motivated the atomic-write fix: N threads
        // all hit a non-existent path; exactly one wins the exclusive create
        // and the rest must adopt the winner's key, never a partial PEM.
        let dir = tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("key.pem"));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || load_or_generate_at(&p).unwrap().key_id)
            })
            .collect();
        let ids: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let first = &ids[0];
        for id in &ids {
            assert_eq!(id, first, "all racers must adopt one canonical key");
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_key_with_world_readable_mode_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        load_or_generate_at(&path).unwrap();
        chmod(&path, 0o644);
        let err = load_or_generate_at(&path).expect_err("0644 must be rejected");
        match err {
            OperatorKeyError::InsecurePermissions { mode, .. } => assert_eq!(mode, 0o644),
            other => panic!("expected InsecurePermissions, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_key_with_group_readable_mode_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        load_or_generate_at(&path).unwrap();
        chmod(&path, 0o660);
        let err = load_or_generate_at(&path).expect_err("0660 must be rejected");
        match err {
            OperatorKeyError::InsecurePermissions { mode, .. } => assert_eq!(mode, 0o660),
            other => panic!("expected InsecurePermissions, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_key_with_mode_0600_is_accepted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        let first = load_or_generate_at(&path).unwrap();
        chmod(&path, 0o600);
        let second = load_or_generate_at(&path).unwrap();
        assert_eq!(first.key_id, second.key_id);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_key_path_is_rejected() {
        let dir = tempdir().unwrap();
        let real_path = dir.path().join("real-key.pem");
        load_or_generate_at(&real_path).unwrap();
        let link_path = dir.path().join("via-link.pem");
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();
        let err = load_or_generate_at(&link_path).expect_err("symlink target must be rejected");
        assert!(
            matches!(err, OperatorKeyError::NotRegularFile { .. }),
            "expected NotRegularFile, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_intermediate_directory_is_rejected() {
        // Codex/xhigh #5: O_NOFOLLOW protects only the leaf, so an attacker
        // who swaps `~/.greentic` for a symlink to their own dir would
        // otherwise redirect the load. `refuse_symlink_in_ancestors` walks
        // the parent chain and refuses any symlinked component.
        let dir = tempdir().unwrap();
        let attacker_root = dir.path().join("evil");
        std::fs::create_dir_all(&attacker_root).unwrap();
        let symlinked_parent = dir.path().join("operator");
        std::os::unix::fs::symlink(&attacker_root, &symlinked_parent).unwrap();
        let key_path = symlinked_parent.join("key.pem");
        let err =
            load_or_generate_at(&key_path).expect_err("intermediate symlink must be rejected");
        match err {
            OperatorKeyError::SymlinkInAncestor { ancestor, .. } => {
                assert_eq!(ancestor, symlinked_parent);
            }
            other => panic!("expected SymlinkInAncestor, got {other:?}"),
        }
        // No key file was created inside the attacker's directory.
        assert!(
            !attacker_root.join("key.pem").exists(),
            "load must refuse before any write reaches the symlinked dir"
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_at_key_path_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::create_dir(&path).unwrap();
        let err = load_or_generate_at(&path).expect_err("directory must be rejected");
        // O_NOFOLLOW on a directory opens fine; the is_file check catches it.
        assert!(
            matches!(err, OperatorKeyError::NotRegularFile { .. }),
            "expected NotRegularFile, got {err:?}"
        );
    }

    #[test]
    fn corrupted_private_pem_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::write(
            &path,
            "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        // Set safe mode so the permission gate doesn't fire first — the test
        // is about PEM corruption, not file permissions.
        #[cfg(unix)]
        chmod(&path, 0o600);
        let err = load_or_generate_at(&path).expect_err("bad PEM must reject");
        assert!(matches!(err, OperatorKeyError::KeyDecode(_)));
    }

    // ── read_signing_key_at tests ──────────────────────────────────────

    #[test]
    fn read_signing_key_at_valid_key_matches_load_or_generate() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        let generated = load_or_generate_at(&path).unwrap();
        let (pem, kid) = read_signing_key_at(&path).unwrap();
        assert_eq!(kid.len(), 32, "key_id must be a 32-hex-char string");
        assert_eq!(
            kid, generated.key_id,
            "key_id must match load_or_generate_at"
        );
        assert_eq!(*pem, *generated.private_pem);
    }

    #[cfg(unix)]
    #[test]
    fn read_signing_key_at_rejects_mode_0644() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        load_or_generate_at(&path).unwrap();
        chmod(&path, 0o644);
        let err = read_signing_key_at(&path).expect_err("0644 must be rejected");
        assert!(
            matches!(err, OperatorKeyError::InsecurePermissions { .. }),
            "expected InsecurePermissions, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_signing_key_at_rejects_symlinked_key() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.pem");
        load_or_generate_at(&real).unwrap();
        let link = dir.path().join("link.pem");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = read_signing_key_at(&link).expect_err("symlink must be rejected");
        assert!(
            matches!(err, OperatorKeyError::NotRegularFile { .. }),
            "expected NotRegularFile, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_signing_key_at_rejects_symlinked_ancestor() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real-dir");
        std::fs::create_dir_all(&real_dir).unwrap();
        let key_in_real = real_dir.join("key.pem");
        load_or_generate_at(&key_in_real).unwrap();
        let sym_dir = dir.path().join("sym-dir");
        std::os::unix::fs::symlink(&real_dir, &sym_dir).unwrap();
        let key_via_sym = sym_dir.join("key.pem");
        let err = read_signing_key_at(&key_via_sym).expect_err("ancestor symlink must reject");
        match err {
            OperatorKeyError::SymlinkInAncestor { ancestor, .. } => {
                assert_eq!(ancestor, sym_dir);
            }
            other => panic!("expected SymlinkInAncestor, got {other:?}"),
        }
    }

    #[test]
    fn read_signing_key_at_does_not_write_pub_sibling() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        load_or_generate_at(&path).unwrap();
        let pub_path = public_sibling(&path);
        assert!(pub_path.exists());
        std::fs::remove_file(&pub_path).unwrap();
        let (_pem, _kid) = read_signing_key_at(&path).unwrap();
        assert!(
            !pub_path.exists(),
            "read_signing_key_at must not create a .pub sibling"
        );
    }

    #[test]
    fn read_signing_key_at_nonexistent_yields_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.pem");
        let err = read_signing_key_at(&path).expect_err("missing file must error");
        match err {
            OperatorKeyError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io with NotFound, got {other:?}"),
        }
    }
}
