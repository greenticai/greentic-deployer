# greentic-operator-trust

Operator signing-key management and trust-root document semantics for the
Greentic deployment stack.

Two modules, both backend-agnostic:

- **`operator_key`** — load/generate the operator's Ed25519 keypair
  (PKCS#8 PEM private key + SPKI PEM public sibling) with hardened file
  handling: `O_NOFOLLOW`, ancestor-symlink refusal, `0600` mode
  enforcement, zeroized key material, and race-safe exclusive creation.
- **`trust_root`** — the `greentic.trust-root.v1` document envelope plus
  the pure add/remove/validate transforms every trust-root store backend
  (file-based `trust-root.json`, SQLite rows in the operator-store-server)
  drives, so key-id canonicalization and validation cannot drift between
  backends.

Consumed by `greentic-deployer` (local file-backed envs) and
`greentic-operator-store-server` (remote envs). Key-id derivation and the
`TrustRoot`/`TrustedKey` verifier types come from
`greentic-distributor-client::signing` — this crate adds no second
derivation path.
