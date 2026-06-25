# Deploy `requiredSecrets` derivation from `CloudTargetRequirementsV1` — Design

- **Date:** 2026-06-25
- **Status:** Approved design (ready for plan)
- **Repo:** `greentic-deployer` (branch `research`)
- **Epic:** describe-secret standardization. This makes the **deploy** credential
  contract speak the same canonical `requiredSecrets` vocabulary the rest of the
  ecosystem uses (the shape D3's designer-admin dialog consumes). Companion:
  `greentic-store-server/docs/superpowers/specs/2026-06-25-describe-secret-standardization-proposal.md`.

## Problem

Every other extension kind now declares operator-provided secrets as a canonical
top-level `requiredSecrets` array of `greentic_types::secrets::SecretRequirement`.
Deploy targets are the exception: their real secret declarations live in
`CloudTargetRequirementsV1` (`greentic-deployer/src/contract.rs`) as
`credential_requirements[].prompt_fields[]` with a `PromptFieldKindV1` discriminator
(`Secret` / `OptionalSecret` mark the secrets; `Required` / `Optional` / `Static`
are plain config). There is no function that turns this into the standardized
`requiredSecrets` shape, so deploy secrets cannot be expressed in, validated
against, or documented with the same vocabulary as the rest of the platform.

A WIT `credential_schema(target_id)` exists but is **not** the right source: it is
empty for the ambient-credential cloud targets and, where populated (single-vm),
carries SSH connection config with no secret/non-secret marker. The authoritative
secret-ness signal is `PromptFieldKindV1::{Secret, OptionalSecret}` in
`CloudTargetRequirementsV1`.

## Goal

Add a single, unit-tested derivation that maps a provider's
`CloudTargetRequirementsV1` to a canonical `Vec<SecretRequirement>`, and expose it
through the existing `greentic-deployer` CLI so authors and docs can obtain the
canonical block. This is a **foundation + authoring aid**, not a UI change.

## Scope decisions (locked in brainstorming)

- **Source = `CloudTargetRequirementsV1`** (not the WIT `credential_schema`): the
  `Secret`/`OptionalSecret` prompt-field kinds are the authoritative secret signal.
- **Wizard stays authoritative; this output is declarative.** The deploy-env
  wizard keeps collecting credentials via the existing `CloudTargetRequirementsV1`
  → `CredentialField` path. The new `requiredSecrets` derivation is the canonical
  declarative vocabulary — it is **not** injected into reference-extension
  `describe.json` (that would be a carrier mismatch: the store deploy *extensions*
  are ambient/local variants, while these secrets belong to the built-in cloud
  targets) and it does **not** change any entry surface.
- **Reuse `greentic_types::secrets::{SecretRequirement, SecretKey, SecretFormat}`**
  — already a `greentic-deployer` dependency (no new dep, no release-train gate).

## Non-goals (explicit follow-ups, not this spec)

- Injecting `requiredSecrets` into reference deploy-extension `describe.json` at
  build time (carrier mismatch — see above).
- DRY-refactoring the admin's `fields_for_target` / deploy-env wizard to consume
  this derivation.
- Enriching the wizard UI with the canonical keys/descriptions.
- Unifying the two credential models (wizard reading `requiredSecrets`).
- Per-target (vs per-provider) derivation, and the `one-of` method semantics
  beyond the flat `required` rule below.

## The derivation

New method in `greentic-deployer/src/contract.rs`:

```rust
impl CloudTargetRequirementsV1 {
    /// Canonical `requiredSecrets` for this provider's credentials: the secret
    /// (and optional-secret) prompt fields across all credential methods, mapped
    /// to `SecretRequirement` and deduped by key. Plain config / static fields
    /// are excluded. Empty when the provider declares no secret fields.
    pub fn required_secrets(&self) -> Vec<SecretRequirement> { /* ... */ }
}
```

Algorithm — iterate `self.credential_requirements`, then each method's
`prompt_fields`, keeping only `PromptFieldKindV1::{Secret, OptionalSecret}`:

- **key**: `SecretKey::parse("<target>/<lower(env_name)>")` where `<target>` is
  `self.target` (e.g. `"aws"`). No prefix stripping — deterministic and reversible
  to the env var. Examples: `aws/aws_secret_access_key`, `azure/arm_client_secret`,
  `gcp/cloudsdk_auth_access_token`. (The minor `aws/aws_…` redundancy is accepted
  and documented; stripping provider prefixes is rejected because the prefixes
  differ across providers — `AWS_`, `ARM_`, none for GCP — and would be
  inconsistent.) A key that fails `SecretKey::parse` is skipped (should not happen
  for these ASCII env names; defensive only).
- **required**: `true` only when the provider has **exactly one** credential method
  AND the field kind is `Secret`; otherwise `false`. Rationale: when alternative
  methods exist (`access-key` vs `profile` vs `web-identity`), no single secret is
  unconditionally required — any one method satisfies the target — so a flat
  `required: true` would be wrong. `OptionalSecret` is always `false`.
- **description**: `"<prompt without a trailing ':'> (<method label>)"`, e.g.
  `"AWS secret access key (Access key pair)"`, taken from the prompt field's
  `prompt` and its owning `CredentialRequirementV1::label`. When the prompt is
  empty, fall back to the env var name.
- **format**: `SecretFormat::Text` (these are text tokens).
- **examples / scope / schema**: omitted.

Post-processing: **dedup by key** (first occurrence wins — a key appearing in two
methods keeps the first method's description), then **sort by key** for
deterministic output.

### Expected output (current contract data)

| Provider | `requiredSecrets` keys (all `required: false` — multiple methods) |
|---|---|
| `aws` | `aws/aws_secret_access_key`, `aws/aws_session_token` |
| `azure` | `azure/arm_client_secret` |
| `gcp` | `gcp/cloudsdk_auth_access_token` |
| `Local` / `K8s` / `Generic` | `[]` (`for_provider` returns `None`) |

(The `Provider` enum is `Local` / `Aws` / `Azure` / `Gcp` / `K8s` / `Generic`;
only `Aws` / `Azure` / `Gcp` have `CloudTargetRequirementsV1`.)

Non-secret fields (`AWS_ACCESS_KEY_ID` = `Required`, `AWS_DEFAULT_REGION`,
`GOOGLE_APPLICATION_CREDENTIALS`, OIDC config) are excluded by the kind filter.

## CLI consumer

New subcommand on the existing `greentic-deployer` clap CLI
(`src/cli/dispatch.rs`):

```
greentic-deployer required-secrets <provider>
```

- Resolves `<provider>` (`aws` | `azure` | `gcp` | …) to the `Provider` enum,
  calls `CloudTargetRequirementsV1::for_provider(provider)`, and prints
  `serde_json::to_string_pretty(&reqs.required_secrets())` — the canonical
  `requiredSecrets` JSON array (camelCase, matching describe-v2).
- A provider with no cloud requirements (`for_provider` → `None`, e.g. `local`)
  prints `[]` and exits 0.
- An unparseable provider string exits non-zero with a clear error listing the
  valid providers.

This is the concrete consumer: authors copy the array into a hand-authored deploy
`describe.json` `requiredSecrets` block, and the docs reference it.

## Docs

Update `greentic-deployer-extensions/docs/declaring-secrets.md` (the hand-authoring
guide) to note that authors of a cloud-backed deploy target can generate the
canonical `requiredSecrets` block with `greentic-deployer required-secrets
<provider>` instead of hand-writing it, and that the keys follow
`<provider>/<lower(env_var)>`.

## Error handling

- The derivation never panics and never errors: an unparseable key is skipped
  (defensive), an empty `credential_requirements` yields `[]`.
- The CLI maps an unknown provider string to a clear non-zero error; a known but
  non-cloud provider yields `[]` and exit 0.

## Testing

In `greentic-deployer/src/contract.rs` unit tests:

- `required_secrets_for_aws_emits_canonical_secret_keys`: asserts exactly
  `[aws/aws_secret_access_key, aws/aws_session_token]`, both `required: false`,
  `format: Text`, descriptions containing the method label; asserts
  `aws/aws_access_key_id` and `aws/aws_default_region` are **absent** (non-secret).
- `required_secrets_for_azure_emits_client_secret`: exactly
  `[azure/arm_client_secret]`.
- `required_secrets_for_gcp_emits_access_token`: exactly
  `[gcp/cloudsdk_auth_access_token]`; `gcp/google_application_credentials` absent.
- `required_secrets_dedup_and_sorted`: a key present in two methods appears once;
  output is sorted by key.
- `required_secrets_single_method_secret_is_required`: a synthetic
  `CloudTargetRequirementsV1` with one method and a `Secret` field yields
  `required: true`; an `OptionalSecret` in the same case yields `false`.
- Non-cloud provider via the public path: `CloudTargetRequirementsV1::for_provider(Provider::Local)` is `None` (existing test already covers this) — the derivation is only reachable through a `Some`.

CLI test (mirroring the existing CLI test pattern in the repo): `required-secrets
aws` prints a JSON array whose parsed form equals the derivation output;
`required-secrets local` prints `[]`; an unknown provider exits non-zero.

## Files touched

- `greentic-deployer/src/contract.rs` — the `required_secrets()` method + unit
  tests (mind the file-size convention if the repo enforces one).
- `greentic-deployer/src/cli/dispatch.rs` (+ wherever the clap command enum is
  defined) — the `required-secrets` subcommand + its handler + a CLI test.
- `greentic-deployer-extensions/docs/declaring-secrets.md` — doc note (separate
  repo; a small companion change, may ship as its own PR).
