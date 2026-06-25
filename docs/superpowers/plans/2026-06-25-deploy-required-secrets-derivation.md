# Deploy `requiredSecrets` Derivation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Derive the canonical `requiredSecrets` block (`Vec<SecretRequirement>`) from a provider's `CloudTargetRequirementsV1` and expose it via a `greentic-deployer required-secrets <provider>` CLI subcommand, so deploy credentials speak the same standardized secret vocabulary as the rest of the platform.

**Architecture:** A pure method `CloudTargetRequirementsV1::required_secrets()` in `src/contract.rs` maps the `Secret`/`OptionalSecret` prompt fields to `greentic_types::secrets::SecretRequirement` (reused — already a dependency). A thin, unit-tested render function + a new top-level clap subcommand print the canonical JSON. A companion doc note ships in a separate repo.

**Tech Stack:** Rust, `greentic_types::secrets::{SecretRequirement, SecretKey, SecretFormat}`, `clap` (derive), `serde_json`.

## Global Constraints

- Reuse `greentic_types::secrets::SecretRequirement` — do NOT define a local type, do NOT add a new dependency (`greentic-types` is already a dep; its `serde` feature is on).
- `SecretRequirement` is `#[non_exhaustive]` with public fields and a `Default` impl: construct via `SecretRequirement::default()` then assign fields — a struct literal will NOT compile from this crate.
- The derivation never panics and never returns `Err`; a key that fails `SecretKey::parse` is skipped (defensive).
- Key format is `<provider>/<lower(env_var)>` with NO prefix stripping (deterministic, reversible).
- `required` is `true` only when the provider has exactly ONE credential method AND the field kind is `Secret`; otherwise `false`.
- Conventional commits. Do NOT add AI attribution / `Co-Authored-By` trailers.
- Gate: `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`. (`contract.rs` has no 500-line cap — it is already ~1300 lines; do not split it.)
- Branch `feat/deploy-required-secrets` already exists (design committed on top of `origin/research`).

---

## File structure

| File | Responsibility | Change |
|------|----------------|--------|
| `src/contract.rs` | deployer contract types + `CloudTargetRequirementsV1` | Add `required_secrets()` method + unit tests |
| `src/main.rs` | top-level clap CLI (`TopLevelCommand`) + dispatch | Add `RequiredSecrets` subcommand, `ProviderArg` value-enum, `render_required_secrets` fn + a unit test |
| `greentic-deployer-extensions/docs/declaring-secrets.md` | deploy secret authoring guide (SEPARATE REPO) | Doc note pointing authors at the CLI |

---

## Task 1: `CloudTargetRequirementsV1::required_secrets()`

**Files:**
- Modify: `src/contract.rs` (add the method in the existing `impl CloudTargetRequirementsV1` block, near `aws()`/`azure()`/`gcp()`; add tests in the existing `#[cfg(test)] mod tests` at line ~1079)

**Interfaces:**
- Consumes: `self.target: String`, `self.credential_requirements: Vec<CredentialRequirementV1>`; each `CredentialRequirementV1 { label: String, prompt_fields: Vec<PromptFieldSpecV1>, .. }`; each `PromptFieldSpecV1 { env_name: String, prompt: String, kind: PromptFieldKindV1, .. }`; `PromptFieldKindV1::{Secret, OptionalSecret}`.
- Produces: `pub fn required_secrets(&self) -> Vec<greentic_types::secrets::SecretRequirement>`

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `src/contract.rs` (after the existing `use super::*;`). The tests reference the secrets types by full path to avoid touching the module's imports:

```rust
#[test]
fn required_secrets_for_aws_emits_only_secret_keys_sorted() {
    let reqs = CloudTargetRequirementsV1::aws().required_secrets();
    let keys: Vec<&str> = reqs.iter().map(|r| r.key.as_str()).collect();
    // Only Secret/OptionalSecret fields, sorted by key; non-secret
    // (AWS_ACCESS_KEY_ID = Required, AWS_DEFAULT_REGION = Static) excluded.
    assert_eq!(keys, vec!["aws/aws_secret_access_key", "aws/aws_session_token"]);

    let secret = &reqs[0];
    assert_eq!(secret.key.as_str(), "aws/aws_secret_access_key");
    // AWS has 3 credential methods → no single secret is unconditionally required.
    assert!(!secret.required);
    assert_eq!(secret.format, Some(greentic_types::secrets::SecretFormat::Text));
    assert_eq!(
        secret.description.as_deref(),
        Some("AWS secret access key (Access key pair)")
    );

    let session = &reqs[1];
    assert!(!session.required); // OptionalSecret → never required
    assert_eq!(
        session.description.as_deref(),
        Some("AWS session token (optional) (Access key pair)")
    );
}

#[test]
fn required_secrets_for_azure_emits_client_secret() {
    let reqs = CloudTargetRequirementsV1::azure().required_secrets();
    let keys: Vec<&str> = reqs.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(keys, vec!["azure/arm_client_secret"]);
    assert!(!reqs[0].required); // 2 methods (client-secret + OIDC)
    assert_eq!(
        reqs[0].description.as_deref(),
        Some("Azure client secret (ARM service principal)")
    );
}

#[test]
fn required_secrets_for_gcp_emits_access_token_only() {
    let reqs = CloudTargetRequirementsV1::gcp().required_secrets();
    let keys: Vec<&str> = reqs.iter().map(|r| r.key.as_str()).collect();
    // GOOGLE_APPLICATION_CREDENTIALS is Required (not secret) → excluded.
    assert_eq!(keys, vec!["gcp/cloudsdk_auth_access_token"]);
    assert!(!reqs[0].required); // 2 methods
    assert_eq!(
        reqs[0].description.as_deref(),
        Some("GCP access token (Access token)")
    );
}

#[test]
fn required_secrets_single_method_secret_is_required_and_dedupes() {
    // Synthetic single-method requirements: a Secret field is unconditionally
    // required; an OptionalSecret is not; a duplicate key is emitted once;
    // a non-secret field is excluded; output is sorted by key.
    let reqs = CloudTargetRequirementsV1 {
        target: "demo".to_string(),
        target_label: "Demo".to_string(),
        provider_pack_filename: "demo.gtpack".to_string(),
        remote_bundle_source_required: false,
        remote_bundle_source_help: None,
        informational_notes: Vec::new(),
        credential_requirements: vec![CredentialRequirementV1 {
            kind: CloudCredentialKind::AwsAccessKey,
            label: "Only method".to_string(),
            env_vars: Vec::new(),
            satisfaction_env_groups: Vec::new(),
            prompt_fields: vec![
                PromptFieldSpecV1 {
                    env_name: "TOKEN".to_string(),
                    prompt: "Token:".to_string(),
                    kind: PromptFieldKindV1::Secret,
                    static_value: None,
                },
                PromptFieldSpecV1 {
                    env_name: "TOKEN".to_string(), // duplicate key → deduped
                    prompt: "Token again:".to_string(),
                    kind: PromptFieldKindV1::Secret,
                    static_value: None,
                },
                PromptFieldSpecV1 {
                    env_name: "OPT".to_string(),
                    prompt: "Optional:".to_string(),
                    kind: PromptFieldKindV1::OptionalSecret,
                    static_value: None,
                },
                PromptFieldSpecV1 {
                    env_name: "PLAIN".to_string(),
                    prompt: "Plain:".to_string(),
                    kind: PromptFieldKindV1::Required,
                    static_value: None,
                },
            ],
            help: String::new(),
        }],
        variable_requirements: Vec::new(),
    }
    .required_secrets();

    let keys: Vec<&str> = reqs.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(keys, vec!["demo/opt", "demo/token"]); // sorted, deduped, PLAIN excluded
    let token = reqs.iter().find(|r| r.key.as_str() == "demo/token").unwrap();
    assert!(token.required); // single method + Secret
    let opt = reqs.iter().find(|r| r.key.as_str() == "demo/opt").unwrap();
    assert!(!opt.required); // OptionalSecret
}

#[test]
fn required_secrets_empty_prompt_falls_back_to_env_name() {
    let reqs = CloudTargetRequirementsV1 {
        target: "demo".to_string(),
        target_label: "Demo".to_string(),
        provider_pack_filename: "demo.gtpack".to_string(),
        remote_bundle_source_required: false,
        remote_bundle_source_help: None,
        informational_notes: Vec::new(),
        credential_requirements: vec![CredentialRequirementV1 {
            kind: CloudCredentialKind::AwsAccessKey,
            label: "M".to_string(),
            env_vars: Vec::new(),
            satisfaction_env_groups: Vec::new(),
            prompt_fields: vec![PromptFieldSpecV1 {
                env_name: "RAW_TOKEN".to_string(),
                prompt: String::new(),
                kind: PromptFieldKindV1::Secret,
                static_value: None,
            }],
            help: String::new(),
        }],
        variable_requirements: Vec::new(),
    }
    .required_secrets();
    assert_eq!(reqs[0].description.as_deref(), Some("RAW_TOKEN (M)"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p greentic-deployer required_secrets 2>&1 | tail -20`
Expected: FAIL — `no method named required_secrets found for struct CloudTargetRequirementsV1`.

- [ ] **Step 3: Implement `required_secrets()`**

Add this method inside the existing `impl CloudTargetRequirementsV1 { … }` block in `src/contract.rs` (e.g. immediately after the `gcp()` constructor). The `#[allow(clippy::field_reassign_with_default)]` is required because `SecretRequirement` is `#[non_exhaustive]`, so the clippy-preferred struct-literal form does not compile from this crate — document that inline:

```rust
    /// Canonical `requiredSecrets` for this provider's credentials: the secret
    /// (and optional-secret) prompt fields across every credential method, mapped
    /// to `greentic_types::secrets::SecretRequirement` and deduped by key. Plain
    /// config and static fields are excluded. The result is sorted by key and is
    /// empty when no secret fields are declared. Never errors — a key that fails
    /// `SecretKey::parse` is skipped.
    ///
    /// `required` is `true` only when this provider exposes a single credential
    /// method and the field is a `Secret`; with alternative methods no single
    /// secret is unconditionally required (any one method satisfies the target).
    pub fn required_secrets(&self) -> Vec<greentic_types::secrets::SecretRequirement> {
        use greentic_types::secrets::{SecretFormat, SecretKey, SecretRequirement};

        let single_method = self.credential_requirements.len() == 1;
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut out: Vec<SecretRequirement> = Vec::new();

        for method in &self.credential_requirements {
            for field in &method.prompt_fields {
                let is_secret = matches!(
                    field.kind,
                    PromptFieldKindV1::Secret | PromptFieldKindV1::OptionalSecret
                );
                if !is_secret {
                    continue;
                }
                let key_str = format!("{}/{}", self.target, field.env_name.to_lowercase());
                let Ok(key) = SecretKey::parse(&key_str) else {
                    continue;
                };
                if !seen.insert(key.as_str().to_string()) {
                    continue; // first occurrence wins
                }

                let base = {
                    let trimmed = field.prompt.trim_end_matches(':').trim();
                    if trimmed.is_empty() {
                        field.env_name.as_str()
                    } else {
                        trimmed
                    }
                };

                // SecretRequirement is #[non_exhaustive]: build via Default, then
                // assign fields (struct-literal form would not compile here).
                #[allow(clippy::field_reassign_with_default)]
                let req = {
                    let mut r = SecretRequirement::default();
                    r.key = key;
                    r.required = single_method
                        && matches!(field.kind, PromptFieldKindV1::Secret);
                    r.description = Some(format!("{base} ({})", method.label));
                    r.format = Some(SecretFormat::Text);
                    r
                };
                out.push(req);
            }
        }

        out.sort_by(|a, b| a.key.as_str().cmp(b.key.as_str()));
        out
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p greentic-deployer required_secrets 2>&1 | tail -20`
Expected: PASS — all five `required_secrets_*` tests green.

- [ ] **Step 5: fmt + clippy**

Run: `cargo fmt --all && cargo clippy -p greentic-deployer --all-targets -- -D warnings 2>&1 | tail -15`
Expected: no warnings. (If clippy still flags `field_reassign_with_default` despite the `#[allow]`, confirm the attribute is on the block expression as shown; if it flags an unused import, ensure the `use` is inside the method.)

- [ ] **Step 6: Commit**

```bash
git add src/contract.rs
git commit -m "feat: derive canonical requiredSecrets from CloudTargetRequirementsV1"
```

---

## Task 2: `required-secrets <provider>` CLI subcommand

**Files:**
- Modify: `src/main.rs` (add to `TopLevelCommand`, add `ProviderArg` + `render_required_secrets` + a unit test)

**Interfaces:**
- Consumes: `CloudTargetRequirementsV1::for_provider(provider: Provider) -> Option<CloudTargetRequirementsV1>` and `.required_secrets()` (Task 1); `crate::Provider` (variants `Local`/`Aws`/`Azure`/`Gcp`/`K8s`/`Generic`).
- Produces: a new `TopLevelCommand::RequiredSecrets` variant; `fn render_required_secrets(provider: Provider) -> String`.

- [ ] **Step 1: Write the failing test**

Add to `src/main.rs` (in its `#[cfg(test)] mod tests`, or create one at the end of the file if none exists — match the file's existing test style):

```rust
#[cfg(test)]
mod required_secrets_cli_tests {
    use super::*;

    #[test]
    fn render_required_secrets_aws_is_canonical_json_array() {
        let json = render_required_secrets(Provider::Aws);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json array");
        let arr = parsed.as_array().expect("array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["key"], "aws/aws_secret_access_key");
        assert_eq!(arr[0]["required"], false);
        assert_eq!(arr[0]["format"], "text");
    }

    #[test]
    fn render_required_secrets_non_cloud_is_empty_array() {
        assert_eq!(render_required_secrets(Provider::Local), "[]");
    }

    #[test]
    fn provider_arg_maps_to_provider() {
        assert_eq!(ProviderArg::Aws.to_provider(), Provider::Aws);
        assert_eq!(ProviderArg::Gcp.to_provider(), Provider::Gcp);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p greentic-deployer required_secrets_cli 2>&1 | tail -20`
Expected: FAIL — `render_required_secrets` / `ProviderArg` not found.

- [ ] **Step 3: Add the `ProviderArg` value-enum and `render_required_secrets`**

In `src/main.rs`, add near the other CLI types (use the existing `Provider` import; `crate::contract::CloudTargetRequirementsV1` is the contract type — match the path the file already uses for contract types, e.g. `greentic_deployer::contract::CloudTargetRequirementsV1` if `main.rs` references library items via the crate name):

```rust
/// Cloud provider selector for `required-secrets`. Mirrors `Provider`'s
/// deploy targets; clap validates the value so an unknown string exits non-zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ProviderArg {
    Local,
    Aws,
    Azure,
    Gcp,
    K8s,
    Generic,
}

impl ProviderArg {
    fn to_provider(self) -> Provider {
        match self {
            ProviderArg::Local => Provider::Local,
            ProviderArg::Aws => Provider::Aws,
            ProviderArg::Azure => Provider::Azure,
            ProviderArg::Gcp => Provider::Gcp,
            ProviderArg::K8s => Provider::K8s,
            ProviderArg::Generic => Provider::Generic,
        }
    }
}

/// `greentic-deployer required-secrets <provider>` — print the canonical
/// `requiredSecrets` JSON array derived from the provider's credential contract.
#[derive(Parser, Debug)]
struct RequiredSecretsCommand {
    /// Cloud provider: aws | azure | gcp (others print an empty array).
    #[arg(value_enum)]
    provider: ProviderArg,
}

/// Render the canonical `requiredSecrets` JSON array for a provider. A provider
/// without cloud credential requirements yields `"[]"`.
fn render_required_secrets(provider: Provider) -> String {
    let reqs = CloudTargetRequirementsV1::for_provider(provider)
        .map(|r| r.required_secrets())
        .unwrap_or_default();
    serde_json::to_string_pretty(&reqs).unwrap_or_else(|_| "[]".to_string())
}
```

NOTE on the `CloudTargetRequirementsV1` path: `main.rs` must import it. Add the matching `use` at the top of `main.rs` (mirror how `main.rs` already imports library types — if it uses `use greentic_deployer::…` for other items, use `use greentic_deployer::contract::CloudTargetRequirementsV1;`; if `contract` is not `pub` at the crate root, the implementer must make `pub use contract::CloudTargetRequirementsV1;` available — verify `CloudTargetRequirementsV1` is already re-exported, since `for_provider` is referenced from the admin crate, implying it is public). Likewise ensure `Provider` is in scope (it already is — `main.rs` uses it in `TopLevelCommand`).

- [ ] **Step 4: Wire the subcommand into `TopLevelCommand`**

In `src/main.rs`, add a variant to the `TopLevelCommand` enum (alongside `Aws`, `Azure`, `Gcp`, `Op`, …):

```rust
    /// Print the canonical requiredSecrets JSON for a deploy provider.
    RequiredSecrets(RequiredSecretsCommand),
```

Then add the dispatch arm in the `match` that handles `TopLevelCommand` (find where the other variants are dispatched, e.g. `TopLevelCommand::Aws(cmd) => …`) and print the rendered JSON:

```rust
        TopLevelCommand::RequiredSecrets(cmd) => {
            println!("{}", render_required_secrets(cmd.provider.to_provider()));
        }
```

(Match the surrounding arms' return/`Ok(())` shape — if the dispatch returns `anyhow::Result<()>` or similar, end the arm with `Ok(())` or the file's convention.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p greentic-deployer required_secrets_cli 2>&1 | tail -20`
Expected: PASS — the three CLI tests green.

- [ ] **Step 6: Verify the binary end-to-end**

Run: `cargo run -p greentic-deployer -- required-secrets aws 2>&1 | tail -20`
Expected: prints a JSON array containing `"key": "aws/aws_secret_access_key"` and `"key": "aws/aws_session_token"`.
Run: `cargo run -p greentic-deployer -- required-secrets local`
Expected: prints `[]`.

- [ ] **Step 7: fmt + clippy + commit**

Run: `cargo fmt --all && cargo clippy -p greentic-deployer --all-targets -- -D warnings 2>&1 | tail -15`
Expected: no warnings.

```bash
git add src/main.rs
git commit -m "feat: add required-secrets CLI subcommand for deploy providers"
```

---

## Task 3: Doc note in `greentic-deployer-extensions` (separate repo)

**Files:**
- Modify: `greentic-deployer-extensions/docs/declaring-secrets.md`

This task is in a DIFFERENT repository (`/home/bima-pangestu/projects/Works/greentic/greentic-deployer-extensions`) and ships as its own branch + PR. Do it after Tasks 1–2 are merged or in parallel; it has no code dependency, only a textual reference.

- [ ] **Step 1: Add the generator note**

In `greentic-deployer-extensions/docs/declaring-secrets.md`, after the existing
example `requiredSecrets` block, add a short section:

```markdown
## Generating the block from a cloud provider's credential contract

For a cloud-backed deploy target, you can generate the canonical `requiredSecrets`
array from the deployer's credential contract instead of hand-writing it:

    greentic-deployer required-secrets aws    # or: azure | gcp

This prints the secret fields (the `Secret` / `OptionalSecret` credential prompts)
as `requiredSecrets` entries, keyed `<provider>/<lower(env_var)>` (e.g.
`aws/aws_secret_access_key`). Non-secret config (regions, profiles, project IDs)
and ambient-credential targets are intentionally omitted. Copy the output into
your `describe.json` `requiredSecrets` (adjust `description`/`required` as needed
for your target). Providers without declared secrets print an empty array.
```

- [ ] **Step 2: Commit (on a branch in that repo)**

```bash
cd /home/bima-pangestu/projects/Works/greentic/greentic-deployer-extensions
git checkout -b docs/required-secrets-cli-note origin/research 2>/dev/null || git checkout -b docs/required-secrets-cli-note
git add docs/declaring-secrets.md
git commit -m "docs: note the greentic-deployer required-secrets generator"
```

(If `docs/declaring-secrets.md` does not exist on the base branch yet — it was authored on the `docs/deploy-required-secrets` branch per the spec — base this change on that branch instead, or create the file with the full guide. Confirm the file's presence first with `git show <base>:docs/declaring-secrets.md`.)

---

## Self-review

**Spec coverage:**
- `CloudTargetRequirementsV1::required_secrets()` with the exact mapping (kind filter, key format, required rule, description, format, dedup, sort) → Task 1. ✔
- Reuse `greentic_types::secrets::SecretRequirement`, no new dep, `#[non_exhaustive]` construction → Task 1 (Global Constraints + Step 3). ✔
- Expected outputs (aws/azure/gcp keys, non-secret exclusion) → Task 1 tests. ✔
- `required` single-method semantics → Task 1 synthetic test. ✔
- CLI `required-secrets <provider>` printing canonical JSON; non-cloud → `[]`; unknown → non-zero (clap value-enum) → Task 2. ✔
- Doc note → Task 3. ✔
- Non-goals (no describe injection, no admin refactor, no wizard change) → respected: only contract.rs + main.rs + a doc. ✔

**Placeholder scan:** none — every code step carries full code and exact expected strings.

**Type consistency:** `required_secrets()` returns `Vec<greentic_types::secrets::SecretRequirement>` in Task 1 and is consumed as such in Task 2's `render_required_secrets`. `ProviderArg::to_provider() -> Provider` and `render_required_secrets(Provider) -> String` are used identically in Task 2's wiring and tests. Key strings (`aws/aws_secret_access_key`, `aws/aws_session_token`, `azure/arm_client_secret`, `gcp/cloudsdk_auth_access_token`) and descriptions match between the implementation rule and the test assertions.
