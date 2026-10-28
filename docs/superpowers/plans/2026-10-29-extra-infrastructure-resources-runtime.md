# Extra infrastructure resources — runtime side (Plan B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]` checkboxes. This plan spans THREE repos; each task names its repo and worktree. Merge order is fixed (see "Release order").

**Goal:** A deployed worker's design-extension tool can obtain the connection of a platform-provided resource (Qdrant `vector-store/qdrant`, Redis `cache/redis`) that the designer staged into the environment's `op` store, without the credential entering logs, argv, manifests or API responses, and with a clear named error (never a localhost fallback) when it is absent.

**Architecture:** The designer already stages ONE JSON document per kind at `secrets://default/default/_/infra/<canonical kind>` through `op secrets put` (merged, designer PR #3841). This plan makes the three downstream repos honour that address:

1. **greentic-deployer** accepts category `infra` as a *default-env-segment, canonical-name* category (the `llm`/`knowledge` shape) so the put lands where the runtime reads, reports a new `infra_secret_category` capability so the designer can verify the binary it resolved, and proves `op secrets delete --prefix` prunes the category.
2. **greentic-runner** gets the typed reader (`greentic_aw_runtime::infra_connection`) and routes `secret://infra/<name>` through the existing extension `host.secrets.get` path (`StoreToolSecretsBackend`) to it. The guest receives a host-normalised, versioned JSON document. No WIT change, no ext-runtime change.
3. **greentic-start** takes the runner publish, lists `infra` among the door's `default`-env categories, pins the read path with tests, and reports an `infra-connections` capability.

**Tech Stack:** Rust 2024, `tokio`, `serde_json`, `secrecy 0.10`, `thiserror`, `greentic-secrets-lib` (`canonical_secret_name`), `greentic-ext-runtime` (`SecretsBackend`).

**Spec:** designer repo `docs/superpowers/specs/2026-10-28-extra-infrastructure-resources-design.md` (§8, §10c), `docs/infra-resources-feed-v1.md` §7; admin plan `greentic-designer-admin-infra/docs/superpowers/plans/2026-10-29-extra-infrastructure-resources-admin.md` (cross-repo checklist).

**Worktrees (read/write only here):**
- `/home/bima-pangestu/projects/orca/workspaces/greentic-deployer-infra`
- `/home/bima-pangestu/projects/orca/workspaces/greentic-start-infra`
- `/home/bima-pangestu/projects/orca/workspaces/greentic-runner-infra`

---

## Global Constraints (exact values)

| Item | Value |
|---|---|
| Secret category | `infra` (designer constant `INFRA_CATEGORY`, `src/orchestrate/infra_stage/mod.rs`) |
| Store-relative path (written by `op secrets put`) | `default/_/infra/<canonical kind>` |
| Dev-store key after deployer mapping | `secrets://default/default/_/infra/<canonical kind>` (env segment `default`, NOT the env id `local`) |
| Tenant / team | tenant `default` (`REMOTE_TENANT`), team `_`, unit-less (one entry per kind per environment) |
| Canonical name | `greentic_secrets_lib::canonical_secret_name(kind)`: `vector-store/qdrant` -> `vector_store_qdrant`, `cache/redis` -> `cache_redis` |
| Staged value (today) | JSON `{host, port(u16), scheme, credential, extras{str:str}}`; IPv6 host UNBRACKETED; no version field |
| Guest-facing URI | `secret://infra/<canonical name>` (the existing `host.secrets.get` URI shape; the extension declares it verbatim in `runtime.permissions.secrets`) |
| Guest-facing document | host-normalised v1: `{"v":1,"kind":"<as asked>","host","port","scheme","base_url","credential","extras"}` |
| Reader schema version | `SCHEMA_VERSION = 1`; absent `v` in the STAGED doc is read as 1; `v > 1` is refused |
| Read tenant order | served tenant first, then `default` (skip the duplicate), same as start's `shared_state/redis_url` |
| Read env segment | pinned `default` (as `scoped_secrets::ENV_SEGMENT`), never `$GREENTIC_ENV` |
| New deployer capability wire name | `infra_secret_category` |
| New start capability string | `infra-connections` |
| Validation mirrored from admin/designer | host non-empty <= 253 bytes, bare DNS/IPv4/IPv6 (no scheme/userinfo/path/port/whitespace); port 1..=65535; scheme alphanumeric <= 16; credential 1..=4096 bytes; extras <= 16 entries, keys/values <= 256 bytes |
| Extras keys used by the admin provisioners | `collection_prefix` (Qdrant), `key_prefix` (Redis) — passed through verbatim, never interpreted by the runtime |
| Commits | conventional (`feat:`/`fix:`/`docs:`/`test:`), NO Claude co-author trailer, never `--no-verify`, never push from this plan |
| Branches | PR base `develop` in all three repos (`main` is stable lane) |

### Local verification rules (read each repo's CLAUDE.md; they differ)

- **deployer:** scope to the package: `cargo fmt -p greentic-deployer -- --check`, `cargo clippy -p greentic-deployer --all-targets --all-features -- -D warnings`, narrow `cargo test -p greentic-deployer <filter>`. All new code that references a feature-gated dependency must be `cfg`-gated; the gate also runs `cargo build --no-default-features` (the capability code is feature-free, keep it so). Do not run `cargo update` (doc-only/no new deps).
- **runner:** `cargo fmt --all --check`, `cargo clippy --all-targets --all-features -- -D warnings` (this is the PR compile gate; tests do NOT run on PRs, only nightly) so run narrow `cargo test -p <crate> <filter>` yourself before relying on a change. Workspace feature unification: if `-p` clippy passes but CI fails, reproduce with the workspace command.
- **start:** `cargo fmt -p greentic-start -- --check`, `cargo clippy -p greentic-start --all-targets -- -D warnings`, `cargo test -p greentic-start -- <filter>`. Husky-like hook: `git config core.hooksPath .githooks` once per clone (runs fmt + workspace clippy on commit; can take minutes — run the commit detached with `setsid nohup` and poll).
- This plan was written WITHOUT running cargo (instruction). Every test below is specified, not executed. Treat "should fail first" as a claim to confirm when you run it.

### Review Focus

1. **The credential never leaves a `SecretString` before the guest boundary.** grep the diff for `format!`/`tracing::`/`Display` touching `credential`; every serde error is mapped to a fixed string (serde_json echoes offending values in `invalid type: string "..."`).
2. **Env segment is `default` on every read and on the deployer write** (the `local`-vs-`default` quirk; precedents #639 `knowledge`, #618 `sorla`, `6afb853` `llm`). A reader that used `$GREENTIC_ENV` (k8s: unset -> `dev`) would miss.
3. **No silent fallback.** Provider `infra` must bypass the existing env-var fallback of `StoreToolSecretsBackend` and the whole `EnvSecretsBackend`.
4. **Older deployer fails silently today** (see R9): `op secrets put` has no category allow-list, so `infra` is currently written at env `local`. The capability + designer gate is the fix; do not rely on a pin comparison alone.
5. Cross-repo constants spelled identically: `infra`, `infra_secret_category`, `infra-connections`, `secret://infra/`.

---

## Rulings (ambiguities and contradictions, decided without asking)

**R1 — Category `infra` is a default-env-segment category with CANONICAL names (not verbatim).** Same shape as `llm`/`knowledge`. Evidence: the staged names are already canonical, and start's reader (`canonicalize_dev_store_secret_uri`) canonicalises every non-`mcp`/`a2a`/`sorla` name, which is a no-op for canonical input. *Cost if wrong:* a verbatim category would let a hyphenated name be written that the canonicalising reader never finds; a rename of the category is a constant change in four places (designer, deployer, runner, start) — keep all four constants in one commit each.

**R2 — Read address: env `default`, tenant order `[served tenant, "default"]`, team `_`, no unit scope.** Designer comment says remote workloads carry tenant `default`; the deployer's Cloud Run `runtime_tenant` answer (`GREENTIC_TENANT`, `env_packs/gcp_cloudrun/deployer.rs:454`) can make the served tenant differ. Following start's `shared_state/redis_url` precedent (`src/shared_backend/mod.rs:85-95`) covers both. UNVERIFIED: whether any live k8s/Cloud Run workload serves a non-`default` tenant today. *Cost if wrong:* one wasted store read. No unit scope: a store holds one connection per kind (designer contract); unit-scoping would require N copies and cannot be staged unit-less.

**R3 — The typed reader lives in `greentic-aw-runtime` (`infra_connection` module beside `scoped_secrets`), not in runner-host.** aw-runtime is already depended on by runner-host, the designer, start and the dw crates, and already owns `scoped_secrets`/`mcp_secrets`. A runner-host-only reader would force the designer (Run Demo / Test chat lanes) to re-implement it. *Cost if wrong:* moving a module between crates in a follow-up; both publish from the same runner merge so no extra release.

**R4 — Delivery to the extension is the EXISTING `host.secrets.get` host function.** `greentic-ext-runtime`'s `secrets::Host::get` permission-gates the URI against `describe.json runtime.permissions.secrets` (prefix test on `/` boundary, `declaration_is_specific` refuses wildcards) and then calls `SecretsBackend::get(uri)`. The runner's `StoreToolSecretsBackend` (agent_node.rs) implements that backend; we add a branch for URIs `secret://infra/<name>`. The extension declares `secret://infra/vector_store_qdrant` — the gate then limits it to its own kind. **Tools only:** a flow `component.exec` node reads via the pack-scoped `host.secrets-store` (URI minted from the reading pack id, `HostState::get`) and cannot reach a unit-less `infra` entry; serving that lane is a separate design (out of scope). The first consumer (Qdrant-backed knowledge extension) is a tool invoked through `knowledge_ext` -> `ExtensionRuntime::invoke_tool_ctx`, so it is covered. *Cost if wrong:* if a consumer needs a flow node, a pack-scoped alias would have to be staged per unit (designer change) — rejected as it multiplies the credential copies.

**R5 — The host returns a normalised, versioned document, not the raw staged bytes.** The designer writes no `v` field. The host parses, validates, and re-emits `{"v":1,"kind",host,port,scheme,base_url,credential,extras}`. This decouples the guest contract from what the designer stages (designer can add `v:1` later; reader treats absent as 1; `v>1` is refused with a named error so an old runtime never half-understands a newer document). Unknown extra top-level fields in the STAGED doc are tolerated (forward compatibility), not echoed. *Cost if wrong:* a guest that wants raw fields it cannot get — add them to the v1 emit.

**R6 — The runtime has no kind allow-list.** The reader is generic over any canonical name; a friendly label table is used only for error text (`vector_store_qdrant` -> "Qdrant"). New kinds need a designer/admin release and, if they need an isolation scheme, an extension — not a runtime release. *Cost if wrong:* none functional.

**R7 — Missing/invalid entry is a named error and BYPASSES the env-var fallback.** `StoreToolSecretsBackend::get` currently falls back to `env_var_name_for_secret(uri)` (`INFRA_VECTOR_STORE_QDRANT`) when the store misses. For provider `infra` that would resurrect the localhost-style silent default the feature forbids. The error is `SecretsError::Backend(msg)` (logged by ext-runtime at `error` with the extension id; `msg` carries the kind and tried URIs, never a value): "infra resource 'vector-store/qdrant' is not connected to this deployment (looked at ...). Add it in workspace settings and deploy again." `NotFound` is not used because ext-runtime renders it as "secret not found: <uri>" which names no remedy.

**R8 — Credential hygiene scope.** Host side: `SecretString`, redacted `Debug`, fixed-text parse errors (use `serde_json::Error::classify()` + line/column only), no `tracing` of the document, normalised doc built into a `SecretString` and exposed only at the single `get` return. Boundary honestly stated: once returned, the credential is in the guest's linear memory and the guest controls what it logs (`host.logging`) — the host cannot prevent a guest from logging it; this is an extension-authoring rule documented in `docs/infra-connection-v1.md`. UNVERIFIED: ext-runtime logs only the URI (read from source for `secrets::get`; not exhaustively for every call path).

**R9 — The deployer ACCEPTS `infra` today and writes it at the WRONG env segment.** `put_env_secret` has no category allow-list: `dev_store_key` falls to `secrets://{env_id}/{rel}` (env id `local`), so a designer deploying with a deployer that predates this plan reports `staged N` and the runtime never finds the entry — silent. Fix is two-part: (a) the category mapping (Task D1), (b) a new `infra_secret_category` capability in `op env capabilities` for the gcp_cloudrun and k8s adapters (Task D2) so the designer can refuse/note when the resolved binary does not report it (override binaries and updater pointers are the cases a pin comparison misses). Designer follow-up F1. *Cost if wrong:* a deployer without the capability remains silently wrong, exactly as today.

**R10 — `env_sor` `RESERVED_CATEGORIES` gains `infra`.** A SoR input may not live in a category read at a different env segment or by a different reader. It currently omits `knowledge` (a pre-existing gap; recorded in Task D1 as an observation, not widened here to keep the diff reviewable — one-line follow-up if wanted).

**R11 — Start needs NO read-path behaviour change.** Verified by reading `secrets_client.rs`: a canonical `infra` name returns `None` from `canonicalize_dev_store_secret_uri` (lookup unchanged), and `knowledge` (same shape) works in production. Start changes are (a) take the runner publish (floors), (b) add `infra` to the secrets door's `RUNNER_CATEGORIES` so a *future* admin mirror of infra entries is written at env `default` instead of the ingress env (today the designer mirrors nothing for infra; this is a pre-emptive guard against the exact `local`-vs-`default` defect), (c) an `infra-connections` capability flag whose test links against `infra_connection::SCHEMA_VERSION` so the flag cannot be claimed by a build that resolved a runner without the reader, (d) read-path pin tests + doc row. *Cost if wrong:* (b)/(c) are cheap and inert.

**R12 — Pruning stale `infra` entries is designer policy; the runtime/deployer only need to make it possible.** Deployer: `op secrets delete --path/--prefix` is category-generic (`DevStorePrefix`, `dev_store_key`), so once R1 holds it removes infra entries from the file that ships whole into every workload; Task D3 pins that with tests. Designer follow-up F2: on a WHOLE-environment deploy, `op secrets list --prefix default/_/infra/` minus the kinds the deploy needs -> `delete --path` each; a unit-scoped deploy NEVER prunes (other units may need the kind); environment teardown deletes the prefix. Runtime behaviour on a pruned entry is the R7 error. *Cost if wrong:* a stale credential keeps shipping to workloads that no longer need it (disclosure window = until the next whole deploy).

**R13 — Publish order (a merge to develop IS a crates.io publish).** Runner first (aw-runtime + runner-host in ONE merge: same repo, same dev-publish run); then start (needs the new aw-runtime/runner-host floor, so it cannot be built before the runner publish exists on crates.io); the deployer has no dependency on either and can merge in parallel with the runner, but must merge before the designer moves `GREENTIC_DEPLOYER_BIN_VER`. Designer pins afterwards (each its own bump PR, one bump per day, ask first): see "Pins the designer will need".

**R14 — Isolation inside a shared instance is the extension's job; the runtime exposes `extras` only.** Admin provisioners give Qdrant a per-tenant collection prefix + collection-scoped key and Redis an ACL user limited to a key prefix (`extras.collection_prefix`, `extras.key_prefix`). The runtime cannot enforce a prefix on arbitrary Qdrant/Redis traffic. `InfraConnection::require_extra(name)` gives an extension author a named error when the prefix is missing so it fails closed instead of using an unprefixed namespace. *Cost if wrong:* an extension that ignores the prefix reads across tenants; mitigated only by documentation and an extension-repo conformance test (out of scope here). Key-name agreement with admin plan Task 7 is a cross-repo checklist item (C3).

**R15 — No caching in the reader.** One store read per `get`. The Cloud Run store is baked per revision and the dev-store read is local; a cache would make a rotated credential linger. (`StoreToolSecretsBackend` already spawns a thread per read — existing cost, unchanged.) *Cost if wrong:* a retrieval-heavy extension pays a file read per call; add a TTL cache later.

**R16 — Serve path (`EnvSecretsBackend`, NATS out-of-process) does not support infra.** It resolves a single env credential for every tenant (documented in `knowledge_ext.rs`), so serving a tenant-scoped connection there would hand every tenant the same one. It returns the R7-style error for `secret://infra/`. UNVERIFIED which deployed lanes ever use the serve path (the Cloud Run/k8s worker uses the per-tenant `TenantRuntime` path, per agent_node.rs ~2033).

**R17 — Designer in-process lanes (Run Demo, Test chat) are out of scope.** They build their own secrets manager; no infra overlay exists there, so an infra-requiring tool run in Run Demo gets the R7 error. Designer follow-up F3. The designer gate already refuses local deploys (`infra_resource_lane_unsupported`).

**R18 — Local test policy vs. the task's "do not run cargo" instruction.** Verification commands below are what the *executor* runs. Rust test suites are slow/CI-bound in the designer repo only; the three runtime repos permit narrow `cargo test -p` runs. Run narrow filters, never the workspace suite.

---

## Cross-repo checklist (designer/admin items this plan creates or depends on)

- [ ] **C1** Designer: gate staging on the deployer's `infra_secret_category` capability (reads `op env capabilities`, `adapter_capabilities.rs`, literal `true` only — the `runtime_pin`/`scale_out_answers` rule); on false: a FAILED `infra-resources` step naming "deployer too old", not a green `staged N`.
- [ ] **C2** Designer: add `INFRA_CAPABLE_DEPLOYER_PIN` / `INFRA_CAPABLE_START_PIN` ratchets (the repo's pin-ratchet idiom) and move `Dockerfile.tools` pins (see below).
- [ ] **C3** Agree `extras` key names with admin plan Task 7: `collection_prefix`, `key_prefix`. The runtime treats extras as opaque strings.
- [ ] **C4** Designer: write `"v":1` in `infra_stage::plan::document` (reader tolerates absence; this makes the staged doc self-describing). Also consider depending on `greentic_aw_runtime::infra_connection` to build the document from the same type (single schema) — optional.
- [ ] **C5** Deployer must never echo the answers file or a value in errors (designer contract §7) — Task D4 pins it.
- [ ] **C6** Designer `store_prune`: F2 pruning policy (R12).
- [ ] **C7** Extension authors: declare `runtime.permissions.secrets: ["secret://infra/<name>"]`; fail closed on a missing `require_extra`. Guest-side typed parser belongs in the extension SDK repo (not in these worktrees) — document the v1 schema, ship the golden fixture.

---

## Release order and pins the designer will later need

1. **runner** merges (Tasks N1–N4) -> `dev-publish` stamps `greentic-aw-runtime` / `greentic-runner-host` `1.2.0-dev.<run id>`. Record the run id: `gh run view <id> -R greenticai/greentic-runner --json headSha -q .headSha` maps it back.
2. **deployer** merges (Tasks D1–D4) in parallel; `greentic-deployer-dev` `1.2.0-dev.<run id>`; the prebuilt release is what `Dockerfile.tools` pins.
3. **start** merges (Tasks S1–S3) after (1): floors name the runner run id from (1).
4. **designer** (separate work, NOT in this plan; each is its own `chore(release)`-style PR; one bump per working day; ask before bumping): `Dockerfile.tools` `GREENTIC_DEPLOYER_BIN_VER` -> (2) AND `GREENTIC_START_BIN_VER` -> (3) in ONE tools-image move (the tag is a digest of the pin text); `Cargo.toml` aw-runtime/runner-host floors only if C4 is taken; `greentic-start-distroless:develop` must be republished from (3) (floating tag for Cloud Run/k8s — not covered by pin comparison, check the image build, not the pin); then the ratchets in C2 and the C1 gate; then the Qdrant knowledge extension release.

Until step 4 lands the designer keeps staging into stores no runtime reads (silent) — C1 must ship in the same designer change as the pin move so it cannot be skipped.

---

# PART 1 — greentic-runner (`/home/bima-pangestu/projects/orca/workspaces/greentic-runner-infra`)

Branch: `feat/infra-connection-reader` from `origin/develop`.

### Task N1: `greentic_aw_runtime::infra_connection` — typed, versioned reader

**Files:**
- Create: `crates/greentic-aw-runtime/src/infra_connection.rs`
- Create: `crates/greentic-aw-runtime/src/infra_connection/tests.rs` (unit tests, `#[cfg(test)] mod tests;`)
- Create: `crates/greentic-aw-runtime/tests/fixtures/infra_connection_v1.json` (golden guest document)
- Modify: `crates/greentic-aw-runtime/src/lib.rs` (add `pub mod infra_connection;` next to `pub mod scoped_secrets;` at line ~60)

**Interfaces:**
- Consumes: `greentic_secrets_lib::{SecretsManager, canonical_secret_name}`, `secrecy::{SecretString, ExposeSecret}`, `crate::scoped_secrets::{ENV_SEGMENT, TENANT_DEFAULT_TEAM}`.
- Produces (exact signatures, bodies elided):
  ```rust
  pub const CATEGORY: &str = "infra";
  pub const SCHEMA_VERSION: u32 = 1;
  pub const REMOTE_TENANT: &str = "default";
  pub const URI_PREFIX: &str = "secret://infra/"; // guest-facing

  pub fn canonical_name(kind: &str) -> String;           // idempotent
  pub fn kind_label(name_or_kind: &str) -> String;       // "Qdrant"/"Redis"/else the input
  pub fn uri_candidates(tenant: &str, kind: &str) -> Result<Vec<String>, InfraConnectionError>;
  pub fn kind_from_guest_uri(uri: &str) -> Option<&str>; // Some("vector_store_qdrant") for secret://infra/vector_store_qdrant

  pub struct InfraConnection { /* host, port, scheme, credential: SecretString, extras */ }
  impl InfraConnection {
      pub fn parse(kind: &str, bytes: &[u8]) -> Result<Self, InfraConnectionError>;
      pub fn host(&self) -> &str;                // unbracketed
      pub fn port(&self) -> u16;
      pub fn scheme(&self) -> &str;
      pub fn base_url(&self) -> String;          // scheme://host:port, IPv6 bracketed
      pub fn credential(&self) -> &SecretString;
      pub fn extra(&self, key: &str) -> Option<&str>;
      pub fn require_extra(&self, key: &str) -> Result<&str, InfraConnectionError>;
      pub fn to_guest_document(&self, kind: &str) -> SecretString; // normalised v1 JSON
  }
  impl std::fmt::Debug for InfraConnection { /* credential "<redacted>" */ }

  #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
  pub enum InfraConnectionError {
      #[error("infra resource '{kind}' is not connected to this deployment (looked at {tried}); add it in workspace settings and deploy again")]
      Missing { kind: String, tried: String },
      #[error("infra resource '{kind}' could not be read from the secret store: {reason}")]
      Unreadable { kind: String, reason: String },        // reason: fixed text, never a value
      #[error("infra resource '{kind}' is malformed: {field}")]
      Invalid { kind: String, field: &'static str },
      #[error("infra resource '{kind}' uses schema version {found}, this runtime reads up to {supported}")]
      UnsupportedVersion { kind: String, found: u32, supported: u32 },
      #[error("infra resource '{kind}' has no '{key}' setting; refusing to use an unscoped namespace")]
      MissingExtra { kind: String, key: String },
      #[error("infra kind '{0}' is not a valid kind")]
      BadKind(String),
  }

  pub async fn read(
      secrets: &dyn greentic_secrets_lib::SecretsManager,
      tenant: &str,
      kind: &str,
  ) -> Result<InfraConnection, InfraConnectionError>;
  ```
  `uri_candidates` builds `secrets://default/<tenant>/_/infra/<canonical>` for `tenant` then `default` (deduplicated), via `crate::scoped_secrets::secret_uri(CATEGORY, tenant, None, &canonical)` — the name is canonical so "verbatim" and "canonical" coincide. `read` stops on the first candidate that returns bytes; a candidate error other than not-found-shaped is remembered; if none resolves: `Missing` when every error looked like not-found, else `Unreadable{reason:"secret store error"}` (do NOT include the backend's error string: some backends include the URI only, but never trust it with a value).

- [ ] **Step 1: Write the failing tests** in `infra_connection/tests.rs` (use a `MapSecrets: SecretsManager` fake like `scoped_secrets::tests`, recording asked URIs):
  - `canonical_name_matches_the_designer_for_both_first_kinds` — `canonical_name("vector-store/qdrant") == "vector_store_qdrant"`, `("cache/redis") == "cache_redis"`, and `canonical_name("vector_store_qdrant") == "vector_store_qdrant"` (idempotent).
  - `uri_candidates_pin_env_default_team_underscore_and_try_the_served_tenant_first` — `uri_candidates("acme","vector-store/qdrant") == ["secrets://default/acme/_/infra/vector_store_qdrant","secrets://default/default/_/infra/vector_store_qdrant"]`; for tenant `default` exactly one URI.
  - `uri_candidates_ignore_the_flow_env` — set `GREENTIC_ENV=prod` (guard helper if the crate has one; else assert the function takes no env input) and assert the same URIs.
  - `bad_kinds_are_refused` — `""`, `"  "`, `"a/b/c/d"`(only if you decide to reject) -> `BadKind`; assert empty/blank only (keep it minimal).
  - `parses_the_exact_document_the_designer_stages` — bytes `{"host":"q.example.com","port":6333,"scheme":"https","credential":"S3CRET","extras":{"collection_prefix":"acme__"}}` -> `host()=="q.example.com"`, `port()==6333`, `scheme()=="https"`, `base_url()=="https://q.example.com:6333"`, `extra("collection_prefix")==Some("acme__")`; absent `v` accepted.
  - `an_ipv6_host_is_bracketed_only_in_base_url` — host `2001:db8::1`, `host()` unbracketed, `base_url()=="https://[2001:db8::1]:6333"`.
  - `a_version_above_one_is_refused_by_name` — `{"v":2,...}` -> `UnsupportedVersion{found:2,supported:1}`; `{"v":1,...}` and absent `v` OK.
  - `unknown_top_level_fields_are_tolerated_and_not_echoed` — extra `"future":"X"` parses; `to_guest_document` output has no `future`.
  - `host_rules_mirror_the_admin` (table): `""`, 254-byte, `"a..b"`, `"-a"`, `"a-"`, `"h:80"`, `"https://h"`, `"u@h"`, `"a b"` -> `Invalid{field:"host"}`; `"1.2.3.4"`, `"2001:db8::1"`, `"q.example.com"` accepted.
  - `port_zero_and_non_numbers_are_refused` — `0` and `"6333"` (string) -> `Invalid{field:"port"}`.
  - `scheme_must_be_alphanumeric_and_short` — `"ht tp"`, 17 chars -> `Invalid{field:"scheme"}`; missing scheme defaults to `https` (admin default) — assert default applies.
  - `credential_bounds` — empty and 4097 bytes -> `Invalid{field:"credential"}`.
  - `extras_bounds` — 17 entries, a 257-byte value, a non-string value -> `Invalid{field:"extras"}`.
  - `debug_never_shows_the_credential` — `format!("{conn:?}")` does not contain `S3CRET`; contains `<redacted>`.
  - `errors_never_contain_a_value` — parse `{"host":"h","port":"S3CRET-IN-A-WRONG-TYPE","credential":"S3CRET"}`; `err.to_string()` and `format!("{err:?}")` contain neither `S3CRET` (serde would print `invalid type: string "S3CRET-IN-A-WRONG-TYPE"`). This is the test that justifies mapping serde errors to fixed text.
  - `missing_entry_names_the_kind_and_both_uris_and_no_value` — `read(empty, "acme", "vector-store/qdrant")` -> `Missing`; message contains `vector-store/qdrant`, both URIs, and the words "deploy again".
  - `read_prefers_the_served_tenant_then_default` — seed only the `default` URI: resolves, and the asked order is `[acme.., default..]`; seed both with different hosts: `acme` wins.
  - `require_extra_fails_closed` — absent -> `MissingExtra{key:"collection_prefix"}`; present returns it; blank string value is treated as absent.
  - `guest_document_matches_the_golden_fixture` — `to_guest_document("vector-store/qdrant").expose_secret()` parsed as `serde_json::Value` equals `tests/fixtures/infra_connection_v1.json` (keys: `v:1,kind,host,port,scheme,base_url,credential,extras`). The fixture is the cross-repo contract (C7).
  - `guest_document_round_trips_through_parse` — `parse(kind, guest_doc_bytes)` accepts its own output (so a guest SDK parser can share the fixture).
- [ ] **Step 2: Run, confirm failure:** `cargo test -p greentic-aw-runtime infra_connection` -> compile error (module absent).
- [ ] **Step 3: Implement** per the signatures. Deserialize into a private `RawDoc { v: Option<u32>, host: String, port: serde_json::Value (check u64 1..=65535), scheme: Option<String>, credential: String, extras: Option<BTreeMap<String,serde_json::Value>> }` then validate field by field so error text is a `field` name only. On `serde_json::from_slice` failure return `Invalid{field:"document"}` (use `e.classify()` only inside a `tracing::debug!` with NO message text). Hold `credential` as `SecretString` immediately after validation; zero the intermediate `String` where `secrecy` allows. Build `to_guest_document` with `serde_json::json!` into a `String` then `SecretString::from`. Keep the file <= 500 lines (move tests out, as planned).
- [ ] **Step 4: Run:** `cargo test -p greentic-aw-runtime infra_connection` -> all pass. `cargo fmt --all --check`, `cargo clippy -p greentic-aw-runtime --all-targets --all-features -- -D warnings`.
- [ ] **Step 5: Commit:** `feat(aw-runtime): typed, versioned reader for staged infrastructure connections`

### Task N2: route `secret://infra/<name>` through `StoreToolSecretsBackend`

**Files:**
- Create: `crates/greentic-runner-host/src/runner/infra_secret.rs` (+ `mod infra_secret;` in `runner/mod.rs`)
- Modify: `crates/greentic-runner-host/src/runner/agent_node.rs` — inside `impl greentic_ext_runtime::SecretsBackend for StoreToolSecretsBackend` (`fn get`, ~line 1076): first statement `if let Some(name) = greentic_aw_runtime::infra_connection::kind_from_guest_uri(uri) { return super::infra_secret::resolve_blocking(self.secrets.clone(), &self.tenant, name); }` — BEFORE `store_uri_candidates` and before the env fallback.
- Test: tests live in `infra_secret.rs` (`#[cfg(test)]`) and one in the existing `agent_node.rs` tests module (`backend_for` helper, ~line 4968).

**Interfaces:**
- Consumes: `greentic_aw_runtime::infra_connection::{read, InfraConnectionError, kind_from_guest_uri}`, `crate::secrets::DynSecretsManager`.
- Produces:
  ```rust
  pub(crate) fn resolve_blocking(
      secrets: crate::secrets::DynSecretsManager,
      tenant: &str,
      name: &str,
  ) -> Result<String, greentic_ext_runtime::SecretsError>;
  ```
  Mirrors the existing dedicated-thread + current-thread-runtime bridge (do not `block_on` on the async executor). Maps: `Ok(conn)` -> `Ok(conn.to_guest_document(name).expose_secret().to_string())`; any `InfraConnectionError` -> `SecretsError::Backend(err.to_string())` (messages are value-free by N1 tests). A thread/runtime build failure -> `Backend("infra resource '<name>': secret store bridge unavailable")`.

- [ ] **Step 1: Write the failing tests:**
  - `an_infra_uri_reads_env_default_even_when_the_backend_env_is_dev` — `backend_for(None, &[("secrets://default/acme/_/infra/vector_store_qdrant", DOC)])` (note `env:"dev"` in the helper) `.get("secret://infra/vector_store_qdrant")` returns a JSON string with `"v":1` and the host; proves the pinned `default` env, not `self.env`.
  - `an_infra_uri_falls_back_to_the_default_tenant` — seed only `secrets://default/default/_/infra/...`, tenant `acme` resolves.
  - `a_missing_infra_entry_is_a_named_backend_error_not_not_found` — error is `SecretsError::Backend`, message contains `vector_store_qdrant` and `deploy again`.
  - `a_missing_infra_entry_never_consults_the_env_var_fallback` — set `INFRA_VECTOR_STORE_QDRANT=http://localhost:6333` (use the crate's env-guard/serial helper if present; if there is none, add a `static ENV_LOCK: Mutex<()>` local to the test module) and assert `get` still errors; the value must not be returned.
  - `an_infra_uri_never_reads_the_unit_scoped_or_provider_scoped_address` — a `MapSecrets` that records asked URIs: none contains `_unit_` and none is `secrets://dev/...`.
  - `a_non_infra_uri_is_unchanged` — existing `two_units_with_one_provider_and_key_each_read_their_own_value` still passes (run it).
  - `the_returned_document_is_value_checked` — seed an invalid doc (port 0): error is `Backend` containing `port` and not the credential.
  - In `infra_secret.rs`: `kind_from_guest_uri_accepts_only_secret_infra_prefix` (`secret://infra/x` yes; `secret://infra` no; `secret://infra/` no; `secret://infra/a/b` no — nested path refused; `secrets://default/..` no; `secret://infrastructure/x` no).
- [ ] **Step 2: Run, confirm failure:** `cargo test -p greentic-runner-host infra_secret` and the `agent_node` filter above.
- [ ] **Step 3: Implement.** Keep the `agent_node.rs` diff to the 3-line hook (the file is ~6k lines; do not add logic there).
- [ ] **Step 4: Run:** the filters above; `cargo clippy --all-targets --all-features -- -D warnings` (workspace, the CI gate).
- [ ] **Step 5: Commit:** `feat(runner-host): serve staged infrastructure connections to extension tools`

### Task N3: the serve path refuses infra instead of reading env; docs and contract fixture

**Files:**
- Modify: `crates/greentic-runner-host/src/runner/agent_node.rs` — `impl SecretsBackend for EnvSecretsBackend` (~line 980): if `kind_from_guest_uri(uri).is_some()` return `Err(SecretsError::Backend("infra resource '<name>' is not available on the out-of-process serve path (it resolves one credential for every tenant); deploy the worker as a unit"))`.
- Create: `docs/infra-connection-v1.md` (the contract: staged document, guest document, URI, permission declaration, error table, `extras` keys, "the guest owns what it logs", lanes, UNVERIFIED list).
- Modify: `CLAUDE.md` — one paragraph under the knowledge/secrets material pointing at the doc and naming the three non-obvious rules (env segment `default`; env-var fallback bypassed; tools only).

- [ ] **Step 1: Test:** `the_serve_path_refuses_an_infra_uri_even_when_the_env_var_is_set` (same env guard as N2) -> `Backend`, message contains `serve path`.
- [ ] **Step 2: Run** `cargo test -p greentic-runner-host serve_path_refuses` -> fails; implement; passes.
- [ ] **Step 3: Docs.** The doc must state, with UNVERIFIED tags: end-to-end with a real guest extension and a real `host.secrets.get` was not run; ext-runtime logging beyond the URI was read for `secrets::get` only; whether a deployed Cloud Run/k8s worker carries tenant `default`.
- [ ] **Step 4: Commit:** `feat(runner-host): refuse infra connections on the shared serve path` and `docs: infra connection contract v1` (two commits).

### Task N4: release checklist (no code)

- [ ] Open the PR against `develop`; CI runs fmt + clippy only. Run the narrow test filters from N1–N3 locally first and say so in the PR body ("full suite left to nightly").
- [ ] After merge, record the `dev-publish` run id and the two published versions (`greentic-aw-runtime`, `greentic-runner-host`) in the PR; start's S1 needs them.
- [ ] Do NOT raise any crate base version (see the dev-lane range note: a base move is whole-graph).

---

# PART 2 — greentic-deployer (`/home/bima-pangestu/projects/orca/workspaces/greentic-deployer-infra`)

Branch: `feat/infra-secret-category` from `origin/develop`. Precedent to copy: commit `d7be9521` (#639, `knowledge`). Plan commit lives in this worktree too.

### Task D1: `infra` is a default-env-segment category

**Files:**
- Modify: `src/cli/secrets.rs` — add `const INFRA_CATEGORY: &str = "infra";` with a doc comment (reader, runner `infra_connection`, designer `infra_stage`); extend `is_default_segment_category_rel_path` to `Some(LLM_CATEGORY | KNOWLEDGE_CATEGORY | INFRA_CATEGORY)`; update the comment block above `dev_store_key` if it enumerates categories.
- Modify: `src/cli/env_sor/validate.rs` — `RESERVED_CATEGORIES` add `"infra"` (R10). Observation for the PR body: `knowledge` is also absent there.
- Tests in `src/cli/secrets.rs` `mod tests` next to the knowledge tests (~line 2089).

**Interfaces:** Produces the key mapping `dev_store_key(&EnvId("local"), "default/_/infra/vector_store_qdrant") == "secrets://default/default/_/infra/vector_store_qdrant"`. Consumes nothing new.

- [ ] **Step 1: Write failing tests:**
  - `an_infra_key_is_written_under_the_default_env_segment` — mirrors `a_knowledge_key_is_written_under_the_default_env_segment`: `local`, and a second env id `prod` both give `secrets://default/default/_/infra/cache_redis`.
  - `an_infra_name_must_still_be_canonical` — `validate_dev_store_secret_path("default/_/infra/vector-store-qdrant")` is `Err`; `.../vector_store_qdrant` is `Ok`. (Guards against a verbatim-exemption slip, R1.)
  - `infra_in_a_non_category_position_is_an_ordinary_key` — tenant named `infra`: `dev_store_key(local,"infra/_/mypack/k") == "secrets://local/infra/_/mypack/k"` (pack-position rule).
  - `a_sor_input_may_not_live_in_the_infra_category` (env_sor validate tests) — assert the existing refusal message path for category `infra`.
- [ ] **Step 2:** `cargo test -p greentic-deployer infra_key` -> fail (key lands under `local`).
- [ ] **Step 3: Implement** the three small edits.
- [ ] **Step 4: Run** `cargo test -p greentic-deployer infra`, `cargo test -p greentic-deployer secrets::tests::a_knowledge` (unchanged), fmt, scoped clippy.
- [ ] **Step 5: Commit:** `fix(secrets): write infra-category keys under the default env segment`

### Task D2: `infra_secret_category` capability

**Files:**
- Modify: `src/env_packs/deployer/capabilities.rs` — add `Capability::InfraSecretCategory`; `ALL: [Capability; 9]`; `as_str -> "infra_secret_category"`; `AdapterCapabilities` field + `NONE` + `has`; doc comment ("the deployer writes `infra` keys where the runtime reads them; a client must not stage infra connections through a deployer that does not report this — it would write them under the environment id and nothing reads them"); update `report_serializes_wire_names_and_missing` expected `missing` array and `Capability::ALL` size assertions.
- Modify: `src/env_packs/gcp_cloudrun/deployer.rs` (~line 1022) and `src/env_packs/k8s/deployer.rs` (~line 597): `infra_secret_category: true` plus a `capability_notes` line.
- Modify: `src/env_packs/aws/deployer.rs` (~666), `src/env_packs/azure_aca/deployer.rs` (~75), and any other struct-literal construction the compiler flags (local_process may use `..NONE`): `false`.
- Tests: extend `src/cli/env_drain_tests.rs` (see `k8s_reports_scale_out_answers`) and the capabilities module tests.

- [ ] **Step 1: Failing tests:**
  - `cloud_run_and_k8s_report_infra_secret_category` (the `k8s_reports_scale_out_answers` shape, both adapters, JSON `capabilities.infra_secret_category == true`).
  - `aws_and_azure_do_not_claim_infra_secret_category` — false.
  - `the_capability_report_lists_nine_wire_names` — `Capability::ALL.len()==9`, each `serde_json::to_value(c) == c.as_str()`.
  - Update `report_serializes_wire_names_and_missing`: `missing` gains `"infra_secret_category"` last.
- [ ] **Step 2:** `cargo test -p greentic-deployer capabilit` -> compile/assert failures.
- [ ] **Step 3: Implement.** The final `cargo build --no-default-features` gate: nothing here is feature-gated; confirm the new field sits in the ungated module (do not add `cfg`).
- [ ] **Step 4:** run the filters; scoped clippy; `cargo build -p greentic-deployer --no-default-features` is part of `ci/local_check.sh` — run it for this task only (it is a build, allowed by this repo's rules; the planner did not run it).
- [ ] **Step 5: Commit:** `feat(env-packs): report the infra_secret_category capability`

### Task D3: pruning works on `infra` (delete / list / prefix)

**Files:** tests only, plus any 1-line fix they expose: `src/cli/secrets/delete_tests.rs`, `tests/op_secrets_delete_cli.rs` (existing patterns).

- [ ] **Step 1: Tests (expected to pass after D1; if one fails, fix the root cause — do not special-case infra):**
  - `delete_prefix_removes_every_infra_entry_and_nothing_else` — put `default/_/infra/vector_store_qdrant` and `default/_/infra/cache_redis` plus `default/_/knowledge/embedding_key`; `delete --prefix default/_/infra/` removes exactly the two (`deleted_count == 2`), knowledge key remains; `deleted_keys[*].store_uri` all start `secrets://default/default/_/infra/`.
  - `delete_one_infra_path_is_idempotent` — second delete -> `deleted:false`.
  - `list_prefix_names_infra_keys_without_values` — `stored_keys` contains the two `path`s (usable as `delete --path`), JSON text contains no value.
  - `a_deleted_infra_credential_does_not_remain_as_a_tombstone_in_the_store_file` — read the store file bytes after delete; the credential's sentinel string is absent (the file ships whole into workloads; this is the R12 disclosure property).
- [ ] **Step 2:** `cargo test -p greentic-deployer infra_prune` / filters used above.
- [ ] **Step 3: Commit:** `test(secrets): pin pruning of infra-category keys`

### Task D4: an `op secrets put` failure never echoes the value (designer contract §7)

**Files:** `src/cli/secrets.rs` (+ test in `src/cli/secrets/` or `tests/`); possibly `src/cli/mod.rs::load_answers` error mapping.

Context: `load_answers` formats `AnswersParse.message` with serde errors (`json: {e}` / `yaml: {e}`); serde prints `invalid type: string "<offending value>"` for a mistyped field. The designer writes JSON, but the YAML fallback (non-`.json` extension) and a malformed `environment_id` can echo caller-controlled text.

- [ ] **Step 1: Tests:**
  - `a_mistyped_put_payload_does_not_echo_the_value` — answers file `{"environment_id": 7, "path":"default/_/infra/cache_redis","value":"{\"credential\":\"TOPSECRET\"}"}` and a variant with `"value": {"credential":"TOPSECRET"}` (wrong type): the returned `OpError` display and debug contain no `TOPSECRET`.
  - `an_empty_value_error_names_no_value` — existing behaviour pinned.
  - `a_non_canonical_infra_name_error_echoes_the_name_not_the_value`.
- [ ] **Step 2:** run; if the first fails (serde echo), change `load_answers`' `AnswersParse` for the `secrets` verbs only to a message built from `e.classify()`, `line`, `column` (no `Display` of the serde error) — `load_answers` is shared by every verb, so make the redaction opt-in via a new `load_answers_redacted::<T>` used by `put`/`get`/`rotate`/`delete`, leaving the others byte-identical. UNVERIFIED that serde_yaml_bw echoes similarly; the test covers both extensions.
- [ ] **Step 3: Docs:** add a short "Secret categories" table to `CLAUDE.md` (categories `mcp`,`a2a`,`sorla` = verbatim at `default`; `llm`,`knowledge`,`infra` = canonical at `default`; everything else = canonical at the env id) so the next category does not rediscover the quirk.
- [ ] **Step 4: Commit:** `fix(secrets): keep secret values out of put/get answer-parse errors` and `docs: secret category table`.

---

# PART 3 — greentic-start (`/home/bima-pangestu/projects/orca/workspaces/greentic-start-infra`)

Branch: `feat/infra-connections` from `origin/develop`. Depends on the runner publish (N4).

### Task S1: take the runner publish; `infra-connections` capability

**Files:**
- Modify: `Cargo.toml` — floors of `[dependencies.greentic-aw-runtime]` (line ~192), `[dependencies.greentic-runner-host]` (~345), the dev-dependency line (~509) and any `greentic-runner-desktop` line to the run id recorded in N4, each with the repo's mandatory rationale comment ("surfaces: `infra_connection` reader + `secret://infra/` route in `StoreToolSecretsBackend`; the resolved-and-verified publish"). Per CLAUDE.md a bare `>=M.m.p-dev` is not a floor — use the full `...-dev.<RUNID>`; all three runner-family floors move together (they must resolve one copy).
- Modify: `Cargo.lock` via `cargo update -p greentic-runner-host -p greentic-aw-runtime` (the repo's one-update-per-session rule; lockfile in the same PR).
- Modify: `src/shared_backend/mod.rs` — `pub const CAPABILITY_INFRA_CONNECTIONS: &str = "infra-connections";` and `capabilities_json` returns `[CAPABILITY_SHARED_STATE_BACKEND, CAPABILITY_INFRA_CONNECTIONS]` (shared-state stays at index 0: existing test asserts `capabilities[0]`).
- Test: `src/shared_backend/tests.rs`.

**Interfaces:** Consumes `greentic_aw_runtime::infra_connection::SCHEMA_VERSION`. Produces the capability string `infra-connections` in `greentic-start capabilities`.

- [ ] **Step 1: Failing tests:**
  - `the_capabilities_document_names_infra_connections` — `doc["capabilities"]` contains `"infra-connections"` and still has `"shared-state-backend"` first (update the existing index test deliberately, not silently).
  - `the_infra_flag_is_backed_by_a_resolved_reader` — `assert_eq!(greentic_aw_runtime::infra_connection::SCHEMA_VERSION, 1);` (fails to COMPILE on a lock that resolved a runner without the module; that is the guard). Put it in the same file with a comment saying why.
  - `a_document_staged_by_the_designer_reads_through_the_resolved_reader` — build the designer's JSON, `InfraConnection::parse("vector-store/qdrant", ..)`, assert `base_url()`. (Cross-repo contract test on the resolved crate.)
- [ ] **Step 2:** `cargo test -p greentic-start shared_backend` -> fail/compile error before the bump.
- [ ] **Step 3:** edit floors, `cargo update` (the two crates only), implement the flag.
- [ ] **Step 4:** `cargo fmt -p greentic-start -- --check`; `cargo clippy -p greentic-start --all-targets -- -D warnings`; the filter above.
- [ ] **Step 5: Commit:** `feat: report infra-connections and take the runner with the infra reader`

### Task S2: the secrets door writes `infra` at env `default`

**Files:** `src/secrets_door.rs` (`RUNNER_CATEGORIES`, line ~327; doc comment above it), `src/secrets_door_tests.rs` (line ~553 and ~677 show the existing category/path tests).

Context: today the designer mirrors nothing for `infra`, so this is pre-emptive. If a later change mirrors infra entries through the admin door, `env_for_path` would write them at the *ingress env* (`local`) — the same silent miss as D1.

- [ ] **Step 1: Failing tests:**
  - extend the loop at line ~553: `for yes in ["mcp","a2a","llm","knowledge","sorla","infra"]` asserts `is_runner_category`.
  - `an_infra_door_secret_is_written_at_env_default` — `env_for_path("_/infra/vector_store_qdrant", "local") == "default"`.
  - `an_infra_pack_segment_in_the_wrong_position_is_not_a_runner_category` — `env_for_path("infra/x/y","local")`: category is the MIDDLE segment, so `x` decides; assert `"local"` for a path whose middle segment is not `infra`.
  - `hydration_does_not_delete_a_staged_infra_entry` — seed `secrets://default/acme/_/infra/cache_redis` in the dev store, run a hydration whose admin answer lists other paths: the infra entry survives (the door deletes only what it wrote earlier — `WRITTEN` map). UNVERIFIED until run; if it fails the door's delete-what-the-admin-no-longer-returns rule would erase designer-staged infra entries, which must be fixed in this task.
- [ ] **Step 2:** `cargo test -p greentic-start secrets_door` -> first two fail.
- [ ] **Step 3: Implement** (one array element).
- [ ] **Step 4:** run; clippy.
- [ ] **Step 5: Commit:** `fix(secrets-door): write infra credentials at the default env segment`

### Task S3: pin the read path with tests; docs

**Files:** `src/secrets_client.rs` (tests only, next to `mcp_uri_tests`), `docs/secrets-flow.md` (add a row to the category/reader table or a short "Runner-read categories" note listing `mcp`,`a2a`,`sorla` verbatim and `llm`,`knowledge`,`infra` canonical at `default`).

- [ ] **Step 1: Tests (no production change expected):**
  - `an_infra_uri_with_a_canonical_name_is_looked_up_unchanged` — `canonicalize_dev_store_secret_uri("secrets://default/default/_/infra/vector_store_qdrant") == None`.
  - `a_hyphenated_infra_name_would_be_normalised_so_the_writer_must_not_produce_one` — `Some("...vector_store_qdrant")` for `vector-store-qdrant` (documents why the deployer refuses it, R1).
  - `a_dev_store_round_trip_reads_the_staged_infra_document` — write via `DevStore::put` the exact deployer key `secrets://default/default/_/infra/cache_redis`, read through the secrets client path; bytes equal. (Same pattern as `reads_seeded_secret_from_dev_store`.)
  - `the_gtunnel_alias_tenant_still_reaches_the_default_tenant_entry` — if the manager's re-tenant fallback applies to this URI shape, a served tenant `default-ba564` falls back to `default` (uses `secrets_gate` candidate chain; UNVERIFIED which layer owns it — pin whichever does, or drop the test and record in R2 that the runner reader's own tenant order is the only fallback).
- [ ] **Step 2:** `cargo test -p greentic-start infra`; fix only if a test exposes a real defect.
- [ ] **Step 3: Commit:** `test: pin the infra secret read path` and `docs: runner-read secret categories`.

---

## What is NOT in this plan (explicit)

- Guest-side typed parser/SDK (lives in the extensions SDK repo; ships the same golden fixture — C7).
- The Qdrant-backed knowledge extension itself and its `x-requires` / `permissions.secrets` declarations.
- Flow `component.exec` nodes consuming infra (R4), Run Demo/Test chat (R17), local/ECS/Container Apps lanes (designer refuses them).
- Designer changes C1–C6 (separate repo, separate PRs, after the pins move).
- Provisioners and per-tenant isolation inside Qdrant/Redis (admin plan Task 7); the runtime only passes `extras` through (R14).

## UNVERIFIED register

1. No cargo command was run while writing this plan; every "fails first" is a claim.
2. A deployed worker's served tenant is `default` on k8s and Cloud Run (designer comments assert it; one live measurement is cited for Cloud Run on 2026-09-15) — R2's fallback covers both.
3. ext-runtime logs only the URI/extension id on the `secrets::get` path (read in source for `secrets::get`, not audited elsewhere).
4. Whether `knowledge_ext`'s `ExtensionRuntime` is built with `StoreToolSecretsBackend` on every deployed lane (graph/deep-worker lanes) — the `dw.agent` per-tenant path at `agent_node.rs ~2033` is; the serve path is not (R16).
5. Whether serde_yaml_bw echoes offending scalars (D4 test decides).
6. End-to-end with a real guest extension, real Qdrant/Redis, real Cloud Run/Kubernetes: not part of this plan; first deployed e2e belongs to the designer rollout.
7. The deployer ships the whole dev-store file into workloads without per-category filtering (read in `CLAUDE.md` and `dev_store_keys.rs` docs; the k8s ConfigMap/Secret path was not re-read).
