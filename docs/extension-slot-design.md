# Design: An N-allowed `Extension` capability slot

Status: **proposal / design review.** No code ships from this document. It
specifies a single addition to the env-pack model — an open `Extension`
namespace — so the team can agree on the shape before any schema bump lands.

Companion to [`env-packs.md`](env-packs.md), which documents the model as it
exists today (closed `CapabilitySlot` enum + open `PackDescriptor` + the
`EnvPackHandler` registry). Read that first; this doc assumes it.

## Motivation

Adding a new *capability family* today is "Path 2" in the authoring guide: a
deploy-spec schema bump (new `CapabilitySlot` variant, `ALL` update,
`as_str` arm, `validate()` lock-step, downstream floor-pins). That is correct
for capabilities that earn a typed, 1-per-env contract — but it is friction
for the long tail of capabilities that are config-shaped or naturally
N-per-env. Every such family currently pays the full closed-enum tax.

This proposal adds **one** variant — `Extension` — whose bindings live in a
parallel N-collection. After that one-time bump, a new config-shaped or
N-per-env capability is a `PackDescriptor` value plus a handler registration:
no schema change, ever again.

## The dividing rule (the conceptual heart)

Every production consumer of a core slot today does the same thing:

```rust
// secrets.rs, credentials.rs, env.rs — all of this shape
env.pack_for_slot(CapabilitySlot::Secrets)   // ask for ONE specific slot, expect ONE binding
```

The consumer knows *at compile time* which capability it needs and demands
exactly one binding. That is what the closed enum buys, and it is the test
for which path a new capability takes:

| Question | Path |
| --- | --- |
| Does **core code** (deployer / start / operator / runner) call `pack_for_slot(X)` for it and link a **typed host interface** (`dyn SecretsManager`, `dyn StateHost`, …)? | **Core slot.** Closed variant, 1-per-env, typed contract. (Path 2.) |
| Is the consumer a **bundle / flow** that resolves the capability **dynamically by name** (`ext://<path>`) and reads config / answers? | **Extension.** Open namespace, N-per-env, no schema bump. (This proposal — Path 3.) |

A core slot is a compile-time dependency of the platform. An extension is a
runtime dependency of a *workload*. That line is mechanical, not a judgment
call — it removes "is this worth a schema bump?" from the decision.

## Why extensions cannot live in `Environment.packs`

`Environment::validate` enforces 1-per-slot with a fixed-size seen-array
indexed by the enum discriminant:

```rust
// environment.rs — the existing 1-per-slot guard
let mut seen = [false; CapabilitySlot::ALL.len()];
for binding in &self.packs {
    let idx = binding.slot as usize;
    if seen[idx] {
        return Err(SpecError::DuplicateCapabilitySlot(binding.slot));
    }
    seen[idx] = true;
}
```

If `Extension` were a slot used inside `packs`, the *second* extension binding
would be falsely rejected as a duplicate. So extensions **must** live in a
separate collection. This is not a workaround — it is exactly the shape the
`Messaging` slot already uses: `Messaging` is a `CapabilitySlot` variant whose
bindings live in `Environment.messaging_endpoints: Vec<MessagingEndpoint>`,
**not** in `packs`, with its own N-uniqueness validation:

```rust
// environment.rs — messaging is already the N-per-env precedent
let mut seen_endpoint_ids = HashSet::...;
let mut seen_provider_instances = HashSet::...;          // unique on (provider_type, provider_id)
for endpoint in &self.messaging_endpoints { ... }
```

`Extension` is the *generalization* of that precedent: where `Messaging` is a
typed N-collection for one known family, `Extension` is an open N-collection
for an unbounded set of families.

## Proposed model

### Schema (`crates/greentic-deploy-spec`)

```rust
// capability_slot.rs — ONE new variant, ever
pub enum CapabilitySlot {
    Deployer, Secrets, Telemetry, Sessions, State, Revocation, Messaging,
    Extension,   // ← new
}
// + ALL entry, + as_str arm ("extension")

// environment.rs — a parallel N-collection (mirrors messaging_endpoints)
pub struct Environment {
    pub packs: Vec<EnvPackBinding>,             // core slots, 1-per-slot (unchanged)
    pub messaging_endpoints: Vec<MessagingEndpoint>,
    #[serde(default)]
    pub extensions: Vec<ExtensionBinding>,      // ← new, N-per-env
    // ...
}

/// An open-namespace capability binding. Unlike EnvPackBinding it carries no
/// `slot` field — its slot is always Extension; its identity is the descriptor
/// path (plus an optional instance id for multi-instance extensions).
pub struct ExtensionBinding {
    pub kind: PackDescriptor,              // e.g. acme.oauth.auth0@1.0.0
    pub pack_ref: PackId,
    /// Distinguishes N instances of the SAME extension type. `None` ⇒ the
    /// descriptor path is the whole key (one instance of this extension).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers_ref: Option<PathBuf>,
    #[serde(default)]
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_binding_ref: Option<PathBuf>,
}
```

### Uniqueness invariant

`validate()` gains an extensions pass mirroring the messaging one:

- Unique on `(kind.path(), instance_id)`. Two bindings with the same path and
  no instance id (or the same path + same instance id) are a
  `DuplicateExtension` error.
- A binding with an `instance_id` and one without, on the same path, is
  allowed (single default + named instances) — or rejected, if the team
  prefers "instance_id all-or-nothing per path." **Open question, see below.**

### Resolution contract

Two consumers, two paths, both already mostly built:

1. **The registry** (`EnvPackRegistry`) already keys handlers on
   `descriptor_path` regardless of slot. An extension handler returns
   `slot() == CapabilitySlot::Extension`. `resolve()` (path + version check)
   works unchanged. `resolve_for_slot(Extension, kind)` accepts any handler
   whose `slot()` is `Extension` — the slot-mismatch check degrades to "is
   this a registered extension," which is the correct semantics for an open
   namespace.

2. **The bundle/flow runtime** reaches an extension by name through a generic
   resolver — proposed scheme `ext://<descriptor-path>[/<instance_id>]` —
   that returns the extension's resolved config/answers blob. This is the
   load-bearing difference from a core slot: **no typed host interface is
   auto-wired.** The runtime hands back config; the consuming component does
   the rest. (Contrast: the `secrets` slot wires a `dyn SecretsManager` the
   runner links directly.)

### `doctor` / `tool-check` semantics

- `op env doctor`: extensions are **never** reported in `missing_slots` — the
  extension namespace is open and opt-in, so "missing" is undefined for it.
  Each extension binding is still resolved against the registry (unknown
  path → `unknown_kinds`; version skew → `version_skew`). Slot-mismatch does
  not apply (every extension handler serves `Extension`).
- `op env tool-check`: each extension handler's `preflight()` runs exactly as
  core handlers' do — an extension that shells out (e.g. an OAuth broker CLI)
  composes checks from `src/tool_check.rs`.

### CLI surface

Mirror the existing `env-packs` verbs under a new `extensions` noun (or reuse
`env-packs` with the binding shape disambiguated by an absent `slot`):

```
gtc op extensions add      --answers add.json      # { kind, pack_ref, instance_id?, answers_ref? }
gtc op extensions update   --answers update.json
gtc op extensions remove   --answers remove.json   # { kind, instance_id? }
gtc op extensions rollback --answers rollback.json
gtc op extensions list     <env_id>
```

Same `--schema` / `--answers` discipline, same `generation` +
`previous_binding_ref` rollback machinery as `env-packs`. **Open question:
new noun vs. overloaded `env-packs`, see below.**

## What extensions can and cannot do

| Can | Cannot |
| --- | --- |
| Carry per-env config + wizard answers a bundle reads via `ext://`. | Be the single typed backend behind a host interface the runner links. |
| Exist N-per-env (multiple instances, keyed by path / instance id). | Be discovered by core code via `pack_for_slot` — core code doesn't know they exist. |
| Be added without a schema bump (descriptor value + handler registration). | Auto-wire a `dyn Trait` into the runtime without additional machinery. |
| Run `preflight()` tool checks like any handler. | Participate in `missing_slots` (the open namespace has no "complete" set). |

If a capability needs the right column, it is a **core slot**, not an
extension. The extension slot does not replace Path 2; it absorbs the long
tail Path 2 was overpaying for.

## Where fast2flow and oauth land under this rule

Applying the dividing rule honestly (this supersedes the speculative
"both are Path 2" framing in the current authoring guide):

- **OAuth** — *borderline, leans core slot.* If the runner must wire an OAuth
  broker the runtime links (the likely shape, since `greentic-oauth` ships a
  broker), it wants a typed core slot. If bundles only need per-env OAuth
  *config* (client registrations, redirect URIs, scopes) and reach it via
  `ext://oauth` while keeping their existing host imports, it is an extension.
  The deciding question: *does the runner call `pack_for_slot(OAuth)` to
  select a broker backend, or do bundles resolve OAuth config by name?*
- **fast2flow** — *workload today; extension if it becomes an env service.*
  It is an app-bundle (a workload), so it is neither slot nor extension unless
  the model changes. If it becomes an env-shared service that bundles call by
  name → extension. If the runner must wire a fast2flow router → core slot.

The extension slot does not auto-resolve either, but it changes the question
from "is this worth a schema bump?" to "core consumer or bundle consumer?"

## Migration

- **Schema version.** Bump `SchemaVersion::ENVIRONMENT_V1` →
  `greentic.environment.v2` (or add `extensions` under v1 as a
  `#[serde(default)]` field if the team treats additive optional fields as
  v1-compatible — the existing `messaging_endpoints` field was added as
  `#[serde(default)]`, suggesting additive-optional is already the v1 norm).
  **Open question, see below.**
- **Existing envs.** `extensions` defaults to empty; no env is forced to
  migrate. `doctor` behavior for existing envs is unchanged (extensions never
  appear in `missing_slots`).
- **`validate()` seen-array.** Untouched — `Extension` is never placed in
  `packs`, so the `[bool; ALL.len()]` 1-per-slot guard does not need to special
  case it. (It *will* size one larger because `ALL` grows by one; that is
  free.)
- **Downstream floor-pins.** Consumers that read `Environment.extensions` floor
  -pin to the spec publish that adds the field, per the workspace
  binary-bifurcation rules.

## Alternatives considered

1. **Keep extending the enum per family (status quo Path 2).** Rejected as the
   default for config-shaped/N families: it pays the full closed-enum tax for
   capabilities that derive no benefit from 1-per-slot or a typed contract.
   Still correct for capabilities that *do* (secrets, state) — this proposal
   does not remove Path 2, it complements it.
2. **Make `CapabilitySlot` itself open (string-keyed).** Rejected. It throws
   away the integrity boundary for the *core* slots too: `doctor`'s
   `missing_slots`, the 1-per-slot guarantee, and the compile-time
   `pack_for_slot(X)` consumers all depend on the closed set. An open
   extension namespace *alongside* the closed core is strictly better than an
   open everything.
3. **Extension-with-declared-interface-id** (extensions carry a host-interface
   id so the runtime can auto-wire them). Deferred. It recreates the typed-slot
   machinery dynamically and is only needed if an extension must link a host
   interface — at which point the dividing rule says make it a core slot
   instead. Revisit only if a concrete case needs a typed interface *and*
   N-per-env simultaneously.

## Open questions for review

1. **`instance_id` policy.** All-or-nothing per path, or default-plus-named?
   Drives the uniqueness predicate in `validate()`.
2. **CLI surface.** New `gtc op extensions` noun, or overload `env-packs` with
   a `slot`-absent binding shape? New noun is clearer; overload is less
   surface.
3. **Schema version.** Additive `#[serde(default)]` field under
   `environment.v1` (consistent with how `messaging_endpoints` landed), or a
   clean `environment.v2` bump? The former is lower-friction; the latter is
   more honest about the model growing.
4. **`ext://` resolver ownership.** Which crate owns the
   `ext://<path>[/<instance>]` → config resolution — the runner-host runtime
   resolver, or a deploy-spec helper consumed by both? (Mirrors the existing
   `secret://` / `state://` resolver question.)
5. **Should `Messaging` fold into `Extension`?** `Messaging` predates this
   proposal and is a typed N-collection. It is *not* proposed to migrate — it
   has a typed runtime contract extensions lack — but the symmetry is worth
   noting for reviewers.

## Reference

| Concern | File |
| --- | --- |
| `CapabilitySlot` enum + `ALL` | `crates/greentic-deploy-spec/src/capability_slot.rs` |
| `Environment` + `validate()` 1-per-slot guard | `crates/greentic-deploy-spec/src/environment.rs` |
| `messaging_endpoints` N-per-env precedent | `crates/greentic-deploy-spec/src/environment.rs` |
| `SchemaVersion` constants | `crates/greentic-deploy-spec/src/version.rs` |
| `EnvPackRegistry` (path-keyed, slot-checked) | `src/env_packs/registry.rs` |
| `EnvPackHandler` trait | `src/env_packs/slot.rs` |
| `pack_for_slot` consumers (the dividing-rule evidence) | `src/cli/secrets.rs`, `src/cli/credentials.rs`, `src/cli/env.rs` |
| Current authoring guide (Path 1 / Path 2) | [`env-packs.md`](env-packs.md) |
