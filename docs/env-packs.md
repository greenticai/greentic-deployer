# Env-Pack Authoring Guide

How to add a new pack that an `Environment` can bind to one of its capability
slots. Covers both the common case (a new implementation under an existing
slot) and the rare case (extending the closed slot enum). Companion to
[`deployment-packs.md`](deployment-packs.md), which documents the orthogonal
notion of deployment-execution packs.

## Model in one diagram

```
┌────────────────────────────────────────────────────────────────────┐
│  Environment (greentic.environment.v1)                             │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │ packs: Vec<EnvPackBinding>   (1 per slot)                  │    │
│  │   ├─ slot:     CapabilitySlot     (CLOSED enum)            │    │
│  │   ├─ kind:     PackDescriptor     (OPEN string + semver)   │    │
│  │   ├─ pack_ref: PackId             (where the artifact is)  │    │
│  │   └─ answers_ref: Option<Path>    (wizard answers)         │    │
│  └────────────────────────────────────────────────────────────┘    │
│                          ↓ resolves to                             │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │ EnvPackRegistry  (in-process)                              │    │
│  │   path string → Box<dyn EnvPackHandler>                    │    │
│  └────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────┘
```

Three layers, with deliberately mixed mutability:

| Layer              | Type                                                   | Mutability                                                   |
| ------------------ | ------------------------------------------------------ | ------------------------------------------------------------ |
| Capability family  | `CapabilitySlot` (`crates/greentic-deploy-spec`)       | **Closed enum.** Adding a variant is a deploy-spec schema bump. |
| Pack identity      | `PackDescriptor` (`<namespace>.<id>@<semver>`)         | **Open.** Any new implementation pack is a new value, not a code change. |
| Native handler     | `EnvPackHandler` trait (`src/env_packs/slot.rs`)       | Open. Phase D plug-ins register via `EnvPackRegistry::register`. |

> **The boundary matters.** If a new pack fits an existing slot, you don't
> touch the enum — you write a descriptor string and register a handler.
> Only when no slot describes the *kind of capability* do you reach for
> a schema bump.

The seven slots today (`CapabilitySlot::ALL`):

| Slot         | Cardinality   | Examples                                                                              |
| ------------ | ------------- | ------------------------------------------------------------------------------------- |
| `deployer`   | 1 per env     | `greentic.deployer.local-process`, `greentic.deployer.k8s`, `greentic.deployer.aws-ecs`, `greentic.deployer.gcp-cloudrun` |
| `secrets`    | 1 per env     | `greentic.secrets.dev-store`, `greentic.secrets.aws-sm`, `greentic.secrets.vault`     |
| `telemetry`  | 1 per env     | `greentic.telemetry.stdout`, `greentic.telemetry.otlp-grpc`                           |
| `sessions`   | 1 per env     | `greentic.sessions.in-memory`, `greentic.sessions.redis`                              |
| `state`      | 1 per env     | `greentic.state.in-memory`, `greentic.state.redis`                                    |
| `revocation` | 1 per env     | (defaults wired by the env runtime; no built-in handler yet)                          |
| `messaging`  | N per env     | Bound via `Environment.messaging_endpoints`, **not** `Environment.packs`.             |

## Decision: which path are you on?

The first cut is **the dividing rule**: *who consumes the capability?*

- **Core code** (deployer / start / operator / runner) calls `pack_for_slot(X)`
  and links a **typed host interface** (`dyn SecretsManager`, `dyn StateHost`,
  …). It's a **core slot** — closed enum, 1-per-env. → **Path 1 or 2.**
- **A bundle / flow** resolves the capability **dynamically by name**
  (`ext://<path>[/<instance>]`) and reads config / answers — no typed interface
  wired. It's an **extension** — open namespace, N-per-env, no schema bump
  per family. → **Path 3.**

```
                   ┌─────────────────────────────────────────────┐
                   │ Does CORE code call pack_for_slot(X) and    │
                   │ link a typed host interface for it?         │
                   └───────────────────┬─────────────────────────┘
                       yes (core slot) │ no (workload resolves by name)
                       ▼               │               ▼
        ┌─────────────────────────┐    │     ┌──────────────────────────┐
        │ Does a slot already      │    │     │ Path 3                    │
        │ exist in CapabilitySlot? │    │     │ Extension binding         │
        ├────────────┬─────────────┤    │     │ (open ns, N-per-env,      │
        │ yes        │ no          │    │     │ no schema bump ever again)│
        ▼            ▼             │    │     └──────────────────────────┘
   ┌─────────┐ ┌──────────────┐    │
   │ Path 1  │ │ Path 2       │    │
   │ New     │ │ Extend the   │    │
   │ desc.   │ │ closed enum  │    │
   └─────────┘ └──────────────┘    │
```

For a core slot, pick **Path 1** unless your capability is genuinely a new
family that no existing slot can host. The 1-per-slot constraint is
intentional — two secrets backends in one env would split the truth source —
so wanting "a second secrets pack" alongside the existing one is almost always
a sign you want a new descriptor (Path 1), not a new slot (Path 2).

For config-shaped or naturally N-per-env capabilities a *workload* reaches by
name, take **Path 3** — it absorbs the long tail that Path 2 overpays for. The
full rationale lives in the Extension-slot design spec
(`docs/extension-slot-design.md`).

## Path 1 — Adding a new pack within an existing slot

This is the common path. No deploy-spec change, no closed-enum touch.

### 1. Pick the descriptor string

Format: `<namespace>.<slot>.<implementation>@<semver>` — lowercase ASCII,
digits, `-`, and `.` only; exactly one `@`; valid SemVer after it. Examples:

- `greentic.secrets.aws-sm@1.0.0`
- `acme.secrets.vault@0.4.2`
- `greentic.telemetry.otlp-grpc@0.1.0`

The path **before** `@` is the registry key. The version is matched against
the handler's [`supported_versions`](#3-implement-envpackhandler) at resolve
time, so an operator pinning `@0.2.0` against a handler that implements only
`^0.1.0` fails closed at `op env doctor`, not silently at deploy.

### 2. Author or vendor the pack artifact

The `.gtpack` archive lives wherever your distribution does (filesystem,
OCI registry, internal store) and is referenced by a `PackId` —
`Environment.packs[i].pack_ref`. Nothing in the env-pack registration
mechanism cares about the archive shape; the slot's runtime cares (e.g. a
`secrets` pack must export the host-side secrets interface). See the relevant
slot's runtime crate (`greentic-secrets`, `greentic-telemetry`, etc.) for the
contract a slot expects of its packs.

### 3. Implement `EnvPackHandler`

```rust
use greentic_deploy_spec::CapabilitySlot;
use semver::VersionReq;
use crate::env_packs::EnvPackHandler;
use crate::tool_check::ToolCheck;

#[derive(Debug)]
pub struct AcmeVaultHandler;

impl EnvPackHandler for AcmeVaultHandler {
    fn slot(&self) -> CapabilitySlot {
        CapabilitySlot::Secrets
    }

    fn descriptor_path(&self) -> &str {
        "acme.secrets.vault"
    }

    fn supported_versions(&self) -> VersionReq {
        "^0.4".parse().expect("valid VersionReq")
    }

    fn preflight(&self) -> Vec<ToolCheck> {
        // Handlers that shell out compose checks from src/tool_check.rs.
        // In-process handlers return Vec::new() (the trait default).
        vec![]
    }
}
```

Phase A handlers are metadata-only; the slot-behaviour body (open a vault
client, fetch a secret, emit a span) lands in Phase D. The trait is the
seam plug-ins implement when Phase D registers them.

### 4. Register the handler

```rust
let mut registry = greentic_deployer::env_packs::EnvPackRegistry::with_builtins();
registry.register(Box::new(AcmeVaultHandler))?;
```

`register` rejects a descriptor path already registered — a plug-in can't
silently shadow a built-in. Built-ins are loaded by `with_builtins()` (see
`src/env_packs/slot.rs::BUILTIN_HANDLERS`).

> Phase A note: the public registry plug-in surface is `EnvPackRegistry::register`,
> but the wiring from a `.gtpack`'s embedded handler binary into `with_builtins()`
> is a Phase D milestone. Today, in-tree handlers (the five `local` ones) ship
> as built-ins; out-of-tree handlers will register through the plug-in hook
> once that mechanism lands.

### 5. (Optional) Make it the default for `local`

If the new descriptor should replace one of the defaults the bootstrap
`local` env binds, add it to `LOCAL_DEFAULT_BINDINGS` in
`src/defaults.rs` and update the matching `LOCAL_<SLOT>_PACK` constant.
A unit test (`builtin_table_matches_default_bindings`) asserts the
built-in table stays in lock-step with the defaults — your change must
flow through both.

Skip this step if the new pack is an *additional* option an operator can
opt into, not the new floor.

### 6. Operator binds it on an env

Mutating verbs (`add`, `update`, `remove`, `rollback`) take their payload as
JSON through `--answers <file>` — the operator CLI is uniformly
schema-driven, not per-flag. `--schema` emits the input schema for a verb
without running it.

```bash
# Inspect the input schema for `add`
gtc op env-packs add --schema

# add.answers.json
# {
#   "environment_id": "demo",
#   "slot": "secrets",
#   "kind": "acme.secrets.vault@0.4.2",
#   "pack_ref": "oci://ghcr.io/acme/greentic-secrets-vault:0.4.2",
#   "answers_ref": "env-packs/secrets/answers.json"
# }
gtc op env-packs add --answers add.answers.json

# Replace an existing binding (bumps generation, stashes previous for rollback)
gtc op env-packs update --answers update.answers.json

# remove.answers.json
# { "environment_id": "demo", "slot": "secrets" }
gtc op env-packs remove   --answers remove.answers.json
gtc op env-packs rollback --answers rollback.answers.json

# `list` takes the env id positionally and emits no schema input
gtc op env-packs list demo
```

`EnvPackBindingPayload` (the `add`/`update` shape) and `EnvPackRemovePayload`
(the `remove`/`rollback` shape) are defined in `src/cli/env_packs.rs`.

Every mutation bumps `EnvPackBinding.generation` and stashes the prior
binding via `previous_binding_ref` so `rollback` can restore it without a
database.

### 7. Verify

```bash
gtc op env doctor demo       # registry resolution + slot consistency + version skew
gtc op env tool-check demo   # per-handler preflight() results
```

`doctor` reports `unknown_kinds` (no handler registered for that descriptor
path), `slot_mismatches` (binding pointed a slot at a handler for a different
slot), and `version_skew` (binding's pinned version not accepted by the
handler's `VersionReq`). `tool-check` returns each binding's
`EnvPackHandler::preflight()` output — handlers that shell out to `aws`,
`kubectl`, etc. populate this from the catalog in `src/tool_check.rs`.

## Path 2 — Adding a new capability slot

Reach for this only when no existing slot describes the *kind of service* you
need to bind per env. This is a deploy-spec schema bump and a coordinated
change across several crates.

### 1. Add the variant

In `crates/greentic-deploy-spec/src/capability_slot.rs`:

```rust
pub enum CapabilitySlot {
    Deployer,
    Secrets,
    // ... existing ...
    Messaging,
    AcmeWidget,   // ← new
}

impl CapabilitySlot {
    pub const ALL: &'static [CapabilitySlot] = &[
        // ... existing ...,
        CapabilitySlot::AcmeWidget,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            // ... existing ...,
            CapabilitySlot::AcmeWidget => "acme-widget",
        }
    }
}
```

### 2. Decide 1-per-env vs N-per-env

The default for `Environment.packs` is 1-per-slot — uniqueness is enforced
by `Environment::validate`. If your slot needs N entries (the way `Messaging`
does), it does **not** belong in `Environment.packs`; add a parallel
collection (`Environment.<slot>_endpoints: Vec<...>`) and document the
uniqueness invariants on the new entity. The `Messaging` slot is the
prototype.

### 3. Implement the first handler

Either as a built-in (in-tree, immortal) or via the plug-in `register` hook
(out-of-tree, opt-in). Built-ins land in `src/env_packs/slot.rs`:

```rust
pub const BUILTIN_HANDLERS: &[BuiltinHandler] = &[
    // ... existing ...,
    BuiltinHandler {
        slot: CapabilitySlot::AcmeWidget,
        descriptor_path: "greentic.acme-widget.in-memory",
        version_req: "^0.1.0",
    },
];
```

The `(slot, descriptor_path)` pair must also appear in
`src/defaults.rs::LOCAL_DEFAULT_BINDINGS` — the in-tree test
`builtin_table_matches_default_bindings` will fail your change otherwise.

### 4. Update `doctor`

`gtc op env doctor` enumerates `CapabilitySlot::ALL` to compute
`missing_slots`. No code change needed in `doctor` itself — extending the
enum and `ALL` is the contract — but be aware that every existing env now
reports the new slot as `missing` until it's bound. Decide whether to:

- Ship a migration that adds the default binding to existing envs
  (`src/cli/migrate.rs` is the place), or
- Document the new `missing_slots` entry as expected and require an
  explicit `op env-packs add`.

### 5. Bump and ship

The deploy-spec `SchemaVersion` lives next to `CapabilitySlot`. Bump it,
update the `schema_str()` helpers, and follow the binary-bifurcation rules
the workspace already enforces (see `/home/vampik/greenticai/CLAUDE.md` —
the canonical chain). Downstream consumers floor-pin to the new spec
version.

## Path 3 — Adding an extension (open, N-per-env)

> **In depth:** this is the summary. The full Path 3 walkthrough — the
> `ext://` grammar, the answers-blob layout, what resolves `ext://` today, and a
> worked example — lives in [`extensions.md`](extensions.md).

Use Path 3 when the capability is consumed by a **workload** (a bundle/flow
resolving it by name), not by core platform code linking a typed host
interface. There is **no schema bump** — an extension is a `PackDescriptor`
value plus a handler registration. The one-time enabling work (the `Extension`
`CapabilitySlot` variant and `Environment.extensions`) already shipped.

### 1. Author or vendor the pack and (optionally) implement a handler

Pick a descriptor path, e.g. `acme.oauth.auth0@1.0.0`. If the extension runs
preflight checks (e.g. shells out to a broker CLI) or you want `doctor` to
recognize it, implement `EnvPackHandler` with `slot() == CapabilitySlot::Extension`
and register it via `EnvPackRegistry::register` (same Phase D hook as Path 1).
Until a handler is registered, `doctor` reports the binding under `extensions`
as an `unknown_kind` — informational, not fatal.

### 2. Operator binds it on an env

```sh
# Inspect the input schema for `add` (no slot field; instance_id is optional)
gtc op extensions add --schema

# add.answers.json
# {
#   "environment_id": "demo",
#   "kind": "acme.oauth.auth0@1.0.0",
#   "pack_ref": "oci://ghcr.io/acme/greentic-oauth-auth0:1.0.0",
#   "instance_id": "primary",                 # omit for the single default instance
#   "answers_ref": "extensions/acme.oauth.auth0-primary/answers.json"
# }
gtc op extensions add --answers add.answers.json

# N instances of the SAME extension coexist — add a second with a distinct
# instance_id. A default (no instance_id) and named instances can also coexist.
gtc op extensions list demo
```

Identity is `(kind.path(), instance_id)` — version-independent. `update`,
`remove`, and `rollback` target a binding by that key (the `@<version>` in a
`remove`/`rollback` payload is ignored). Each mutation bumps `generation` and
stashes the previous binding for one-step `rollback`, exactly like `env-packs`.

`rollback` reverts the previous `update` only — it is **not** an undo for
`remove`. A `remove` is terminal: there is no binding left to roll back to, so
`rollback` after a `remove` returns *not found*. To restore a removed
extension, `add` it again. (Same contract as `env-packs`; multi-step history is
out of scope.)

### 3. Resolve it from a workload

A bundle/flow reaches the binding by name through `ext://<path>[/<instance>]`
(`ext://acme.oauth.auth0/primary`), which the runtime resolves to the binding's
config/answers blob. No typed host interface is auto-wired — the consuming
component reads config and does the rest. (Contrast a core slot, where the
runner links a `dyn Trait` directly.)

## CLI surface reference

All env-pack management goes through `gtc op env-packs <verb>`:

| Verb       | Purpose                                                                              |
| ---------- | ------------------------------------------------------------------------------------ |
| `add`      | Create a binding for an unbound slot. Fails if the slot is already bound (use `update`). |
| `update`   | Replace an existing binding; bumps `generation`; stashes the previous binding.       |
| `remove`   | Detach a slot. Subsequent reads via the runtime resolver fail closed.                |
| `rollback` | Restore the previous binding for a slot (one step back).                             |
| `list`     | Enumerate bindings for an env.                                                       |

Extension (Path 3) bindings are managed through the parallel
`gtc op extensions <verb>` noun (same verb set), keyed on
`(kind.path(), instance_id)` instead of a slot:

| Verb       | Purpose                                                                              |
| ---------- | ------------------------------------------------------------------------------------ |
| `add`      | Bind an extension. Fails if `(path, instance_id)` is already bound (use `update`).   |
| `update`   | Replace a binding by `(path, instance_id)`; bumps `generation`; stashes the previous. |
| `remove`   | Detach a binding by `(path, instance_id)`.                                           |
| `rollback` | Restore the previous binding for `(path, instance_id)` (one step back).              |
| `list`     | Enumerate extension bindings for an env.                                             |

Companion verbs on `gtc op env`:

| Verb         | Purpose                                                                            |
| ------------ | ---------------------------------------------------------------------------------- |
| `doctor`     | Static health: missing/unknown/slot-mismatched/version-skewed bindings.            |
| `tool-check` | Runtime health: each handler's `preflight()` result.                               |

Every verb honours `--schema` (emit the input schema, no side-effects) and
`--answers <path>` (non-interactive replay).

## Validation and safety nets

| Surface                                                            | What it catches                                                                                     |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| `EnvPackRegistry::resolve`                                         | Unknown descriptor path, unsupported version (`VersionUnsupported`).                                |
| `EnvPackRegistry::resolve_for_slot`                                | A binding pointing a slot at a handler that serves a different slot (`SlotMismatch`).               |
| `EnvPackRegistry::register`                                        | Two handlers claiming the same descriptor path (`DuplicateRegistration`).                           |
| `Environment::validate`                                            | Slot uniqueness across `Environment.packs` (1-per-slot invariant).                                  |
| `gtc op env doctor`                                                | Composite of all of the above + a "missing slots" report.                                           |
| `gtc op env tool-check`                                            | Each handler's `preflight()` — surfaces missing CLIs, expired auth, network reachability.           |
| `EnvPackBinding.generation` + `previous_binding_ref`               | Rollback to the immediately prior binding without a database.                                       |

## Pitfalls

- **The closed enum is the integrity boundary, not a limitation.** Don't
  reach for Path 2 to dodge writing a real handler — most asks fit Path 1.
- **`PackDescriptor.path()` is the registry key.** Two handlers with the
  same `descriptor_path()` reject each other at `register`. Plug-ins must
  pick a namespace they own.
- **Version skew is checked, not silently accepted.** Pinning `@9.9.9`
  against a handler that implements `^0.1.0` surfaces in `op env doctor` —
  but a binding's `kind` is loaded from disk, so updating the handler's
  `supported_versions()` doesn't retroactively heal old envs. Bump the
  handler's req before the operators upgrade their bindings, not after.
- **The 1-per-slot invariant applies to `Environment.packs`, not to the
  capability family in general.** If you need N services of the same kind
  per env, follow the `Messaging` pattern: a parallel collection with its
  own uniqueness invariants, **not** multiple entries in `Environment.packs`.
- **Built-in vs plug-in shadowing is rejected, not last-wins.**
  `register` returns `DuplicateRegistration` on a path conflict — there is
  no way for a plug-in to silently override a built-in.

## Worked examples

### Adding a Vault secrets backend (Path 1)

Slot exists (`Secrets`), no schema bump. New descriptor
`acme.secrets.vault@0.4.2`, handler implements `EnvPackHandler` for
`CapabilitySlot::Secrets`, registered through `EnvPackRegistry::register`.
Operator binds it with `gtc op env-packs update --env prod --slot secrets
--kind acme.secrets.vault@0.4.2 --pack-ref oci://.../vault:0.4.2`. The next
`op env doctor` reports the binding healthy; the next deploy reads secrets
through the Vault handler.

### Adding fast2flow as an env service (Path 2 or Path 3)

> **Apply the dividing rule first.** If fast2flow becomes an env-shared service
> that bundles call **by name** (`ext://...`), it is a **Path 3 extension** — no
> schema bump. Only if the **runner must wire a fast2flow router as a typed host
> interface** does it earn a **Path 2 core slot**. The Path 2 walkthrough below
> applies to the latter case.

**Today fast2flow is not an env-pack.** The workspace explainer
([`/home/vampik/greenticai/deploy_explained.md`](../../deploy_explained.md))
lists it as an *app-bundle* — the kind of workload that *runs on* an env,
not the kind of service the env *exposes*. Reconfirm that's the intent
before proceeding.

If the intent is to give every env a fast2flow service the bundles can call
into (rather than embedding fast2flow components inside each bundle), the
work is a Path 2 schema bump:

1. Add `CapabilitySlot::Fast2Flow` to `crates/greentic-deploy-spec`.
2. Pick cardinality: almost certainly 1-per-env (one chat→flow router for
   the env). Add `CapabilitySlot::Fast2Flow` to `Environment.packs`'
   uniqueness check.
3. Decide whether `local` ships a built-in (`greentic.fast2flow.embedded@0.1.0`
   maybe) or whether the slot stays unbound by default.
4. Implement at least one handler. The fast2flow library lives in
   `greentic-fast2flow` (`greentic-biz` org); the handler binds the env's
   runtime to that library's router.
5. The bundles' runtime resolver gains a `fast2flow://` lookup that
   resolves through `Environment.packs[Fast2Flow]`.

Pre-spec-bump alternative: keep fast2flow as an app-bundle and let bundles
that need it consume it via the existing inter-bundle plumbing. That avoids
the schema bump entirely and is the lower-risk path if "one fast2flow per
env" is a convenience, not a hard requirement.

### Adding OAuth as an env-pack (Path 2 or Path 3)

> **Apply the dividing rule first.** OAuth is borderline. If bundles only need
> per-env OAuth **config** (client registrations, redirect URIs, scopes) and
> reach it via `ext://oauth` while keeping their existing host imports, it is a
> **Path 3 extension**. Only if the **runner must wire an OAuth broker backend**
> the runtime links does it earn a **Path 2 core slot**. The Path 2 walkthrough
> below applies to the latter case.

The current `greentic-oauth` crate ships a broker + SDK; today its
configuration is consumed per-bundle through host imports, not bound as an
env-pack. If the goal is "one OAuth broker per env, all bundles share it"
(the natural shape — OAuth client registrations, redirect URIs, and refresh
tokens are env-scoped, not bundle-scoped), the work is Path 2:

1. Add `CapabilitySlot::OAuth` to `crates/greentic-deploy-spec`.
2. Cardinality: 1-per-env. One broker, many bundles consume.
3. Default for `local`: probably an embedded broker
   (`greentic.oauth.embedded@0.1.0`) wrapping `greentic-oauth`'s in-process
   mode.
4. Handlers for hosted brokers (`greentic.oauth.auth0@1.0.0`,
   `greentic.oauth.cognito@1.0.0`, …) register through the Phase D plug-in
   hook.
5. Bundles that today resolve OAuth config through their own host imports
   migrate to the env-pack resolver — same migration shape as the
   secrets/state backend.

If only a subset of envs need OAuth, leaving the slot unbound by default
(no `LOCAL_DEFAULT_BINDINGS` entry, `op env doctor` reports it `missing`
until explicitly bound) is the right shape.

## Reference

| Concern                                  | File                                                             |
| ---------------------------------------- | ---------------------------------------------------------------- |
| `CapabilitySlot` enum + `ALL`             | `crates/greentic-deploy-spec/src/capability_slot.rs`             |
| `PackDescriptor` parsing                  | `crates/greentic-deploy-spec/src/capability_slot.rs`             |
| `EnvPackBinding` shape                    | `crates/greentic-deploy-spec/src/environment.rs`                 |
| `Environment` + `pack_for_slot`           | `crates/greentic-deploy-spec/src/environment.rs`                 |
| `EnvPackHandler` trait                    | `src/env_packs/slot.rs`                                          |
| Built-in handler table                    | `src/env_packs/slot.rs::BUILTIN_HANDLERS`                        |
| Registry                                  | `src/env_packs/registry.rs::EnvPackRegistry`                     |
| `LOCAL_DEFAULT_BINDINGS`                  | `src/defaults.rs`                                                |
| CLI: `gtc op env-packs <verb>`            | `src/cli/env_packs.rs`                                           |
| CLI: `gtc op env doctor` / `tool-check`   | `src/cli/env.rs::doctor`, `src/cli/env.rs::tool_check`           |
| Workspace explainer                       | `/home/vampik/greenticai/deploy_explained.md`                    |
| Companion doc (orthogonal pack concept)   | [`deployment-packs.md`](deployment-packs.md)                     |
