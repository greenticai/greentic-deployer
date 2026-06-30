# Extension Authoring Guide

How to add a new **extension** — an open-namespace, N-per-env capability a
*workload* (a bundle or flow) resolves **by name** at runtime, rather than one
core platform code links as a typed host interface. This is the deep-dive for
**Path 3** in [`env-packs.md`](env-packs.md); read the dividing rule there first
if you are not sure whether you want an extension or a core slot.

## When is it an extension?

The one question that decides it (full decision tree in
[`env-packs.md`](env-packs.md#decision-which-path-are-you-on)):

> *Who consumes the capability?*
>
> - **Core code** (deployer / start / operator / runner) calls
>   `pack_for_slot(X)` and links a **typed host interface** (`dyn
>   SecretsManager`, `dyn StateHost`, …). → core slot (Path 1/2), closed enum,
>   1-per-env.
> - **A workload** resolves the capability **dynamically by name**
>   (`ext://<path>[/<instance>]`) and reads its config/answers — no typed
>   interface wired. → **extension (Path 3)**, open namespace, N-per-env, no
>   schema bump per family.

Config-shaped or naturally N-per-env capabilities a bundle reaches by name are
extensions. Per-env OAuth client config a bundle reads (client id, redirect
URI, scopes), a per-env feature catalog, a per-tenant connector profile — these
are extensions. A secrets backend the runner links as `dyn SecretsManager` is
**not**; that is a core slot.

| | Core slot (`Environment.packs`) | Extension (`Environment.extensions`) |
| --- | --- | --- |
| Slot family | `CapabilitySlot` — **closed enum** | always `CapabilitySlot::Extension` |
| Cardinality | 1 per slot per env | **N per env** |
| Identity | `slot` | `(kind.path(), instance_id)` |
| Adding a new family | deploy-spec schema bump (Path 2) | **never** — a descriptor value, no schema change |
| Consumed by | core code via `pack_for_slot` + a typed `dyn Trait` | a workload via `ext://<path>[/<instance>]` |
| Managed with | `gtc op env-packs <verb>` | `gtc op extensions <verb>` |
| Doctor | `missing_slots` if unbound | open namespace — never "missing" |

## Model in one diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│  Environment (greentic.environment.v1)                                 │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │ extensions: Vec<ExtensionBinding>   (N per env)                  │   │
│  │   ├─ kind:        PackDescriptor   `<ns>.<id>@<semver>`          │   │
│  │   ├─ pack_ref:    PackId           (where the artifact is)       │   │
│  │   ├─ instance_id: Option<String>   (None ⇒ the default instance) │   │
│  │   ├─ answers_ref: Option<Path>     (env-relative config blob)    │   │
│  │   ├─ generation:  u64              (bumped on every mutation)    │   │
│  │   └─ previous_binding_ref          (one-step rollback)           │   │
│  └────────────────────────────────────────────────────────────────┘   │
│        identity = (kind.path(), instance_id)   ← version-independent    │
│                          ↑ resolved by name                            │
│  workload config:  "oauth": "ext://acme.oauth.auth0/primary"           │
│                          ↓ at ingress config-injection                 │
│  becomes the bound binding's answers blob:  {"client_id": …, …}        │
└──────────────────────────────────────────────────────────────────────┘
```

`ExtensionBinding` carries **no `slot` field** — its slot is always
`CapabilitySlot::Extension`. Bindings live in `Environment.extensions`, never in
`Environment.packs`, so the 1-per-slot rule does not apply. Two bindings collide
only when they share both the descriptor path **and** the instance selector; a
`None` (default) instance and any number of `Some(..)` named instances on the
same path coexist.

### The `ext://` reference grammar

A workload names an extension with an `ext://` URI. The authoritative grammar
lives in `ExtensionRef` (`crates/greentic-deploy-spec/src/refs.rs`):

```
ext://<descriptor-path>[/<instance-id>]
```

- **No env segment.** Unlike `secret://<env>/…` and `runtime://<env>/…`, an
  extension ref carries no env id — the env is implicit in the resolving
  workload's context.
- **`<descriptor-path>`** is the `PackDescriptor` *path* — version-independent.
  Use `ext://acme.oauth.auth0`, **not** `ext://acme.oauth.auth0@1.0.0`; the
  binding owns the concrete version. The path must contain a `.` and is limited
  to lowercase ASCII, digits, `-`, and `.`.
- **`<instance-id>`** (optional) selects one of N instances of the same type.
  Charset is lowercase ASCII, digits, and `-` — it deliberately excludes `.`
  and `/`, so an instance id can never be mistaken for a path segment or inject
  a second path component. The body is split on the **first** `/` only, so a
  ref is always exactly two segments.

`ext://acme.oauth.auth0` selects the default (unnamed) instance;
`ext://acme.oauth.auth0/primary` selects the named one. Lookup is
`Environment::extension_for_ref` → match on `(path, instance_id)`.

## Adding an extension, step by step

There is **no schema bump and no closed-enum touch** — the `Extension`
`CapabilitySlot` variant and `Environment.extensions` already shipped. Adding
an extension is a descriptor value, an operator binding, and a config blob.

### 1. Pick a descriptor path and author/vendor the pack

Format: `<namespace>.<id>@<semver>` — lowercase ASCII, digits, `-`, `.`, exactly
one `@`, valid SemVer after it. The path before `@` is the identity key (the
version is independent — see below). Examples:

- `acme.oauth.auth0@1.0.0`
- `acme.catalog.features@0.3.1`

The `.gtpack` artifact lives wherever your distribution does (filesystem, OCI
registry, internal store) and is referenced by a `PackId` —
`ExtensionBinding.pack_ref`. Nothing in the binding mechanism inspects the
archive shape; the *consuming workload* decides what it expects of the pack.

### 2. (Optional) Implement and register a handler

You only need a handler if you want `doctor` to recognize the extension or run
preflight checks (e.g. shell out to a broker CLI). Implement `EnvPackHandler`
with `slot() == CapabilitySlot::Extension` and register it via
`EnvPackRegistry::register` — the same Phase D plug-in hook as Path 1 (see
[`env-packs.md` §3–4](env-packs.md#3-implement-envpackhandler)).

Until a handler is registered, `doctor` reports the binding under `extensions`
as an `unknown_kind`. This is **informational, not fatal** — the open namespace
is the point. Most config-only extensions never register a handler.

### 3. Bind it on an env

Extension bindings are managed through `gtc op extensions <verb>`. Mutating
verbs take their payload as JSON through `--answers <file>`; `--schema` emits
the input schema for a verb without running it.

```sh
# Inspect the input schema for `add` (no `slot` field; instance_id optional)
gtc op extensions add --schema

# add.answers.json — ExtensionBindingPayload
# {
#   "environment_id": "demo",
#   "kind": "acme.oauth.auth0@1.0.0",
#   "pack_ref": "oci://ghcr.io/acme/greentic-oauth-auth0:1.0.0",
#   "instance_id": "primary",                                  # omit for the default instance
#   "answers_ref": "extensions/acme.oauth.auth0-primary/answers.json"
# }
gtc op extensions add --answers add.answers.json

# N instances of the SAME extension coexist — add another with a distinct
# instance_id. A default (no instance_id) and named instances also coexist.
gtc op extensions add --answers add-secondary.answers.json

# list takes the env id positionally and emits no schema input
gtc op extensions list demo
```

`add` fails with a conflict if `(path, instance_id)` is already bound — use
`update`. The `ExtensionBindingPayload` and `ExtensionRemovePayload` shapes are
defined in `src/cli/extensions.rs`.

### 4. Provide the answers blob

`op extensions add` records `answers_ref` **verbatim** — nothing writes or
validates the file. **You provide it.** The path is resolved relative to the
env directory (`<store-root>/<env-id>`); the conventional layout is
`extensions/<path>[-<instance>]/answers.json`. For the binding above:

```sh
# <store-root>/demo/extensions/acme.oauth.auth0-primary/answers.json
{
  "client_id": "abc123",
  "redirect_uri": "https://demo.example/callback",
  "scopes": ["openid", "profile"]
}
```

A binding with **no** `answers_ref` resolves to an empty object `{}` (bound, but
carries no config). A binding whose `answers_ref` points at a missing or invalid
file **fails closed** at resolution time — it does not silently pass the raw
`ext://` string through to the component.

### 5. Reference it from a workload

A workload names the binding by putting an `ext://` string where a config value
goes. For example, a messaging provider's config:

```yaml
# (provider config, authored in the bundle/flow)
oauth: "ext://acme.oauth.auth0/primary"
```

At provider config-injection time the runtime replaces that string with the
bound extension's resolved answers blob — the exact analogue of `secret://`
resolution that sits beside it. The component reads ordinary config and does the
rest; **no typed host interface is auto-wired.** (Contrast a core slot, where
the runner links a `dyn Trait` directly.)

### 6. Verify

```sh
gtc op extensions list demo     # the bound extensions and their generations
gtc op env doctor demo          # registry resolution; extensions reported in their own block
```

`doctor`'s `extensions` block reports `count`, plus `unknown_kinds` (no handler
registered — expected for config-only extensions), `slot_mismatches` (a core
pack mis-bound as an extension), and `version_skew`. It never reports an
extension as "missing" — the namespace is open by design.

## Runtime resolution: what is wired today

Be precise about where `ext://` actually resolves — the seam is real but
narrow today, with Phase D work outstanding.

| Path | `ext://` resolved? |
| --- | --- |
| **Legacy messaging-provider config injection** (greentic-start `build_injected_config`) | ✅ Yes — provider config values that are `ext://` strings are replaced with the bound binding's answers blob, fail-closed. |
| **New-model provider path** (revision-routed serving → `invoke_provider_for_revision`) | ❌ No config injection at all — neither `secret://` nor `ext://`. Wired when Phase D config injection lands. |
| **Flow-node config** | ❌ Bypasses greentic-start entirely (read by the runner engine). Flow-component `ext://` is a future runner-side change. |

The resolver (`greentic-start/src/extension_resolver.rs`) runs at ingress
config-injection: it pre-scans for any `ext://` value (so the env store is only
read when one is actually present), loads the active `Environment`, and rewrites
each `ext://` value to its resolved blob, memoizing per raw ref so a ref under
several keys reads the blob from disk once. Resolution is **fail-closed**: an
unparseable ref, an unbound ref (e.g. after `op extensions remove`), or an
unreadable/invalid answers blob fails the ingress rather than reaching the
component as opaque config.

## Lifecycle: generation and rollback

Every mutation bumps `ExtensionBinding.generation` and stashes the prior binding
via `previous_binding_ref`, so `rollback` restores the immediately prior state
without a database — identical machinery to `env-packs`.

```sh
gtc op extensions update   --answers update.answers.json    # bumps generation, stashes previous
gtc op extensions rollback --answers rollback.answers.json  # restore the pre-update binding
gtc op extensions remove   --answers remove.answers.json    # detach; subsequent ext:// reads fail closed
```

`remove`/`rollback` payloads (`ExtensionRemovePayload`) identify a binding by
`(kind.path(), instance_id)` — the `@<version>` in the payload's `kind` is
**ignored** for matching, because the path is the version-independent key.

`rollback` reverts the previous `update` only — it is **not** an undo for
`remove`. A `remove` is terminal: there is no binding left, so `rollback` after
a `remove` returns *not found*. To restore a removed extension, `add` it again.
(Same contract as `env-packs`; multi-step history is out of scope.)

## CLI surface reference

All extension management goes through `gtc op extensions <verb>`:

| Verb | Purpose |
| --- | --- |
| `add` | Bind an extension. Fails if `(path, instance_id)` is already bound (use `update`). |
| `update` | Replace a binding by `(path, instance_id)`; bumps `generation`; stashes the previous. |
| `remove` | Detach a binding by `(path, instance_id)`. Subsequent `ext://` reads fail closed. |
| `rollback` | Restore the previous binding for `(path, instance_id)` (one step back). |
| `list` | Enumerate extension bindings for an env (positional `<ENV_ID>`). |

Every mutating verb honours `--schema` (emit the input schema, no side-effects)
and `--answers <path>` (non-interactive replay). `list` takes the env id
positionally and emits no input schema.

Payload shapes (`src/cli/extensions.rs`):

| Payload | Used by | Fields |
| --- | --- | --- |
| `ExtensionBindingPayload` | `add`, `update` | `environment_id`, `kind`, `pack_ref` (required); `instance_id`, `answers_ref` (optional) |
| `ExtensionRemovePayload` | `remove`, `rollback` | `environment_id`, `kind` (required); `instance_id` (optional). `@<version>` in `kind` ignored. |

## Validation and safety nets

| Surface | What it catches |
| --- | --- |
| `ExtensionRef::try_new` | Missing `ext://` scheme, empty/dot-less path, illegal path/instance charset. |
| `ExtensionBinding::validate` | Illegal instance-id charset on a stored binding. |
| `Environment::validate` | `(kind.path(), instance_id)` uniqueness across `Environment.extensions` (`DuplicateExtension`). |
| `op extensions add` | Conflict when `(path, instance_id)` is already bound (use `update`). |
| `op extensions remove`/`rollback` | `NotFound` when the `(path, instance_id)` key is not bound. |
| `gtc op env doctor` | Per-extension registry resolution: `unknown_kinds`, `slot_mismatches`, `version_skew` (open namespace ⇒ no `missing`). |
| Runtime resolver (greentic-start) | Fail-closed on unparseable / unbound / unreadable refs at config-injection. |
| `generation` + `previous_binding_ref` | One-step rollback without a database. |

## Pitfalls

- **An `ext://` ref carries no version and no env segment.** Use
  `ext://acme.oauth.auth0/primary`, not `ext://demo/acme.oauth.auth0@1.0.0`.
  The path is the version-independent key; the binding owns the version; the env
  is implicit.
- **`None` and named instances on one path coexist; two `None` collide.**
  Identity is `(path, instance_id)`. A default instance plus N named instances
  is the supported shape; a second default on the same path is a conflict.
- **The answers blob is operator-provided.** `add` only records `answers_ref` —
  it never writes or validates the file. A missing or malformed blob fails
  closed at ingress, not at `add`. Write the file before the workload runs.
- **`ext://` does not resolve everywhere yet.** Today it resolves only in the
  legacy messaging-provider config path. The new-model provider path and
  flow-node config do not resolve it (see *Runtime resolution* above). Don't
  assume an `ext://` placed in a flow node will be substituted.
- **`rollback` is not an undo for `remove`.** It reverts the last `update`.
  After a `remove`, re-`add` to restore.
- **`doctor` `unknown_kind` is expected for config-only extensions.** A handler
  is optional; the unknown-kind line is informational, not a failure.

## Worked example: a per-env OAuth config extension

A bundle needs per-env OAuth client config (client id, redirect URI, scopes) and
reads it **by name** while keeping its existing host imports. By the dividing
rule that is a **Path 3 extension**, not a core slot — no schema bump.

```sh
# 1. add.answers.json
cat > add.answers.json <<'JSON'
{
  "environment_id": "demo",
  "kind": "acme.oauth.auth0@1.0.0",
  "pack_ref": "oci://ghcr.io/acme/greentic-oauth-auth0:1.0.0",
  "instance_id": "primary",
  "answers_ref": "extensions/acme.oauth.auth0-primary/answers.json"
}
JSON
gtc op extensions add --answers add.answers.json

# 2. Provide the answers blob the binding points at.
mkdir -p "$GREENTIC_STORE/demo/extensions/acme.oauth.auth0-primary"
cat > "$GREENTIC_STORE/demo/extensions/acme.oauth.auth0-primary/answers.json" <<'JSON'
{ "client_id": "abc123", "redirect_uri": "https://demo.example/callback", "scopes": ["openid", "profile"] }
JSON

# 3. In the bundle's provider config, reference it by name:
#      oauth: "ext://acme.oauth.auth0/primary"
#    At ingress config-injection the runtime substitutes the blob above.

# 4. Verify.
gtc op extensions list demo     # shows acme.oauth.auth0@1.0.0 / primary, generation 0
gtc op env doctor demo          # extensions block: count 1, unknown_kind (no handler — expected)
```

If a second env needs a different Auth0 tenant, bind a second instance
(`"instance_id": "secondary"`) and reference `ext://acme.oauth.auth0/secondary`.
No schema change, no new slot — that is the long tail Path 3 absorbs.

## Reference

| Concern | File |
| --- | --- |
| `ExtensionBinding` shape + `extension_for_ref` | `crates/greentic-deploy-spec/src/environment.rs` |
| `ExtensionRef` grammar + instance-id charset | `crates/greentic-deploy-spec/src/refs.rs` |
| `PackDescriptor` / `PackId` | `crates/greentic-deploy-spec/src/capability_slot.rs` |
| CLI: `gtc op extensions <verb>` | `src/cli/extensions.rs` |
| Doctor `extensions` block | `src/cli/env.rs` |
| Runtime `ext://` resolver | `greentic-start/src/extension_resolver.rs` |
| Companion: core slots (Path 1/2) | [`env-packs.md`](env-packs.md) |
| Design rationale | Extension-slot design spec (`docs/extension-slot-design.md`, currently in greentic-deployer PR #238 — not yet on `develop`) |
