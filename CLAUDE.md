# CLAUDE.md

Agent orientation for `greentic-deployer`. Read this before changing anything
here; the repo contains **two unrelated deployment architectures** and picking
the wrong one is the most common way to waste a session.

## ⚠ Two architectures live in this repo

| | Legacy: **IaC rendering** | Current: **env-packs** |
|---|---|---|
| Entry | `src/apply.rs`, `src/providers/{aws,gcp,azure,k8s,local}.rs` | `src/env_packs/`, driven by `src/cli/` |
| CLI | `greentic-deployer plan/apply/destroy` | `greentic-deployer op env …` |
| What it does | Renders Terraform / Bicep / Deployment-Manager **files for you to apply** | **Calls cloud APIs directly** and owns an environment store |
| Talks to cloud | Shells out to `terraform`/`tofu`, `aws`, `az` | Typed SDKs (GCP) / CLI (AWS, Azure) |
| State | None | `<store-root>/<env-id>/…` |

**`.codex/repo_overview.md` documents only the legacy layer.** It has zero
mentions of `env_packs`, `cloudrun`, or `op env` — and `.codex/global_rules.md`
tells agents to regenerate it every PR, so it is a *generated artifact*, not a
place to record durable knowledge. Do not trust it for anything under
`src/env_packs/`, and do not add lasting notes to it. Put them here.

If a task says "deploy", "Cloud Run", "environment", "revision", or "traffic
split", you want **env-packs**.

## Build & Test

```bash
bash ci/local_check.sh          # the full gate — run before every PR
```

It runs, in order: `cargo fmt --all -- --check` → `cargo clippy --all-targets
--all-features -- -D warnings` → two `internal-tools` fixture binaries →
`cargo test --all` → `cargo doc --no-deps` → **`cargo build --no-default-features`**.

That last step is the one that catches people:

> **All new code must be `cfg`-gated behind its feature.** The final gate builds
> with *no* features, so anything referencing a feature-gated dependency without
> a `#[cfg(feature = "…")]` fails CI even though the default build is green.

Scope commands to this package in the shared workspace — `cargo fmt --all` and
`cargo clippy` without `-p` reach into sibling repos through path deps and will
reformat someone else's uncommitted work:

```bash
cargo fmt -p greentic-deployer
cargo clippy -p greentic-deployer --all-targets --all-features -- -D warnings
cargo test -p greentic-deployer --no-fail-fast
```

## Features

`default = bundle-upload-aws, runtime-secrets-aws, creds-aws, deploy-aws-ecs,
creds-gcp, deploy-gcp-cloudrun, k8s-client`

Each cloud has a **two-tier** split, and the distinction is load-bearing:

| Tier | Example | Pulls SDK deps? | Contains |
|---|---|---|---|
| `creds-<cloud>` | `creds-gcp` | no | credential scaffold, bootstrap rendering, the env-pack handler |
| `deploy-<cloud>-<svc>` | `deploy-gcp-cloudrun` | **yes** (`google-cloud-*`) | the real target that makes live API calls |

So `--no-default-features --features creds-gcp` must still compile with no
`google-cloud-*` dependency at all. When you add a live-deploy code path, gate it
on the `deploy-*` feature, not the `creds-*` one.

A binary built without `deploy-gcp-cloudrun` still **binds** the Cloud Run
deployer kind and plans a perfectly green deploy — it just cannot execute it.
Only `op env doctor` resolves the binding against the handler registry and
reports it under `unknown_kinds`. See `docs/cloudrun-deployment.md` §3.

## Env-packs

An env-pack binds a **capability slot** on an environment. Deployer slots:

| Descriptor | Module | Live deploy? |
|---|---|---|
| `greentic.deployer.gcp-cloudrun` | `src/env_packs/gcp_cloudrun/` | yes — typed Google SDK |
| `greentic.deployer.aws-ecs` | `src/env_packs/aws/` | yes |
| `greentic.deployer.k8s` | `src/env_packs/k8s/` | yes — `kube` client |
| `greentic.deployer.local-process` | `src/env_packs/local_process/` | local only |

Shared plumbing: `registry.rs` (descriptor → handler), `slot.rs`
(`EnvPackHandler`), `deployer/` (the `Deployer` trait every deployer implements),
`render.rs`.

For the Cloud Run subsystem specifically — module map, the seam, the invariants
a change must not break, and how to test without touching GCP — read
**[`docs/cloudrun-internals.md`](docs/cloudrun-internals.md)**.

## CLI shape

```
greentic-deployer op [GLOBAL FLAGS] <noun> <verb> [VERB FLAGS]
```

**Global flags go before the noun**, not after the verb. This is the single most
common malformed command:

```bash
# right
greentic-deployer op --store-root ./state --answers env.json env up --yes
# wrong — --answers is not a verb flag
greentic-deployer op env up --answers env.json --yes
```

Useful surfaces when you need ground truth rather than a guess:

- `op env apply --schema` — dumps the `greentic.env-manifest.v1` JSON Schema.
  Authoritative for manifest fields. (Known stub gap: it omits `packs[].answers`,
  which every real manifest uses.)
- `op env doctor <env>` — resolves bindings against the registry; the only verb
  that reports a deployer kind this binary cannot execute.
- `op env tool-check` — per-binding external-tool preflight.

## Which binary?

- **`greentic-deployer`** — this crate. On the develop lane it publishes as
  **`greentic-deployer-dev`** (binary bifurcation), so `cargo binstall
  greentic-deployer-dev` gets the nightly.
- **`gtc op …`** delegates to `greentic-operator`, a **different crate on its own
  release cadence**. It inherits this crate's default features, so new deployers
  ride along automatically — but only once a release carries them. A stable `gtc`
  can lag this repo by an entire capability.
- `--version` prints `greentic-deployer 1.2.0-dev.0` for *every* nightly; the
  build identity lives only in the crates.io version. **A stale `-dev` binary is
  indistinguishable from a current one.** Re-binstall when behaviour surprises you.

## `bundle-upload upload oci://…` pushes monolithically, and must keep doing so

Artifact Registry accepts a blob-upload `POST` and the FIRST `PATCH`, hands back
an upload location of a different shape (`/v2/<project>/<repo>/pkg/blobs/…`),
and answers a SECOND `PATCH` with `405 Method Not Allowed` — that location is
finished with `PUT` and takes no further chunk. `oci-client`'s default blob push
is chunked at 4 MiB, so **every blob over 4 MiB failed and every smaller one
succeeded**, with an error naming only a `405`. Nothing in the message mentions
size, which is why the lane read as broken rather than as size-dependent; and
because a `.gtbundle` under 4 MiB is common, it looked like it worked.

`oci-client`'s own monolithic fallback does not rescue it: `push_blob` retries
monolithically only on `SpecViolationError`, which `extract_location_header`
raises solely for an unexpected *success* status. A clean `405` becomes
`ServerError { code: 405 }` and is returned verbatim.

`bundle_upload::oci_pusher::MonolithicRegistryPusher` is the fix — an
`oci_client::Client` with `use_monolithic_push: true`, i.e. the spec's other
blob-upload flow (`POST` then one `PUT`). It branches on nothing: no host
sniffing, no `Location`-shape heuristic. **Do not swap this path back to
`DefaultRegistryClient`** (which offers no way to set that flag from outside)
without re-testing a bundle over 4 MiB against a real Artifact Registry.
`oci_pusher`'s tests drive a stub that reproduces both AR behaviours, and one of
them pins that `DefaultRegistryClient` still fails there.

Verified live on 2026-09-24: an 8,572,928-byte bundle pushed to
`asia-southeast1-docker.pkg.dev` and pulled back byte-identical.

## Testing without a cloud account

Every deployer has a fake. Do not reach for a live account to test logic:

- `InMemoryCloudRun` (`gcp_cloudrun/deploy_target.rs`) — an in-memory fake
  implementing the full `CloudRunTarget` seam.
- `UnconfiguredCloudRunTarget` — the default; every verb fails honestly rather
  than silently no-op'ing.
- Request-building and response-parsing are pure free functions (`build_*`,
  `*_from`, `classify_*`) so they unit-test without any client.

The live E2E is opt-in and **bills a real project**:

```bash
GREENTIC_GCP_E2E=1 GTC_GCP_E2E_PROJECT=… GTC_GCP_E2E_REGION=… \
  cargo test -p greentic-deployer --test gcp_cloudrun_e2e
```

The gate is **exactly `1`** — unset, `0`, `true`, or anything else skips.
Deliberately stricter than the K8s E2E's mere-presence check, so the common
"disable it" reflex `GREENTIC_GCP_E2E=0` cannot arm a run that bills a project.
Arming it while a `GTC_GCP_E2E_*` scope var is missing is a hard failure naming
the exact var, not an opaque GCP error three calls later.

## Conventions

- **Edition 2024.** Core crates `1.1.x` on `main`, `1.2.0-dev.N` on `develop`.
- **Base PRs on `develop`.** `main` is the stable lane.
- **Fail closed.** A missing credential, an unreadable secret, an unknown pack
  kind — every one of these is an error, never a silent fallback to a broader
  identity or a no-op. Preserve this when editing; it is the repo's main safety
  property.
- **`cargo update` once per repo per session**, on the first Rust-touching PR
  only, and the lockfile lands in the *same* PR. Skip entirely for doc-only work.
- Cross-repo dependencies resolve from crates.io, not path deps. Local `path =`
  overrides are for development only.

## Docs map

| File | Audience | Covers |
|---|---|---|
| `docs/cloudrun-deployment.md` | operators | how to deploy to Cloud Run |
| `docs/cloudrun-internals.md` | agents / contributors | how the Cloud Run deployer is built |
| `docs/k8s-deployment.md` | operators | the declarative sibling path |
| `docs/env-packs.md` | contributors | authoring an env-pack |
| `docs/deployment-packs.md` | contributors | the legacy deployment-pack contract |
| `examples/cloudrun-demo/` | everyone | a runnable, live-verified walkthrough |
| `docs/superpowers/` | historical | design specs and plans; **may be superseded** |

## Parent workspace

This repo is one of ~85 checked out side-by-side under `/home/vampik/greenticai`.
The root `CLAUDE.md` there carries ecosystem-wide conventions (release lanes, the
manifest, the dep graph). `greentic-bundle` ↔ `greentic-deployer` form a
dependency cycle via the `greentic-deploy-spec` crate — plan their builds
together, not in strict tier order.
