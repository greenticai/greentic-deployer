# Kubernetes Deployment Guide

How a Greentic digital worker is deployed to, and served from, a Kubernetes
cluster using the **environment-pack** model of `greentic-deployer` (the
`op env …` CLI surface). Covers the mental model, the rendered objects, the
declarative and imperative authoring paths, deploying to a brand-new real
cluster, a configuration reference, how to reach the worker, the known
production gaps, and troubleshooting.

> **Audience.** Written for both humans and LLM agents. Section headings are
> stable anchors; commands are copy-paste runnable; every claim about rendered
> objects or config keys is sourced from `src/env_packs/k8s/`. Where a behaviour
> is a known limitation it is called out explicitly rather than glossed over.

> **Scope.** This is the **env-pack** K8s path (`op env apply` / `op env
> reconcile` against the `greentic.deployer.k8s@1.0.0` env-pack). It is distinct
> from the lower-level **deployment-pack** adapters in the repo README
> (`k8s-raw`, `helm`, `operator`, `juju-k8s`), which materialize handoff
> manifests/scripts from a provider pack and do not manage an environment store.
> Use this guide when you want a runtime to **pull a bundle, serve it, and route
> traffic** on K8s. Use the deployment-pack adapters when you want rendered
> manifests to hand to your own GitOps pipeline.

---

## 1. Mental model — two independent axes

The single most important thing to internalize: **the cluster and the
environment id are two independent axes.** They are frequently conflated; they
are not the same thing.

| Axis | What it decides | How you set it |
|------|-----------------|----------------|
| **Cluster locality** | *Which* Kubernetes cluster the objects land in (kind, EKS, GKE, AKS, k3s, on-prem). | The kubeconfig **context** (`kubeconfig_context` deployer answer, or the current context). The deployer is cluster-agnostic — nothing is kind-specific. |
| **Environment id** | The logical environment name (`local`, `prod`, `staging`), which drives the **namespace** (`gtc-<id>`) and the store partition. | `environment.id` in the env-manifest, or `op env create <id>`. |

A local store is **single-operator**: its authorization boundary is OS
filesystem ownership, so **named environments are first-class** — you may keep
the id `local` while targeting a remote production cluster, or give it a real
name like `prod`. A *shared, multi-operator* control plane (an operator-store
server with RBAC) is a separate, still-future effort; until then each operator's
named environments live in their own local store.

### The store vs. the cluster

The deployer separates **authoring** from **applying**:

```
   author (writes the STORE)              apply (writes the CLUSTER)
   ┌─────────────────────────┐            ┌─────────────────────────┐
   │ op env apply --answers  │  ───────▶  │ op env reconcile <id>   │
   │ op env create / deploy  │   store    │ op env apply-revision   │
   │ op env-packs add …      │            │                         │
   └─────────────────────────┘            └─────────────────────────┘
        local FS store                          kube API server
   <store-root>/<env-id>/…                  namespace gtc-<env-id>
```

- **`op env apply` / `op deploy` / `op env-packs add`** mutate the **store**
  (the desired state). They never touch the cluster.
- **`op env reconcile <id>`** renders the desired state to manifests and pushes
  them onto the **live cluster** (and prunes workers for revisions no longer
  present). `op env apply-revision` is the surgical, single-revision counterpart.

There is **no `--reconcile` flag on apply** — the two steps are deliberately
separate so that authoring is offline/dry-runnable and applying is an explicit,
auditable act against a cluster.

---

## 2. What gets rendered onto the cluster

`op env reconcile <id>` renders a fixed set of objects into namespace
`gtc-<env-id>`. From a webchat+Telegram env this is **15 objects**:

| Kind | Count | Name(s) / purpose |
|------|-------|-------------------|
| `Namespace` | 1 | `gtc-<env-id>` (see [namespace derivation](#namespace-derivation)). |
| `Deployment` | 2 | `gtc-router` (ingress routing, HA — ≥2 replicas) + one `gtc-worker-<revision>` per active revision (runs the bundle). |
| `Service` | 2 | `ClusterIP` on port **8080**, one for the router and one per worker. |
| `ConfigMap` | 2 | `gtc-runtime-config` (projected runtime config) + `gtc-env-store` (`environment.json`). |
| `Secret` | 1 | `gtc-dev-secrets` — base64 of the operator dev-store, rendered only when the env binds a secrets pack (see [secrets](#5-secrets--the-dev-store-bridge)). `optional: true`. |
| `NetworkPolicy` | 5 | Default-deny + scoped allow rules (e.g. `gtc-allow-worker-egress`, rendered when a routed revision has a `bundle_source_uri`). |
| `PodDisruptionBudget` | 1 | Keeps the router available during voluntary disruptions. |

Key facts about the rendered topology:

- **Services are `ClusterIP` on port 8080.** The deployer renders **no Ingress
  and no LoadBalancer** — external exposure is bring-your-own (see
  [§7](#7-reaching-the-worker)).
- **No `imagePullPolicy` is set.** A non-digest tag (e.g. `:develop`) therefore
  defaults to `IfNotPresent`, and a warm node can serve a **stale** cached
  layer. Pin `runtime_image` to a digest for deterministic pulls in production.
- **The worker pulls its bundle over OCI at boot.** Reconcile records a
  `bundle_source_uri`; the worker (greentic-start) fetches the `.gtbundle` from
  the registry, re-verifies it against the recorded `bundle_digest`
  (two-point integrity), materializes it, and serves the revision.
- **Pod security:** distroless image, runs as uid `65532` with
  `readOnlyRootFilesystem: true`; `HOME` (`/var/greentic`) is a writable
  `emptyDir`.

### Namespace derivation

`namespace_for_env(env_id)` (`src/env_packs/k8s/manifests.rs`):

- **Clean ids** (lowercase `[a-z0-9-]`, no leading/trailing `-`, and
  `gtc-<id>` ≤ 63 chars) → `gtc-<id>` verbatim. `local` → `gtc-local`,
  `prod` → `gtc-prod`.
- **Ids requiring lossy sanitization** (uppercase, `.`, `_`) or exceeding the
  RFC 1123 63-char limit → a collision-proof hash suffix:
  `gtc-<sanitized-prefix>-<hash8>`. Distinct ids that sanitize identically still
  get unique namespaces.

---

## 3. Prerequisites

- **`kubectl`** with a working context for the target cluster
  (`kubectl config get-contexts`).
- **A built deployer binary** (or the `gtc op` router that embeds the deployer
  library). Build from source with **default features** — the `k8s-client`
  feature is default-on and required by `reconcile`:
  ```bash
  cargo build -p greentic-deployer --bin greentic-deployer
  # binary at target/debug/greentic-deployer; invoke `… op …`
  ```
  A stale binary built `--no-default-features` will fail reconcile with
  `conflict: this build was compiled without the k8s-client feature`.
- **Cluster internet egress** — the worker pulls the runtime image and the
  bundle from public `ghcr.io` at boot. For private registries see
  [§9](#9-known-gaps--production-caveats).
- **A runtime image.** The default is
  `ghcr.io/greenticai/greentic-start-distroless:develop`. For Telegram-via-tunnel
  you need an image that ships `cloudflared` (the `:develop` distroless image
  carries it).

The CLI surface is `<deployer> op [GLOBAL FLAGS] <noun> <verb> [ARGS]`. The
global flags that matter here come **before** the noun:

| Flag | Meaning |
|------|---------|
| `--store-root <DIR>` | Location of the local FS store (desired state). |
| `--answers <PATH>` | The env-manifest (for `env apply`) or a verb's answer payload (e.g. `op deploy`). |
| `--store-url <URL>` | Target a remote operator-store server instead of the local FS store (shared control plane; RBAC enforced server-side). |

---

## 4. Quickstart — declarative deploy to a local kind cluster

The fastest path: **2 JSON files, 2 commands** (plus one-time cluster
bring-up). Brings up **Webchat *and* Telegram**. This is the K8s analog of the
local `setup --answers … && start --cloudflared on` two-liner.

The two files (a complete, working set lives in
`my_demos/k8s-deploy-demo/declarative/` in the workspace):

**`k8s.env.json`** — the env-manifest (`greentic.env-manifest.v1`):

```json
{
  "schema": "greentic.env-manifest.v1",
  "environment": { "id": "local", "name": "k8s", "gui_enabled": true },
  "trust_root": "bootstrap",
  "packs": [
    { "slot": "deployer", "kind": "greentic.deployer.k8s@1.0.0", "pack_ref": "builtin", "answers_ref": "deployer-answers.json" },
    { "slot": "secrets",  "kind": "greentic.secrets.dev-store@1.0.0", "pack_ref": "builtin" }
  ],
  "bundles": [
    {
      "bundle_id": "webchat-bot",
      "bundle_source_uri": "oci://ghcr.io/greenticai/greentic-demo-bundles/webchat-bot:v1",
      "bundle_digest": "sha256:4f560749ec709e75b6063cdeccab15ed5074c2e60bc5f772c2d3b7d4bd992363",
      "route_binding": {
        "hosts": [],
        "path_prefixes": ["/"],
        "tenant_selector": { "tenant": "tenant-default", "team": "default" }
      }
    }
  ],
  "secrets": [
    { "path": "tenant-default/_/messaging-telegram/telegram_bot_token", "from_env": "TELEGRAM_DEMO_BOT_TOKEN" }
  ],
  "messaging_endpoints": [
    { "name": "webchat-bot", "provider_type": "messaging.telegram.bot", "links": ["webchat-bot"] }
  ]
}
```

**`deployer-answers.json`** — the K8s deployer pack's answers
(`answers_ref` above):

```json
{
  "runtime_image": "ghcr.io/greenticai/greentic-start-distroless:develop",
  "tunnel": "cloudflared"
}
```

Then:

```bash
export STORE=/tmp/gtc-k8s-demo/.greentic/environments
export HERE=$PWD/my_demos/k8s-deploy-demo/declarative   # adjust to where the files live
mkdir -p "$STORE"

# one-time cluster
kind create cluster --name gtc-demo
kind export kubeconfig --name gtc-demo

# 1. author the env from ONE manifest (env + trust-root + 2 packs + OCI bundle
#    staged pullable + Telegram endpoint + bot-token secret). The bot token is
#    passed inline so it reaches the apply process on any shell, and is never
#    written to a file.
env TELEGRAM_DEMO_BOT_TOKEN=<your-bot-token> \
  greentic-deployer op --store-root "$STORE" --answers "$HERE/k8s.env.json" env apply --yes

# 2. push rendered objects onto the cluster
greentic-deployer op --store-root "$STORE" env reconcile local
```

Reach it:

```bash
# webchat — port-forward the worker; with a tunnel up the console lives on the
# loopback admin listener (main port + 1 = 8081). The boot banner prints the port.
WORKER=$(kubectl -n gtc-local get deploy -l component=worker -o jsonpath='{.items[0].metadata.name}')
kubectl -n gtc-local rollout status deploy/"$WORKER" --timeout=180s
kubectl -n gtc-local port-forward deploy/"$WORKER" 8081:8081
#   → http://localhost:8081/chat

# Telegram — nothing more to do. At boot the worker staged the dev-store secrets,
# spawned a cloudflared tunnel, and auto-registered the Telegram webhook.
#   confirm: curl -s "https://api.telegram.org/bot<token>/getWebhookInfo" | jq .
```

Teardown: `kind delete cluster --name gtc-demo`.

### What collapsed into the two files

| File | Replaces these `op` calls |
|------|---------------------------|
| `k8s.env.json` (`op env apply`) | `env create` + 2× `env-packs add` + `trust-root bootstrap` + `bundles add` + `revisions stage` + `revisions warm` + `traffic set` + `messaging endpoint add` + `endpoint link-bundle` + `secrets put` |
| `deployer-answers.json` | the deployer pack's `runtime_image` + `tunnel` answers |

---

## 5. Secrets — the dev-store bridge

The K8s model does **not** yet integrate a real secrets backend (AWS SM / Vault
/ native K8s `secretKeyRef`). Instead, when an env binds the
`greentic.secrets.dev-store@1.0.0` pack:

1. `op env apply` (or `op secrets put`) writes secret values into the operator's
   **local dev-store** (`<store>/<env>/.greentic/dev/.dev.secrets.env`,
   AES-256-GCM per secret).
2. At **reconcile** the deployer base64-encodes that dev-store file and renders
   it as the `gtc-dev-secrets` K8s Secret.
3. A `stage-dev-secrets` busybox **init container** copies the file into the
   worker's writable `HOME` at
   `$HOME/.greentic/environments/<id>/.greentic/dev/.dev.secrets.env` — the path
   greentic-start's DevStore resolves. (It must be a writable medium: the
   DevStore opens the file `write+create` with `flock` on every read, so a
   read-only Secret mount would fail.)
4. The worker pod template carries a `greentic.ai/dev-store-hash` annotation
   derived from the secret bytes, so re-reconciling after a secret change
   **rolls the worker pods** (otherwise the init container only copies once at
   pod start).

**Portability note.** The dev-store master key is `SHA256($GREENTIC_DEV_MASTER_KEY)`,
defaulting to `SHA256("")` when unset on both host and pod. With the default
(unset) the `.dev.secrets.env` file is fully portable — decryptable in-pod with
no extra key material.

This is the **Phase-E gap**: it works, but it is not a production secrets
backend. See [§9](#9-known-gaps--production-caveats).

---

## 6. Deploying to a new / real cluster (EKS, GKE, AKS, on-prem, k3s)

Same worker, same two-command flow as the kind quickstart — only the cluster
changes. The deployer connects with `kube::Config::from_kubeconfig` (your named
context) or `Config::infer()` (current context, then in-cluster ServiceAccount).

### What you must change vs. the kind quickstart

| Where | Field | Set to |
|-------|-------|--------|
| `deployer-answers.json` | `kubeconfig_context` | Your cluster's context name. **Or omit** to use the current context. |
| `k8s.env.json` | `environment.public_base_url` | The **HTTPS** URL your Ingress/LoadBalancer serves (Telegram webhooks require HTTPS). |
| at apply time | `TELEGRAM_DEMO_BOT_TOKEN` | Your bot token (passed inline, never written to a file). |

**Strongly recommended:** pin `runtime_image` to a **digest** so a warm node
can't serve a stale `:develop` layer:

```json
"runtime_image": "ghcr.io/greenticai/greentic-start-distroless@sha256:<digest>"
```

### Two public-exposure options

**A. Bring-your-own Ingress/LoadBalancer (production-shaped).** Set
`environment.public_base_url` to your HTTPS host and wire your Ingress/LB so
that `https://<host>` → the **worker** Service on port 8080, TLS terminated at
the edge. At boot the worker reads `public_base_url` and auto-registers the
Telegram webhook against it — no tunnel needed. Leave `tunnel` off / unset.

**B. Zero-infra cloudflared tunnel (demo / no Ingress).** Set
`"tunnel": "cloudflared"` in `deployer-answers.json` and **remove**
`public_base_url`. The worker spawns a `cloudflared` quick tunnel and
self-discovers a `*.trycloudflare.com` URL. Trade-offs: the URL is **ephemeral**
(changes every restart) and the tunnel is **single-revision** (a traffic split
would register N competing webhooks). Good for a demo on a real cluster; not a
stable production endpoint.

### Deploy as a named environment (e.g. `prod`)

`apply` bootstraps only the `local` env, so a named env is **created explicitly
first** (one extra, deliberate command — naming `prod` is an explicit act), then
applied and reconciled. The namespace follows the id (`prod` → `gtc-prod`).

```bash
# 0. create the named env
greentic-deployer op --store-root "$STORE" env create prod

# 1. apply a manifest whose environment.id is "prod"
env TELEGRAM_DEMO_BOT_TOKEN=<token> \
  greentic-deployer op --store-root "$STORE" --answers "$HERE/prod.env.json" env apply --yes

# 2. reconcile onto the cluster under namespace gtc-prod
greentic-deployer op --store-root "$STORE" env reconcile prod
```

Two manifest deltas vs the `local` quickstart for a named env:

- `environment.id`: `"prod"` (drives the `gtc-prod` namespace).
- each `bundles[]` entry needs a `"customer_id"` — the billing principal,
  **required** for non-`local` envs (`local` defaults it to `local-dev`).

### Cluster credentials for reconcile

The deployer authenticates to the kube API as your **ambient kubeconfig**
identity for reconcile. For in-cluster or bound-identity operation, the
deployer's API identity is bound via `op credentials rotate` after the bootstrap
rules pack is applied, and validation runs typed `SelfSubjectAccessReview`
probes against the operations in `credentials.rs::VALIDATED_K8S_OPERATIONS`.
Kubernetes credential **material** is never recorded in the env-manifest or the
deployer answers.

---

## 7. Reaching the worker

| Surface | How | Why |
|---------|-----|-----|
| **Telegram (public)** | Ingress/LB → worker Service `:8080` over HTTPS (option A), or the cloudflared tunnel (option B). The worker auto-registers the webhook at boot. | Provider webhooks self-authenticate (secret-token header). |
| **Webchat `/chat` (private)** | `kubectl port-forward` to the worker. | `/chat` and `/workers/invoke` are **loopback-trusted** and intentionally not served through the public edge. |

**The loopback-trust rule.** The revision server trusts a caller only when
`(peer is loopback) AND (no public tunnel fronts this listener)`:

- **No tunnel:** the console is on the **main** serve port (`8080`); a
  `port-forward 8080:8080` is a genuine loopback peer and gets `/chat` + 200.
- **Tunnel up:** the main port is fronted by cloudflared, so it serves provider
  **webhooks only** (`/chat` → 405, `/workers/invoke` → 403). A separate
  **loopback-only admin listener** (main port + 1 = `8081`) keeps serving the
  console. `port-forward 8081:8081` for `/chat`; the boot banner prints the
  exact admin port. This lets webchat and Telegram run **simultaneously**.

This is a deliberate security posture: cloudflared forwards from loopback, so
public tunnel traffic would otherwise read as loopback and bypass the
`/workers/invoke` gate. Routing the console to an untunneled, loopback-scoped
admin listener closes that without exposing anything new to the network.

---

## 8. Configuration reference

### Deployer answers (`greentic.deployer.k8s@1.0.0`, `answers_ref`)

A flat JSON object keyed by wizard question id
(`src/env_packs/k8s/manifests.rs::K8sParams`). All keys optional; unknown keys
are **rejected** (fail closed on version skew).

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `kubeconfig_context` | string | current context | Which kubeconfig context `reconcile` targets. Client-targeting only — not a manifest knob. |
| `namespace` | string (RFC 1123 label) | `gtc-<env-id>` | Override the namespace every object lands in. |
| `runtime_image` | string `[a-z0-9.\-_/:@]+` | `ghcr.io/greenticai/greentic-start-distroless:develop` | Container image for router + worker pods. Pin to a digest in production. |
| `router_replicas` | int (string or number) | `2` | Router replica count. Must be **≥ 2** (HA). |
| `tunnel` | `"off"` \| `"cloudflared"` | `off` | Worker public-exposure mode. `cloudflared` → worker spawns a quick tunnel (single-revision only). |
| `oci_insecure_registries` | string[] (`host[:port]`) | `[]` | Registry authorities the worker/router may pull bundles from over plain HTTP. Rendered as `GREENTIC_OCI_INSECURE_REGISTRIES`. Empty → HTTPS only. |

### Env-manifest (`greentic.env-manifest.v1`) — K8s-relevant fields

| Field | Notes |
|-------|-------|
| `environment.id` | Drives the namespace (`gtc-<id>`) and the store partition. Only `local` is auto-bootstrapped by `apply`; other ids need `op env create <id>` first. |
| `environment.gui_enabled` | Serve the `/chat` console (loopback-trusted). |
| `environment.public_base_url` | HTTPS URL for webhook auto-registration (option A). Omit when using a tunnel (the tunnel URL wins). |
| `trust_root` | `"bootstrap"` to mint the env trust-root. |
| `packs[]` | `slot` ∈ `deployer` / `secrets` / … (lowercase). For K8s: a `deployer` slot bound to `greentic.deployer.k8s@1.0.0` (+ `answers_ref`), and a `secrets` slot bound to `greentic.secrets.dev-store@1.0.0` if you need pod secrets. |
| `bundles[]` | Declare the bundle by `bundle_source_uri` (an `oci://` ref the worker pulls) + a `bundle_digest` integrity pin (`sha256:<hex>`) — **no local `bundle_path` needed on the apply host**. `route_binding` selects host/path-prefix + `tenant_selector`. Non-`local` envs require `customer_id`. |
| `secrets[]` | `{ path, from_env }` — values come from `from_env` (read at apply) or paste; **secret values never go in the manifest**. |
| `messaging_endpoints[]` | `{ name, provider_type, links }`. `provider_type: "messaging.telegram.bot"`; `links` references a `bundle_id`. The URI segment for the bot-token secret is fixed `messaging-telegram` (not the endpoint name). |

---

## 9. Known gaps & production caveats

All verified in source. None silently broken — each is a deliberate current
limitation with a workaround.

- **No managed Ingress/LoadBalancer.** The deployer renders only `ClusterIP`
  Services on `:8080`. External exposure is BYO-Ingress ([§7](#7-reaching-the-worker)
  option A) or the ephemeral cloudflared tunnel (option B). There is no
  first-class stable-hostname mode yet.
- **Secrets use the dev-store bridge, not a real backend.** The bot token is
  base64'd from the operator's local dev-store into a K8s Secret. It works but
  is not AWS SM / Vault / native `secretKeyRef`. This is the **Phase-E** gap
  ([§5](#5-secrets--the-dev-store-bridge)).
- **No `imagePullSecrets`.** A private runtime image or private bundle registry
  is not yet supported by the rendered manifests. The demo image and bundle are
  public ghcr. Use `oci_insecure_registries` only for plain-HTTP dev registries.
- **No `imagePullPolicy`.** Non-digest tags default to `IfNotPresent`; pin a
  digest for deterministic pulls.
- **Tunnel is single-revision.** Each worker pod spawns its own cloudflared
  tunnel, so a traffic split registers N competing webhooks. For multi-revision
  / production use BYO-Ingress with a stable `public_base_url`.
- **Reconcile authenticates as your ambient kubeconfig.**
- **Named envs are first-class but single-operator.** The local store authorizes
  any env id under filesystem ownership (audited as the `local-owner` policy). A
  *shared, multi-operator* control plane — an operator-store server (`--store-url`)
  with RBAC, idempotency replay, and CAS — exists in scaffold form but the
  remote `revisions stage`/`warm` verbs are not yet wired end-to-end. Until then,
  each operator's named envs live in their own local store.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `conflict: this build was compiled without the k8s-client feature` | A deployer binary built `--no-default-features`. | Rebuild with default features: `cargo build -p greentic-deployer --bin greentic-deployer`. |
| Worker `CrashLoopBackOff` / no revision served | Bundle digest mismatch, or registry not reachable from the pod. | Check the pod has internet egress; verify `bundle_digest` matches the `oci://` artifact. The worker fails closed on digest mismatch. |
| Telegram `setWebhook` fails to resolve host | Fresh `*.trycloudflare.com` not yet globally resolvable, or local DNS can't resolve it. | Wait ~15–30s; verify reachability via a public resolver (`dig +short @1.1.1.1 <host>`) rather than local DNS, then `getWebhookInfo`. |
| `port-forward` returns 502 after a rollout | `port-forward` binds one pod; a rollout replaces it. | Restart the `port-forward`. |
| `/chat` returns 405/403 over the tunnel | Loopback-trust posture: the tunneled main port serves webhooks only. | Port-forward the **admin** listener (`8081`, main+1). The boot banner prints the port. |
| Webhook registration not visible in `kubectl logs` | greentic-start logs registration via OTLP / `system.log`, not pod stdout. | Confirm with Telegram `getWebhookInfo`, not `kubectl logs`. |
| Secret change didn't take effect | Init container copies the dev-store once at pod start. | Re-reconcile — the `greentic.ai/dev-store-hash` annotation rolls the pods on a data change. |

---

## 11. Glossary

| Term | Meaning |
|------|---------|
| **env-pack** | A pluggable capability bound to an environment slot (`deployer`, `secrets`, …). The K8s deployer is `greentic.deployer.k8s@1.0.0`. |
| **store** | The local FS (or remote) record of desired state, partitioned per env id. Written by `apply`/`deploy`, read by `reconcile`. |
| **reconcile** | Render the store's desired state to manifests and push them onto the live cluster (and prune stale workers). |
| **revision** | A staged, integrity-pinned snapshot of a bundle (`pack_list`, `config_digest`, `bundle_digest`, …). The worker pulls and serves it. |
| **route_binding** | How a bundle's traffic is selected — host(s), path prefix(es), and `tenant_selector`. |
| **dev-store bridge** | The mechanism that gets operator secrets into the pod via a rendered Secret + init container (the Phase-E placeholder for a real backend). |
| **loopback-trust** | The rule gating `/chat` + `/workers/invoke`: trusted only when the peer is loopback AND no tunnel fronts the listener. |
| **admin listener** | A loopback-only listener (main port + 1) that serves the console while the main port is tunneled. |

---

## 12. Runnable demos (workspace, not in this repo)

End-to-end runnable demos with driver scripts live under `my_demos/` in the
greentic workspace (not version-controlled in this repo):

- `my_demos/k8s-deploy-demo/declarative/` — the 2-file / 2-command declarative
  flow above (`k8s.env.json`, `deployer-answers.json`, `RUN.md`).
- `my_demos/k8s-deploy-demo/real-cluster/` — the same flow targeting a real
  remote cluster, with named-env and Ingress notes.
- `my_demos/k8s-deploy-demo/demo.sh` — a scripted driver with `real-*` verbs
  (prereqs/up/setup/serve/chat/telegram/status/down) wrapping the whole flow.
- `my_demos/k8s-telegram-webchat-demo/` — a self-contained interactive demo
  (webchat `/chat` + Telegram) in local kind, OCI-pulling from ghcr.

These are the source material this guide generalizes; the commands here are the
repo-canonical reference.
