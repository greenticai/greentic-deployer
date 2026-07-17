# Google Cloud Run Deployment Guide

How a Greentic digital worker is deployed to, and served from, **Google Cloud
Run** using the **environment-pack** model of `greentic-deployer` (the
`op env …` CLI surface). Covers the mental model, what lands in your project,
the one-command path, the seed/secret contract, access modes, the
zero-idle-cost claim and how to verify it, a configuration reference, the known
gaps, and troubleshooting.

> **Audience.** Written for both humans and LLM agents. Section headings are
> stable anchors; commands are copy-paste runnable; every claim about created
> resources or config keys is sourced from `src/env_packs/gcp_cloudrun/`. Where
> a behaviour is a known limitation it is called out explicitly rather than
> glossed over.

> **Scope.** This is the **env-pack** Cloud Run path (`op env up` /
> `op env apply-revision` against the `greentic.deployer.gcp-cloudrun@1.0.0`
> env-pack). It is distinct from:
> - the lower-level **deployment-pack** `gcp` adapter in the repo README, which
>   renders Terraform for you to hand to your own pipeline and does not manage
>   an environment store; and
> - the older `gcp-cloud-run-local` **extension** path described in
>   `docs/superpowers/*-gcp-cloud-run*`, which those documents' headers now mark
>   as superseded by this one.
>
> Use this guide when you want a runtime to **pull a bundle, serve it, and route
> traffic** on Cloud Run.

---

## 1. Mental model — why Cloud Run is not Kubernetes

If you have read the [Kubernetes guide](k8s-deployment.md), the store half is
identical and the apply half is not. The difference in one line: **there is no
cluster and no reconcile.**

| | Kubernetes | Cloud Run |
|---|---|---|
| **Apply model** | Declarative. `op env reconcile` renders the whole desired state and prunes what is gone. | **Imperative.** Each verb drives one API call sequence. There is no `op env reconcile` for Cloud Run. |
| **Unit of serving** | A Deployment + Service per revision, in namespace `gtc-<env-id>`. | One **Cloud Run Service per deployment**, holding N revisions with a traffic split. |
| **Locality axis** | The kubeconfig context. | The `project` + `region` answers. |
| **Filesystem** | A real (if ephemeral) container FS. | Read-only except `/tmp`, which is **in-memory**. |
| **Idle cost** | Nodes bill whether or not traffic arrives. | **Scales to zero — no compute billed while idle.** This is the whole point. |

The environment id is still an independent axis from the project: `local`,
`staging`, and `prod` can all live in one GCP project (they get distinct
Services, runtime service accounts, and secrets), or in separate projects.

### The store vs. the project

```
   author (writes the STORE)              apply (writes GOOGLE CLOUD)
   ┌─────────────────────────┐            ┌─────────────────────────┐
   │ op env apply --answers  │  ───────▶  │ op env up               │
   │ op env-packs add …      │   store    │ op env apply-revision   │
   │ op revisions stage/warm │            │ op env apply-traffic    │
   └─────────────────────────┘            └─────────────────────────┘
        local FS store                        run.googleapis.com
   <store-root>/<env-id>/…              + secretmanager.googleapis.com
```

`op env up` is the one command that does both halves: it applies the manifest to
the store, then warms every present revision and pushes every recorded traffic
split to Cloud Run.

---

## 2. What gets created in your project

For an environment `<env>` in project `<project>`, region `<region>`:

| Resource | Name | Created by | Notes |
|---|---|---|---|
| Cloud Run **Service** | `gtc-svc-<deployment-ulid>` | `op env up` / `apply-revision` | One per *deployment*, not per revision. Lowercased; DNS-label safe. |
| Cloud Run **Revision** | `gtc-svc-<deployment-ulid>-<revision-ulid>` | each warm | 61 chars — under Cloud Run's 63-char limit. |
| **Secret Manager secret** | `<secret_prefix>-environment` (default `gtc-<env>-environment`) | first warm | Holds the seed. One secret, several **versions** (see §5). |
| **Runtime service account** | `gtc-<env>-runtime@<project>.iam.gserviceaccount.com` | **you** (bootstrap Terraform) | The identity revisions run as. Override with the `service_account` answer. |
| **Deployer service account** | `gtc-<env>-deployer@<project>…` | **you** (bootstrap Terraform) | The identity that *deploys*. Not needed if you deploy as yourself. |
| IAM: `secretAccessor` | on the seed secret, for the runtime SA | first warm | Cloud Run refuses a revision whose SA cannot read a mounted version. |
| IAM: `run.invoker` for `allUsers` | on the Service | warm, when `access_mode: public` | See §6. |

The deployer creates **nothing else**. In particular it **never** creates an
Artifact Registry repository — not even when you set `ar_repo`. That answer only
*points at* a repository you have already provisioned, by rewriting the image
reference to `<region>-docker.pkg.dev/<project>/<ar_repo>/…`; set it without
creating the repository first and you get a failed image pull, not a cache. By
default the worker image and your bundle are pulled straight from public GHCR,
which is what keeps standing storage cost at zero (§8).

---

## 3. Prerequisites

1. **A GCP project with billing enabled.** Cloud Run has a free tier, but the
   project must still have billing attached.
2. **APIs enabled**: `run.googleapis.com`, `secretmanager.googleapis.com`.
3. **The two service accounts + the deployer's IAM role.** The deployer creates
   neither — render the bootstrap Terraform and apply it. Binding the env-pack
   comes first, because the renderer reads the bound deployer kind:

   ```bash
   # 1. Bind the deployer (this is just the store half of the quickstart manifest).
   gtc op env apply --answers cloudrun.env.json --yes

   # 2. Render the bootstrap pack. `admin_profile` identifies the admin who will
   #    run terraform; the material is required by the CLI but unused by the GCP
   #    renderer, which mints no credentials.
   cat > bootstrap.json <<'JSON'
   { "environment_id": "local",
     "admin_profile": "you@example.com",
     "admin_material_inline": "unused-by-gcp-render" }
   JSON
   gtc op credentials bootstrap --answers bootstrap.json
   ```

   The pack lands in the env's store dir:

   ```
   <store-root>/<env>/rules/greentic.deployer.gcp-cloudrun/
     ├── gcp-cloudrun-bootstrap.tf
     ├── README.md
     └── index.json
   ```

   Review it, then apply (the pack recommends OpenTofu; Terraform works too):

   ```bash
   cd <store-root>/<env>/rules/greentic.deployer.gcp-cloudrun
   tofu init && tofu apply -var project_id=<project>
   ```

   It enables the two APIs, creates `gtc-<env>-deployer` and `gtc-<env>-runtime`,
   defines a custom role holding exactly the permission list the deployer
   validates, and binds it. The Artifact Registry resources are present but
   **commented out**; if you want a pull-through cache, uncomment and apply them
   **first**, then set `ar_repo` to the repository id they create — the answer
   alone provisions nothing. The bootstrap is render-only: `"bound": false` in
   the output means no credential was minted and nothing was written to your
   project by this step.
4. **Credentials for the deployer (ADC).** The deployer runs as the **ambient**
   Application Default Credentials chain unless the env binds a deployer
   session. Any of:
   - `gcloud auth application-default login` (deploy as yourself — simplest for
     a scratch project), or
   - `export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json` for the
     `gtc-<env>-deployer` service account, or
   - run on a GCP VM / Cloud Build with the deployer SA attached (metadata
     server).

   Whichever you pick, the ambient identity must be able to act on the project
   `GTC_GCP_E2E_PROJECT`/`project` names.

> **Gap: preflight validation needs a bound credential.**
> `op credentials requirements` runs the real `projects.testIamPermissions`
> probe and would tell you exactly which permissions are missing *before* your
> first deploy. It refuses on an env with no `credentials_ref`
> (`env <id> has no credentials_ref; run op credentials bootstrap first`), and
> the GCP bootstrap is render-only, so it does not set one. **On the ambient-ADC
> path the preflight is therefore not reachable**, and the first `op env up` is
> where a missing permission surfaces. Read the Terraform's custom role for the
> authoritative list.

---

## 4. Quickstart — one file, one command

One env-manifest describes the whole environment:

```jsonc
// cloudrun.env.json
{
  "schema": "greentic.env-manifest.v1",
  "environment": { "id": "local", "name": "cloudrun-demo" },
  "trust_root": "bootstrap",
  "packs": [
    {
      "slot": "deployer",
      "kind": "greentic.deployer.gcp-cloudrun@1.0.0",
      "pack_ref": "builtin",
      "answers": {
        "project": "my-project",
        "region": "europe-west1",
        "access_mode": "public"
      }
    },
    { "slot": "secrets", "kind": "greentic.secrets.dev-store@1.0.0", "pack_ref": "builtin" }
  ],
  "bundles": [
    {
      "bundle_id": "cloudrun-demo",
      "bundle_source_uri": "oci://ghcr.io/greenticai/greentic-demo-bundles/webchat-bot:v1",
      "bundle_digest": "sha256:4f560749ec709e75b6063cdeccab15ed5074c2e60bc5f772c2d3b7d4bd992363",
      "route_binding": { "path_prefixes": ["/"] }
    }
  ]
}
```

```bash
gtc op env up --answers cloudrun.env.json --yes
# or the sugar:  gtc start cloudrun --answers cloudrun.env.json
```

One JSON envelope comes back on stdout, carrying the URL Cloud Run assigned:

```json
{"noun":"env","op":"up","result":{
  "environment_id":"local",
  "kind":"greentic.deployer.gcp-cloudrun@1.0.0",
  "warmed":["gtc-svc-01k0…"],
  "endpoints":[{"deployment_id":"01k0…","url":"https://gtc-svc-01k0…-ew.a.run.app"}],
  "endpoint_url":"https://gtc-svc-01k0…-ew.a.run.app",
  "applied_splits":0
}}
```

`endpoint_url` is a convenience field, present only when the env fronts exactly
one Service; read `endpoints` for the general case.

Preview without touching Google Cloud — this stops after the store plan and
never reaches the Cloud Run dispatch, so it needs no credentials:

```bash
gtc op env up --answers cloudrun.env.json --dry-run
```

**Bundles must be remote.** Cloud Run pulls your bundle from a registry at boot,
so a `bundle_path` pointing at a local `.gtbundle` on your laptop is unreachable
from the container. Use `bundle_source_uri` (`oci://…`) with a `bundle_digest`.

---

## 5. Secrets — the seed contract

The runtime needs its environment (and, in dev, its secret store) at boot, and
Cloud Run has no persistent disk. The deployer stages both into **Secret
Manager** and mounts them read-only:

```
Secret Manager                          container
┌───────────────────────────────┐       ┌──────────────────────────┐
│ <secret_prefix>-environment   │       │ /seed/environment.json   │  ← version N
│   version N   → environment.json ─────▶ /seed/<dev-store path>   │  ← version N+1
│   version N+1 → dev-store      │       └──────────────────────────┘
└───────────────────────────────┘                   │
                                     GREENTIC_SEED_DIR=/seed
                                                    │
                                                    ▼
                                     greentic-start's boot-copy
                                       → $HOME/.greentic/… ($HOME=/tmp)
```

Load-bearing details:

- **One secret, several versions**, each projected at a different relative path.
  Cloud Run forbids nested mounts, so the seed tree is projected as subdirectory
  items of one volume rather than as several volumes.
- **Versions are pinned numerically**, never `latest` — a revision always boots
  the exact seed it was created with.
- The runtime SA is granted `secretAccessor` on the secret before the revision is
  created. Cloud Run rejects a revision whose SA cannot read a mounted version,
  so this ordering is not optional.
- `HOME=/tmp` because Cloud Run's root filesystem is read-only except `/tmp`,
  which is **in-memory**. The seed is re-copied on every cold start.
- The deployer's own credential is **excluded** from the seed — a workload never
  receives the identity that deployed it.

### Secret ownership

The seed secret is stamped with a `greentic-env` label identifying the owning
environment. A second environment configured with the same `secret_prefix`
refuses to stage rather than write into the first one's secret:

```
Secret Manager secret `gtc-shared-environment` belongs to environment `prod-…`,
but this is environment `staging-…`. Two environments cannot share one secret —
each would grant its own runtime service account read over the other's staged
seed. Give this environment a distinct `secret_prefix` answer.
```

`op env destroy` applies the same check before deleting: a secret owned by
another environment is reported under `skipped_secrets` and left intact.

---

## 6. Access modes — Cloud Run is private by default

| `access_mode` | What it does | Use when |
|---|---|---|
| `public` (default) | Grants `roles/run.invoker` to `allUsers` on the Service. The URL is reachable by anyone. | Webhooks (Telegram, Slack), demos, anything the public internet must reach. |
| `authenticated` | Grants nothing. The URL returns **403** without a Google-signed identity token. | Internal services; you bring your own caller identity. |

A Cloud Run URL is **unreachable until an invoker binding exists** — if you
deploy with `authenticated` and then `curl` the URL, a 403 is the correct,
expected answer, not a bug:

```bash
# authenticated mode: mint a token for the call
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" "$URL/healthz"
```

> **Org policy.** `constraints/iam.allowedPolicyMemberDomains` blocks `allUsers`
> bindings in many organizations. If `public` fails with a policy error, either
> get an exception for the project or use `authenticated` and put your own
> authenticating front end in front of it.

> **`public` exposes the runtime's own probe routes**, including `/status`
> (which reports env id and active bundle/revision counts) and `/healthz`. That
> is a property of greentic-start's route table, not of this deployer. Do not
> use `public` for an environment whose existence is itself sensitive.

---

## 7. Reaching the worker

```bash
URL=$(gtc op env up --answers cloudrun.env.json --yes | jq -r '.result.endpoint_url')

curl -fsS "$URL/healthz"    # → ok        (liveness — a STATIC route)
curl -fsS "$URL/status"     # → greentic.status.v1 diagnostics
```

**`/healthz` proves less than it looks like it does.** It is a static route: it
answers `200 ok` from a runtime that pulled no bundle and loaded nothing. To
know the deploy actually *worked*, read `/status`:

```json
{"schema":"greentic.status.v1","env_id":"local","listen_addr":"0.0.0.0:8080",
 "bundles_active":1,"deployments_routed":1,"revisions_active":1}
```

`bundles_active` and `revisions_active` are non-zero only once the seeded
environment resolved, the bundle pulled from the registry, and its packs loaded.
**`bundles_active: 0` with a healthy `/healthz` is the signature of a boot that
came up but found no work** — see §11.

Beyond the probes, the worker serves whatever your bundle's `route_binding`
declares (`/` in the quickstart).

---

## 8. Zero idle cost — the claim, and how to check it

The reason to run on Cloud Run: **an idle environment bills no compute.** With
`min_instances: 0` (the default) Cloud Run scales to zero after its idle window
and you pay for requests, not for time.

The honest acceptance criterion is **not** "it costs nothing". It is:

> **Zero Cloud Run compute cost while idle, plus an enumerated, bounded set of
> standing charges.**

Those standing charges, in the default configuration:

| Resource | Standing cost while idle |
|---|---|
| Cloud Run Service, 0 instances | **Zero.** No compute billed. |
| Secret Manager | The seed secret's **active versions** — a few cents/month. |
| Artifact Registry | **Zero — the deployer creates no repository, ever.** If *you* provision one and point `ar_repo` at it, its cached-artifact storage bills; that is the trade-off for a pull-through cache. |
| Cloud Logging | Whatever your log retention costs; unrelated to idleness. |

To verify, after ~15 minutes of no traffic:

```bash
# 1. Scaled to zero? Read the container/instance_count metric for the service.
#    Console → Cloud Run → <service> → METRICS → "Container instance count"
#    is the readable form; it should flatten to 0 after the idle window.

# 2. Enumerate what still bills. The point of this step is that the list is
#    SHORT and KNOWN — not that it is empty.
gcloud secrets list --project <project>
#   → expect exactly the seed secret(s) this env staged.
gcloud artifacts repositories list --project <project>
#   → expect EMPTY unless you set `ar_repo`.
gcloud run services list --project <project> --region <region>
#   → the Service exists but, at 0 instances, bills no compute.
```

The first request after idling pays a **cold start**: the container starts and
re-copies the seed from the mounted secret. Set `min_instances: 1` to trade the
cold start for a standing compute bill — that is a deliberate choice against the
reason you are here.

---

## 9. Configuration reference

Deployer answers (`greentic.deployer.gcp-cloudrun@1.0.0`), as `packs[].answers`
in the manifest or via `answers_ref`:

| Key | Required | Default | Notes |
|---|---|---|---|
| `project` | **yes** | — | GCP project id. |
| `region` | **yes** | — | e.g. `europe-west1`. |
| `access_mode` | no | `public` | `public` \| `authenticated`. See §6. |
| `ar_repo` | no | *(unset)* | Id of an **already-provisioned** Artifact Registry remote repo to pull the image through instead of direct GHCR. **Creates nothing** — provision it first (§3) or the pull fails. Adds storage cost (§8). |
| `runtime_image_tag` | no | `develop` | Tag of `ghcr.io/greenticai/greentic-start-distroless`. |
| `runtime_image_digest` | no | *(unset)* | `sha256:…`. **Prefer this over a tag** — see §10. |
| `service_account` | no | `gtc-<env>-runtime@<project>.iam.gserviceaccount.com` | Runtime identity. |
| `secret_prefix` | no | `gtc-<env>` | Seed secret name prefix. **Must differ between environments sharing a project** (§5). |
| `cpu` | no | `"1"` | |
| `memory` | no | `"512Mi"` | |
| `max_instances` | no | `"1"` | **Do not raise in dev** — see §10. |
| `min_instances` | no | `"0"` | `0` = scale to zero. Raising it forfeits zero idle cost. |
| `concurrency` | no | `"80"` | Requests per instance. |

Environment variables read by the deployer itself:

| Var | Effect |
|---|---|
| `GREENTIC_GCP_WARM_READY_TIMEOUT_SECS` | Bound the wait for a revision to become ready. |
| `GOOGLE_APPLICATION_CREDENTIALS` | Standard ADC key path. |

---

## 10. Known gaps & production caveats

- **`max_instances = 1` is a correctness constraint, not a cost tuning knob.**
  The environment/session store is per-instance and lives in in-memory `/tmp`. A
  second instance would have its own store and would not see the first's state,
  and neither survives a cold start. Raising `max_instances` scales a runtime
  whose state does not coordinate. A durable multi-instance store (shared
  Postgres/backend) is the prerequisite for lifting this and is **not built
  yet**.
- **Ephemeral state.** Seeded state is immutable boot config. Runtime writes to
  the store do not survive a cold start. Do not run a workload that expects
  durable local state.
- **Tag caching.** Both the direct-GHCR path and an AR remote repo cache tags for
  up to ~1h, so a moving tag (`:develop`) can serve a stale image. Pin
  `runtime_image_digest` (and your `bundle_digest`) for anything you care about.
- **Basis-point granularity.** Cloud Run traffic is whole integer percents
  summing to exactly 100. Splits that are not whole multiples of 100 bps
  (i.e. not whole percents) are **rejected**, not silently rounded.
- **No `op env reconcile`** for Cloud Run; there is no declarative prune. Use
  `op env destroy` to reclaim.
- **No `op env render`** for Cloud Run.
- **Secret version accumulation.** Each warm adds seed versions; they are not
  garbage-collected. `op env destroy` deletes the whole secret.
- **Native GCP Secret Manager `secret://` backend** (as the *runtime's* secrets
  backend, rather than the dev-store) is not implemented. Nor is Vault on Cloud
  Run, GCS bundle upload, or custom domains.

---

## 11. Troubleshooting

**`/healthz` is 200 but `/status` shows `bundles_active: 0`.**
The container booted but loaded no bundle. Almost always the bundle reference:
the `bundle_source_uri` is unreachable from Cloud Run (private registry, no
credential on the runtime SA) or the `bundle_digest` does not match what the tag
now resolves to. Check the revision logs:
```bash
gcloud logging read \
  'resource.type="cloud_run_revision"
   AND resource.labels.service_name="gtc-svc-<deployment-ulid>"' \
  --project <project> --limit 50 --freshness=1h
```

**The URL returns 403.**
`access_mode: authenticated` (by design — §6), or a `public` deploy whose
`allUsers` binding was refused by org policy. The deploy would have surfaced the
policy error; re-read the `op env up` output.

**`Secret … belongs to environment …`.**
Two environments share a `secret_prefix`. Give this one a distinct
`secret_prefix` (§5). This is a refusal, not a failure — it stopped a
cross-environment secret leak.

**Revision never becomes ready / the warm times out.**
The container is not binding `$PORT`, or is crash-looping. Read the logs as
above. Raise `GREENTIC_GCP_WARM_READY_TIMEOUT_SECS` only if you have confirmed
it is slow rather than broken.

**`PermissionDenied` on the first deploy.**
The error names the permission Google refused. Compare it against the custom role
in the rendered `gcp-cloudrun-bootstrap.tf` — that file is the authoritative list
of what the deployer needs. The usual cause is deploying **as yourself** after
bootstrapping a *deployer service account*: the Terraform grants the role to
`gtc-<env>-deployer`, not to your user. Either impersonate it
(`GOOGLE_APPLICATION_CREDENTIALS` pointing at its key) or grant your user the
same role. (`op credentials requirements` would probe this for you, but is not
reachable on the ambient path — see §3.)

**`op env destroy` refuses.**
The env binds a provider-teardown deployer but this build cannot tear it down
(missing the `deploy-gcp-cloudrun` feature), so it refuses rather than orphan
your Cloud Run resources. Either use a build with the feature, or
`--force-local` to purge local state only — and then delete the Service and
secret by hand.

**Reclaiming everything.**
```bash
gtc op env destroy <env> --confirm
```
Deletes each Service the env created and the seed secret it owns, then removes
local state. Verify:
```bash
gcloud run services list --region <region> --project <project>
gcloud secrets list --project <project>
```

---

## 12. Glossary

| Term | Meaning |
|---|---|
| **Service** | The Cloud Run resource that owns a URL and a traffic split. One per Greentic *deployment*. |
| **Revision** | An immutable Cloud Run configuration+image snapshot. Traffic is split across revisions. Maps 1:1 to a Greentic revision. |
| **Seed** | The `environment.json` (+ dev-store) staged into Secret Manager and mounted at `/seed` for the runtime to boot from. |
| **Warm** | Create the Cloud Run revision and wait for it to be ready. Never moves traffic. |
| **Env-pack** | The pluggable capability binding (`deployer`, `secrets`, …) on an environment. |
| **Scale to zero** | Cloud Run running **no** instances while idle, so no compute is billed. |

---

## See also

- [Kubernetes Deployment Guide](k8s-deployment.md) — the declarative,
  cluster-based sibling of this path.
- [Env-Pack Authoring Guide](env-packs.md) — how the `deployer` slot is bound.
- `tests/gcp_cloudrun_e2e.rs` — the live lifecycle this guide describes,
  executable against a real project with `GREENTIC_GCP_E2E=1`.
