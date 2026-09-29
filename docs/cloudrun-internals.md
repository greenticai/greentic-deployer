# Cloud Run deployer — internals

How the `greentic.deployer.gcp-cloudrun@1.0.0` env-pack is built, for anyone
**changing** it. If you want to *use* it, read
[`cloudrun-deployment.md`](cloudrun-deployment.md) instead — this document
describes no user-facing workflow and that one describes no internals.

Everything here is sourced from `src/env_packs/gcp_cloudrun/`. Where a rule looks
arbitrary, the reason is given: several of them exist because the obvious
implementation was wrong in a way that only shows up under concurrency or
failure.

---

## 1. Module map

| File | LOC | Owns |
|---|---:|---|
| `mod.rs` | 239 | The `EnvPackHandler` — slot, descriptor path, version req, accessors. |
| `deployer.rs` | 2044 | The `Deployer` verbs: warm / drain / archive / traffic-split. Answer parsing, name derivation, the seed contract, ownership stamping. |
| `real_target.rs` | 1370 | The production `CloudRunTarget`, backed by `google-cloud-*`. Request building, response parsing, error classification. |
| `deploy_target.rs` | 1174 | The `CloudRunTarget` **seam** + the in-memory fake + the unconfigured default. |
| `credentials.rs` | 1145 | `DeployerCredentials`: ADC principal resolution + the `testIamPermissions` preflight. |
| `bootstrap.rs` | 414 | Renders the minimum-privilege Terraform module (deployer SA, runtime SA, custom role). |
| `bound_session.rs` | 261 | Resolves the env's bound credential material into live `Credentials`. |
| `shared_state.rs` | ~450 | Redis + VPC answers, the `multi_instance_safe` capability and the multi-instance `gate`. |
| `redis_secret.rs` | ~230 | The Redis URL's own env-owned secret: reuse an unchanged value, prune superseded versions after a ready warm. |
| `sor/` | ~1100 | SoR units (SoRLa phase 3E): the SorServiceTarget seam + fake, pure builders, bring-up/retire, the real target. |

Feature gating is two-tier and deliberate:

- `creds-gcp` — the handler, credentials scaffold, and bootstrap. **No
  `google-cloud-*` dependency.** `--no-default-features --features creds-gcp`
  must build clean.
- `deploy-gcp-cloudrun` — adds `bound_session` + `real_target` and the SDK deps.

New live-deploy code goes behind `deploy-gcp-cloudrun`. `ci/local_check.sh` ends
with `cargo build --no-default-features`, so an ungated reference fails CI even
when the default build is green.

---

## 2. No `gcloud`. Typed SDK.

There are **no shell-outs anywhere in this module** — no `Command::new`, no
`gcloud`. It links Google's official Rust clients:

| Crate | Drives |
|---|---|
| `google-cloud-run-v2` | `Services`, `Revisions` |
| `google-cloud-secretmanager-v1` | seed staging |
| `google-cloud-iam-v1` | invoker policy, secret-accessor grant |
| `google-cloud-auth` | credential resolution, token refresh |
| `google-cloud-gax` / `-lro` | error codes, long-running-operation polling |

This is **not** how the other providers here work — `src/aws.rs` shells out to
the `aws` CLI and `src/azure.rs` to `az`. Do not "make Cloud Run consistent" with
them; the typed path is the intended direction, not the outlier to fix.

Cloud Run clients are built against the **regional** endpoint
`https://{region}-run.googleapis.com` so long-running operations poll the region
that owns them. Secret Manager is global and uses its default endpoint.

> The `gcloud` strings you will find in `src/apply.rs` belong to the **legacy IaC
> path** (rendered `terraform import` helpers, guarded by `command -v gcloud`).
> They are unrelated to this module.

---

## 3. The `CloudRunTarget` seam

Every side effect goes through one trait (`deploy_target.rs:298`), with three
implementations:

| Impl | Where | Purpose |
|---|---|---|
| `RealCloudRunTarget` | `real_target.rs:203` | Production. Talks to Google. |
| `InMemoryCloudRun` | `deploy_target.rs:634` | The fake. Full behaviour, no network. |
| `UnconfiguredCloudRunTarget` | `deploy_target.rs:406` | The **default**. Every verb fails honestly. |

The unconfigured default matters: a handler built without a real client must
*refuse*, not silently succeed. Preserve that when adding a verb — a new method
whose default implementation returns `Ok(())` would turn a broken build into a
green no-op deploy.

`deployer.rs` drives the seam and holds all policy. `real_target.rs` holds no
policy — it translates seam calls into API calls and classifies errors. Keep that
split: logic added to `real_target.rs` is logic that cannot be tested without a
cloud account.

### Identity bridge

The seam addresses a Service by `deployment_id` and a revision by
`(deployment_id, revision_id)`. Both map to **deterministic** Cloud Run names, so
a fresh process re-derives every name without persisting Cloud Run ids:

```
service  gtc-svc-{deployment-ulid}                  (lowercased, DNS-label safe)
revision gtc-svc-{deployment-ulid}-{revision-ulid}   (61 chars ≤ the 63 limit)
```

Reading live traffic back into seam types means recovering a `RevisionId` from a
revision name — `parse_revision_id_from_name` is the exact inverse of
`revision_name`. **Change one and you must change the other.**

---

## 4. Credentials

Two branches, resolved in `bound_session.rs`:

```
env.credentials_ref bound?
├─ yes → resolve_credentials_token   (env var → dev-store → FAIL)
│         └─ parse as GCP credential JSON:
│              "service_account"  → service-account key
│              "external_account" → Workload Identity Federation
└─ no  → ambient_adc_credentials()
          GOOGLE_APPLICATION_CREDENTIALS → gcloud ADC file → metadata server
```

Whichever resolves is injected into all three clients at construction
(`RealCloudRunTarget::resolve`), and `google-cloud-auth` handles refresh.

**Invariant — a bound credential never falls back.** Material that is missing,
unparseable, or of an unsupported `type` is a hard error. It must *not* degrade
to the ambient identity: an environment that declares a narrow scoped SA would
otherwise silently run as whatever broad identity the operator happens to be
logged in as. This is the reason the parse is fail-closed rather than
best-effort; do not "improve" it into a fallback.

**Known limitation — the principal is usually invisible.** `resolve_adc_identity`
can only report `client_email` when ADC is a service-account *key file*, because
`google-cloud-auth` exposes a token and nothing else. With `gcloud` user
credentials or the metadata server it reports the `"(ADC principal)"` sentinel.
Any feature that needs to know *who* is deploying has to account for that.

Scope requested is the coarse `cloud-platform`. Tightening it buys nothing — the
SA's IAM roles are the real authorization boundary.

---

## 5. The permission contract

`REAL_CLOUDRUN_TARGET_IAM_PERMISSIONS` (`real_target.rs:67`) lists the 15
permissions a live deploy actually exercises. `VALIDATED_GCP_PERMISSIONS`
(`credentials.rs:54`) is what the preflight probes, and what `bootstrap.rs` bakes
into the rendered custom role.

A test (`real_target.rs:1362`) asserts **`REAL_… ⊆ VALIDATED_…`**.

> **If you add an SDK call, add its permission to `REAL_…` in the same change.**
> The test then forces you to add it to `VALIDATED_…` too, which flows into the
> bootstrap Terraform. That chain is why a missing permission fails CI rather
> than a customer's first `op env up`. Do not weaken the test to get green.

`VPC_EGRESS_PERMISSIONS` (`vpcaccess.connectors.use`, `compute.subnetworks.use`)
is deliberately outside `VALIDATED_…`: it is probed only when the binding answers
a VPC (`with_vpc_egress`), so a credential bootstrapped before VPC egress keeps
passing, while `bootstrap_permissions()` always grants it.

The preflight itself asks Google rather than inferring from role names:
`projects:testIamPermissions` (Cloud Resource Manager) and
`{sa}:testIamPermissions` (IAM), over plain REST via `reqwest`.

---

## 6. Deploy-time invariants

These four are load-bearing. Each replaced an obvious implementation that was
wrong.

### Intent is fingerprinted before staging

`revision_intent(...)` hashes image, runtime SA, scaling, session affinity,
secret name, boot env, and the NAMES of secret-sourced env vars (never their
version or value) **before** anything is staged. A warm is retried
routinely (the CLI re-runs `op env up`; a previous attempt may have died
mid-flight), and the trait requires the second call with the same input to
succeed. Computing intent first means a retry knows what it wants **without
minting secret versions to find out**.

Existence alone is not convergence: a live revision with a *different* intent is
a `Conflict`, not a success. Cloud Run revisions are immutable, so new material
means a new revision — never an in-place update.

### The invoker policy is applied last

Only after the new revision is proven ready. The policy is **service-wide**, not
per-revision, so applying it earlier changes access on the revision *currently
serving traffic* even when this deploy then fails or times out. A
`public`→`authenticated` flip is an outage; the inverse exposes production on a
failed deploy. Deferring past the readiness wait means a failed revision never
touches live access.

Note the Service upsert alone does **not** set this policy — it is a separate IAM
resource, so a `public` service 403s without it.

### The seed secret is claimed, not probed

`secret_prefix` is a free-text answer, so two environments in one project can
resolve to the same secret name while keeping *different* runtime service
accounts. Probe-then-create is not a boundary: two concurrent warms both observe
`Absent`, and the loser's seed lands in the winner's secret — handing one
environment's SA read access over the other's dev-store.

So `ensure_secret` claims the name in **one operation** and returns whether it
already existed; ownership is decided from the returned stamp. The create path is
the only one that stages, so it is the only one that needs the guard.

The owner stamp is a readable prefix plus **208 bits of SHA-256 over the original
env id**. The digest is the identity; the prefix is decoration. An earlier
32-bit digest had findable collisions between two valid env ids — a full bypass
of the ownership boundary. **Do not shorten it**, and do not fold the id into the
label charset instead (`a.b` and `a-b` render identically, which reads two
environments as one owner).

### Writes carry an etag

Cloud Run collapses service, task-set, and listener into one `Service` whose
`traffic[]` is under optimistic-concurrency control. `get_service` returns the
etag; `upsert_service` and `set_traffic` carry it as a precondition. A stale
write surfaces as `PreconditionFailed` (mapped from gRPC `ABORTED` /
`FAILED_PRECONDITION`, or HTTP 409/412) and the deployer **re-reads and
recomputes** rather than replaying stale state. Retries are bounded so a genuine
conflict errors instead of spinning.

---

## 7. The seed contract

The runtime needs its environment at boot and Cloud Run has no persistent disk,
so the deployer stages into Secret Manager and mounts read-only.

- **One secret, several versions**, projected at different relative paths. Cloud
  Run forbids nested mounts, so the seed tree is subdirectory *items* of one
  volume, never several volumes.
- **Versions are pinned numerically, never `latest`** — a revision always boots
  the exact seed it was created with. This is what makes an immutable revision
  meaningful.
- `secretAccessor` is granted to the runtime SA **before** the revision is
  created. Cloud Run rejects a revision whose SA cannot read a mounted version,
  so this ordering is not optional.
- `HOME=/tmp` because Cloud Run's root filesystem is read-only except `/tmp`,
  which is in-memory. The seed is re-copied on every cold start.
- The deployer's own credential is **excluded** from the seed. A workload never
  receives the identity that deployed it.

Boot env vars are set by `runtime_boot_env`. `GREENTIC_GATEWAY_LISTEN_ADDR=0.0.0.0`
is required — greentic-start otherwise binds loopback and Cloud Run's health
check never passes.

---

## 8. Testing

No real GCP in CI. Every request-build and response-parse step is a pure free
function (`build_*`, `*_from`, `classify_*`) unit-tested with SDK types built via
their builders. The async glue that `.await`s a client is exercised only by the
gated live E2E.

```bash
cargo test -p greentic-deployer --no-fail-fast          # unit + integration
bash ci/local_check.sh                                  # the full gate
```

The live lifecycle test bills a real project and is armed by **exactly**
`GREENTIC_GCP_E2E=1` — unset, `0`, or `true` all skip:

```bash
GREENTIC_GCP_E2E=1 GTC_GCP_E2E_PROJECT=… GTC_GCP_E2E_REGION=… \
  cargo test -p greentic-deployer --test gcp_cloudrun_e2e
```

Missing a `GTC_GCP_E2E_*` scope var while armed fails immediately naming the
exact var, rather than surfacing as an opaque GCP error three calls later.

---

## 9. Deliberate omissions

Not gaps to fix casually — each has a reason:

- **No `op env reconcile` / `op env render`.** Cloud Run is imperative; there is
  no cluster to diff against and no prune step.
- **Multi-instance is gated, not free** (`shared_state::gate`, run in
  `warm_revision` before any provider call). "Multi-instance" is the EFFECTIVE
  ceiling (`multi_instance_shape`): `max_instances = 0` renders an unset
  `maxInstanceCount`, which Cloud Run reads as its default (up to 100), and
  `min_instances > 1` keeps several warm. Only `max_instances == 1` with
  `min_instances <= 1` (the default) is single. A second instance gets its own
  in-memory store, so three things must be shared first, and the gate refuses
  unless all hold:
  - **Sessions + flow state** — `redis_url` makes `runtime_boot_env` add
    `GREENTIC_RUNNER_SESSION_BACKEND=redis` / `GREENTIC_RUNNER_STATE_BACKEND=redis`,
    and the URL rides as `GREENTIC_RUNNER_REDIS_URL` from one pinned version of
    its OWN env-owned secret, `<secret_prefix>-redis-url` (owner-guarded — an
    existing one stamped by another env or by nobody is refused —
    accessor-granted). An unchanged URL reuses the newest enabled version that
    already holds it, so all deployments share one version. A NEW value mints
    a version, and once that warm's revision is ready (after the invoker grant)
    every enabled version older than the immediately previous one is disabled
    and destroyed: the previous one stays because the revisions still serving
    (a warm adds its revision at 0 %) and a rollback pin it. Destroy/list are
    optional permissions (`SECRET_VERSION_PRUNE_PERMISSIONS`, granted by the
    bootstrap role, not preflighted); without them the old versions stay and
    the warm only warns. A deployment not re-warmed across two URL changes pins
    a destroyed version — accepted, since that value was superseded twice. The
    seed secret is never pruned; URL versions PD4 staged there before this
    stay until `op env destroy`, which also deletes the Redis URL secret (only
    when this env stamped it).
  - **Revision pins** — the same version also feeds
    `GREENTIC_REVISION_PIN_REDIS_URL`.
  - **Generated secrets** — greentic-start's `revision_secrets` mints a missing
    declared `generated` secret at boot, per instance. The CLI
    (`cli::cloudrun_generated_secrets`) pre-mints each one into the env dev store
    (never re-minting an existing one), stages, and checks the staged bytes; the
    handler carries the verdict as `GeneratedSecretSeed` and only `Complete`
    passes.

  A VPC route is also required (the URL carries AUTH and v1 has no TLS —
  `rediss://` is refused, P5-R5). `shared_state::multi_instance_safe(&params)` is
  the adapter capability (Redis + VPC answered); the gate adds the seed check.
  Redis/VPC answers move `revision_intent` (secret-env NAMES, boot selectors, and
  `revision_intent_with_vpc`); their absence leaves it byte-identical.
- **Traffic splits must be whole percents.** Cloud Run works in whole integer
  percents summing to 100; non-multiples of 100 bps are rejected, never silently
  rounded.
- **Secret versions accumulate.** Each warm adds versions; nothing GCs them.
  `op env destroy` deletes the whole secret.

### Drain and capabilities (P5-R2 / P5-R3)

`drain_revision` first reads the live Service and confirms its `traffic[]`
gives the revision **0 %** — the live traffic, not the recorded split, because
a split recorded but never pushed still routes requests. Traffic pinned to
`LATEST` (or any entry not attributable to a named revision) is never read as
drained. Only after that does it wait the revision's `drain_seconds` (capped by
`GREENTIC_DEPLOYER_DRAIN_MAX_SECONDS`) as grace for requests in flight at the
cut, then confirms again. Cloud Run then scales the revision to zero itself.
The archive branch of `op env apply-revision` runs the same check without
waiting and refuses (`not-drained`) unless `--force-drain`.

**A whole-bundle retire is different.** One Service per deployment, and its
`traffic[]` always sums to 100 %, so the Service's last revision can never
reach 0 %. When the deployment is retiring (`op bundles retire` marked it
`archived`), drain confirmation is "no messaging endpoint still routes to the
bundle" plus the drain window, and the archive step deletes the whole Service.
The 0 % check applies only to retiring one revision while others of the same
Service keep serving; a revision that is the Service's only one is told to
retire the bundle, not to push a split.

The adapter claims `drain`,
`traffic_split`, `ingress_managed`, `remove`; it does **not** claim
`multi_instance_safe` (the session store is `/tmp`, see above) or
`private_registry_auth`.

---

## 10. SoR units (SoRLa phase 3E)

`op env up` on a Cloud Run environment deploys each declared `sor_units[]`
entry as its own Cloud Run service `gtc-sor-<unit_id>` BEFORE any worker is
warmed, because a worker finds its SoR through the route document
`default/_/sorla/<sor>` in the dev store, and a revision keeps the seed it was
created with. There is no `op env reconcile` here: the whole SoR phase runs
inside `op env up` (`cli::env_cloudrun_sor`, core in `cli::env_sor::cloudrun`).

- **Two seams.** Inputs are versions of ONE owner-stamped secret
  `<secret_prefix>-sor-<unit_id>` staged through `CloudRunTarget` (same
  claim-then-write ownership rule as the seed, but an unstamped secret is
  refused, not adopted). The service goes through `sor::target::SorServiceTarget`
  because it is addressed by name, not `DeploymentId`.
- **Intent, not existence.** The service carries `greentic-sor-intent`, a
  digest of image, pack, runtime identity, every input and the fixed shape. A
  re-run with the same intent stages nothing and deploys nothing — unless the
  latest revision FAILED, which is always redeployed.
- **Order per run:** stage → Artifact Registry reader grant (best effort; a
  refusal is a `sor_notes` entry carrying the `gcloud` command) → upsert → wait
  (`GREENTIC_GCP_SOR_READY_TIMEOUT_SECS`, default 300) → `allUsers` invoker →
  route document → workers → traffic → retire → narrow the ledger.
- **Retirement** deletes only what this environment's owner stamp owns, and
  never a service or secret a declared unit still uses.
- **Permissions.** The SoR path needs nothing beyond
  `REAL_CLOUDRUN_TARGET_IAM_PERMISSIONS` (pinned by
  `sor::real::tests::the_sor_permission_contract_holds`). The reader grant's
  `artifactregistry.repositories.{get,set}IamPolicy` are deliberately NOT
  validated.
- **Ledger.** `sor-units.applied.json` entries carry `cloud_run: {service,
  secret, project, region}` instead of `namespace`; a ledger of the other lane
  is refused, not migrated. `op env destroy` retires every Cloud Run SoR unit it
  records.
- **Live E2E:** `tests/gcp_cloudrun_sor_e2e.rs` (`GREENTIC_GCP_E2E=1`).

---

## See also

- [`cloudrun-deployment.md`](cloudrun-deployment.md) — the operator-facing guide.
- [`env-packs.md`](env-packs.md) — authoring an env-pack.
- `../CLAUDE.md` — repo orientation, and the two-architectures warning.
- `tests/gcp_cloudrun_e2e.rs` — the executable version of the lifecycle above.
- `tests/gcp_cloudrun_sor_e2e.rs` — the SoR-unit lifecycle in §10, live.
