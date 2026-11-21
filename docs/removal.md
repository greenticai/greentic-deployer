# Removing things from an environment

Audience: operators. Covers `op traffic clear`, `op bundles retire`, and
`op env apply --prune`.

Two rules decide everything below:

- **Omission is never deletion.** `op env apply` is upsert-only by default: a
  bundle, endpoint or secret you drop from the manifest stays in the
  environment. Removal is always an explicit command.
- **Retire is a sequence, not a delete.** A deployment leaves an environment by
  clearing its traffic, draining, archiving every revision, and only then being
  removed. Tenant data is never destroyed by any of these commands — that is a
  separate workflow.

Every command here is **idempotent**. Re-running one after a failure finishes
the work instead of repeating it; the environment store is the checkpoint.

These verbs act on the local store (`--store-root`). Against a remote store
(`--store-url`) they answer `not supported` until the A8 contract grows routes
for them — `env apply --prune` included (refused, never silently ignored).

## `op traffic clear`

```bash
# Move 100 % of the traffic to one revision (it must be Ready).
greentic-deployer op traffic clear local --deployment <DEPLOYMENT_ULID> --survivor <REVISION_ULID>

# Remove the split entirely — only for a deployment already retiring.
greentic-deployer op traffic clear local --deployment <DEPLOYMENT_ULID>
```

- With `--survivor`, this is `op traffic set <survivor>=100%` with the same
  admission check and one-step rollback. With no `--idempotency-key`, the key is
  derived from the deployment and survivor, so a retry does not advance the
  generation.
- Without `--survivor`, the split is removed. That takes the deployment
  offline, so it is refused (`conflict`, "is not retiring") unless the
  deployment's status is already `archived` — which `op bundles retire` sets.

Output: `{"op":"clear","noun":"traffic","result":{"mode":"survivor"|"cleared","changed":…}}`.

## `op bundles retire`

```bash
greentic-deployer op bundles retire local <BUNDLE_ID_OR_DEPLOYMENT_ULID> [--customer <ID>] [--store-only]
```

Runs, in order:

1. **clear** — refuses if a messaging endpoint links the bundle (or welcomes into
   it) and no other deployment of the same bundle id survives: unlink it first
   with `op messaging endpoint unlink-bundle`. Otherwise marks the deployment
   retiring (status `archived`) and removes its split.
2. **drain** — stamps each `Ready` revision `Draining`, then calls the bound
   deployer's `drain_revision` for every draining revision.
3. **teardown, then archive** — per revision, tears it down through the bound
   deployer (`archive_revision` — the same path as `op env apply-revision`)
   FIRST, and archives it in the store only once that succeeded. Teardown also
   re-runs for already-archived revisions (it is idempotent).
4. **remove** — removes the deployment and its archived revisions.

If a teardown fails, that revision stays un-archived and the retire stops
**before** step 4, so the store keeps the record of what may still be running.
Fix the cause and run the same command again.

A bound deployer that cannot tear revisions down (e.g. `local-process`) is
refused up front, before anything changes (`conflict`, "lacks the `remove`
capability"). An environment with no deployer binding at all reports each hook
as `"unavailable"` and the retire proceeds on the store alone. `--store-only`
skips the provider on purpose — for an environment whose provider is gone for
good; anything still running provider-side is left for an orphan sweep.

A bundle id deployed for several customers needs `--customer` (or pass the
deployment ULID). Retiring something that is not there answers
`"state": "absent"` rather than an error.

Output (`result`): `state` (`retired` | `absent`), `deployment_id`,
`bundle_id`, `customer_id`, `marked_retiring`, `split_cleared`, `drained`,
`drain_hook[]`, `archived`, `teardown[]` (each `{revision_id, result:
done|unavailable, detail?}`), `pruned_revision_ids`.

## `op env apply --prune --confirm-prune`

```bash
greentic-deployer op --answers env.json env apply --prune --confirm-prune --yes
```

After the normal upsert apply has executed and verified, prune retires, whole,
each deployment this **manifest owns** but no longer declares (the sequence
above, one audit event each). It never touches revisions inside a deployment
the manifest still declares — an unrouted `Ready` revision there may be a
warmed canary waiting for `op traffic set`.

**Ownership** is recorded per manifest by every successful `op env apply` in
`<env_dir>/env-apply-ownership.json` (captured by env snapshots). The owner key
is a hash of the manifest file's canonical path, so:

- a manifest only ever prunes what IT declared before — two manifests applied
  to one environment never prune each other's bundles, and a deployment both
  claim is never pruned;
- moving or renaming the manifest starts a fresh, empty ownership;
- a deployment the manifest matches by `(bundle_id, customer_id)` is adopted
  and owned from then on;
- a deployment added by hand (`op bundles add`, `op deploy`), or applied before
  this ledger existed, is never pruned until a manifest has declared it once.

Refusals, all before anything — the upsert half included — is mutated:

- `--prune` without `--confirm-prune` → `invalid-argument`.
- a bound deployer without the `remove` capability → `conflict`.
- a messaging endpoint the whole retire set would strand → `conflict`, naming
  it (checked across the set, so two deployments of one bundle cannot vouch
  for each other).

`--dry-run` / `--check` with `--prune --confirm-prune` report the plan under
`prune` (`planned: true`, `owner`, `retire[]`); `--check` counts pending prune
items as drift. Without `--prune` the report carries no `prune`
key at all — default apply output is unchanged.

After a prune on K8s, run `op env reconcile` so the router's runtime config
stops naming the removed deployment.

## Pruning during `op env up`

```bash
greentic-deployer op --store-root ./state --answers env.json env up --prune --confirm-prune --dry-run
greentic-deployer op --store-root ./state --answers env.json env up --prune --confirm-prune --non-interactive
```

`env up` forwards both flags to the same ownership-aware apply/retire engine.
Without `--prune`, omitted deployments remain. `--yes` and
`--non-interactive` do not replace `--confirm-prune`: missing confirmation
fails before cluster provisioning or environment creation, including dry runs.
Dry runs report `result.prune.retire` deployment IDs and change nothing.
A successful imperative bring-up includes apply's `result.prune` retirement
report. A failed retirement stops before bring-up; the store and ownership
ledger retain the unfinished deployment so the same operation can retry it.
Endpoint links and welcome flows retain the existing refusal checks. Handle
those explicitly through the supported endpoint operations; pruning does not
unlink routes, force a drain, or ignore teardown/readiness failures.

### Designer coordination and the removed-worker incident

Verified against develop `379ed6b` and Designer's pinned deployer
`0f04a869eb7347dc453a8298f73005a7e8a6bd38`: there are no intervening
changes to `env_up.rs`, the prune engine, `env.rs`, or the Cloud Run deployer.
The prune implementation arrived in `3b1c715` (#628), capability refusal in
`182555c` (#633), and drain-window overrides in `0210aa8` (#634). Readiness
conditions and provider log URLs were already added by `a072fe6` (#617).
Those improvements do not remove omitted deployments during `env up`.

The removed `invoice-review-worker-2` deployment remains in the persisted
environment with a traffic split targeting a failed immutable revision.
Cloud Run bring-up warms split-selected revisions from that store, rather
than just the latest manifest's workers. Retrying the same revision preserves
its seed's pinned secret versions and therefore repeats the old credential
failure. This fix retires an authorized owned omission before that warm;
it does not change immutable revision or credential behavior.

Designer needs a separate coordinated change:

- Resolve a deployer release/build containing this fix and update its pinned
  commit or binary. Its current pin cannot accept these `env up` flags.
- Send **both** flags on the normal `env up` call only after confirmed removals
  within the selected deployment scope. Omission alone is insufficient.
- Keep a stable canonical answers-file path per manifest/scope and retain the
  ownership ledger with the store and snapshots. Temporary paths or renamed
  files acquire a new empty owner; pre-ledger deployments are unmanaged until
  explicitly adopted by a manifest. Shared deployments claimed by another
  manifest are protected. Do not repurpose a single owner for partial scopes.
- Keep apply/prune inside `env up` so the existing before/after snapshot and
  failed-deploy cleanup encompass the whole operation. Do not add a separate
  mutating `env apply` ahead of that snapshot. Preserve retry checkpoints after
  retirement failure; do not recreate a removed worker during cleanup.
- Consume the dry-run retirement IDs for review and handle endpoint/welcome
  flow refusals through the existing explicit removal workflow.

The existing stale deployment also needs a **separate authorized one-time
retirement** if the original manifest owner cannot prune it. Confirm the
store/environment, exact deployment ID, ownership, endpoint links and welcome
flows first, then use the normal lifecycle (example only, not executed):

```bash
greentic-deployer op --store-root <reviewed-store> bundles retire <environment-id> 01M7N57ARXJW6N5TCCMJPZT1AE
```

Do not use `--store-only` or `--force-drain` to work around this incident.
Handle any linked routes explicitly before retrying. The failed revision
`01M7N57AWG0H4JWTW0D5VFPFC7` must be drained/torn down through the supported
lifecycle; readiness failures for any remaining worker still fail deployment.
No production retirement, credential rotation, IAM change or deployment was
performed for this fix.

### Readiness diagnostic compatibility

The leading sentence remains
`Cloud Run revision <logical revision ULID> did not become ready within <N>s`
(with backticks around the ID). The diagnostic now appends deterministic
`Cloud Run provider revision` and `service` names, plus project and region.
The provider revision comes first so a consumer extracting the first `gtc-…`
resource sees the revision rather than its shorter service-name prefix.
Provider conditions and `Revision logs: <URL>` remain appended when Cloud Run
supplies them. Logical IDs and existing error kinds are preserved; no secret
material is added. Designer's log extractor should prefer the explicit
`provider revision` field (`gtc-svc-<deployment-ulid>-<revision-ulid>`) rather
than treating the first backticked logical ID as a provider resource name.
Coordinate that parser change separately; the message remains a textual
provider error, not a new structured error schema.
