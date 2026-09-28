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
for them.

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
3. **archive** — archives every revision in the store, then tears each one down
   through the bound deployer (`archive_revision` — the same path as
   `op env apply-revision`). Teardown runs for already-archived revisions too:
   an earlier attempt may have archived one and then failed to tear it down.
4. **remove** — removes the deployment and its archived revisions.

If a teardown fails, the retire stops **before** step 4, so the store keeps the
record of what is still running. Fix the cause and run the same command again.

An environment with no deployer binding, or a deployer with no live
single-revision path (`local-process`), reports each hook as `"unavailable"`
and the retire proceeds on the store alone. `--store-only` does the same on
purpose — for an environment whose provider is gone for good; anything still
running provider-side is left for an orphan sweep.

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

After the normal upsert apply has executed and verified, prune removes what
this environment's manifest **owns** but no longer declares:

- an owned deployment missing from the manifest is retired whole (the sequence
  above, one audit event each);
- in an owned deployment that is still declared, a settled revision
  (`Ready | Draining | Inactive | Failed`) that its split no longer routes to is
  archived and torn down. `Staged` / `Warming` revisions are left alone — they
  may be a rollout in flight.

**Ownership** is recorded by every successful `op env apply` in
`<env_dir>/env-apply-ownership.json`: the deployments its manifest declared. A
deployment added by hand (`op bundles add`, `op deploy`), or applied before this
ledger existed, is not in it and is never pruned until a manifest has declared
it once.

Refusals, all before anything is mutated:

- `--prune` without `--confirm-prune` → `invalid-argument`.
- a retire that would strand a messaging endpoint → `conflict`, naming it.

`--dry-run` / `--check` with `--prune --confirm-prune` report the plan under
`prune` (`planned: true`, `retire[]`, `archive_revisions[]`); `--check` counts
pending prune items as drift. Without `--prune` the report carries no `prune`
key at all — default apply output is unchanged.

After a prune on K8s, run `op env reconcile` so the router's runtime config
stops naming the removed deployment.
