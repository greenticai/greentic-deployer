# Airgap Update Quickstart

How to move a signed update plan and its artifacts across an air-gapped
boundary using `greentic-deployer op updates {export,import,apply,cas-gc}`.

> **Audience.** Operators running Greentic environments on networks that cannot
> reach the plan server or artifact registries directly.

> **Commands below say `greentic-deployer` on purpose.** `gtc op ...` delegates
> to `greentic-operator`, a separate binary on its own release cadence.

---

## Prerequisites

- A **staging-side** machine with network access (or a prior `op updates get`).
- A **receiving-side** machine with the target environment's local store.
- An Ed25519 signing key trusted by both sides (in the environment's
  `trust-root.json`).

---

## 1. Stage the plan (staging side)

```bash
greentic-deployer op updates get <ENV_ID> \
  --plan-url https://plans.example.com/v1/plan
```

Or from local files:

```bash
greentic-deployer op updates get <ENV_ID> \
  --plan-file plan.json --plan-sig-file plan.json.sig
```

---

## 2. Export the envelope

### Content-only plan

```bash
greentic-deployer op updates export <ENV_ID> \
  --plan-id <PLAN_ID> \
  --out /mnt/usb/update.gtupdate \
  --signing-key operator-key.pem
```

### Plan carrying binary artifacts

Supply each binary file via the repeatable `--binary-blob` flag. Each file's
SHA-256 must match a `binaries[].digest` in the plan:

```bash
greentic-deployer op updates export <ENV_ID> \
  --plan-id <PLAN_ID> \
  --out /mnt/usb/update.gtupdate \
  --signing-key operator-key.pem \
  --binary-blob /path/to/gtc-linux-amd64 \
  --binary-blob /path/to/gtc-darwin-arm64
```

A file matching no plan binary is a hard error. Two files with the same digest
are rejected.

### Target filtering

Include only binaries for specific platforms (content artifacts always
included):

```bash
greentic-deployer op updates export <ENV_ID> \
  --plan-id <PLAN_ID> \
  --out /mnt/usb/update.gtupdate \
  --signing-key operator-key.pem \
  --binary-blob /path/to/gtc-linux-amd64 \
  --targets x86_64-unknown-linux-gnu
```

### Delta export

Use the receiving side's import receipt to skip blobs it already holds:

```bash
greentic-deployer op updates export <ENV_ID> \
  --plan-id <PLAN_ID> \
  --out /mnt/usb/delta.gtupdate \
  --signing-key operator-key.pem \
  --base-receipt /mnt/usb/import-receipt.json \
  --base-receipt-sig /mnt/usb/import-receipt.json.sig
```

The receipt must cover the same environment id and be signed by a trusted key.

---

## 3. Transfer

Copy the `.gtupdate` file to the receiving machine (USB, optical media,
one-way diode).

---

## 4. Import (receiving side)

```bash
greentic-deployer op updates import <ENV_ID> \
  --envelope /mnt/usb/update.gtupdate \
  --signing-key operator-key.pem \
  --stage
```

Without `--stage` the plan lands in `inbox`. The `--staleness-days` flag
(default: 30) controls the advisory age threshold; plans older than this
produce a warning but are still imported.

After import, copy the receipt back to the staging side for future delta
exports:

```bash
cp ~/.greentic/updates/<ENV_ID>/import-receipt.json     /mnt/usb/
cp ~/.greentic/updates/<ENV_ID>/import-receipt.json.sig /mnt/usb/
```

---

## 5. Apply

```bash
greentic-deployer op updates apply <ENV_ID> --plan-id <PLAN_ID>
```

Re-verifies the plan end to end, snapshots the environment, drives the
env-apply pipeline, and marks the plan `applied` on success (or restores the
snapshot on failure). Binary artifacts are **not** installed by this verb;
binary self-update is handled by `greentic-start`.

---

## 6. Delta workflow

```
Staging side                    USB / diode           Receiving side
────────────                    ───────────           ──────────────
get (or plan-build+publish)
export --base-receipt ──────►   delta.gtupdate  ────► import --stage
                                                      apply
                          ◄──── receipt files    ◄─── (copy receipt)
```

Each delta carries only the blobs the receiver lacks.

---

## 7. CAS garbage collection

```bash
greentic-deployer op updates cas-gc <ENV_ID> --signing-key operator-key.pem
```

Removes CAS blobs not referenced by any non-evicted staged plan, then rewrites
the import receipt. **Do not run concurrently with `op updates import`** on the
same environment; a concurrent GC can evict blobs of a plan admitted after its
snapshot. Recovery: re-import with the full envelope.

---

## Troubleshooting

### "blob(s) missing on disk" on export

The plan references binary blobs not in the staging tree. Supply them via
`--binary-blob`. The error names the missing digests.

### "matches no binary in the plan"

A `--binary-blob` file's SHA-256 does not match any plan binary. The error
names the file and its computed digest.

### Signing-identity preflight failure

Both export and import preflight-verify the signing key against the trust root
before any output. If the key-id is not registered:

```
signing identity `<key-id>` is not trusted by env `<env-id>`'s trust root
```

Register the key or pass `--trust-root <path>` to override the lookup.

### Staleness advisory (default 30 days)

Import warns for plans older than `--staleness-days`. Advisory only; the plan
is still imported. Increase with `--staleness-days 90`.

### cas-gc "corrupt marker" abort

A `state.json` under a staged plan is invalid JSON. GC aborts without evicting
anything (a skipped plan would make its blobs look orphaned). Repair or remove
the corrupt plan directory before retrying.

### CAS integrity failure on delta import

A CAS-held blob's on-disk content does not match its digest. Import aborts
before writing any new state. Recovery: re-import with the full envelope.
