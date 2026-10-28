# Azure Container Apps: seed, secrets and bundle delivery (decision record)

Status: decided 2026-10-27 for the first implementation of
`src/env_packs/azure_aca` (`greentic.deployer.azure-aca@1.0.0`). **No Azure
subscription or credential existed when this was written, so nothing below was
exercised against Azure.** Every fact that only a live call can settle is marked
`NEEDS_LIVE`; the code implements the conservative default and isolates the
choice behind ONE function so the live E2E can flip it. Sibling record for the
runtime contract this reuses: `docs/aws-ecs-seed-and-bundle-delivery.md`
(`GREENTIC_SEED_DIR` layout, `OCI_USERNAME` / `OCI_PASSWORD`).

## Decisions (user, final)

| # | Decision |
|---|---|
| D1 | ARM REST over `reqwest`, behind an `AcaDeployTarget` trait with a mockable `AzureHttp` transport. No `azure_*` crates. |
| D2 | The bundle is pulled by greentic-start from the operator's ACR using an ACR repository-scoped token injected as `OCI_USERNAME` / `OCI_PASSWORD`. The password is an ACA secret referenced by `secretRef`; only its presence is in the revision intent. |
| D3 | Public HTTPS on the platform `*.azurecontainerapps.io` domain. No certificate handling. |
| D4 | Default location `southeastasia`. No live testing in this change. |
| D5 | The operator provides the managed environment, Log Analytics workspace and ACR. A `az` setup script is shipped by `op credentials bootstrap`. |
| D6 | Service principal with a client secret (Entra client-credentials flow). |

## Pinned values (one constant each)

| Item | Value | Where | Status |
|---|---|---|---|
| ARM api-version | `2024-03-01` | `arm_paths::API_VERSION` | `NEEDS_LIVE` (GA, has `initContainers`, `volumes`, `ingress.traffic[]`; confirm) |
| App name limit | 32 characters | `naming::APP_NAME_MAX` | `NEEDS_LIVE` |
| Revision suffix | `r` + lowercased revision id, `[a-z0-9-]`, no `--`, at most 64 | `naming::revision_suffix` | documented by Microsoft Learn |
| Seed size cap | `SEED_MAX_BYTES = 24_576` | `seed::SEED_MAX_BYTES` | `NEEDS_LIVE` (per-secret cap not found in docs; 24 KiB is the Key Vault limit, conservative) |
| Seed mechanism | `SecretRef` env into the init container | `seed` module (init script + `deployer_warm::plan`) | `NEEDS_LIVE` (secret volume into an init container, and `/` in a volume `path`, unverified) |
| Secrets update | full `PUT` re-sending every secret from `listSecrets` | `deployer_warm::merge_secrets` | `NEEDS_LIVE` (whether a `PATCH` merges secrets by name is unverified) |
| cpu / memory pairs | consumption pairs `0.25/0.5Gi` .. `4/8Gi`, memory = 2 x cpu | `sizing::snap` | `NEEDS_LIVE` |
| Intent read-back | container env `GREENTIC_REVISION_INTENT` on `GET revision` | `status::intent_from_revision` | `NEEDS_LIVE` (whether the revision GET exposes `template.containers[].env` is unverified; if absent the revision reads as unstamped, which is a CONFLICT, never an adoption) |
| Platform ingress | `ingress.external=true`, `targetPort=8080`, `allowInsecure=false` | `arm_body` | documented |

## Seed delivery

greentic-start reads `GREENTIC_SEED_DIR` (here `/seed`) holding
`environment.json` and, when the environment has a dev store,
`.greentic/dev/.dev.secrets.env` (the contract is the AWS record's section 3).

1. Each seed file is stored as an app-scope ACA secret named by CONTENT:
   `seed-env-<12 hex of sha256>` and `seed-dev-<12 hex>`. A secret name that is a
   function of its bytes is immutable, so a re-warm of identical inputs adds
   nothing and a live revision never sees its secret change.
2. A busybox **init container** receives each file as a `secretRef` environment
   variable (`GREENTIC_SEED_<STEM>`) plus its expected digest
   (`GREENTIC_SEED_<STEM>_SHA256`, plain: a digest is public), writes it onto an
   `EmptyDir` volume mounted at `/seed` with `printf '%s'`, then verifies with
   `sha256sum -c`. The worker container mounts the same volume read-only.
3. A seed file that is over `SEED_MAX_BYTES`, not UTF-8, or containing a NUL is
   refused with a named error BEFORE any ARM write. Never truncated.

Fallback when `NEEDS_LIVE` shows secret volumes reach init containers and accept
a nested `path`: switch the init container to a secret volume in `arm_body` + `deployer_warm::plan` (raises the cap; the
init container then only copies). Only the secretRef-env mechanism is implemented.

## Secrets are read-modify-write

ARM `GET` never returns secret values, and a whole-app `PUT` that omits a secret
deletes it. A warm therefore calls `listSecrets`, merges the new content-addressed
secrets into the full set and re-sends everything (`secrets_with_values`, which
refuses to drop an existing value). A secret still referenced by a non-inactive
revision is never deleted; the fake enforces this and the real target never
issues a secret delete.

## Bundle pull (D2)

The runtime image is public GHCR (no `registries[]`). The bundle is pulled by
greentic-start from the ACR named in `bundle_source_uri` with the explicit pair
`OCI_USERNAME` (plain env, part of the intent) / `OCI_PASSWORD` (ACA secret,
`secretRef`, only its presence in the intent). The token is the ACR
repository-scoped token created by the setup script (`content/read` scope map;
no expiry is requested: `NEEDS_LIVE` confirms the token-password expiry options).
Ambient managed-identity pull would need a greentic-start change and is a later
phase.

## Revisions and traffic

One Container App per deployment, `activeRevisionsMode: Multiple`, one ACA
revision per Greentic revision. Every `PUT` carries an explicit traffic list:
the first revision at 100, a later revision at 0 with every earlier revision at
its prior weight and `latestRevision: false`. A split rewrites `ingress.traffic`
only. Weights are whole percents, so a split must be a multiple of 100 bps
(refused by `op env up`'s preflight and by the verb). `max_instances` must be 1
(single writer of the per-replica seed); `min_instances` is 0 (scale to zero) or
1 (keep warm).

## Not verified against Azure

Everything. All ARM shapes are golden JSON written from documentation, all
behaviour is proven by the in-memory fake and a recording transport. See the
`NEEDS_LIVE` rows above and Task 12 of the plan for the gated harness.
