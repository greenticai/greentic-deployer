# PR-30: Generate target-bound greentic-secrets provider bindings

## Current Baseline

Cloud deploys already promote runtime application secrets into the target cloud
secret store:

- AWS promotes to AWS Secrets Manager.
- GCP promotes to Google Secret Manager.
- Azure promotes to Azure Key Vault.

The generated Terraform currently bridges those cloud secrets back into
`greentic-start` as environment-backed secrets:

- `runtime_secret_env` maps canonical env names such as
  `GREENTIC_SECRET__DEV__DEMO_____MESSAGING_WEBCHAT_GUI__JWT_SIGNING_KEY` to
  cloud secret names.
- `runtime_secret_env` also keeps the bare key alias for compatibility, for
  example `jwt_signing_key`.
- `secrets://...` URIs are not used directly as container env var names.
- `GREENTIC_SECRETS_BACKEND=env` and `GREENTIC_ALLOW_ENV_SECRETS=1` are set
  when runtime secrets are present.
- AWS already adds `task_runtime_secrets` IAM read permissions for the task
  role.
- GCP and Azure modules already wire runtime identity access to Secret Manager
  and Key Vault respectively.

`greentic-start` also already has a secrets-pack discovery path. It searches
for `.gtpack` files under `providers/secrets/{tenant}/{team}`,
`providers/secrets/{tenant}`, `providers/secrets/`, or the
`GREENTIC_SECRETS_MANAGER_PACK` override. Today that path only selects the
small backend file inside the pack (`assets/secrets_backend.json`,
`assets/secrets-backend.json`, `secrets_backend.json`, or
`secrets-backend.json`) and the effective runtime backends are still only
`dev-store` or `env`.

This means PR-30 should not be implemented as a blind deletion of
`runtime_secret_env`. That env bridge is the current compatibility path and
must remain until `greentic-start` can consume provider bindings at runtime.
It also means injecting a `providers/secrets/*.gtpack` file is not sufficient
proof that cloud-provider runtime lookup is active; deployer must generate the
new binding contract.

## Problem

The current cloud behavior still makes runtime application secret lookup depend
on deployer-generated env vars. That keeps `greentic-start` coupled to deployer
injection details even though the actual secret values already live in the
target cloud secret store.

`greentic-secrets` already contains provider packs for AWS Secrets Manager, GCP
Secret Manager, Azure Key Vault, Kubernetes, Vault, and local/dev use. The next
design should let deployer output select one of those providers explicitly and
let `greentic-start` resolve canonical `secrets://...` URIs through that
provider instead of through env aliases.

## Goal

For each supported target, generate a `greentic.secrets.binding.v1` config that
tells `greentic-start` which `greentic-secrets` provider pack to use and how to
configure it.

Target mapping:

- AWS -> `greentic.secrets.aws-sm`
- GCP -> `greentic.secrets.gcp-sm`
- Azure -> `greentic.secrets.azure-kv`
- local/dev -> `greentic.secrets.dev`

The first deployer PR should add the binding artifact and preserve the existing
env bridge. Removal of runtime app secret env injection should happen only after
the `greentic-start` binding support is merged and covered by an end-to-end
compatibility test.

The deployer binding work should be coordinated with:

- `../greentic-start/.codex/PR-SECRET-01-deployment-compat-harness.md`
- `../greentic-start/.codex/PR-SECRET-02-use-greentic-secrets-providers.md`

## Binding Shape

Align with `../greentic-start/.codex/PR-SECRET-02-use-greentic-secrets-providers.md`.
A representative generated binding is:

```json
{
  "schema_version": "greentic.secrets.binding.v1",
  "provider_id": "greentic.secrets.aws-sm",
  "pack": "providers/secrets/aws-sm.gtpack",
  "config": {
    "region": "eu-north-1",
    "prefix": "greentic/dev/demo/_"
  }
}
```

The file path must be stable and shared with `greentic-start`, for example:

```text
state/config/platform/secrets-provider.json
```

or another agreed runtime config path.

This binding is distinct from the existing secrets-pack backend selector. The
deployer must not assume that a pack containing `assets/secrets_backend.json`
with `backend: "env"` satisfies this PR.

## AWS Requirements

AWS generation should:

1. Include or reference the AWS secrets provider pack.
2. Generate a secrets provider binding with provider id `greentic.secrets.aws-sm`.
3. Write the binding in the stable path expected by `greentic-start`.
4. Preserve existing generated secret promotion to AWS Secrets Manager.
5. Preserve existing task-role read permissions for the runtime secret namespace.
6. Keep the current env bridge until `greentic-start` provider binding support is
   available.
7. After `greentic-start` binding support lands, switch runtime app secret
   lookup to the provider binding and then remove per-secret ECS env injection.

Admin TLS/bootstrap secrets may remain separate if they are not part of app
runtime secret lookup.

## GCP Requirements

GCP generation should:

- bind `greentic.secrets.gcp-sm`
- write the binding in the stable path expected by `greentic-start`
- preserve existing generated secret promotion to Google Secret Manager
- preserve existing runtime service account access to Secret Manager
- keep the current env bridge until `greentic-start` provider binding support is
  available
- remove per-secret Cloud Run env injection only after binding-based runtime
  lookup is active

## Azure Requirements

Azure generation should:

- bind `greentic.secrets.azure-kv`
- write the binding in the stable path expected by `greentic-start`
- preserve existing generated secret promotion to Azure Key Vault
- preserve existing managed identity access to Key Vault secrets
- keep the current env bridge until `greentic-start` provider binding support is
  available
- remove per-secret Container App secret/env injection only after binding-based
  runtime lookup is active

## Tests

Add failing tests first:

- AWS generated output contains `greentic.secrets.binding.v1`.
- AWS generated output selects `greentic.secrets.aws-sm`.
- AWS generated binding is distinct from the existing
  `assets/secrets_backend.json` backend selector and is written to the runtime
  config path agreed with `greentic-start`.
- GCP generated output selects `greentic.secrets.gcp-sm`.
- Azure generated output selects `greentic.secrets.azure-kv`.
- AWS Terraform still grants task-role read permissions for runtime secrets.
- GCP and Azure generated modules still grant runtime identity access to their
  cloud secret stores.
- Generated secret promotion still creates or resolves cloud secret values.
- During the compatibility phase, generated task/container output still contains
  canonical env secret names such as
  `GREENTIC_SECRET__DEV__DEMO_____MESSAGING_WEBCHAT_GUI__JWT_SIGNING_KEY` and
  does not contain raw `secrets://...` env names.
- After `greentic-start` provider binding support lands, add a second-phase test
  proving runtime app secret env injection is absent while binding-based lookup
  passes.
- The `greentic-start/scripts/test_deployment.sh` generate-mode harness can be
  used in two phases:
  - before env removal, `--expect-secrets-provider greentic.secrets.aws-sm`
    should pass and `--expect-no-runtime-secret-env` should fail;
  - after `greentic-start` binding support is active and deployer removes env
    injection, both `--expect-secrets-provider greentic.secrets.aws-sm` and
    `--expect-no-runtime-secret-env` should pass.

## Acceptance Criteria

- Cloud deployer output binds to a `greentic-secrets` provider pack.
- The generated binding uses the PR-SECRET-02 contract, not only the existing
  secrets-pack backend-selector file.
- Current generated secret discovery and cloud promotion behavior is unchanged.
- Current runtime identity permissions for AWS, GCP, and Azure are preserved.
- The env bridge remains available until `greentic-start` can read the binding.
- In the final target design, runtime app secrets are no longer passed through
  container environment variables.
- The deployer and start repos have an end-to-end pre-deploy compatibility
  check for the binding path.

## Dependencies

- `greentic-start` PR-SECRET-02 must load and use the binding before env
  injection is removed.
- `greentic-start` PR-SECRET-01 provides the cross-repo generate-mode harness
  that should be used to prove this deployer output and start runtime remain in
  sync.
- `greentic-secrets` provider packs already exist for AWS/GCP/Azure; PR-30 must
  decide whether deployer references built `.gtpack` artifacts, vendors them, or
  records a provider-pack URI/path for the runtime to resolve.
- `greentic-secrets` must expose any missing runtime binding metadata/config
  fields needed by `greentic-start`.
