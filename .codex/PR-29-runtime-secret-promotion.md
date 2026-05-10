# PR-29 — Runtime secret promotion for cloud deploys

## Goal
Make cloud deploys work without copying local dev secret files into the uploaded bundle.

When `gtc start --target aws --upload-bundle ...` runs, the local bundle should remain free of secret values. The deploy flow should instead:

- pass the local bundle root to `greentic-deployer`
- discover all runtime secret requirements from the local bundle and packs
- resolve secret values from the local dev secrets store and process environment
- write those values into the target cloud secret manager
- configure the remote runtime so `greentic-start` reads promoted cloud secrets through its generic env backend

This PR must keep `gtc` target-agnostic. `gtc` may pass generic bundle location information, but it must not learn AWS/GCP/Azure/Vault-specific secret behavior.

## Why this PR exists
The deep-research AWS deployment only worked after local dev secret files were included in the bundle. That indicates the deployment path is currently relying on local secret files being available remotely, instead of promoting local setup secrets into the target cloud secret manager during deployment.

The intended architecture is:

```text
greentic-setup
  captures setup answers
  writes local dev secrets

gtc
  resolves/prepares bundle
  passes local bundle root and deploy artifact reference

greentic-deployer
  discovers required runtime secrets
  resolves local values
  writes values to the cloud secret manager
  wires runtime IAM/config

remote greentic-start
  reads secrets through the existing env secrets backend
```

## Scope

### In scope
- Add a generic `--bundle-root` argument to cloud deployer invocations.
- Teach `greentic-deployer` to collect required runtime secrets from the local bundle.
- Teach `greentic-deployer` to resolve secret values from:
  - `.greentic/dev/.dev.secrets.env`
  - `.greentic/state/dev/.dev.secrets.env`
  - `GREENTIC_DEV_SECRETS_PATH`
  - process environment using the canonical env key mapping
- Promote resolved secrets into the selected provider's real cloud secret manager:
  - AWS -> AWS Secrets Manager
  - GCP -> GCP Secret Manager
  - Azure -> Azure Key Vault
- Wire provider runtime permissions/config so the deployed runtime can read promoted secrets.
- Add tests that prove secret values are not required inside the uploaded bundle.

### Out of scope
- Teaching `gtc` cloud-provider-specific behavior.
- Embedding secret values into `.gtbundle`, `.gtpack`, or uploaded bundle contents.
- Passing secret values through Terraform variable files or generated IaC files.
- `greentic-start` direct AWS/GCP/Azure secret-manager readers. The deployer-side runtime wiring now uses the existing env secrets backend instead.
- `gtc` passing `--bundle-root`. This must land in a companion PR in `greentic`; this PR includes deployer-side `--bundle-root` support plus bundle-root inference from local pack paths.

## Current state

### `gtc`
Cloud `gtc start` currently invokes `greentic-deployer` with:

```text
--bundle-pack <local app pack path>
--provider-pack <local provider pack path>
--bundle-source <remote-or-local deploy artifact>
--bundle-digest <sha256>
```

It does not pass the local bundle root as a first-class argument.

Relevant file:
- `../greentic/src/bin/gtc/deploy/cloud_deploy/deployment_state.rs`

### `greentic-setup`
`greentic-setup` already persists setup answers into a local dev secrets store and seeds aliases from pack secret requirements when pack paths are known.

Relevant files:
- `../greentic-setup/src/secrets.rs`
- `../greentic-setup/src/qa/persist.rs`
- `../greentic-setup/src/engine/executors.rs`

This makes `greentic-setup` the right owner for local capture. It should not directly upload secrets to cloud targets.

### `greentic-deployer`
Before PR-29, `greentic-deployer` received the deploy artifact reference and local pack paths, but it did not promote app/runtime/provider secrets into cloud secret managers.

PR-29 adds deployer-side runtime secret discovery/resolution plus provider-owned promotion for AWS, GCP, and Azure.

Relevant files:
- `src/main.rs`
- `src/config.rs`
- `src/contract.rs`
- `src/aws.rs`
- `src/azure.rs`
- `src/gcp.rs`
- `src/runtime_secrets.rs`
- `src/apply.rs`
- `src/bin/replay_deployer_scaffolds.rs`
- `src/bin/build_fixture_gtpacks.rs`
- `fixtures/packs/aws/terraform/modules/operator/main.tf`
- `fixtures/packs/aws/terraform/modules/operator-gcp/main.tf`
- `fixtures/packs/aws/terraform/modules/operator-azure/main.tf`
- `fixtures/packs/aws/assets/schemas/generate-input.schema.json`

### `greentic-start`
`greentic-start` currently supports dev-store and env secret backends. The deployer-side runtime wiring uses the existing env backend by asking the cloud platform to inject secret values as environment variables from the provider's secret manager.

Relevant files:
- `../greentic-start/src/secrets_backend.rs`
- `../greentic-start/src/secrets_gate.rs`
- `../greentic-start/src/secrets_client.rs`
- `../greentic-start/src/secrets_manager.rs`

## Design

### 1. Add `--bundle-root`
Add a generic local bundle root argument to `greentic-deployer` cloud commands:

```text
greentic-deployer aws apply \
  --bundle-root ./deep-research-demo-bundle \
  --bundle-pack ./deep-research-demo-bundle/packs/... \
  --provider-pack ./deep-research-demo-bundle/packs/aws.gtpack \
  --bundle-source s3://bucket/prefix/deep-research-demo.gtbundle \
  --bundle-digest sha256:...
```

`gtc` should pass `resolved.bundle_dir` as `--bundle-root` for cloud deploys.

This is a generic deployer contract extension. `gtc` must not inspect required secrets, upload secrets, or branch on cloud provider secret-manager behavior.

Implemented in this repo:
- `greentic-deployer` accepts `--bundle-root` on AWS, Azure, and GCP commands.
- If `--bundle-root` is omitted, deployer attempts to infer the bundle root from a local pack path under `<bundle>/packs/...`.
- The companion `greentic` PR should still pass `--bundle-root <resolved.bundle_dir>` explicitly.

### 2. Discover required runtime secrets in deployer
Add a deployer-side runtime secret discovery module.

Inputs:
- `--bundle-root`
- `--bundle-pack`
- `--provider-pack`
- target tenant/team/environment

Discovery should inspect:
- pack `assets/secret-requirements.json`
- setup answer metadata or generated provider config where applicable
- pack manifests or runtime metadata that declare `secrets://...` requirements

Implemented in this repo:
- `src/runtime_secrets.rs` scans the selected app pack, selected provider pack, and pack entries under `<bundle-root>/packs`.
- Directory packs and `.gtpack` archives are supported.
- `.gtpack` archives may be ZIP or legacy tar while older bundles remain in circulation.
- `assets/secret-requirements.json`, `assets/secret_requirements.json`, `secret-requirements.json`, and `secret_requirements.json` are recognized.

Implemented output shape:

```rust
struct RuntimeSecretRequirement {
    uri: String,
    provider_id: String,
    key: String,
    required: bool,
    source: PathBuf,
}
```

The canonical URI format must match the existing `greentic-start` behavior:

```text
secrets://{environment}/{tenant}/{team}/{provider}/{key}
```

Do not treat the set of keys already present in the dev secrets file as authoritative. The authoritative list is the bundle/packs. The dev secrets file and process environment are value sources.

### 3. Resolve local secret values
Add a deployer-side resolver that checks value sources in this order:

1. Process environment using the canonical env key mapping.
2. `GREENTIC_DEV_SECRETS_PATH`, when set.
3. `<bundle-root>/.greentic/dev/.dev.secrets.env`
4. `<bundle-root>/.greentic/state/dev/.dev.secrets.env`

The resolver should:
- preserve existing canonical secret URI semantics
- support aliases seeded by `greentic-setup`
- fail apply with a clear missing-secret report when a required secret has no value
- never log secret values
- redact values in JSON output, traces, diagnostics, and errors

Implemented in this repo:
- `SecretValue` redacts `Debug`.
- Missing-secret diagnostics list checked sources only.
- Values are read through `greentic-secrets-lib` `DevStore` for local dev secret files.

Example missing-secret error:

```text
missing required runtime secrets for aws deploy:
  - secrets://dev/demo/default/openai/api_key
    checked:
      - env GREENTIC_SECRET__DEV__DEMO__DEFAULT__OPENAI__API_KEY
      - .greentic/dev/.dev.secrets.env
      - .greentic/state/dev/.dev.secrets.env
```

### 4. Promote secrets through the selected provider
Promotion is provider-owned. Shared deployer code discovers requirements and resolves local values; cloud provider modules upload those values to their own secret manager.

Implemented provider paths:
- AWS provider: AWS Secrets Manager through AWS SDK.
- GCP provider: GCP Secret Manager through real `gcloud secrets` commands.
- Azure provider: Azure Key Vault through real `az keyvault secret set`.

There are no fake provider implementations. If provider configuration or credentials are missing, promotion fails before apply.

### 4a. AWS Secrets Manager

Use AWS provider-owned deployer code to create/update secret values before or during apply. Do not pass raw secret values through Terraform variables or generated `.tfvars`; Terraform state can retain secret values even when variables are marked sensitive.

Recommended AWS naming:

```text
greentic/{environment}/{tenant}/{team}/{provider}/{key}
```

The URI-to-name mapping must be deterministic and shared with the runtime reader. If secret names need escaping, implement one small shared helper and test it thoroughly.

Promotion should be idempotent:
- create secret if missing
- update secret value if present and changed
- tag managed secrets with deployment metadata
- never delete runtime secrets during apply

Suggested AWS tags:
- `greentic:managed-by = greentic-deployer`
- `greentic:environment`
- `greentic:tenant`
- `greentic:team`
- `greentic:bundle-digest`
- `greentic:secret-uri`

Implemented details:
- AWS creates missing secrets and updates existing ones with `PutSecretValue` through the AWS CLI. This keeps deployer behavior aligned with the user's active AWS CLI credentials and avoids SDK SSO refresh-token drift.
- Runtime app/provider secret values are not passed through Terraform.
- Managed secret tags include provider and secret-manager metadata.

### 4b. GCP Secret Manager
Implemented details:
- GCP promotion uses `gcloud secrets create` and `gcloud secrets versions add --data-file -`.
- Secret values are passed over stdin, not written into Terraform files.
- Project discovery uses `GREENTIC_DEPLOY_TERRAFORM_VAR_GCP_PROJECT_ID`, `GOOGLE_CLOUD_PROJECT`, or `GCLOUD_PROJECT`.
- Secret names are flattened and length-bounded for GCP.

### 4c. Azure Key Vault
Implemented details:
- Azure promotion uses `az keyvault secret set`.
- Vault discovery uses `GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_KEY_VAULT_NAME`, `GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_KEY_VAULT_URI`, or `GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_KEY_VAULT_ID`.
- Secret names are flattened and length-bounded for Key Vault.
- `az` requires file input for this shape, so deployer uses a temporary file and does not write values to generated artifacts.

### 5. Wire runtime access
Update Terraform packs/modules so deployed runtimes can read promoted runtime secrets.

Do not pass runtime secret values through Terraform variables or generated files. The deployer promotes values directly to the provider secret manager, then Terraform configures the platform to inject those provider-managed secret references into the container environment.

```text
GREENTIC_SECRETS_BACKEND=env
GREENTIC_ALLOW_ENV_SECRETS=1
GREENTIC_SECRETS_MANAGER_PACK=providers/deployer/<provider>.gtpack
```

The task role needs narrowly scoped permissions:

```json
{
  "Action": ["secretsmanager:GetSecretValue"],
  "Resource": ["arn:aws:secretsmanager:...:secret:greentic/<env>/<tenant>/<team>/*"]
}
```

If runtime writes are needed for mutable values such as webhook public URL secrets, add `secretsmanager:PutSecretValue` only for the specific managed prefix or specific mutable secret names.

Implemented in this repo:
- AWS ECS task role receives scoped `secretsmanager:GetSecretValue`.
- AWS ECS task definitions receive `secrets` entries that reference AWS Secrets Manager secret names produced by deployer.
- AWS runtime gets `GREENTIC_SECRETS_BACKEND=env`, `GREENTIC_ALLOW_ENV_SECRETS=1`, and `GREENTIC_SECRETS_MANAGER_PACK=providers/deployer/aws.gtpack`.
- GCP Cloud Run runtime receives `value_source.secret_key_ref` entries that reference GCP Secret Manager secret names produced by deployer.
- GCP Cloud Run runtime gets `GREENTIC_SECRETS_BACKEND=env`, `GREENTIC_ALLOW_ENV_SECRETS=1`, and `GREENTIC_SECRETS_MANAGER_PACK=providers/deployer/gcp.gtpack`.
- GCP Cloud Run service account receives `roles/secretmanager.secretAccessor`.
- Azure Container App runtime receives `secret` and `env.secret_name` entries that reference Azure Key Vault secret names produced by deployer.
- Azure Container App runtime gets `GREENTIC_SECRETS_BACKEND=env`, `GREENTIC_ALLOW_ENV_SECRETS=1`, and `GREENTIC_SECRETS_MANAGER_PACK=providers/deployer/azure.gtpack`.
- Azure Container App receives a system-assigned identity and Key Vault Secrets User role assignment.

### 6. Runtime env backend compatibility
The deployer now avoids teaching `greentic-start` provider-specific secret-manager backends. Provider-specific secret-manager access stays in deployer/Terraform/cloud platform configuration.

Runtime behavior:
- deployer writes secret values to AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault
- Terraform configures ECS, Cloud Run, or Container Apps to inject those provider-managed secrets into the runtime environment
- `greentic-start` reads through the existing `env` backend

Follow-up to validate in `greentic-start`:
- confirm `EnvSecretsManager` can read the exact secret URI keys injected by deployer on each cloud platform, or add canonical env-key lookup using the existing `GREENTIC_SECRET__...` mapping
- preserve existing team wildcard behavior
- keep secret values out of logs

### 7. Keep local mode unchanged
Local starts should continue to read from dev-store/env as they do today.

No local flow should require AWS credentials merely because cloud secret promotion support exists.

### 8. Build deployer packs with `greentic-pack`
The deployer provider `.gtpack` files must be built with the canonical pack tooling. The previous fixture builder manually wrote tar archives, which caused ZIP-only consumers to fail with:

```text
invalid Zip archive: Could not find EOCD
```

Implemented in this repo:
- `src/bin/build_fixture_gtpacks.rs` now calls `greentic-pack build --in <replayed-pack-root>` and copies the produced `.gtpack` into `dist/`.
- `src/bin/replay_deployer_scaffolds.rs` overlays the complete fixture content into the replayed scaffold, so Terraform/charts/charms/snap assets survive the `greentic-pack` build.
- Replayed scaffold `pack.yaml` is stamped with the crate version.
- The generic `greentic.deployer.v1` extension remains compatible with `greentic-pack` validation.
- The richer deployer contract is stored under `greentic.deployer.contract.v1`, and `greentic-deployer` still reads old packs that embedded the richer contract under `greentic.deployer.v1`.
- `dist/aws.gtpack`, `dist/azure.gtpack`, and `dist/gcp.gtpack` are now ZIP archives and include the expected Terraform trees.

### 9. Avoid deployment collisions
Cloud resource names and Terraform backend keys must not be shared accidentally across different users or workspaces.

Observed failure:
- one user deployed `greentic-1b256a8e`
- another Terraform run reused the same deterministic prefix and replaced/deleted the same ECS service, ALB target group, and task definition
- the replacement task also lacked the new cloud secret wiring, so the URL flapped between healthy, 503, and partially working runtime states

Implemented in this repo:
- default Terraform `deployment_name_prefix` now includes provider, tenant, environment, and a local deployment identity seed
- the local deployment identity seed comes from `GREENTIC_DEPLOYMENT_ID` when set, otherwise owner plus workspace path
- explicit shared deployments are still supported with `GREENTIC_DEPLOY_TERRAFORM_VAR_DEPLOYMENT_NAME_PREFIX` or `GREENTIC_DEPLOYMENT_NAME_PREFIX`
- existing generated tfvars continue to preserve an explicit non-legacy prefix for updates/stops
- existing legacy shared prefixes such as `greentic-1b256a8e` for `aws/demo/dev` are ignored on regeneration, so rerunning deployer moves to an isolated default prefix
- default S3 Terraform backend keys include the deployment prefix, preventing remote-state collisions when `GREENTIC_TERRAFORM_BACKEND_BUCKET` is used without an explicit key

## Required repo changes

### `greentic`
- Add `--bundle-root <resolved.bundle_dir>` to the deployer args in cloud deploy.
- Add/adjust tests asserting cloud deployer invocation includes `--bundle-root`.
- Keep this target-agnostic.

### `greentic-deployer`
- Add CLI/config field `bundle_root: Option<PathBuf>`.
- Infer bundle root from local pack paths when `--bundle-root` is absent.
- Add runtime secret discovery and local value resolution.
- Add provider-owned secret promotion:
  - AWS Secrets Manager
  - GCP Secret Manager
  - Azure Key Vault
- Add Terraform inputs for runtime secret prefix/scope plus provider secret references, not raw values.
- Add cloud runtime permissions and env secret injection for AWS, GCP, and Azure.
- Add collision-resistant default deployment naming/state identity, while preserving explicit deployment prefixes.
- Keep provider-specific logic in provider modules, not in shared discovery/resolution.
- Build fixture/provider `.gtpack` artifacts through `greentic-pack`, not manual archive writers.

### `greentic-start`
- Validate env backend lookup for deployed secret URI env names.
- If cloud platforms reject URI-shaped env names, add canonical env-key lookup using `GREENTIC_SECRET__...` aliases while keeping provider-specific cloud behavior out of `greentic-start`.
- Add unit tests for env backend URI/canonical-key lookup and team fallback behavior.

## Safety requirements
- Secret values must not be written to:
  - uploaded bundles
  - generated Terraform variable files
  - Terraform state through managed secret-version resources
  - logs
  - JSON command output
  - `.codex` artifacts
- The apply command must fail before infrastructure changes if a required secret value is missing.
- The missing-secret report must list secret identifiers and checked sources, not values.
- Promotion currently runs only for execute-local cloud apply flows where a bundle root can be supplied or inferred and required secrets exist.
- If a future opt-out is added, it must be explicit, for example `--no-promote-runtime-secrets`, and must warn that the remote runtime must already have the required secrets.

## Tests

### Unit tests
- `gtc` cloud apply builds deployer args with `--bundle-root`.
- Deployer CLI parses `--bundle-root`.
- Secret requirement discovery reads `assets/secret-requirements.json`.
- Local resolver checks env and dev-store paths in the documented order.
- URI-to-provider-secret-name mapping is stable.
- Redaction prevents values appearing in formatted errors and JSON summaries.
- `greentic-start` selects env backend and resolves deployed secret env keys correctly. Companion repo if canonical aliases are needed.

### Integration-style tests without live cloud credentials
- Fake provider secret managers record create/update calls.
- Missing required secret fails before apply.
- Resolved secrets produce remote references and IAM scope.
- Uploaded bundle fixture does not contain `.dev.secrets.env`.

Implemented validation in this repo:
- `cargo check`
- `cargo check --no-default-features`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test runtime_secrets --lib`
- `cargo test request_defaults --lib`
- `cargo run --features internal-tools --bin replay_deployer_scaffolds`
- `cargo run --features internal-tools --bin build_fixture_gtpacks`
- `cargo test --test multicloud_terraform_fixture`
- `cargo test --test pr04_terraform_pack`
- `file dist/aws.gtpack dist/azure.gtpack dist/gcp.gtpack`
- `unzip -l dist/aws.gtpack terraform/main.tf terraform/modules/operator/main.tf`
- `bash ci/local_check.sh`

### Manual smoke
With local dev secrets present but excluded from bundle:

```text
gtc wizard --answers https://github.com/greenticai/greentic-demo/releases/latest/download/deep-research-demo-aws-create-answers.json
gtc setup ./deep-research-demo-bundle --answers https://github.com/greenticai/greentic-demo/releases/latest/download/deep-research-demo-aws-setup-answers.json
gtc start ./deep-research-demo-bundle --target aws --upload-bundle s3://<bucket>/<prefix>/
```

Expected result:
- uploaded bundle does not contain local dev secret files
- AWS Secrets Manager contains the required runtime secrets
- ECS task role can read them and inject them into the container env
- remote runtime starts and resolves provider secrets through the env backend

Equivalent GCP/Azure manual smokes should verify GCP Secret Manager and Azure Key Vault respectively.

## Acceptance criteria
- Cloud deploys no longer require `.greentic/dev/.dev.secrets.env` or `.greentic/state/dev/.dev.secrets.env` inside the uploaded bundle.
- `gtc` remains target-agnostic.
- `greentic-deployer` owns deployment-time secret promotion.
- `greentic-start` owns runtime secret reads through the existing secrets abstraction; provider-specific cloud reads stay in deployer/cloud platform wiring.
- AWS, GCP, and Azure deployer-side promotion and runtime wiring are implemented.
- Runtime reads may require a companion `greentic-start` PR only if the deployed platform cannot expose URI-shaped env keys and canonical aliases are needed.
- Secret values are never logged or written to generated artifacts.
- Default tests do not require live AWS credentials.

## Implementation notes
- Prefer reusing existing Greentic secret URI/env-key helpers if available in shared crates.
- If no shared helper exists, add the smallest local helper first, then consider extracting it later after both deployer and start use the same semantics.
- Avoid Terraform-managed `aws_secretsmanager_secret_version` for runtime app secrets unless the team explicitly accepts Terraform state exposure. Admin/operator TLS secrets currently use Terraform, but runtime app/provider secrets should be handled more conservatively.
- Keep all provider-specific logic in deployer/provider modules and deployment packs, not in `gtc`.
