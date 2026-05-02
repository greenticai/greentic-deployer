# GCP Deployment Pack Fixture

This fixture represents the `greentic.deploy.gcp` deployment pack — the
cloud-specific provider pack consumed by the `gcp` adapter surface
(`provider=gcp`, `strategy=iac-only`).

It is stored as pack-owned assets and conformance tests instead of core
`greentic-deployer` logic, mirroring the `fixtures/packs/terraform/`
multi-cloud fixture but trimmed to GCP-only modules and providers.

Contents:

- `contract.greentic.deployer.v1.json`: pack-local deployer contract with
  GCP-specific flow ids (`plan_gcp`, `apply_gcp`, `destroy_gcp`,
  `status_gcp`, `rollback_gcp`, `generate_gcp`)
- `assets/schemas/*.json`: input, output, and execution-result schemas
- `assets/examples/*.json`: request/output examples (cloud=gcp)
- `terraform/*`: deterministic GCP-only Terraform file snapshots

Current scope:

- single-cloud GCP only — for the multi-cloud terraform-backed baseline see
  `fixtures/packs/terraform/`
- compute/runtime path: Cloud Run v2 service with public ingress
- secrets path: GCP Secret Manager with `GREENTIC_ADMIN_*_PEM` and
  `GREENTIC_ADMIN_*_SECRET_REF` env contract
- canonical secret-reference output names match AWS/Azure parity outputs
  emitted by `fixtures/packs/terraform/`
- `gcs` remote state backend configured at the root module

Production-oriented admin cert flow:

1. deployment outputs expose canonical secret refs:
   - `admin_ca_secret_ref`
   - `admin_server_cert_secret_ref`
   - `admin_server_key_secret_ref`
   - `admin_client_cert_secret_ref`
   - `admin_client_key_secret_ref`
   - `admin_relay_token_secret_ref`
2. the platform injects matching PEM payload env vars into the Cloud Run
   container:
   - `GREENTIC_ADMIN_CA_PEM`
   - `GREENTIC_ADMIN_SERVER_CERT_PEM`
   - `GREENTIC_ADMIN_SERVER_KEY_PEM`
   - `GREENTIC_ADMIN_CLIENT_CERT_PEM`
   - `GREENTIC_ADMIN_CLIENT_KEY_PEM`
   - `GREENTIC_ADMIN_RELAY_TOKEN`
3. trace env vars carry the Secret Manager resource ids:
   - `GREENTIC_ADMIN_CLIENT_CERT_SECRET_REF`
   - `GREENTIC_ADMIN_CLIENT_KEY_SECRET_REF`
   - `GREENTIC_ADMIN_RELAY_TOKEN_SECRET_REF`
4. `greentic-start` materializes PEM payloads into runtime files and logs
   the selected source and refs

Remote bundle source note:

- the Cloud Run container executes `greentic-start start --bundle <bundle_source>`
- `http(s)://` and `oci://` bundle refs work directly
- `repo://` and `store://` bundle refs also require runtime registry mapping
  env vars:
  - `GREENTIC_REPO_REGISTRY_BASE`
  - `GREENTIC_STORE_REGISTRY_BASE`
- this fixture therefore accepts:
  - `repo_registry_base`
  - `store_registry_base`
- deployers should set those when using `repo://` or `store://` bundle
  sources so runtime can resolve the bundle after deploy

GCP note:

- `gcp_project_id` selects the target project for Secret Manager and Cloud
  Run resources
- `gcp_region` selects the deployment region for the Cloud Run service
- `admin_access_mode` defaults to `http-bearer-relay` and is exposed as a
  pack output for the platform's admin path selection
- `operator_endpoint` resolves from `public_base_url` when provided,
  otherwise from the Cloud Run-assigned `*.run.app` URI
- public invocation is granted via `roles/run.invoker` for `allUsers` —
  production users restrict this further via IAM
