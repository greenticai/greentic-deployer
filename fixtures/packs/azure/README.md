# Azure Deployment Pack Fixture

This fixture represents the `greentic.deploy.azure` deployment pack — the
cloud-specific provider pack consumed by the `azure` adapter surface
(`provider=azure`, `strategy=iac-only`).

It is stored as pack-owned assets and conformance tests instead of core
`greentic-deployer` logic, mirroring the `fixtures/packs/terraform/`
multi-cloud fixture but trimmed to Azure-only modules and providers.

Contents:

- `contract.greentic.deployer.v1.json`: pack-local deployer contract with
  Azure-specific flow ids (`plan_azure`, `apply_azure`, `destroy_azure`,
  `status_azure`, `rollback_azure`, `generate_azure`)
- `assets/schemas/*.json`: input, output, and execution-result schemas
- `assets/examples/*.json`: request/output examples (cloud=azure)
- `terraform/*`: deterministic Azure-only Terraform file snapshots

Current scope:

- single-cloud Azure only — for the multi-cloud terraform-backed baseline
  see `fixtures/packs/terraform/`
- compute/runtime path: Azure Container Apps with Log Analytics workspace
- secrets path: Azure Key Vault with `GREENTIC_ADMIN_*_PEM` and
  `GREENTIC_ADMIN_*_SECRET_REF` env contract; falls back to versionless
  ref strings when `azure_key_vault_id` is unset
- canonical secret-reference output names match AWS/GCP parity outputs
  emitted by `fixtures/packs/terraform/`
- `azurerm` remote state backend configured at the root module

Production-oriented admin cert flow:

1. deployment outputs expose canonical secret refs:
   - `admin_ca_secret_ref`
   - `admin_server_cert_secret_ref`
   - `admin_server_key_secret_ref`
   - `admin_client_cert_secret_ref`
   - `admin_client_key_secret_ref`
   - `admin_relay_token_secret_ref`
2. the platform injects matching PEM payload env vars into the Container
   App revision:
   - `GREENTIC_ADMIN_CA_PEM`
   - `GREENTIC_ADMIN_SERVER_CERT_PEM`
   - `GREENTIC_ADMIN_SERVER_KEY_PEM`
   - `GREENTIC_ADMIN_CLIENT_CERT_PEM`
   - `GREENTIC_ADMIN_CLIENT_KEY_PEM`
   - `GREENTIC_ADMIN_RELAY_TOKEN`
3. trace env vars carry the Key Vault secret ids:
   - `GREENTIC_ADMIN_CA_SECRET_REF`
   - `GREENTIC_ADMIN_SERVER_CERT_SECRET_REF`
   - `GREENTIC_ADMIN_SERVER_KEY_SECRET_REF`
   - `GREENTIC_ADMIN_CLIENT_CERT_SECRET_REF`
   - `GREENTIC_ADMIN_CLIENT_KEY_SECRET_REF`
   - `GREENTIC_ADMIN_RELAY_TOKEN_SECRET_REF`
4. `greentic-start` materializes PEM payloads into runtime files and logs
   the selected source and refs

Remote bundle source note:

- the Container App revision executes
  `greentic-start start --bundle <bundle_source>`
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

Azure note:

- `azure_key_vault_uri` keeps the ref contract stable for output-only
  scenarios (no Key Vault writes)
- `azure_key_vault_id` enables real `azurerm_key_vault_secret` creation;
  when unset, outputs return versionless secret-ref strings instead
- `azure_location` selects the deployment region for the Container App
  Environment, Log Analytics workspace, and (when enabled) Key Vault writes
- `admin_access_mode` defaults to `http-bearer-relay` and is exposed as
  a pack output for the platform's admin path selection
- `operator_endpoint` resolves from `public_base_url` when provided,
  otherwise from the Container App-assigned FQDN
