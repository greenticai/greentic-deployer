# Azure Deployment Pack Fixture

This fixture represents the `greentic.deploy.azure` deployment pack for `PR-04`.

It is a provider-specific extension pack built on the shared Terraform-based
deployment layout, but versioned as an Azure pack rather than a generic
multicloud pack.

Contents:

- `contract.greentic.deployer.v1.json`: pack-local deployer contract
- `assets/schemas/*.json`: input, output, and execution-result schemas
- `assets/examples/*.json`: request/output examples
- `terraform/*`: deterministic Terraform file snapshots

Current scope:

- the pack input contract is Azure-specific and no longer asks the caller to
  choose a cloud
- the underlying Terraform asset tree is still shared-layout so provider packs
  can evolve with minimal drift
- canonical secret-reference output names remain aligned with the multicloud
  contract so higher layers can stay cloud-agnostic

Production-oriented admin cert flow:

1. deployment outputs expose canonical secret refs:
   - `admin_ca_secret_ref`
   - `admin_server_cert_secret_ref`
   - `admin_server_key_secret_ref`
2. the platform injects matching PEM payload env vars into runtime:
   - `GREENTIC_ADMIN_CA_PEM`
   - `GREENTIC_ADMIN_SERVER_CERT_PEM`
   - `GREENTIC_ADMIN_SERVER_KEY_PEM`
3. deployers may also inject trace env vars:
   - `GREENTIC_ADMIN_CA_SECRET_REF`
   - `GREENTIC_ADMIN_SERVER_CERT_SECRET_REF`
   - `GREENTIC_ADMIN_SERVER_KEY_SECRET_REF`
4. `greentic-start` materializes PEM payloads into runtime files and logs the selected source and refs

This is the intended production path across AWS, Azure, and GCP. Local
bundle-managed cert files remain a dev fallback, not the production target.

Remote bundle source note:

- cloud runtime executes `greentic-start start --bundle <bundle_source>`
- `http(s)://` and `oci://` bundle refs work directly
- `repo://` and `store://` bundle refs also require runtime registry mapping env vars:
  - `GREENTIC_REPO_REGISTRY_BASE`
  - `GREENTIC_STORE_REGISTRY_BASE`
- this Terraform fixture therefore accepts:
  - `repo_registry_base`
  - `store_registry_base`
- deployers should set those when using `repo://` or `store://` bundle sources so runtime can resolve the bundle after deploy

Azure note:

- `azure_key_vault_uri` keeps the ref contract stable for output-only scenarios
- `azure_key_vault_id` enables real `azurerm_key_vault_secret` creation for:
  - `greentic-admin-ca-<environment>`
  - `greentic-admin-server-cert-<environment>`
  - `greentic-admin-server-key-<environment>`
- `azure_location` selects the deployment region for the Azure runtime slice
- Azure runtime currently uses Azure Container Apps for the first real deployment path
- Azure still lacks AWS-level parity for ingress, logs, and status depth

GCP note:

- `gcp_project_id` selects the target project for Secret Manager and Cloud Run
- `gcp_region` selects the deployment region for the GCP runtime slice
- GCP runtime currently uses Cloud Run for the first real deployment path
- admin cert PEM env vars are injected from Secret Manager references at runtime
- GCP still lacks AWS-level parity for ingress, logs, and status depth
