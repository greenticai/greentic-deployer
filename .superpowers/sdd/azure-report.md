# Azure Deployment Pack Report

## Status
PASS

## Build + Validate Summary
- `cargo run --features internal-tools --bin build_fixture_gtpacks`: PASS — `dist/tenant-manager-azure.gtpack` built and validated (greentic.deploy.tenant-manager-azure v1.1.0-dev.0)
- `terraform validate`: Success! (Terraform v1.10.5, azurerm >= 3.85 / 4.78.0 installed)
- Pack capabilities: 6 (generate, plan, apply, destroy, status, rollback)

## Architecture
- Azure Database for PostgreSQL Flexible Server (Postgres 16) — password generated and stored in Key Vault
- Azure Container Apps — tenant-manager container with Key Vault secret refs via SystemAssigned identity
- Custom domain binding — `azurerm_container_app_custom_domain` gated by `create_dns_record`

## Concerns
- `terraform plan` not run (azurerm requires live Azure credentials; `terraform validate` is the ceiling without real creds)
- `azurerm_container_app_custom_domain` resource requires a pre-verified domain in Azure and the Container App ID
- Route module accepts `container_app_id` as an input (passed from `module.service.app_id`) rather than using a data source, to avoid credential lookups at validate time
- The postgres module requires an existing Key Vault ID (`var.key_vault_id`) — passed from root variables rather than being created inline

## Review Fixes (2026-06-21)

### Fix 1 — CRITICAL: `key_vault_id` contract drift resolved
- Added `key_vault_id` to `generate-input.schema.json` properties (type string) and `required` array
- Added placeholder value to `assets/examples/generate-request.json`
- Added `key_vault_id` to `expected_variables` list in `assets/examples/plan-output.json`

### Fix 2 — Dead `container_app_name` in route module removed
- Removed `variable "container_app_name"` block from `modules/route/variables.tf`
- Removed `container_app_name = module.service.app_name` line from root `main.tf` `module "route"` block

### Fix 3 — Unused `offline_plan` root variable removed
- Removed `variable "offline_plan"` block from root `variables.tf`
- Removed `offline_plan = true` line from `staging.tfvars.example`

### Verification
- All 3 JSON files parse: OK
- `terraform validate`: Success! The configuration is valid.
- `cargo run --features internal-tools --bin build_fixture_gtpacks`: all 13 packs built and validated (including `dist/tenant-manager-azure.gtpack`)
