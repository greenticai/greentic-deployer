# tenant-manager-azure deployment pack

Deploys the containerized greentic-tenant-manager to Azure: Azure Database for PostgreSQL Flexible Server +
Azure Container Apps (running the tenant-manager image) + a custom domain binding.
Consumed via `greentic-deployer azure <cmd> --provider-pack dist/tenant-manager-azure.gtpack`.

## Architecture

- **Azure Database for PostgreSQL Flexible Server (Postgres 16)**: managed database with a generated password stored in Azure Key Vault
- **Azure Container Apps**: serverless container hosting the tenant-manager on port 8080 with external ingress enabled
- **Custom domain**: `azurerm_container_app_custom_domain` binds a verified custom domain to the Container App

## Required inputs

| Variable | Description |
|---|---|
| `azure_subscription_id` | Azure subscription ID (UUID) |
| `azure_resource_group` | Azure resource group name to deploy into |
| `azure_location` | Azure region (e.g. `eastus`, `westeurope`) |
| `image_uri` | Digest-pinned tenant-manager container image |
| `domain_name` | Custom domain to bind to the Container App |
| `key_vault_id` | Resource ID of an existing Azure Key Vault used to store the generated DB password |
| `master_key_secret_id` | Azure Key Vault secret identifier for `GREENTIC_TM_MASTER_KEY` |
| `platform_secret_hash_secret_id` | Azure Key Vault secret identifier for `GREENTIC_PLATFORM_SECRET_HASH` |

## Optional inputs

| Variable | Default | Description |
|---|---|---|
| `db_sku_name` | `B_Standard_B1ms` | PostgreSQL Flexible Server SKU name |
| `create_dns_record` | `true` | Whether to create a custom domain binding |
| `offline_plan` | `false` | Note: the azurerm provider cannot fully skip credentials; `terraform validate` is the ceiling without real creds |

## Module layout

- `modules/postgres` — PostgreSQL Flexible Server + password stored in Key Vault
- `modules/service` — Container App Environment + Container App with Key Vault secret refs
- `modules/route` — Custom domain binding on the Container App

## Pre-requisites

1. An Azure subscription with the following resource providers registered: `Microsoft.App`, `Microsoft.DBforPostgreSQL`, `Microsoft.KeyVault`
2. A resource group already created at `azure_resource_group`
3. An Azure Key Vault with the two secrets (`master_key_secret_id`, `platform_secret_hash_secret_id`) already present
4. The custom domain must be pre-verified in Azure (CNAME pointing to the Container App ingress)
5. A service principal or managed identity with Contributor rights on the resource group and Key Vault Secrets Officer role
