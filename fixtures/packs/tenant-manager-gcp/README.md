# tenant-manager-gcp deployment pack

Deploys the containerized greentic-tenant-manager to GCP: Cloud SQL Postgres +
Cloud Run (the tenant-manager image) + a custom-domain mapping.
Consumed via `greentic-deployer gcp <cmd> --provider-pack dist/tenant-manager-gcp.gtpack`.

## Architecture

- **Cloud SQL (Postgres 16)**: managed database with a generated password stored in Secret Manager
- **Cloud Run v2**: serverless container hosting the tenant-manager on port 8080, connected to Cloud SQL via the Cloud SQL proxy sidecar pattern
- **Domain mapping**: `google_cloud_run_domain_mapping` maps a verified custom domain to the Cloud Run service

## Required inputs

| Variable | Description |
|---|---|
| `gcp_project_id` | GCP project ID |
| `gcp_region` | GCP region (e.g. `us-central1`) |
| `image_uri` | Digest-pinned tenant-manager container image |
| `domain_name` | Custom domain (must be verified in GCP) |
| `master_key_secret_id` | Secret Manager secret ID for `GREENTIC_TM_MASTER_KEY` |
| `platform_secret_hash_secret_id` | Secret Manager secret ID for `GREENTIC_PLATFORM_SECRET_HASH` |

## Optional inputs

| Variable | Default | Description |
|---|---|---|
| `db_tier` | `db-f1-micro` | Cloud SQL machine tier |
| `create_dns_record` | `true` | Whether to create a domain mapping resource |
| `offline_plan` | `false` | Note: the Google provider cannot fully skip credentials; `terraform validate` is the ceiling without real creds |

## Pre-requisites

1. A GCP project with the following APIs enabled: `sqladmin`, `run`, `secretmanager`
2. A service account with sufficient IAM roles: Cloud SQL Admin, Cloud Run Admin, Secret Manager Admin
3. The custom domain must be verified in [Google Search Console](https://search.google.com/search-console)
4. The two Secret Manager secrets (`master_key_secret_id`, `platform_secret_hash_secret_id`) must already exist in the project
