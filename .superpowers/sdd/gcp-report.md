# GCP Deployment Pack — Implementation Report

## Status: DONE

## Files Created

### Pack root
- `fixtures/packs/tenant-manager-gcp/contract.greentic.deployer.v1.json` — verbatim copy of AWS contract (same 6 capabilities, same `*_terraform` flow ids)
- `fixtures/packs/tenant-manager-gcp/README.md` — GCP-specific documentation

### Assets — schemas (7 files)
- `assets/schemas/generate-input.schema.json` — GCP inputs: `gcp_project_id`, `gcp_region`, `image_uri`, `domain_name`, `db_tier` (default `db-f1-micro`), `master_key_secret_id`, `platform_secret_hash_secret_id`
- `assets/schemas/generate-output.schema.json` — provider=gcp, supported_clouds=["gcp"]
- `assets/schemas/plan-output.schema.json` — provider=gcp, contains `image_uri` in expected_variables
- `assets/schemas/apply-execution-output.schema.json` — identical to AWS (provider-agnostic)
- `assets/schemas/destroy-execution-output.schema.json` — identical to AWS
- `assets/schemas/rollback-execution-output.schema.json` — identical to AWS
- `assets/schemas/status-output.schema.json` — identical to AWS
- `assets/schemas/status-execution-output.schema.json` — identical to AWS

### Assets — examples (8 files)
All referenced by the contract's `example_refs`. No unreferenced files created.
- `assets/examples/generate-request.json` — GCP dummy values (Artifact Registry URI, us-central1, Secret Manager IDs)
- `assets/examples/generate-output.json` — provider=gcp, lists 14 generated terraform files
- `assets/examples/plan-output.json` — provider=gcp
- `assets/examples/apply-execution-output.json` — provider=gcp, endpoint=https://id.example.com
- `assets/examples/destroy-execution-output.json` — modules: route, service, cloudsql
- `assets/examples/rollback-execution-output.json` — same shape as AWS
- `assets/examples/status-output.json` — pack_id=`greentic.deploy.tenant-manager-gcp`
- `assets/examples/status-execution-output.json` — provider=gcp

### Terraform (13 HCL files)

**Root:**
- `terraform/providers.tf` — `hashicorp/google >= 5.0`, `hashicorp/random >= 3.5`; no `offline_plan` skip (google provider cannot fully skip creds — `validate` is the ceiling)
- `terraform/variables.tf` — `gcp_project_id`, `gcp_region`, `image_uri`, `db_tier`, `domain_name`, `master_key_secret_id`, `platform_secret_hash_secret_id`, `offline_plan`, `create_dns_record`
- `terraform/main.tf` — wires cloudsql → service → route; passes db outputs into service
- `terraform/outputs.tf` — `service_url`, `db_connection_name`, `cloud_run_uri`
- `terraform/staging.tfvars.example` — dummy values, `create_dns_record = false`
- `terraform/.gitignore` — `.terraform/`, `.terraform.lock.hcl`, `*.tfplan`, `terraform.tfvars`

**modules/cloudsql:**
- `main.tf` — `random_password`, `google_secret_manager_secret` + `_version` (stores DB password), `google_sql_database_instance` (POSTGRES_16, tier var), `google_sql_database` (tenant_manager), `google_sql_user` (tmadmin)
- `variables.tf` — `name`, `gcp_project`, `gcp_region`, `db_tier`
- `outputs.tf` — `connection_name`, `db_host` (public_ip_address), `db_name`, `db_user`, `db_password_secret_id`

**modules/service:**
- `main.tf` — `google_cloud_run_v2_service` with Cloud SQL annotation (`run.googleapis.com/cloudsql-instances`), `TENANT_DATABASE_URL` plain env (unix socket path via `/cloudsql/<connection_name>`), three secret envs via `value_source.secret_key_ref` (db password, master key, platform hash); startup + liveness probes to `/healthz`; `google_cloud_run_v2_service_iam_member` allUsers run.invoker
- `variables.tf` — `name`, `gcp_project`, `gcp_region`, `image_uri`, `db_connection_name`, `db_host`, `db_name`, `db_user`, `db_password_secret_id`, `master_key_secret_id`, `platform_secret_hash_secret_id`
- `outputs.tf` — `service_uri`, `service_name`

**modules/route:**
- `main.tf` — `google_cloud_run_domain_mapping` gated by `count = var.create_dns_record ? 1 : 0`
- `variables.tf` — `name`, `gcp_project`, `gcp_region`, `domain_name`, `service_name`, `create_dns_record`
- `outputs.tf` — `service_url = "https://${var.domain_name}"`

### Scaffold registry
- `examples/answers/deployer-scaffolds/tenant-manager-gcp.json` — mirrors tenant-manager-aws.json with GCP display_name/pack_id
- `testdata/answers/deployer-scaffolds/index.json` — added `tenant-manager-gcp.json` entry in alphabetical order (between tenant-manager-aws and terraform)

## Build Output

```
built and validated dist/tenant-manager-gcp.gtpack
PACK  greentic.deploy.tenant-manager-gcp  1.1.0-dev.0  dist/tenant-manager-gcp.gtpack
```

All 12 packs built and validated (no regressions).

## Extension-list Output

```
{
  "source": "pack",
  "extension": {
    "id": "greentic.deploy.tenant-manager-gcp",
    "kind": "pack",
    "target": { "family": "multi_target", "target": "gcp" },
    "summary": "Deployment extension contract loaded from dist/tenant-manager-gcp.gtpack"
  },
  "provider": "Gcp",
  "aliases": ["greentic.deploy.tenant-manager-gcp", "gcp"],
  "handlers": [
    {
      "id": "pack.greentic.deploy.tenant-manager-gcp",
      "execution_kind": "executable",
      "supported_capabilities": ["generate", "plan", "apply", "destroy", "status", "rollback"]
    }
  ]
}
```

6 capabilities confirmed: generate, plan, apply, destroy, status, rollback.

## Terraform Validate

```
Success! The configuration is valid.
```

`terraform init -backend=false` ran against `hashicorp/google v7.37.0` + `hashicorp/random v3.9.0`. `.terraform/` and `.terraform.lock.hcl` were deleted before commit — `validate` is the ceiling since the google provider requires real GCP project credentials for `plan`.

## Deletions

No existing files were deleted. No unreferenced example files were created (contract's `example_refs` was grepped first; only the referenced 8+8 schema/example files were written).

## Deviations from AWS Template

| AWS | GCP | Reason |
|---|---|---|
| `aws_region`, VPC/subnet/ACM/SG inputs | `gcp_project_id`, `gcp_region` only | GCP Cloud Run is serverless — no VPC/subnet required for basic deployment |
| RDS module | cloudsql module | GCP equivalent: Cloud SQL |
| ECS Fargate service module | Cloud Run v2 service module | GCP equivalent: Cloud Run |
| ALB + Route53 route module | domain mapping route module | GCP equivalent: `google_cloud_run_domain_mapping` |
| `aws_secretsmanager_secret` | `google_secret_manager_secret` | Provider-native secret store |
| Secrets via ECS `secrets` array | Secrets via `value_source.secret_key_ref` | Cloud Run v2 pattern |
| Cloud SQL connection via Cloud SQL Proxy in sidecar | `run.googleapis.com/cloudsql-instances` annotation + unix socket URL | Standard Cloud Run → Cloud SQL pattern; no separate proxy container needed |
| `skip_credentials_validation` etc. on AWS provider | No offline skip on google provider | Google provider doesn't support credential-skipping; validate is the ceiling |

## Notes

- `terraform plan` was NOT run — the google provider needs real GCP project credentials. `terraform validate` confirms the HCL is syntactically correct and all references resolve.
- The `db_host` output (public IP) is captured but not used in the `TENANT_DATABASE_URL` since Cloud Run uses the unix socket path (`/cloudsql/<connection_name>`) via the Cloud SQL annotation pattern. The `db_host` is available as an output for operators who need the IP directly.
- Domain mapping requires the domain to be verified in Google Search Console before `terraform apply` — documented in README.

---

## Fix Report — 2026-06-21

### Fix 1: Remove dead `db_host` plumbing

Removed `variable "db_host"` from `modules/service/variables.tf` and the corresponding `db_host = module.cloudsql.db_host` line from the `module "service"` block in root `main.tf`. The `cloudsql` module's `db_host` output (public IP address) was left in place — it is a harmless informational output not referenced by anything after the service variable was dropped.

Confirmed via grep: only three locations referenced `db_host` before the fix (root main.tf pass-through, cloudsql outputs.tf, service variables.tf). No other consumers.

### Fix 2: `service_url` output honors `create_dns_record`

The route module does not receive the Cloud Run service URI as a variable, so the cleanest fix was at the root `outputs.tf` level. Changed root `output "service_url"` from a plain delegation to `module.route.service_url` to a conditional:

```hcl
output "service_url" {
  value = var.create_dns_record ? module.route.service_url : module.service.service_uri
}
```

`var.create_dns_record` is already declared in root `variables.tf` (bool, default true). `module.service.service_uri` is the `google_cloud_run_v2_service.this.uri` attribute, already exported by the service module. The route module's `outputs.tf` (`"https://${var.domain_name}"`) is left unchanged — it is only reached when `create_dns_record = true`.

No count-gated resource is referenced directly in the output (the count-gated `google_cloud_run_domain_mapping` is inside the route module; the output value itself is a plain string interpolation from a variable, not the resource attribute), so no Terraform error from referencing a count-gated resource.

### Optional Minor: `deletion_protection` comment

Added `# TODO: set deletion_protection = true for production deployments` above `deletion_protection = false` in `modules/cloudsql/main.tf`.

### Verification

```
terraform init -backend=false  →  "Terraform has been successfully initialized!"
terraform validate             →  "Success! The configuration is valid."
```

```
cargo run --features internal-tools --bin build_fixture_gtpacks
→ All 12 packs built and validated (no regressions)
   including: PACK  greentic.deploy.tenant-manager-gcp  1.1.0-dev.0  dist/tenant-manager-gcp.gtpack
```
