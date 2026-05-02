# AWS Deployment Pack Fixture

This fixture represents the `greentic.deploy.aws` deployment pack — the
cloud-specific provider pack consumed by the `aws` adapter surface
(`provider=aws`, `strategy=iac-only`).

It is stored as pack-owned assets and conformance tests instead of core
`greentic-deployer` logic, mirroring the `fixtures/packs/terraform/`
multi-cloud fixture but trimmed to AWS-only modules and providers.

Contents:

- `contract.greentic.deployer.v1.json`: pack-local deployer contract with
  AWS-specific flow ids (`plan_aws`, `apply_aws`, `destroy_aws`, `status_aws`,
  `rollback_aws`, `generate_aws`)
- `assets/schemas/*.json`: input, output, and execution-result schemas
- `assets/examples/*.json`: request/output examples (cloud=aws)
- `terraform/*`: deterministic AWS-only Terraform file snapshots

Current scope:

- single-cloud AWS only — for the multi-cloud terraform-backed baseline see
  `fixtures/packs/terraform/`
- compute/runtime path: ECS Fargate behind an Application Load Balancer
- secrets path: AWS Secrets Manager with `GREENTIC_ADMIN_*_PEM` and
  `GREENTIC_ADMIN_*_SECRET_REF` env contract
- canonical secret-reference output names match Azure/GCP parity outputs
  emitted by `fixtures/packs/terraform/`
- `s3` remote state backend configured at the root module

Production-oriented admin cert flow:

1. deployment outputs expose canonical secret refs:
   - `admin_ca_secret_ref`
   - `admin_server_cert_secret_ref`
   - `admin_server_key_secret_ref`
2. the platform injects matching PEM payload env vars into the ECS task:
   - `GREENTIC_ADMIN_CA_PEM`
   - `GREENTIC_ADMIN_SERVER_CERT_PEM`
   - `GREENTIC_ADMIN_SERVER_KEY_PEM`
3. trace env vars carry the Secrets Manager ARNs:
   - `GREENTIC_ADMIN_CA_SECRET_REF`
   - `GREENTIC_ADMIN_SERVER_CERT_SECRET_REF`
   - `GREENTIC_ADMIN_SERVER_KEY_SECRET_REF`
4. `greentic-start` materializes PEM payloads into runtime files and logs
   the selected source and refs

Remote bundle source note:

- the ECS task executes `greentic-start start --bundle <bundle_source>`
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

AWS note:

- `aws_use_default_vpc` (default `true`) reuses the default VPC + default
  subnets; set `false` to provision a dedicated `10.42.0.0/16` VPC with two
  public subnets across availability zones
- `public_base_url` defaults to `http://${aws_lb.this.dns_name}` when unset
- ALB listener is HTTP-only on port 80; production users wrap the ALB with
  ACM + HTTPS listener separately
- ECS task IAM role allows `secretsmanager:GetSecretValue` for the three
  admin cert secrets and `ssmmessages:*` for `enable_execute_command`
