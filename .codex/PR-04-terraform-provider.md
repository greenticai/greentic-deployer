# PR-04 — Terraform deployment pack

## Goal
Implement a Terraform-rendering deployment pack that can own surrounding infrastructure as well as operator deployment references.

## Packaging rule
This PR must deliver a deployment pack. The core deployer must not regain Terraform execution logic.

## Scope
This deployment pack generates Terraform configuration; it does not embed cloud-specific behavior unless explicitly modeled.

## Must support modules for
- Kubernetes operator deployment inputs
- Redis endpoint / secret references
- DNS / load balancer wiring
- object store or OCI registry references
- OTLP / observability endpoints

## Output
Generate:
- `main.tf`
- `variables.tf`
- `outputs.tf`
- `providers.tf`
- module folders where needed
- environment-specific `.tfvars.example`

## Constraints
- generated Terraform must be deterministic
- references should be digest-pinned where applicable
- secret values must not be written to generated files
- remote state config should be templated, not assumed

## Plan / apply integration
- `plan` returns suggested `terraform init/plan` commands and expected variables
- `apply` only runs when explicitly enabled by the operator/executor
- rollback is documented as config rollback plus `terraform apply`, not hidden magic

## Tests
- deployment-pack conformance tests
- golden snapshots
- validation for missing variables
- target module presence tests

## Implemented shape
This repo now includes a concrete `PR-04` fixture deployment pack under:

- `fixtures/packs/terraform/contract.greentic.deployer.v1.json`
- `fixtures/packs/terraform/assets/schemas/*`
- `fixtures/packs/terraform/assets/examples/*`
- `fixtures/packs/terraform/terraform/*`

Delivered coverage includes:
- contract asset/reference validation
- generate/plan/apply/rollback schema validation
- required Terraform file and module presence checks
- deterministic output and digest-pinning checks
- secret omission checks
- `terraform init/plan` command guidance checks
- templated remote state/provider configuration checks

This was implemented as a deployment-pack fixture plus conformance tests, not as new Terraform execution logic inside `greentic-deployer`.
