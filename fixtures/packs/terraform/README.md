# Terraform Deployment Pack Fixture

This fixture represents the `greentic.deploy.terraform` deployment pack for `PR-04`.

It is stored as pack-owned assets and conformance tests instead of core
`greentic-deployer` logic.

Contents:

- `contract.greentic.deployer.v1.json`: pack-local deployer contract
- `assets/schemas/*.json`: input, output, and execution-result schemas
- `assets/examples/*.json`: request/output examples
- `terraform/*`: deterministic Terraform file snapshots

