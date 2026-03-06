# Helm Deployment Pack Fixture

This fixture represents the `greentic.deploy.helm` deployment pack for `PR-03`.

It is stored as pack-owned assets and conformance tests instead of core
`greentic-deployer` logic.

Contents:

- `contract.greentic.deployer.v1.json`: pack-local deployer contract
- `assets/schemas/*.json`: input, output, and execution-result schemas
- `assets/examples/*.json`: values inputs and execution examples
- `chart/*`: golden Helm chart structure

