# K8s Raw Deployment Pack Fixture

This fixture represents the `greentic.deploy.k8s-raw` deployment pack for `PR-02`.

It is intentionally stored as pack-owned assets plus conformance tests instead of new
`greentic-deployer` runtime logic.

Contents:

- `contract.greentic.deployer.v1.json`: pack-local deployer contract
- `assets/schemas/*.json`: input, output, and execution-result schemas
- `assets/examples/*.json`: example requests and executor outputs
- `assets/examples/rendered-manifests.yaml`: golden multi-document Kubernetes manifest output

