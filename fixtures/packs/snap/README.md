# Snap Deployment Pack Fixture

This fixture represents the `greentic.deploy.snap` deployment pack for `PR-05`.

It includes two explicit models:

- fetch mode
- embedded bundle mode

Contents:

- `contract.greentic.deployer.v1.json`: pack-local deployer contract
- `assets/schemas/*.json`: input, output, and execution-result schemas
- `assets/examples/*.json`: fetch/embedded requests and outputs
- `snap/fetch/snapcraft.yaml`: fetch-mode golden output
- `snap/embedded/snapcraft.yaml`: embedded-mode golden output

