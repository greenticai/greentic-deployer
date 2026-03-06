# PR-05 — Snap deployment pack

## Goal
Implement a Snap deployment pack with two explicit models:
1. fetch mode
2. embedded bundle mode

## Deployment-pack responsibilities

### Fetch mode
Generate snap artifacts/config that assume:
- snap contains the operator binary only
- bundle is fetched at runtime by digest
- userspace SquashFS reader is used
- writable dirs map to:
  - `$SNAP_COMMON/state`
  - `$SNAP_COMMON/cache`
  - `$SNAP_COMMON/logs`

### Embedded mode
Generate snap artifacts/config that assume:
- bundle is packaged in the snap
- refresh requires a new snap revision
- active bundle path is internal to the snap payload

## Required output
- `snapcraft.yaml`
- app/service definitions
- environment variable mapping
- interfaces/plugs/slots requirements
- post-refresh guidance if needed

## Security requirements
- no assumption of shell availability
- no privileged mount requirement by default
- userspace reader must be the default path

## Runtime details the deployment pack must model
- Redis URL injection
- admin API binding restricted to local/private
- cache directory sizing guidance
- startup bundle verification behavior
- log path documentation

## Tests
- deployment-pack conformance tests
- snapshot tests for both fetch and embedded modes
- validation that embedded mode requires bundle input

## Implemented shape
This repo now includes a concrete `PR-05` fixture deployment pack under:

- `fixtures/packs/snap/contract.greentic.deployer.v1.json`
- `fixtures/packs/snap/assets/schemas/*`
- `fixtures/packs/snap/assets/examples/*`
- `fixtures/packs/snap/snap/fetch/snapcraft.yaml`
- `fixtures/packs/snap/snap/embedded/snapcraft.yaml`

Delivered coverage includes:
- contract asset/reference validation
- fetch-mode and embedded-mode input/output schema validation
- two-mode snapcraft snapshot coverage
- fetch-mode runtime/bundle modeling checks
- embedded-mode bundle path checks
- private admin binding and writable-dir checks
- no-shell / no-privileged-mount default checks

This was implemented as a deployment-pack fixture plus conformance tests, not as new Snap runtime logic inside `greentic-deployer`.
