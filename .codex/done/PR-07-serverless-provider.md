# PR-07 — Serverless container deployment pack

## Goal
Generate deployment artifacts for environments that run a single container image with restricted filesystem and no privileged mount support.

## Packaging rule
This PR must be implemented as a deployment pack, not as deployer-core provider code.

## Assumptions
- userspace SquashFS access only
- writable `/tmp` available
- bundle fetched at startup or supplied via remote object/OCI source
- external Redis mandatory

## Deployment-pack outputs
Because serverless platforms differ, this deployment pack should output a normalized package:
- environment variable specification
- required secrets list
- startup contract
- health endpoint requirements
- container command / args
- deployment descriptor templates for supported serverless families if applicable

## Runtime specifics that must be modeled
- startup fetch timeout
- warm failure behavior
- Redis connect retry policy
- no dependency on local durable storage
- admin API private-only or disabled externally

## Tests
- deployment-pack conformance tests
- validation that mount mode is rejected
- snapshot of env/config contract

## Implemented shape
This repo now includes a concrete `PR-07` fixture deployment pack under:

- `fixtures/packs/serverless/contract.greentic.deployer.v1.json`
- `fixtures/packs/serverless/assets/schemas/*`
- `fixtures/packs/serverless/assets/examples/*`

Delivered coverage includes:
- contract asset/reference validation
- generate/plan schema validation
- normalized env/config descriptor snapshot coverage
- explicit mount-mode rejection checks
- `/tmp`-only writable filesystem checks
- private admin API exposure checks
- startup/warm-failure/retry modeling checks

This was implemented as a generic constrained-runtime deployment-pack fixture plus conformance tests, not as new serverless provider logic inside `greentic-deployer`.
