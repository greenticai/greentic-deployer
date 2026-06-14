# PR-03 — Helm deployment pack

## Goal
Generate a Helm deployment pack for the production operator deployment, reusing the same target-neutral inputs as raw Kubernetes.

## Packaging rule
This PR must ship as a deployment pack, not core deployer logic.

## Required chart structure
- `Chart.yaml`
- `values.yaml`
- `templates/deployment.yaml`
- `templates/service.yaml`
- `templates/ingress.yaml`
- `templates/configmap.yaml`
- `templates/networkpolicy.yaml`
- `templates/serviceaccount.yaml`
- `templates/rbac.yaml`
- `templates/hpa.yaml`
- helper templates as needed

## Chart requirements
- all security defaults enabled
- image pinned by digest, not tag-only
- admin API listener configurable and disabled from public exposure by default
- Redis external dependency values clearly modeled
- bundle source configurable as OCI/object-store/prefetched volume

## Plan behavior
The deployment pack must emit:
- rendered chart output
- recommended `helm upgrade --install` invocation
- rollback command template
- values diff guidance

## Not allowed
- hardcoded cluster assumptions
- public admin API exposure by default
- shelling out during `generate`

## Tests
- deployment-pack conformance tests
- chart render snapshots with multiple values profiles
- required-values validation
- digest pinning tests

## Implemented shape
This repo now includes a concrete `PR-03` fixture deployment pack under:

- `fixtures/packs/helm/contract.greentic.deployer.v1.json`
- `fixtures/packs/helm/assets/schemas/*`
- `fixtures/packs/helm/assets/examples/*`
- `fixtures/packs/helm/chart/*`

Delivered coverage includes:
- contract asset/reference validation
- input/output schema validation
- Helm chart structure checks
- digest pinning and admin API default checks
- command/guidance output checks
- template security-default and no-shell-generate checks

This was implemented as a deployment-pack fixture plus conformance tests, not as new provider logic inside `greentic-deployer`.
