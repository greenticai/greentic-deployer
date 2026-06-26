# PR-02 — Kubernetes raw manifests deployment pack

## Goal
Implement a first-class raw Kubernetes deployment pack that emits production-ready manifests for the stateless operator architecture.

## Packaging rule
This PR must deliver a deployment pack, not new provider logic inside `greentic-deployer`.
The operator/control plane will invoke the pack through the deployer runtime.

## What this deployment pack must generate

### Required manifests
- `Namespace`
- `ServiceAccount`
- `Role` / `RoleBinding` or namespaced RBAC set
- `ConfigMap` for non-secret runtime config
- `Secret` references only
- `Deployment`
- `Service`
- `Ingress` or Gateway API resources
- `NetworkPolicy`
- `HorizontalPodAutoscaler`
- optional `PodDisruptionBudget`

### Operator deployment specifics
The generated Deployment must enforce:
- distroless image
- non-root user
- read-only root filesystem
- writable mounts only for:
  - `/tmp`
  - `/var/cache/greentic`
  - `/var/lib/greentic` only if required by policy
  - `/var/log/greentic` only if needed
- env vars or mounted config for:
  - Redis connection
  - active bundle source
  - admin API listener
  - OTLP endpoint
  - safe/degraded mode defaults

### Probes
Generate:
- liveness probe → `/healthz`
- readiness probe → `/readyz`
- optional startup probe → `/status`

### Upgrade modes
The deployment pack must support:
- rolling
- blue/green
- canary render support when orchestration is external

### NetworkPolicy requirements
Allow:
- ingress from ingress controller / gateway
- egress to Redis
- egress to artifact source / object store / registry if startup pull is enabled
- egress to OTLP collector if configured

Deny broad unrestricted egress by default unless explicitly requested.

## Plan / apply behavior
- `generate` renders YAML + a plan file
- `plan` explains create/update/delete drift at resource level
- `apply` may emit executor-facing `kubectl` guidance, but generation must work with no cluster access

## Tests
- deployment-pack conformance tests
- snapshot tests for all manifests
- validation tests for required inputs
- golden tests for security context and probes

## Implemented shape
This repo now includes a concrete `PR-02` fixture deployment pack under:

- `fixtures/packs/k8s-raw/contract.greentic.deployer.v1.json`
- `fixtures/packs/k8s-raw/assets/schemas/*`
- `fixtures/packs/k8s-raw/assets/examples/*`

Delivered coverage includes:
- contract asset/reference validation
- input/output schema validation
- golden raw manifest validation
- required resource set checks
- security context and probe checks
- NetworkPolicy/HPA/PDB policy checks
- upgrade-mode declaration checks

This was implemented as a deployment-pack fixture plus conformance tests, not as new provider logic inside `greentic-deployer`.
