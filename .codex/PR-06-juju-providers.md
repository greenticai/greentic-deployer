# PR-06 — Juju deployment pack set (machine model + Kubernetes model)

## Goal
Implement Juju as a concrete deployment-pack target, not a vague future placeholder.

## This PR must deliver two distinct Juju deployment packs
1. `juju-machine`
2. `juju-k8s`

They share inputs but render different artifacts and lifecycle instructions.

## A. Juju machine model deployment pack

### Packaging choice
Default strategy:
- deploy a charm that installs and manages the Snap-based operator
- the charm must configure runtime via charm config + relations
- the operator service is managed under Juju control

### Required charm responsibilities
The generated machine charm must:
- install or refresh the operator snap
- configure bundle source and digest
- configure Redis relation data
- configure admin API bind address
- configure OTLP / observer endpoint settings
- manage restart on config changes when required
- expose health and status through Juju status reporting

### Required relation models
At minimum model relations or config bindings for:
- `redis`
- `ingress` or public endpoint integration
- `observability` / OTLP
- optional `secrets`

### Charm outputs
Generate:
- `charmcraft.yaml`
- `metadata.yaml`
- `config.yaml`
- `src/charm.py` or equivalent scaffold if charm code generation is in scope
- deployment README with:
  - `juju deploy`
  - relation wiring commands
  - upgrade commands
  - rollback guidance

## B. Juju Kubernetes model deployment pack

### Packaging choice
Generate a Kubernetes charm that manages operator workload in a pod.

### Required behavior
The k8s charm must:
- template workload image by digest
- configure bundle source/digest
- wire Redis and observability relations
- expose public ingress relation separately from admin listener
- propagate readiness / active / blocked / waiting states from operator status

### Required output
Generate:
- `charmcraft.yaml`
- `metadata.yaml`
- `config.yaml`
- charm source scaffold
- rendered workload spec fragments or templates as appropriate

## C. Shared Juju deployment-pack rules

### Deployment plan output
The plan must emit exact commands for:
- deploy
- relate/integrate
- config set
- upgrade charm
- refresh bundle digest
- remove application

### Status mapping
Define a clean mapping from operator status to Juju application/unit status:
- warm in progress → waiting/maintenance
- active and ready → active
- degraded mode → blocked or active with message depending on severity
- failed activation → blocked

### Not allowed
- a single vague `juju` renderer that ignores machine vs k8s differences
- shell-only instructions without generated charm assets
- hidden assumptions about relation names

## Tests
- separate snapshot suites for machine and k8s deployment packs
- command plan golden tests
- relation-required validation tests

## Implemented shape
This repo now includes two concrete `PR-06` fixture deployment packs under:

- `fixtures/packs/juju-machine/*`
- `fixtures/packs/juju-k8s/*`

Delivered coverage includes:
- separate machine and k8s contract fixtures
- separate machine and k8s charm scaffolds
- input/output schema validation for both packs
- exact Juju command-plan golden checks
- relation-required validation checks
- machine charm file/relation checks
- k8s charm digest-pin and status-mapping checks

This was implemented as two deployment-pack fixtures plus conformance tests, not as new Juju orchestration logic inside `greentic-deployer`.
