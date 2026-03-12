# Nightly E2E

This document defines the current nightly verification shape for
`greentic-deployer`.

## Goal

Nightly should answer one question clearly:

- does the unified deployer still perform the expected lifecycle for each
  adapter tier without regressing the stable `single-vm` path

## Ownership

- Environment setup and long-lived target sandboxes: Dmytro
- Adapter matrix and command semantics: `greentic-deployer`

## Matrix Source

The source of truth is:

- [ci/nightly_matrix.json](../ci/nightly_matrix.json)

It tracks:

- target tier
- adapter name
- expected mode: `execute` or `handoff`
- external environment requirement
- lifecycle steps to run nightly

## Tier Policy

- Tier 1: highest confidence targets, must run real `apply/status/destroy`
- Tier 2: strong adapter baselines, at minimum must validate generated handoff
  artifacts and synthesized status
- Tier 3: lower-depth adapters, still exercised nightly but may remain
  handoff-oriented until their executors mature

Current tiering:

- Tier 1: `single-vm`, `terraform`, `aws`, `gcp`, `azure`
- Tier 2: `k8s-raw`, `helm`, `operator`
- Tier 3: `serverless`, `snap`, `juju-machine`, `juju-k8s`

## Minimum Nightly Flow

For each matrix entry:

1. prepare the target-specific environment
2. run the listed adapter lifecycle steps
3. capture stdout/stderr and generated handoff artifacts
4. mark the target as pass/fail with the failing step

## Expectations

- `single-vm` must stay green; it is the OSS stability baseline
- Tier 1 adapters should fail the nightly if `apply/status/destroy` regress
- Tier 2 and Tier 3 adapters should at minimum fail nightly on:
  - command invocation regressions
  - missing handoff artifacts
  - invalid synthesized status
  - broken fixture contracts

## Next Hardening

- promote more adapters from `handoff` to `execute`
- add machine-readable nightly report output
- wire the matrix into CI or an external scheduler once Dmytro's environments
  are available
