# PR-01 — canonical `greentic.deployer.v1` contract, with deployment-pack-owned schemas, questions, planner, and dispatch

## Goal
Define the canonical deployer contract without forcing `greentic-pack` or the core deployer runtime to know target-specific deployer details.

## Core rule
`greentic-pack` may know that a pack offers:

`greentic.deployer.v1`

and may scaffold generic contract capabilities such as:
- generate
- plan
- apply
- destroy
- status
- rollback

But target-specific schemas, setup/update questions, examples, planner behavior, and dispatch metadata are owned by the deployment pack itself.

## Contract responsibilities
The deployer contract should define generic capability semantics, such as:
- `generate`: render artifacts or generated outputs from deployer input
- `plan`: produce a plan / diff / intent report
- `apply`: execute deployment changes if the deployer supports execution
- `destroy`: remove previously applied deployment artifacts/resources
- `status`: return deployment status/health/progress
- `rollback`: move back to a prior deployment state if supported

All six capabilities should be supported by the contract model:
- `generate`
- `plan`
- `apply`
- `destroy`
- `status`
- `rollback`

Support must be capability-driven, not CLI-driven. The operator/control plane will invoke deployment packs through the library/runtime, not through a deployer CLI.

## Ownership rule
The deployment pack owns:
- deployer input schema
- per-capability input/output schemas
- per-capability execution-result schemas
- deployer-specific validation rules
- deployer-specific wizard/setup/update questions
- target-specific examples and docs
- planner inputs and planning behavior
- dispatch metadata needed by the operator to invoke each capability

That means one deployer may define fields for:
- a proprietary scheduler
- a niche appliance platform
- a future cloud service

without any core tooling change in `greentic-pack` or the core deployer runtime.

## Suggested pack-local assets
A deployment pack may choose to define assets such as:

```text
assets/schemas/deployer-generate.schema.json
assets/schemas/deployer-plan.schema.json
assets/schemas/deployer-apply.schema.json
assets/schemas/deployer-destroy.schema.json
assets/schemas/deployer-status.schema.json
assets/schemas/deployer-rollback.schema.json
assets/schemas/deployer-apply-execution.schema.json
assets/schemas/deployer-destroy-execution.schema.json
assets/schemas/deployer-status-execution.schema.json
assets/dispatch/*.json
assets/examples/*
flows/generate.*
flows/plan.*
flows/apply.*
flows/destroy.*
flows/status.*
flows/rollback.*
```

These are examples of pack-local ownership, not `greentic-pack` requirements about specific field names.

## I18n requirement
If this PR introduces or updates deployer-facing wizard/setup/update docs, QASpecs, or interactive prompts anywhere in deployer-owned assets, those changes must be i18n-ready:
- all user-facing strings keyed
- English locale updated
- locale registry/catalog updated as needed
- localized snapshots or fixture coverage added where patterns already exist

## Tests
- contract DTO/capability tests
- pack-local schema loading tests
- generic contract conformance tests
- planner/dispatch ownership tests
- typed operator payload tests for all six capabilities
- execution outcome payload tests and execution-schema validation tests
- i18n-aware docs/prompt/QASpec snapshot tests where applicable

## Implemented shape
The current implementation in `greentic-deployer` now includes:
- library-only capability-first runtime, no deployer CLI
- canonical `greentic.deployer.v1` contract DTOs
- pack-owned planner contract and per-capability flow dispatch
- typed operator payloads for `generate`, `plan`, `apply`, `destroy`, `status`, and `rollback`
- typed executor outcomes for `apply`, `destroy`, and `status`
- pre-execution payload validation via pack-owned `output_schema_ref`
- post-execution outcome validation via pack-owned `execution_output_schema_ref`
- stable runtime handoff artifacts for operators and external executors
