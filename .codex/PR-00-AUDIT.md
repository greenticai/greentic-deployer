# PR-00-AUDIT — greentic-deployer production reset audit

## Goal
Produce a precise map of the current deployer code so follow-up PRs can remove obsolete logic and rebuild the production deployer cleanly.

## Why this PR exists
The deployer is the repo most likely to contain legacy assumptions, experimental targets, stale traits, and half-overlapping code paths. Before any rebuild, we need a surgical audit that identifies:
- what is still used
- what is only scaffolding
- what conflicts with the new `greentic.deployer.v1` model
- what can be deleted outright

## Audit tasks

### 1. CLI and command surface inventory
Document:
- all binaries
- all subcommands
- all flags
- current request/response output formats
- any hidden / deprecated flags
- any commands that execute deployments directly instead of rendering plans/artifacts

### 2. Trait and module map
Produce a module map with:
- provider traits
- render/apply/remove/status/rollback entrypoints
- config structs
- target-specific modules
- template/rendering modules
- shell/process invocation utilities

### 3. Runtime behavior audit
For each deployment target already present or partially present, capture:
- what inputs it expects
- whether it renders files or executes commands
- whether it persists state locally
- whether it assumes mutable runtime binaries
- whether it supports rollback semantics
- whether it depends on shell tools

### 4. Dead code / overlap analysis
Identify:
- legacy target providers no longer referenced
- duplicate renderer code
- duplicate path resolution logic
- stale DTOs
- old template folders
- code paths unreachable from current CLI/API

### 5. Test inventory
List:
- unit tests
- snapshot tests
- integration tests
- fixture directories
- tests that validate old behavior and will need replacement

### 6. Wizard fit assessment
Because pack/flow/component wizards now exist, the deployer audit must identify where the deployer should stop handcrafting app structure and instead consume scaffolded packs/components/flows.

## Deliverables
- `docs/audit/module-map.md`
- `docs/audit/cli-surface.md`
- `docs/audit/target-matrix.md`
- `docs/audit/deletion-candidates.md`
- `docs/audit/test-inventory.md`

## Mandatory outcome
A deletion list labeled:
- safe to remove now
- remove after migration shim
- keep and adapt

No production PR should merge before this audit lands.
