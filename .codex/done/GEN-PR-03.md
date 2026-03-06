PR-03: Add greentic-deployer-packgen (thin orchestrator calling CLIs), then wire CI in a minimal way

Intent: now that the contract works, add packgen without rewriting the universe. Start by generating one pack and validating the provider-extension part; expand later.

TASK: PR-03 (greentic-deployer): Add greentic-deployer-packgen orchestrator (CLI-calling), minimal CI hook

Repo: greentic-deployer

Goal
Create greentic-deployer-packgen (Rust) that generates deployer provider packs by calling canonical CLIs:
- greentic-pack new/build/add-extension provider/doctor
- greentic-flow new/add-step/update-step/doctor/answers
- greentic-component pack/doctor (only for local components; otherwise reference existing ones)

Hard constraints
- Packsgen must NOT handroll pack.yaml or flow yaml beyond what the CLIs write.
- Provide --dry-run and --verbose.
- Deterministic, non-interactive.
- Minimal initial scope: generate one provider pack end-to-end + run doctor validate on it.
- Networked validator pulls must be gated: require env GREENTIC_TEST_OCI=1 for OCI validation tests; ask permission right before network commands.

Behavior (minimum)
Command:
  greentic-deployer-packgen generate --provider <name> --out <dir> [--strict] [--dry-run] [--verbose]
Steps performed:
  1) greentic-pack new -> out dir
  2) greentic-pack add-extension provider -> id deployer.<provider>, kind deployer (or events/deployer per repo rules), title...
  3) greentic-flow new + add-step -> create deploy_<provider>_iac flow and include write-files step (reuse the flow pattern from PR-02)
  4) greentic-pack build -> produce dist/<pack>.gtpack
  5) greentic-pack doctor --validate --validator-pack <deployer validator> --pack <gtpack>
     - In non-strict mode, assert only that provider-extension errors are absent (parse output).
     - In strict mode, require full success.

CI minimal wiring
- Add ci/gen_packs.sh that runs packgen for the chosen provider and writes to dist/.
- Add a CI job step before publish to run ci/gen_packs.sh (but do NOT refactor every workflow; minimal insertion).

Tests
- Unit tests for command sequence in --dry-run (assert it includes pack new, add-extension provider, flow new/add-step, pack build, doctor --validate).
- Integration test gated by GREENTIC_TEST_OCI=1 that runs doctor validate and asserts provider-extension passes.

Acceptance criteria
- packgen can generate one provider pack deterministically.
- The pack includes the provider extension declaration.
- The pack’s iac flow calls write-files (same pattern as PR-02).
- CI calls packgen at least in one workflow path before publishing.
