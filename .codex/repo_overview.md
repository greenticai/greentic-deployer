# Repository Overview

## HOME-03 pre-change inspection (2026-10-11)

Baseline `1b462e7b9fb561c72d185d184dd4ceba01312f7f`: `src/spec.rs`
rejects ARM64 but silently accepts unknown YAML/JSON fields. `src/single_vm.rs`
interpolates spec values into systemd units, Docker arguments and environment
files; its name check alone does not bound those values. This increment hardens
the existing specification boundary before adding host privileges. Shared host
types belong to greentic-types draft PR #214; no duplicate model or unreleased
path dependency will be introduced here. ARM64 enablement, native preflight,
operator-owned access policy and rollback remain separate integration work.
The referenced repo_overview_task.md is absent; this update follows actual
source inspection and the available global_rules.md routine.

## HOME-03 post-change verification

`DeploymentSpecV1` now rejects unknown fields at all eleven object boundaries
and validates values before they reach systemd/Docker/environment rendering.
Four regression tests cover nested JSON/YAML privilege requests, injected
directives/options, path and timeout bounds, and supported digest references.
Existing path-separator diagnostics are preserved. The migration notes are in
`docs/home-03-spec-validation.md`, linked from README.

`TMPDIR=/private/tmp bash ci/local_check.sh` passed (exit 0): formatting, all-target
all-feature Clippy, thirteen scaffold replays, fixture pack verification,
3,399 tests with 15 pre-existing ignores, documentation and the no-default-feature
baseline build. Tool versions: Rust 1.95.0, greentic-pack 1.1.5, greentic-flow 1.1.4.
Log: `/tmp/iot-home-03-deployer-final-check.log`. Documentation emits 69 existing
warnings and the baseline build four existing warnings; no warning-free claim
is made. The initial run's 77 signing-key fixture failures came from macOS's
symlinked `/var` temp path; the real temp path resolves them without disabling
security checks. The initial path-error assertion regression is fixed.

ARM64, shared host mappings, native access/ownership preflight, consistent
preview/plan/apply enforcement and rollback remain unfinished. The current
change is an input-validation prerequisite, not completion of HOME-03.

## 1. High-Level Purpose
- `greentic-deployer` is a Rust CLI/library that builds deployment plans from Greentic packs, chooses a deployment pack mapping, and generates provider-specific IaC/artifacts for apply/destroy workflows.
- It introspects pack manifests (local dirs, `.gtpack` archives, or distributor fetches), resolves config/secrets/telemetry via `greentic-config` and `greentic-secrets`, and emits Terraform/Bicep/Deployment Manager snippets plus manifests for AWS/Azure/GCP; Local/K8s rely on deployment-pack executors.
- Platform bootstrap scaffolding loads `.gtpack` locally, verifies signatures/digests, resolves bootstrap flows, reports host capabilities, executes a minimal bootstrap flow runner with CLI/JSON/HTTP/MQTT interaction support, applies config/secrets outputs, tracks status history, and persists bootstrap state with upgrade/rollback metadata.

## 2. Main Components and Functionality
- **Path:** `src/main.rs`
  - **Role:** CLI entrypoint parsing args and delegating to deployer logic.
  - **Key functionality:** Builds `CliArgs`, loads configuration, handles explain-config output, runs deployment flow via `apply::run`; platform commands preview packs, enforce verification policy, build host capabilities, and execute the bootstrap flow runner with interaction policy (CLI/json).
- **Path:** `src/config.rs`
  - **Role:** CLI definitions and configuration resolution.
  - **Key functionality:** Supports plan/apply/destroy subcommands with provider/strategy/pack/distributor flags; resolves greentic-config layers (including explicit file) and validates offline policy; determines IaC tool; exposes provider output paths and telemetry/paths accessors; defines platform interaction flags (`interaction` including http/mqtt), listener/network controls (`--allow-listeners`, `--allow-network`, `--net-allowlist`, `--bind`, `--interaction-timeout`, `offline_only`, `bootstrap_state`), secrets backend selection (`--secrets-backend`, default file path), and non-interactive IO (`--answers`, `--output`).
- **Path:** `src/apply.rs`
  - **Role:** Orchestrates plan/apply/destroy execution.
  - **Key functionality:** Builds plan via pack introspection, resolves deployment-pack dispatch, executes deployment pack if an executor is registered; otherwise runs provider backend to generate artifacts and writes them under `deploy/<provider>/<tenant>/<env>`; renders plan summaries/JSON/YAML; integrates secrets fetch/push, telemetry context, dry-run/preview/yes flags; runs IaC commands (terraform/tofu) via runner abstraction.
- **Path:** `src/deployment.rs`
  - **Role:** Maps provider/strategy to deployment pack flows and optional executor hook.
  - **Key functionality:** Default dispatch table pointing at demo packs; env var overrides (`DEPLOY_TARGET_<PROV>_<STRAT>_PACK_ID/FLOW_ID`); optional `DeploymentExecutor` registry; falls back to legacy provider shims when no executor is registered.
- **Path:** `src/pack_introspect.rs`
  - **Role:** Reads pack manifests and constructs provider-agnostic deployment plans.
  - **Key functionality:** Loads `manifest.cbor` from directory, `.gtpack` tar, or distributor via HTTP source; infers deployment hints (target/provider/strategy), runner/channel/messaging/telemetry/secrets plans; infers component roles/profiles → infrastructure summaries; enforces path safety for local packs.
- **Path:** `src/plan.rs`
  - **Role:** Plan context modeling and derived hints.
  - **Key functionality:** Defines component roles/profiles/targets, telemetry and messaging context builders, channel ingress/OAuth hints based on base domain, secret scope resolution, plan assembly helper with summary output.
- **Path:** `src/providers/` (`aws.rs`, `azure.rs`, `gcp.rs`)
  - **Role:** Legacy provider backends emitting IaC artifacts and manifests.
  - **Key functionality:** Render templated Terraform (AWS), Bicep (Azure), and Deployment Manager YAML (GCP) with runner services, secrets wiring, telemetry/env vars, channel ingress env vars, channel/OAuth comments; AWS adds ECS network config (subnets/SG vars, optional public IP) plus CloudWatch log groups and CPU target-tracking autoscaling; Azure enables ingress for external components and adds autoscaling headroom; GCP sets ingress policy per component and a slight autoscaling buffer; write apply/destroy manifests listing secrets, OAuth redirects, telemetry, and artifact paths.
- **Path:** `src/providers/local.rs`, `src/providers/k8s.rs`
  - **Role:** Templated backends for Local/K8s targets (still expect an executor for real deployment).
  - **Key functionality:** Local emits `compose.yaml` with runner env/ingress/telemetry/secrets plus plan/README; K8s emits `k8s.yaml` (Deployments/Services/Ingress for external components, env/telemetry/secrets, basic scaling) plus plan/README; both write apply/destroy manifests and skip terraform/tofu execution.
- **Path:** `src/iac.rs`
  - **Role:** IaC tool selection and command execution abstraction.
  - **Key functionality:** Resolves terraform vs opentofu from CLI/env/PATH; runs init/plan/apply or init/destroy sequences; dry-run command listing; errors when binaries missing.
- **Path:** `src/secrets.rs`
  - **Role:** Secret resolution and push to provider stores.
  - **Key functionality:** Uses `greentic-secrets` resolver scoped by tenant/env; fetches secrets with provider paths, supports test overrides, aggregates missing secrets into actionable error; pushes resolved secrets back to provider before apply/destroy.
- **Path:** `src/telemetry.rs`
  - **Role:** Telemetry initialization.
  - **Key functionality:** Builds telemetry export config from greentic-config (stdout or OTLP) and initializes tracing with provider/tenant context.
- **Path:** `src/path_safety.rs`
  - **Role:** Guards against path traversal in user-supplied pack paths.
  - **Key functionality:** Normalizes relative paths under repo root and rejects absolute/escaping paths.
- **Path:** `src/bin/gen_example_manifests.rs`
  - **Role:** Helper to regenerate example pack manifests.
  - **Key functionality:** Writes minimal `manifest.cbor` files for the example packs.
- **Path:** `examples/acme-pack`, `examples/acme-plus-pack`
  - **Role:** Sample packs for demonstrating plan/apply flows.
  - **Key functionality:** Provide manifests/components used in docs/tests to produce IaC outputs for multiple providers.
- **Path:** `src/platform.rs`
  - **Role:** Platform command helper to load local `.gtpack` and summarize manifest/digest.
  - **Key functionality:** Validates pack path, reads manifest from gtpack via pack_introspect, computes sha256 digest, verifies signatures per policy (warn vs strict), resolves bootstrap flow ids, loads bootstrap flow bytes, builds host capabilities from interaction flags, executes the bootstrap flow runner, applies secrets writes/config patches with rollback snapshots, performs upgrade preflight (version/digest present, newer version), saves bootstrap state with rollback references, and prints/writes redacted bootstrap output (optional `--output`).
- **Path:** `src/platform/oci.rs`
  - **Role:** Optional OCI resolver for platform packs.
  - **Key functionality:** Parses `oci://` references, enforces network policy/allowlists (allow-network + allowlist, offline blocked), fetches OCI manifests/blobs (https by default, http for localhost), verifies manifest header + layer digests, caches downloaded gtpacks under the bootstrap directory by digest with an index, and reuses cached copies when available; computes pack digest helper.
- **Path:** `src/platform/flow.rs`
  - **Role:** Resolves bootstrap flows/components from manifest.
  - **Key functionality:** Picks install/upgrade/installer IDs from `bootstrap` block or defaults (`platform_install`/`platform_upgrade`/`installer`); validates referenced flows exist.
- **Path:** `src/bootstrap/state.rs`
  - **Role:** Bootstrap state persistence helpers.
  - **Key functionality:** Defines `BootstrapState` (version/digest/timestamps/env_kind/last_upgrade/rollback_ref), load/save JSON to a configurable path (default `/var/lib/greentic/bootstrap/state.json`), upgrade preflight checks, rollback references, and pluggable backends (file default; k8s stub errors clearly when selected without support).
- **Path:** `src/bootstrap/flow_runner.rs`
  - **Role:** Minimal bootstrap flow executor.
  - **Key functionality:** Parses ygtc steps, routes prompts through adapters, captures output/status history (`waiting_for_answers` → `validating` → `applying_config` → `deploying` → `completed/failed`), denies unsupported steps.
- **Path:** `src/bootstrap/output.rs`
  - **Role:** Bootstrap output contract and redaction helpers.
  - **Key functionality:** Defines versioned `BootstrapOutput` with config patch, secret writes, warnings, and ready flag; supports serde round-tripping and redaction of secret values for safe persistence.
- **Path:** `src/bootstrap/cli.rs`
  - **Role:** Interaction adapters for bootstrap prompting.
  - **Key functionality:** `CliPromptAdapter` renders questions with defaults to stdout and reads answers from stdin; `JsonPromptAdapter` feeds answers from a provided JSON object for non-interactive runs; `DenyPromptAdapter` errors when prompts are disallowed (e.g., JSON-only interaction).
- **Path:** `src/bootstrap/capabilities.rs`
  - **Role:** Host capability model for bootstrap interaction.
  - **Key functionality:** Builds allowed adapters (cli/json/http/mqtt) from the interaction registry and policy flags (allow_listeners, allow_network, offline_only, allowlist presence), recording disabled reasons for transparency.
- **Path:** `src/bootstrap/interaction.rs`
  - **Role:** Interaction adapter registry and policy.
  - **Key functionality:** Defines adapter trait/kinds and registry, applies policy (listeners/network/offline/allowlist) to filter available adapters for `--interaction` modes (cli/json/http/mqtt).
- **Path:** `src/bootstrap/network.rs`
  - **Role:** Network allowlist and policy enforcement.
  - **Key functionality:** Parses comma-separated allowlists (hosts/CIDRs), normalizes hostnames/addresses, and enforces outbound policy (`--allow-network`, `offline_only`, allowlist) for adapters.
- **Path:** `src/bootstrap/http_adapter.rs`
  - **Role:** HTTP interaction adapter.
  - **Key functionality:** Hosts a minimal local HTTP server to serve schema and accept answers when explicitly allowed (allow_listeners + allow_network), enforces timeouts/read boundaries, and emits status updates.
- **Path:** `src/bootstrap/mqtt_adapter.rs`
  - **Role:** MQTT interaction adapter (mock transport).
  - **Key functionality:** Provides a mock broker and MQTT prompt adapter that exchanges schema/answers over topics, publishes status updates, supports timeouts, and can enforce allowlisted brokers via network policy.
- **Path:** `src/bootstrap/secrets.rs`
  - **Role:** Secrets intent executor for bootstrap.
  - **Key functionality:** Parses secrets backend URIs (default `file:/var/lib/greentic/secrets.db`; optional `k8s:<namespace>/<name>` stub), executes `secrets_writes` intents to the backend, stores values with scope/metadata (base64 encoded for k8s stub), and rejects unsupported backends or missing values.
- **Path:** `src/bootstrap/config_patch.rs`
  - **Role:** Applies installer-emitted config patches.
  - **Key functionality:** Determines default config patch path (next to bootstrap state), snapshots existing config, writes JSON patches, and supports restore on failure.
- **Path:** `src/bootstrap/state.rs`
  - **Role:** Bootstrap state persistence and upgrade checks.
  - **Key functionality:** Defines `BootstrapState`, load/save JSON, upgrade compatibility checks (requires existing install and newer version), helpers to stamp install/upgrade timestamps, and records rollback references.
- **Path:** `fixtures/platform-pack/`
  - **Role:** Reference platform pack fixture for tests/CI.
  - **Key functionality:** Contains `pack.yaml`, install/upgrade flows, and stub installer.wasm used to build `.gtpack` in tests.
- **Path:** `docs/platform_bootstrap_example.md`
  - **Role:** Developer-facing bootstrap example.
  - **Key functionality:** Shows how to run platform install in CLI/JSON modes and an air-gapped flow using the fixture pack.
- **Path:** `docs/platform_bootstrap_adapters.md`
  - **Role:** Adapter reference for bootstrap installers.
  - **Key functionality:** Documents CLI/JSON/HTTP/MQTT behaviors, policy flags (`--allow-network`, `--allow-listeners`, `--net-allowlist`, `--offline-only`), HTTP endpoint shapes, MQTT topic conventions, and points to reference flows in fixtures.
- **Path:** `tests/acme_e2e.rs`
  - **Role:** Integration tests for plan building from tar/directory packs.
  - **Key functionality:** Builds sample manifests, writes gtpack/dir packs, ensures `build_plan` constructs expected plan details.
- **Path:** `tests/platform_adapter_fixtures.rs`
  - **Role:** Smoke coverage for adapter fixture flows.
  - **Key functionality:** Loads JSON `.ygtc` fixtures for multi-step wizard, HTTP, and MQTT examples; executes via prompt adapters to ensure files remain parseable and outputs contain expected endpoints/topics.
- **Path:** `tests/platform_resolver.rs`
  - **Role:** Validates platform pack loading behavior.
  - **Key functionality:** Builds a temp gtpack, ensures manifest is read and digest computed; asserts missing pack errors and signature verification policies (warn/strict/invalid signature).
- **CI/Release:** `.github/workflows/release.yml` skips failing the publish job when the crate version is already present on crates.io (matches “already uploaded” or “already exists on crates.io index”).
- **Packaging:** `Cargo.toml` sets `package.metadata.binstall` so `cargo binstall greentic-deployer` fetches release tarballs from GitHub Releases (URL template `greentic-deployer-v{version}-{target}.tgz`).
- **Path:** `tests/bootstrap_flow_resolution.rs`
  - **Role:** Ensures bootstrap flow resolution respects manifest hints and defaults.
  - **Key functionality:** Resolves explicit bootstrap block, falls back to defaults when absent, errors on missing referenced flows.
- **Path:** `tests/bootstrap_installer_stub.rs`
  - **Role:** End-to-end bootstrap flow execution against a stub installer pack.
  - **Key functionality:** Builds a fixture gtpack with platform install/upgrade flows and stub installer.wasm; verifies bootstrap flow returns ready=true with expected config patch via a prompt-denying adapter.
- **Path:** `tests/bootstrap_output.rs`
  - **Role:** Validates bootstrap output serialization/redaction and flow parsing.
  - **Key functionality:** Round-trips `BootstrapOutput`, redacts secret values, and ensures flow runner extracts output from `installer_call` steps.
- **Path:** `tests/bootstrap_json_adapter.rs`
  - **Role:** Validates non-interactive answers handling.
  - **Key functionality:** Confirms JSON adapter supplies answers to prompt steps without interaction.
- **Path:** `tests/bootstrap_secrets.rs`
  - **Role:** Verifies secrets intent execution.
  - **Key functionality:** Confirms file backend writes secret values with scope/metadata and rejects unsupported backends.
- **Path:** `tests/bootstrap_state.rs`
  - **Role:** Ensures bootstrap state read/write compatibility and upgrade checks.
  - **Key functionality:** Missing state yields None; round-trip JSON persists all fields; upgrade preflight blocks missing/downgrade; upgrade helper stamps last_upgrade_at.
- **Path:** `tests/bootstrap_state_backend.rs`
  - **Role:** Validates bootstrap state backend selection.
  - **Key functionality:** File backend round-trips state; k8s backend currently errors clearly when unavailable.
- **Path:** `tests/interaction_registry.rs`
  - **Role:** Validates adapter policy and mode filtering.
  - **Key functionality:** Confirms listener gating, allowlist requirements for outbound adapters, mode-specific adapter selection (cli/json/http/mqtt), and disabled-by-default listener behavior.
- **Path:** `tests/interaction_http.rs`
  - **Role:** Exercises HTTP adapter scaffold.
  - **Key functionality:** Spins up HTTP adapter on localhost, fetches schema, posts answers, and ensures the bootstrap flow runs when policy allows.
- **Path:** `tests/mqtt_adapter.rs`
  - **Role:** Exercises MQTT adapter mock transport.
  - **Key functionality:** Uses in-memory broker to verify schema publication, answers reception, status publishing, and enforces allowlist/denial when brokers are not permitted.
- **Path:** `tests/platform_install_state.rs`
  - **Role:** Validates config patch writing and state persistence around install flows.
  - **Key functionality:** Stub platform pack runs install flow, writes config_patch JSON, and saves state only on success; failure to write config leaves state absent.
- **Path:** `tests/platform_fixture_install.rs`
  - **Role:** Integration test against reference fixture pack.
  - **Key functionality:** Builds a `.gtpack` from `fixtures/platform-pack`, runs bootstrap install flow via JSON adapter, and asserts outputs (cluster name, secret write).

## 3. Work In Progress, TODOs, and Stubs
- No explicit TODO/FIXME markers in source.
- `greentic-deployer-packgen` plus `ci/gen_packs.sh` now replace the old `scripts/gen_placeholders.sh`, generating provider packs via canonical CLIs and keeping `dist/*.gtpack` in sync with the placeholder flows/components.
- The magical smoke harness described in `.codex/DEP-PR-01.md` (fixture pack + script) still needs implementation.
- `src/deployment.rs`: Default dispatch table points to demo deployment packs; real environments are expected to override via env vars or register a `DeploymentExecutor`.
- Local/K8s backends emit compose/k8s templates but still require deployment pack mappings or an executor to perform real deployments.
- Platform commands are partially scaffolded: bootstrap flow runner parses installer output and applies config/secrets/state with rollback snapshots, but deploy plan execution is stubbed (no real platform deploy yet) and installer/wasm execution is not wired.
- Listener-based adapters (http/mqtt) are placeholders; they remain disabled unless explicitly allowed via flags.
- Kubernetes bootstrap state backend is stubbed (errors clearly when selected); only file backend is functional today.

## 4. Broken, Failing, or Conflicting Areas
- Current run: `ci/local_check.sh` passes (fmt, clippy, docs, tests, IaC smoke for aws/azure/gcp dry-runs). No known failing tests or build warnings.

## 5. Notes for Future Work
- Keep `ci/local_check.sh` green; it already exercises fmt, clippy, tests, docs, and IaC smoke.
- Wire real deployment-pack mappings or a `DeploymentExecutor` to replace demo defaults.
- Implement actual platform bootstrap execution: invoke installer components (WASM), feed prompts through adapters, and persist bootstrap state/output safely.
- Implement or integrate Local/K8s provider handling (via deployment packs or shims) if those targets are required.
- Expand provider IaC renderers if richer infrastructure/templates are needed beyond current templates.
