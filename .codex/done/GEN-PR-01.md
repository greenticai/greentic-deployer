PR-01: Add a canonical write-files WIT + component template (no packgen yet)

Intent: unblock “emit README/placeholder” immediately by creating a minimal write-files component using greentic-component scaffolding patterns, with tests.

TASK: PR-01 (greentic-deployer): Introduce write-files component + WIT world

Repo: greentic-deployer

Goal
Add a minimal, canonical “write files” component that flows can call to emit README/placeholder files to a host-mounted output directory.

Hard constraints
- Do NOT touch pack generation or CI refactors in this PR.
- Do NOT add interactive prompts anywhere.
- Keep scope strictly to: WIT spec + component scaffold + basic tests/docs.

Deliverables
1) WIT world spec
- Add a WIT package/world (in the repo’s chosen WIT location) named exactly:
  greentic:host/iac-write-files@1.0.0
- Define:
  record file-spec { path: string, content: string, overwrite: bool }
  record write-error { code: u32, message: string, path: option<string> }
  write-files: func(files: list<file-spec>) -> result<list<string>, write-error>
- Semantics:
  - Writes are confined under a preopened dir /out (WASI preopen).
  - Reject absolute paths and any path traversal using "..".
  - Create parent directories.
  - overwrite=false errors if file exists.
  - Return list of written relative paths.

2) Component scaffold
- Create a new component (e.g. components/iac-write-files) using the repo’s standard component layout.
- Implement write-files using WASI filesystem calls writing under /out.
- Add a minimal component manifest referencing the WIT world.

3) Tests
- Add unit tests for path validation (absolute, "..", normal).
- Add an integration test that runs the component in a harness (if the repo has one) or at minimum tests the core write logic with a temp dir mounted as /out.
- The tests must run offline (no network pulls).

4) Docs
- Add a short README for the component explaining:
  - how host mounts /out
  - example FileSpec list
  - the security/path rules

Acceptance criteria
- `cargo test` passes.
- The component builds for wasm32-wasip2 (or the repo’s chosen target).
- The world name and function signature are stable and match above.
- No other repo refactors included.
Proceed without repeatedly asking for permission; only ask if you need network access (should not).
