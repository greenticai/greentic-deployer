PR-02: Update exactly ONE deploy_<provider>_iac flow to call write-files (prove end-to-end)

Intent: demonstrate the flow→component contract works. Keep it to one provider so it’s not a refactor bomb.

TASK: PR-02 (greentic-deployer): Update one deploy_<provider>_iac flow to emit README/placeholder via write-files

Repo: greentic-deployer

Goal
Pick ONE provider (the smallest/most used) and update its deploy_<provider>_iac flow to call the new iac-write-files component to emit:
- README.md
- placeholder file (e.g. <provider>.placeholder or iac.placeholder)

Hard constraints
- Do NOT introduce packgen yet.
- Do NOT update all providers; only one flow.
- Do NOT handcraft answer JSON blindly. Use greentic-flow answers (or the repo’s existing answer schema mechanism) if available; otherwise store a static example payload alongside the flow with clear schema.

Implementation details
- Add a flow step that calls the write-files component with a list of 2 FileSpec items.
- Ensure output paths are relative (no leading /).
- Use overwrite=false for README unless you need idempotency (then overwrite=true but justify in comment).

Tests
- Add a small smoke test script (or test) that:
  - runs the flow locally in whatever minimal harness the repo has, OR
  - directly invokes the component with the payload used by the flow and verifies output files exist.
- The purpose is to prove the contract; keep it lightweight.

Acceptance criteria
- Running the flow (or the component payload used by the flow) produces the two files in the mounted output dir.
- No network required.
