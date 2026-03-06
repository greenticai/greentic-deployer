# PK-PR-02 — Placeholder flows that emit IaC skeletons for default providers

## Goal
Ensure each placeholder pack exposes the flow deployer expects:
- `deploy_<provider>_iac`

Flow behavior (emit-only):
- read plan input (existing deploy-plan world / binding)
- write README.md + one provider-specific placeholder file in output dir
- no cloud API calls

## Shared helper (optional)
If there is no reliable way to write files from flows today, add a shared write-file component:
- created via `greentic-component new/build/doctor`
- interface: write text to relative path under mounted output dir

## Outputs (deterministic)
- aws: README.md + `main.tf` (placeholder)
- azure: README.md + `main.tf`
- gcp: README.md + `main.tf`
- k8s: README.md + `Chart.yaml`
- local: README.md + `local.sh`
- generic: README.md

## Acceptance criteria
- ✅ Deployer invocation creates these files
- ✅ Packs pass doctor
- ✅ Smoke can assert filenames

## Files
- provider flows
- optional `components/write-file/`
