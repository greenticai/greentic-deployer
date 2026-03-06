# PK-PR-01 — Generate placeholder deployment packs via CLI steps (no handcrafted corruption)

## Goal
Create placeholder deployment packs for default providers (aws/local/azure/gcp/k8s/generic) using ONLY CLI-driven generation:
- `greentic-pack new/build/doctor`
- `greentic-flow new/add-step/doctor`
- optional `greentic-component new/build/doctor` for shared helper components

This prevents corrupt packs.

## Source and output layout
- Source: `providers/deployer/<provider>/`
- Output: `dist/greentic.demo.deploy.<provider>.gtpack`

## Script: `scripts/gen_placeholders.sh`
For each provider:
1) `greentic-pack new --template <deployment-pack-template> --out providers/deployer/<provider>`
   - Template must be a template pack ref (OCI/Store/Repo) or a local template dir in this repo.
   - Do NOT add hardcoded enums into greentic-pack code for this PR; use a template input.
2) `greentic-flow new --out ... --name deploy_<provider>_iac`
3) `greentic-flow add-step ...` add minimal emit skeleton step(s) (PK-PR-02)
4) `greentic-flow doctor`
5) `greentic-pack build` -> dist
6) `greentic-pack doctor` on dist pack

## Acceptance criteria
- ✅ Running script produces 6 dist packs
- ✅ Each pack passes doctor
- ✅ No handcrafted manifests beyond minimal name/id substitutions

## Files
- `scripts/gen_placeholders.sh`
- `templates/deployer-pack/` (if OCI template not yet available)
- provider directories
