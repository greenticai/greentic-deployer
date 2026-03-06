# PK-PR-03 — CI gating for packs: build + doctor + smoke + publish GHCR

## Goal
Prevent publishing broken packs.

## Pipeline
- build: run `scripts/gen_placeholders.sh` and build -> dist
- doctor: `greentic-pack doctor` each dist pack
- smoke: run deployer smoke harness using dist packs
- publish: only when above pass (tags/main policy)

## Acceptance criteria
- ✅ GHCR publish blocked on failures
- ✅ Logs clearly indicate failing provider/pack

## Files
- `.github/workflows/ci.yml`
- `ci/local_check.sh`
