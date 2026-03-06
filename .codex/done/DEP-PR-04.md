# DEP-PR-04 — Gate publishing on CLI-built packs: build + doctor + smoke before GHCR publish

## Goal
Publishing placeholder deployment packs to GHCR must be gated on:
- packs generated/built via CLI steps
- `greentic-pack doctor` passes on all built packs
- deployer smoke passes

## Implementation plan
- Add `ci/local_check.sh` that runs:
  1) generate packs (PK-PR-01)
  2) build packs -> dist
  3) doctor dist packs
  4) smoke deployer using dist packs
- Add GitHub Actions workflow with jobs: build -> doctor -> smoke -> publish (publish only on tags)

## Acceptance criteria
- ✅ GHCR publish never happens if doctor or smoke fails
- ✅ Local check reproduces CI

## Files
- `.github/workflows/ci.yml`
- `ci/local_check.sh`
- docs update
