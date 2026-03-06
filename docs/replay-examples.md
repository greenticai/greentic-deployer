# Replay Examples

Deployment-pack example fixtures in this repo are treated as replay-backed scaffolds.

Answer documents live under:

- `examples/answers/deployment-packs/*.json`
- `examples/answers/deployer-scaffolds/*.json`
- `testdata/answers/deployment-packs/replay-index.json`
- `testdata/answers/deployer-scaffolds/index.json`

There are two replay layers:

1. capability/example replay metadata under `examples/answers/deployment-packs/*.json`
2. real `greentic-pack wizard` scaffold answers under `examples/answers/deployer-scaffolds/*.json`

The scaffold replay path is:

1. `greentic-pack wizard validate --answers ...`
2. `greentic-pack wizard apply --answers ...`
3. provider-specific fixture assets from `fixtures/packs/*` are overlaid onto the generated scaffold

The capability/example replay layer is still modeled as:

1. answer document points to a deployment-pack fixture
2. answer document references the expected example input/output assets
3. smoke tests verify those references are still valid and stable

## Regenerate workflow

When the wizard tooling is available locally:

1. regenerate scaffolded deployer packs with:

```bash
cargo run --bin replay_deployer_scaffolds
```

2. inspect the generated sources under `target/replayed-pack-scaffolds/*`
3. update the provider-specific fixture assets under `fixtures/packs/*` as needed
4. update the capability/example replay docs under `examples/answers/deployment-packs/*` if fixture examples change
5. run:

```bash
./scripts/ci-smoke.sh
```

## Stability rule

If a replay answer document changes, its referenced fixture assets must change in the same review.
