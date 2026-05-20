#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> replay-backed deployment-pack smoke tests"
cargo test --test pr08_replay_examples

echo "==> fixture tool prerequisites"
ci/ensure_fixture_tools.sh

echo "==> replay deployer scaffolds"
cargo run --features internal-tools --bin replay_deployer_scaffolds
