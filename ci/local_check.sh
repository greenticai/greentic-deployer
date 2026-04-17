#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> cargo fmt --check"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --all-targets --all-features -- -D warnings

echo "==> replay deployer scaffolds"
cargo run --features internal-tools --bin replay_deployer_scaffolds

echo "==> build and validate fixture gtpacks"
cargo run --features internal-tools --bin build_fixture_gtpacks

echo "==> cargo test"
cargo test --all

echo "==> cargo doc"
cargo doc --no-deps

echo "==> cargo build --no-default-features (baseline)"
cargo build --no-default-features

echo "==> cargo build --features extensions"
cargo build --features extensions

echo "==> cargo test --features extensions"
cargo test --features extensions

echo "Local check completed successfully."
