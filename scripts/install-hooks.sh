#!/usr/bin/env bash
# One-time setup: point git at the in-repo .githooks/ directory so local
# commits and pushes run fmt + clippy + full ci/local_check.sh before
# being sent to origin.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

git config core.hooksPath .githooks
chmod +x .githooks/pre-commit .githooks/pre-push

echo "git hooks installed from .githooks/"
echo "  pre-commit: cargo fmt --check + cargo clippy -D warnings"
echo "  pre-push:   ci/local_check.sh (fmt + clippy + test + features matrix)"
echo
echo "To bypass in emergency: git commit --no-verify / git push --no-verify"
echo "To disable entirely:    git config --unset core.hooksPath"
