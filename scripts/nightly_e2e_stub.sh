#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/ci/nightly_matrix.json"

echo "Nightly E2E stub"
echo "matrix=${MATRIX}"
echo "owner=Dmytro"
echo
echo "This script intentionally does not perform live deployments."
echo "It exists as the stable handoff entrypoint for future nightly wiring."
echo
echo "Current adapters in nightly matrix:"
python3 - <<'PY' "${MATRIX}"
import json
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)
for entry in payload["targets"]:
    print(f'- tier={entry["tier"]} adapter={entry["adapter"]} mode={entry["mode"]} env={entry["environment"]}')
PY
