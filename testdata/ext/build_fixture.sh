#!/usr/bin/env bash
# Regenerate the in-repo fixture extension.wasm. Run manually; output is committed.
# Requires: wat2wasm (install via `apt install wabt` or `cargo install wabt`).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/greentic.deploy-testfixture/extension.wasm"
WAT="$(mktemp --suffix=.wat)"
cat > "${WAT}" <<'EOF'
(module)
EOF
wat2wasm -o "${OUT}" "${WAT}"
rm -f "${WAT}"
echo "regenerated ${OUT}"
