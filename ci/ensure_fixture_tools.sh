#!/usr/bin/env bash
set -euo pipefail

required_bins=(greentic-pack greentic-flow)
required_specs=(greentic-pack@0.5.6 greentic-flow@0.5.8)

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
if [[ -d "$cargo_home/bin" ]]; then
  export PATH="$cargo_home/bin:$PATH"
fi

missing=()
for bin in "${required_bins[@]}"; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    missing+=("$bin")
  fi
done

if ((${#missing[@]} == 0)); then
  echo "Greentic fixture tools are already installed."
  exit 0
fi

echo "Missing Greentic fixture tool(s): ${missing[*]}"

binstall_bin="$(command -v cargo-binstall || true)"
if [[ -z "$binstall_bin" && -x "$cargo_home/bin/cargo-binstall" ]]; then
  binstall_bin="$cargo_home/bin/cargo-binstall"
fi

if [[ -z "$binstall_bin" ]]; then
  echo "cargo-binstall is required to install fixture tools."
  echo "In GitHub Actions, add a preceding step that uses cargo-bins/cargo-binstall@main."
  exit 1
fi

"$binstall_bin" --no-confirm --force "${required_specs[@]}"

for bin in "${required_bins[@]}"; do
  command -v "$bin" >/dev/null 2>&1
done
