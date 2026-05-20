#!/usr/bin/env bash
set -euo pipefail

required_bins=(greentic-pack greentic-flow)
required_specs=(greentic-pack@0.5.6 greentic-flow@0.5.8)

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

if ! cargo binstall --version >/dev/null 2>&1; then
  echo "cargo-binstall is required to install fixture tools."
  echo "Install it first with: cargo install cargo-binstall"
  exit 1
fi

cargo binstall --no-confirm "${required_specs[@]}"

for bin in "${required_bins[@]}"; do
  command -v "$bin" >/dev/null 2>&1
done
