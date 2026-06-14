#!/usr/bin/env bash
set -euo pipefail

required_bins=(greentic-pack greentic-flow)
required_versions=(0.5.8 0.5.11)
required_specs=(greentic-pack@0.5.8 greentic-flow@0.5.11)

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
mkdir -p "$cargo_home/bin"
export PATH="$cargo_home/bin:$PATH"

missing=()
for i in "${!required_bins[@]}"; do
  bin="${required_bins[$i]}"
  version="${required_versions[$i]}"
  if ! command -v "$bin" >/dev/null 2>&1; then
    missing+=("$bin")
    continue
  fi

  actual="$("$bin" --version 2>/dev/null || true)"
  expected="$bin $version"
  if [[ "$actual" != "$expected" ]]; then
    missing+=("$bin")
  fi
done

if ((${#missing[@]} == 0)); then
  echo "Greentic fixture tools are already installed at required versions."
  exit 0
fi

echo "Missing or stale Greentic fixture tool(s): ${missing[*]}"

binstall_bin="$(command -v cargo-binstall || true)"
if [[ -z "$binstall_bin" && -x "$cargo_home/bin/cargo-binstall" ]]; then
  binstall_bin="$cargo_home/bin/cargo-binstall"
fi

if [[ -z "$binstall_bin" ]]; then
  echo "cargo-binstall is required to install fixture tools."
  echo "In GitHub Actions, add a preceding step that uses cargo-bins/cargo-binstall@main."
  exit 1
fi

"$binstall_bin" --no-confirm --force --disable-strategies compile "${required_specs[@]}"

for i in "${!required_bins[@]}"; do
  bin="${required_bins[$i]}"
  version="${required_versions[$i]}"
  command -v "$bin" >/dev/null 2>&1
  actual="$("$bin" --version 2>/dev/null || true)"
  expected="$bin $version"
  if [[ "$actual" != "$expected" ]]; then
    echo "Expected $expected, got ${actual:-<no version output>}" >&2
    exit 1
  fi
done
