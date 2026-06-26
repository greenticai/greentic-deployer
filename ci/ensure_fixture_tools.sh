#!/usr/bin/env bash
set -euo pipefail

required_bins=(greentic-pack greentic-flow)
required_specs=(greentic-pack greentic-flow)

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
mkdir -p "$cargo_home/bin"
export PATH="$cargo_home/bin:$PATH"

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

install_with_cargo() {
  local spec="$1"
  echo "Installing $spec with cargo install without version pinning."
  cargo install --locked --force "$spec" || cargo install --force "$spec"
}

binstall_bin="$(command -v cargo-binstall || true)"
if [[ -z "$binstall_bin" && -x "$cargo_home/bin/cargo-binstall" ]]; then
  binstall_bin="$cargo_home/bin/cargo-binstall"
fi

if [[ -z "$binstall_bin" ]]; then
  echo "cargo-binstall is unavailable; falling back to cargo install without version pinning."
  for spec in "${missing[@]}"; do
    install_with_cargo "$spec"
  done
else
  if ! "$binstall_bin" --no-confirm --force --disable-strategies compile "${required_specs[@]}"; then
    echo "cargo-binstall failed; falling back to cargo install without version pinning."
    for spec in "${missing[@]}"; do
      install_with_cargo "$spec"
    done
  fi
fi

for bin in "${required_bins[@]}"; do
  command -v "$bin" >/dev/null 2>&1
done
