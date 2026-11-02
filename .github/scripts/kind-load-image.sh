#!/usr/bin/env bash
# Load a (possibly multi-platform) registry image into a kind cluster.
#
# `kind load docker-image` pipes `docker save` into `ctr images import
# --all-platforms`. With Docker's containerd image store, `docker pull` of a
# multi-platform tag keeps the full image index but fetches content for the
# runner's platform only, so the import fails with
# `ctr: content digest sha256:...: not found` before any test runs.
#
# Saving just the node's platform gives an archive whose index references only
# content that exists, which `--all-platforms` then imports cleanly.
set -euo pipefail

img="${1:?usage: kind-load-image.sh <image> <kind-cluster-name>}"
cluster="${2:?usage: kind-load-image.sh <image> <kind-cluster-name>}"
platform="${KIND_LOAD_PLATFORM:-linux/amd64}"
archive="$(mktemp "${RUNNER_TEMP:-/tmp}/kind-image.XXXXXX.tar")"
trap 'rm -f "$archive"' EXIT

docker pull --platform "$platform" "$img"
if docker save --help 2>&1 | grep -q -- '--platform'; then
  docker save --platform "$platform" -o "$archive" "$img"
else
  # Older Docker: no --platform on save, and no containerd image store either,
  # so the plain save already contains only the pulled platform.
  docker save -o "$archive" "$img"
fi
kind load image-archive "$archive" --name "$cluster"
