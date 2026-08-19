#!/usr/bin/env bash
# Stage the matching vigolium-audit blob into the go:embed path before a
# cross-compiled vigolium build.
#
# goreleaser invokes this as a per-target build pre-hook:
#     stage-audit-blob.sh <goos> <goarch>
#
# The embed path pkg/audit/bin/_bin/vigolium-audit is a SINGLE file consumed by
# go:embed, so cross builds MUST run sequentially (goreleaser -p 1) — parallel
# builds would race on this shared path and bake the wrong-arch blob into a
# binary. The loader-marker check in build/npm/build.mjs is the backstop that
# fails the release if a wrong-OS blob still ends up embedded.
set -euo pipefail

goos="${1:?usage: stage-audit-blob.sh <goos> <goarch>}"
goarch="${2:?usage: stage-audit-blob.sh <goos> <goarch>}"

# Map Go arch names to the vigolium-audit blob naming (amd64 -> x64).
case "$goarch" in
  amd64) blob_arch="x64" ;;
  arm64) blob_arch="arm64" ;;
  *) echo "[stage-audit-blob] unsupported goarch: $goarch" >&2; exit 1 ;;
esac

# Bun emits the windows target with an .exe suffix. The destination name stays
# extensionless for every target because it is a fixed go:embed path
# (pkg/audit/bin/embed.go); the extractor re-adds .exe at runtime on Windows.
blob_ext=""
if [ "$goos" = "windows" ]; then
  blob_ext=".exe"
  if [ "$goarch" != "amd64" ]; then
    echo "[stage-audit-blob] windows/$goarch is not a supported target -- Bun has no" >&2
    echo "  bun-windows-arm64 compile target, so no audit blob exists for it." >&2
    exit 1
  fi
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
src="$repo_root/platform/vigolium-audit/build/dist/vigolium-audit-$goos-$blob_arch$blob_ext"
dst="$repo_root/pkg/audit/bin/_bin/vigolium-audit"

if [ ! -f "$src" ]; then
  echo "[stage-audit-blob] missing audit blob: $src" >&2
  echo "  run 'make update-audit' to build the cross-compile blobs first." >&2
  exit 1
fi

# Sanity: confirm the blob's container format matches the requested target
# before embedding it. Catches a mislabeled or corrupt dist artifact.
desc="$(file -b "$src")"
case "$goos" in
  linux)
    echo "$desc" | grep -q "ELF" || {
      echo "[stage-audit-blob] $src is not an ELF binary (got: $desc)" >&2; exit 1; } ;;
  darwin)
    echo "$desc" | grep -q "Mach-O" || {
      echo "[stage-audit-blob] $src is not a Mach-O binary (got: $desc)" >&2; exit 1; } ;;
  windows)
    echo "$desc" | grep -q "PE32" || {
      echo "[stage-audit-blob] $src is not a PE binary (got: $desc)" >&2; exit 1; } ;;
esac

mkdir -p "$(dirname "$dst")"
cp "$src" "$dst"
chmod +x "$dst"
echo "[stage-audit-blob] staged vigolium-audit-$goos-$blob_arch$blob_ext -> _bin/vigolium-audit ($desc)"
