#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRAY="$(cd "$DIR/.." && pwd)"
ROOT="$(cd "$TRAY/.." && pwd)"

OUT_DIR="$TRAY/resources/bin"
mkdir -p "$OUT_DIR"

TARGET_OS="${TINFOIL_TRAY_GOOS:-$(go env GOOS)}"
BIN_NAME="tinfoil"
case "$TARGET_OS" in
  windows) BIN_NAME="tinfoil.exe" ;;
esac
OUT="$OUT_DIR/$BIN_NAME"

cd "$ROOT"

build_one() {
  local goos="$1" goarch="$2" out="$3"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags="-s -w" -o "$out" .
}

case "$TARGET_OS" in
  darwin)
    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT
    build_one darwin amd64 "$TMPDIR/tinfoil-amd64"
    build_one darwin arm64 "$TMPDIR/tinfoil-arm64"
    lipo -create "$TMPDIR/tinfoil-amd64" "$TMPDIR/tinfoil-arm64" -output "$OUT"
    ;;
  windows)
    build_one windows amd64 "$OUT"
    ;;
  linux)
    build_one linux "$(go env GOARCH)" "$OUT"
    ;;
  *)
    build_one "$TARGET_OS" "$(go env GOARCH)" "$OUT"
    ;;
esac

echo "Built $OUT"
