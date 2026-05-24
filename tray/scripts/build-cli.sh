#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRAY="$(cd "$DIR/.." && pwd)"
ROOT="$(cd "$TRAY/.." && pwd)"

OUT_DIR="$TRAY/resources/bin"
mkdir -p "$OUT_DIR"

BIN_NAME="tinfoil"
case "${GOOS:-$(go env GOOS)}" in
  windows) BIN_NAME="tinfoil.exe" ;;
esac

cd "$ROOT"
go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/$BIN_NAME" .

echo "Built $OUT_DIR/$BIN_NAME"
