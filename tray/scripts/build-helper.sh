#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
  echo "build-helper.sh: skipping (only required on macOS)"
  exit 0
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
SRC="$ROOT/native/macos/tinfoil-trust.swift"
PLIST="$ROOT/native/macos/Info.plist"
OUT_DIR="$ROOT/native/build"
OUT_BIN="$OUT_DIR/tinfoil-trust"

mkdir -p "$OUT_DIR"

xcrun swiftc \
  -O \
  -target arm64-apple-macos11 \
  -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker "$PLIST" \
  "$SRC" \
  -o "$OUT_BIN"

if [[ -n "${MAC_CERT_IDENTITY:-}" ]]; then
  echo "Signing tinfoil-trust with identity: $MAC_CERT_IDENTITY"
  codesign --force --sign "$MAC_CERT_IDENTITY" --options runtime --timestamp "$OUT_BIN"
elif security find-identity -p codesigning -v 2>/dev/null | grep -q "Developer ID Application"; then
  IDENTITY=$(security find-identity -p codesigning -v | grep "Developer ID Application" | head -n1 | awk -F'"' '{print $2}')
  echo "Signing tinfoil-trust with auto-detected identity: $IDENTITY"
  codesign --force --sign "$IDENTITY" --options runtime --timestamp "$OUT_BIN"
else
  echo "No Developer ID Application identity found; signing tinfoil-trust ad-hoc"
  codesign --force --sign - "$OUT_BIN"
fi

echo "Built $OUT_BIN"
