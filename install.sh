#!/bin/sh
# tinfoil-cli install script
# This script detects your OS/architecture, downloads the latest tinfoil-cli
# release, verifies it against the SHA-256 digest published by the GitHub
# release API, and installs it to /usr/local/bin.
#
# The digest comes from api.github.com, an origin independent of the release
# download CDN, so a compromised download path cannot substitute a different
# archive. For provenance verification against the release workflow identity,
# download the archive and verify its Sigstore attestation with
# `gh attestation verify` before installing.
#
# Usage: curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sh

set -eu

REPO="tinfoilsh/tinfoil-cli"

main() {
  echo "tinfoil-cli install script"

  if [ "$#" -gt 0 ]; then
    echo "Error: unknown argument: $1"
    echo "Usage: install.sh"
    exit 1
  fi

  # -------------------------------
  # 1. Detect operating system
  # -------------------------------
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$OS" in
    linux)
      OS="linux"
      ;;
    darwin)
      OS="darwin"
      ;;
    *)
      echo "Error: Unsupported operating system: $OS"
      exit 1
      ;;
  esac

  # -------------------------------
  # 2. Detect CPU architecture
  # -------------------------------
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64)
      ARCH="amd64"
      ;;
    arm64|aarch64)
      ARCH="arm64"
      ;;
    arm*)
      ARCH="arm"
      ;;
    *)
      echo "Error: Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac

  echo "Detected OS: $OS, Architecture: $ARCH"

  # -------------------------------
  # 3. Choose a downloader: curl or wget
  # -------------------------------
  if command -v curl >/dev/null 2>&1; then
      DOWNLOADER="curl -fsSL"
  elif command -v wget >/dev/null 2>&1; then
      DOWNLOADER="wget -qO-"
  else
      echo "Error: This installer requires curl or wget."
      exit 1
  fi

  # -------------------------------
  # 4. Fetch the release metadata and the published asset digest
  # -------------------------------
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
  if ! RELEASE_JSON="$($DOWNLOADER "$API_URL")"; then
      echo "Error: Could not fetch release metadata."
      exit 1
  fi
  # The tag_name might be like "v0.0.2". We remove a leading "v" if present.
  VERSION="$(printf '%s\n' "$RELEASE_JSON" | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')"
  if [ -z "$VERSION" ]; then
      echo "Error: Could not determine latest version."
      exit 1
  fi
  echo "Latest version: $VERSION"

  ASSET="tinfoil-cli_${VERSION}_${OS}_${ARCH}.tar.gz"
  ASSETS_JSON="$(printf '%s\n' "$RELEASE_JSON" | sed -n '/"assets": \[/,/^  \],/p')"
  EXPECTED_DIGEST="$(printf '%s\n' "$ASSETS_JSON" | grep -A 80 "\"name\": \"${ASSET}\"" | grep -m1 '"digest": "sha256:' | sed -E 's/.*sha256:([0-9a-f]{64}).*/\1/')"
  if [ -z "$EXPECTED_DIGEST" ]; then
      echo "Error: No SHA-256 digest published for ${ASSET}."
      echo "The download was not installed."
      exit 1
  fi

  # -------------------------------
  # 5. Construct the download URL using the asset naming convention
  # -------------------------------
  URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET}"
  echo "Downloading tinfoil-cli from: $URL"

  # -------------------------------
  # 6. Download the tarball
  # -------------------------------
  TMPDIR="$(mktemp -d)"
  # Ensure cleanup on exit
  trap 'rm -rf "$TMPDIR"' EXIT
  cd "$TMPDIR"

  echo "Downloading tarball..."
  if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$URL" -o "$ASSET"
  else
      wget -qO "$ASSET" "$URL"
  fi

  # -------------------------------
  # 7. Verify the download against the digest from the release API
  # -------------------------------
  echo "Verifying SHA-256 digest..."
  if command -v sha256sum >/dev/null 2>&1; then
      if ! printf '%s  %s\n' "$EXPECTED_DIGEST" "$ASSET" | sha256sum -c -; then
          echo "Error: SHA-256 digest mismatch. The download was not installed."
          exit 1
      fi
  elif command -v shasum >/dev/null 2>&1; then
      if ! printf '%s  %s\n' "$EXPECTED_DIGEST" "$ASSET" | shasum -a 256 -c -; then
          echo "Error: SHA-256 digest mismatch. The download was not installed."
          exit 1
      fi
  else
      echo "Error: sha256sum or shasum is required to verify the download."
      exit 1
  fi
  echo "Digest verified."

  # -------------------------------
  # 8. Extract and install the binary
  # -------------------------------
  echo "Extracting tarball..."
  tar -xzf "$ASSET"

  # The archive should contain the binary named "tinfoil"
  if [ ! -f "./tinfoil" ]; then
      echo "Error: tinfoil binary not found in the archive."
      exit 1
  fi

  chmod +x tinfoil

  # -------------------------------
  # 9. Install the binary to /usr/local/bin
  # -------------------------------
  echo "Installing tinfoil to /usr/local/bin..."
  if [ "$(id -u)" -ne 0 ]; then
      if command -v sudo >/dev/null 2>&1; then
          sudo mv tinfoil /usr/local/bin/tinfoil
      else
          echo "Error: Root privileges are required. Please run as root or install sudo."
          exit 1
      fi
  else
      mv tinfoil /usr/local/bin/tinfoil
  fi

  echo "tinfoil installed successfully!"
  echo "You can now run it with: tinfoil"
}

main "$@"
