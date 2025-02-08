#!/bin/sh
# tinfoil-cli install script
# This script detects your OS/architecture, downloads the latest tinfoil-cli binary,
# and installs it to /usr/local/bin.
#
# Usage: curl -fsSL https://github.com/tinfoilanalytics/tinfoil-cli/raw/main/install.sh | sh

set -eu

main() {
  echo "tinfoil-cli install script"

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
  # 4. Fetch the latest version using GitHub API
  # -------------------------------
  API_URL="https://api.github.com/repos/tinfoilanalytics/tinfoil-cli/releases/latest"
  # The tag_name might be like "v0.0.2". We remove a leading "v" if present.
  VERSION="$($DOWNLOADER "$API_URL" | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')"
  if [ -z "$VERSION" ]; then
      echo "Error: Could not determine latest version."
      exit 1
  fi
  echo "Latest version: $VERSION"

  # -------------------------------
  # 5. Construct the download URL using the asset naming convention:
  #    tinfoil-cli_<version>_<os>_<arch>.tar.gz
  # -------------------------------
  URL="https://github.com/tinfoilanalytics/tinfoil-cli/releases/latest/download/tinfoil-cli_${VERSION}_${OS}_${ARCH}.tar.gz"
  echo "Downloading tinfoil-cli from: $URL"

  # -------------------------------
  # 6. Download and extract the binary
  # -------------------------------
  TMPDIR="$(mktemp -d)"
  # Ensure cleanup on exit
  trap 'rm -rf "$TMPDIR"' EXIT
  cd "$TMPDIR"

  echo "Downloading tarball..."
  if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$URL" -o tinfoil-cli.tar.gz
  else
      wget -qO tinfoil-cli.tar.gz "$URL"
  fi

  echo "Extracting tarball..."
  tar -xzf tinfoil-cli.tar.gz

  # The archive should contain the binary named "tinfoil"
  if [ ! -f "./tinfoil" ]; then
      echo "Error: tinfoil binary not found in the archive."
      exit 1
  fi

  chmod +x tinfoil

  # -------------------------------
  # 7. Install the binary to /usr/local/bin
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

main
