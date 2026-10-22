#!/bin/sh
# tinfoil-cli install script
# This script detects your OS/architecture, downloads the latest tinfoil-cli
# release, and installs it to /usr/local/bin. Release verification is opt-in:
# pass --verify-release to authenticate the download before installing.
#
# With --verify-release, the archive is authenticated against the release
# workflow's Sigstore attestation before anything is installed: the
# attestation is fetched from api.github.com and checked against a pinned
# workflow identity, so a network-path attacker would need to compromise TLS
# to two independent origins and forge a Sigstore certificate chain to serve
# a tampered binary.
#
# Verification requires the GitHub CLI (gh). Without --verify-release, the
# script installs the download without checking its attestation.
#
# Usage: curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sh
#        curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sh -s -- --verify-release

set -eu

REPO="tinfoilsh/tinfoil-cli"
WORKFLOW="tinfoilsh/tinfoil-cli/.github/workflows/release.yml"
VERIFY_RELEASE=false

main() {
  echo "tinfoil-cli install script"

  for arg in "$@"; do
    case "$arg" in
      --verify-release)
        VERIFY_RELEASE=true
        ;;
      *)
        echo "Error: unknown argument: $arg"
        echo "Usage: install.sh [--verify-release]"
        exit 1
        ;;
    esac
  done

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
  # 3. Require the GitHub CLI for verification
  # -------------------------------
  if [ "$VERIFY_RELEASE" = "true" ]; then
    if ! command -v gh >/dev/null 2>&1; then
      echo "Error: --verify-release requires the GitHub CLI (gh)."
      echo "Install gh from https://cli.github.com/ and re-run, or omit"
      echo "--verify-release to install without attestation verification."
      exit 1
    fi
    if ! gh attestation verify --help >/dev/null 2>&1; then
      echo "Error: the installed gh does not support 'attestation verify'."
      echo "Upgrade gh (https://cli.github.com/), or omit --verify-release"
      echo "to install without attestation verification."
      exit 1
    fi
  fi

  # -------------------------------
  # 4. Choose a downloader: curl or wget
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
  # 5. Fetch the latest version using GitHub API
  # -------------------------------
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
  # The tag_name might be like "v0.0.2". We remove a leading "v" if present.
  VERSION="$($DOWNLOADER "$API_URL" | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')"
  if [ -z "$VERSION" ]; then
      echo "Error: Could not determine latest version."
      exit 1
  fi
  echo "Latest version: $VERSION"

  # -------------------------------
  # 6. Construct the download URL using the asset naming convention:
  #    tinfoil-cli_<version>_<os>_<arch>.tar.gz
  # -------------------------------
  URL="https://github.com/${REPO}/releases/latest/download/tinfoil-cli_${VERSION}_${OS}_${ARCH}.tar.gz"
  echo "Downloading tinfoil-cli from: $URL"

  # -------------------------------
  # 7. Download the tarball
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

  # -------------------------------
  # 8. Optionally verify the Sigstore attestation before extracting anything.
  #    gh fetches the attestation from api.github.com by digest, checks the
  #    signature against the Sigstore root of trust, and --cert-identity
  #    enforces an exact SAN match on the signing workflow: the identity
  #    must be this repository's release workflow run from this release
  #    tag, so an attestation from a branch run or a different tag fails.
  # -------------------------------
  if [ "$VERIFY_RELEASE" = "true" ]; then
      EXPECTED_SAN="https://github.com/${WORKFLOW}@refs/tags/v${VERSION}"
      echo "Verifying release attestation..."
      if ! gh attestation verify tinfoil-cli.tar.gz \
          --repo "$REPO" \
          --cert-identity "$EXPECTED_SAN" \
          --predicate-type https://slsa.dev/provenance/v1; then
          echo "Error: attestation verification failed (expected identity: ${EXPECTED_SAN})."
          echo "The download was not installed."
          exit 1
      fi
      echo "Attestation verified."
  else
      echo "Installing without release verification; the download is only"
      echo "protected by TLS. Re-run with --verify-release to authenticate it"
      echo "(requires gh)."
  fi

  # -------------------------------
  # 9. Extract and install the binary
  # -------------------------------
  echo "Extracting tarball..."
  tar -xzf tinfoil-cli.tar.gz

  # The archive should contain the binary named "tinfoil"
  if [ ! -f "./tinfoil" ]; then
      echo "Error: tinfoil binary not found in the archive."
      exit 1
  fi

  chmod +x tinfoil

  # -------------------------------
  # 10. Install the binary to /usr/local/bin
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
