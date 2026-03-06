# Tinfoil CLI

A command-line interface for verifying Tinfoil enclave attestations and making verified HTTP requests.

[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/cli-sdk)

## Installation

### Pre-built binaries

Download the latest release for your OS from the [Releases](https://github.com/tinfoilsh/tinfoil-cli/releases) page.

### Install Script

You can also install tinfoil CLI using our install script. This script automatically detects your operating system and architecture, downloads the correct binary, and installs it to `/usr/local/bin`.

Run the following command:

```sh
curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sh
```

Note: If you receive permission errors, you may need to run the command with sudo:

```sh
curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sudo sh
```

### Build from source

1. Ensure you have Go installed.
2. Clone the repository:

```bash
git clone https://github.com/tinfoilsh/tinfoil-cli.git
cd tinfoil-cli
```

3. Build the binary:

```bash
go build -o tinfoil
```

## Command Reference

```text
Usage:
  tinfoil [command]

Available Commands:
  attestation Attestation commands
  certificate Audit enclave certificate
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  http        Make verified HTTP requests
  proxy       Run a local HTTP proxy

Flags:
  -h, --help          Help for tinfoil
  -e, --host string   Enclave hostname
  -r, --repo string   Enclave config repo
  -t, --trace         Trace output
  -v, --verbose       Verbose output

Use "tinfoil [command] --help" for more information about a command.
```

## Attestation

### Verify Attestation

Use the `attestation verify` command to manually verify that an enclave is running the expected code. The output will be a series of INFO logs describing each verification step.

Sample successful output:

```bash
$ tinfoil attestation verify \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router
INFO[0000] Fetching latest release for tinfoilsh/confidential-model-router
INFO[0000] Fetching sigstore bundle from tinfoilsh/confidential-model-router for digest f2f48557c8b0c1b268f8d8673f380242ad8c4983fe9004c02a8688a89f94f333
INFO[0001] Fetching trust root
INFO[0001] Verifying code measurements
INFO[0001] Fetching attestation doc from inference.tinfoil.sh
INFO[0001] Verifying enclave measurements
INFO[0001] Public key fingerprint: 5f6c24f54ed862c404a558aa3fa85b686b77263ceeda86131e7acd90e8af5db2
INFO[0001] Measurements match
```

### JSON Output

You can also record the verification to a machine-readable audit log. Use the `attestation verify --json` command for this purpose.

```bash
tinfoil attestation verify \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router \
  -j > verification.json
```

Or use the `-l` flag to specify the output file directly:

```bash
tinfoil attestation verify \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router \
  -j -l verification.json
```

The audit log record includes the timestamp, enclave host, code and enclave measurement fingerprints, and the verification status.

## Certificate Audit

The `certificate audit` command verifies that a TLS certificate matches the enclave's attestation document.

### Audit from Server

```bash
tinfoil certificate audit -s inference.tinfoil.sh
```

### Audit from Certificate File

```bash
tinfoil certificate audit -c /path/to/certificate.pem
```

### Command Options

- `-s, --server`: Server to connect to for retrieving the certificate
- `-c, --cert`: Path to a PEM encoded certificate file

## HTTP Requests

The `http` command makes verified HTTP requests to Tinfoil enclaves with attestation verification.

### GET Request

```bash
tinfoil http get https://inference.tinfoil.sh/health \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router
```

### POST Request

```bash
tinfoil http post https://inference.tinfoil.sh/v1/chat/completions \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router \
  -b '{"model": "deepseek-r1-0528", "messages": [{"role": "user", "content": "Hello"}]}'
```

### Command Options

- `-b, --body`: HTTP POST body
- `-s, --stream`: Stream response output (POST only)

## Proxy

The proxy runs a local HTTP server that handles attestation verification and forwards requests to a Tinfoil enclave. This lets you use Tinfoil's verified inference from any language or tool that can make HTTP requests — PHP, Ruby, Java, curl, or anything else — without needing a native Tinfoil SDK.

On startup, the proxy verifies the enclave's attestation (hardware attestation, Sigstore bundle, measurement comparison) and pins the TLS certificate. If the enclave's certificate rotates, the proxy automatically re-verifies before continuing. If verification fails, requests are rejected.

### Basic Usage

```bash
tinfoil proxy \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router \
  -p 8080
```

Once running, send requests to `http://localhost:8080` as if it were an OpenAI-compatible API:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $TINFOIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-r1-0528",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

Your API key is passed through to the enclave via the `Authorization` header — the proxy does not inject or store credentials.

### Docker

The proxy is available as a Docker image, which is useful for running it alongside other services in Docker Compose:

```bash
docker run -p 8080:8080 ghcr.io/tinfoilsh/tinfoil-cli:<version> \
  proxy \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router \
  -b 0.0.0.0
```

Example `docker-compose.yml`:

```yaml
services:
  tinfoil-proxy:
    image: ghcr.io/tinfoilsh/tinfoil-cli:<version>
    command: >
      proxy
      -e inference.tinfoil.sh
      -r tinfoilsh/confidential-model-router
      -b 0.0.0.0
      -p 8080
    ports:
      - "8080:8080"

  your-app:
    # Your application connects to http://tinfoil-proxy:8080
    environment:
      - INFERENCE_URL=http://tinfoil-proxy:8080
```

### Command Options

- `-p, --port`: Port to listen on. Defaults to `8080`.
- `-b, --bind`: Address to bind to. Defaults to `127.0.0.1`.
- `-e, --host`: The hostname of the enclave.
- `-r, --repo`: The enclave config repo.
- `--log-format`: Logger output format (`text` or `json`). Defaults to `text`.

By default, the proxy binds to `127.0.0.1` (localhost only). To expose the proxy on all interfaces (required in Docker), use `-b 0.0.0.0`.

## Docker

A docker image is available at `ghcr.io/tinfoilsh/tinfoil-cli`.

## Troubleshooting

Common error resolutions:

- `PCR register mismatch`: Running enclave code differs from source repo


## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
