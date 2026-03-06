# Tinfoil CLI

A command-line interface for verifying Tinfoil enclave attestations and making verified HTTP requests.

[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/cli-sdk)

## Installation

```sh
curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sh
```

Or download a binary from the [Releases](https://github.com/tinfoilsh/tinfoil-cli/releases) page. A Docker image is also available at `ghcr.io/tinfoilsh/tinfoil-cli`.

## Proxy

Run a local proxy that verifies enclave attestation and forwards requests. This lets any language or tool (PHP, Ruby, Java, curl, etc.) use Tinfoil without a native SDK — just point your HTTP client at `localhost`.

The proxy verifies the enclave on startup (hardware attestation, Sigstore bundle, measurement comparison) and pins the TLS certificate. If the certificate rotates, the proxy re-verifies automatically. If verification fails, requests are rejected.

```bash
tinfoil proxy \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router \
  -p 8080
```

Then send requests to `http://localhost:8080` using the OpenAI-compatible API:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $TINFOIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-r1-0528",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

The proxy passes your `Authorization` header through to the enclave — it does not inject or store credentials.

### Docker

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

### Proxy Options

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --port` | `8080` | Port to listen on |
| `-b, --bind` | `127.0.0.1` | Address to bind to (use `0.0.0.0` in Docker) |
| `-e, --host` | | Enclave hostname |
| `-r, --repo` | | Enclave config repo |
| `--log-format` | `text` | `text` or `json` |

## HTTP Requests

Make one-off verified requests directly, without running the proxy:

```bash
# GET
tinfoil http get https://inference.tinfoil.sh/health \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router

# POST
tinfoil http post https://inference.tinfoil.sh/v1/chat/completions \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router \
  -b '{"model": "deepseek-r1-0528", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Attestation Verification

Manually verify that an enclave is running the expected code:

```bash
tinfoil attestation verify \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router
```

```
INFO[0000] Fetching latest release for tinfoilsh/confidential-model-router
INFO[0000] Fetching sigstore bundle for digest f2f48557c8b0...
INFO[0001] Verifying code measurements
INFO[0001] Fetching attestation doc from inference.tinfoil.sh
INFO[0001] Verifying enclave measurements
INFO[0001] Public key fingerprint: 5f6c24f54ed862c4...
INFO[0001] Measurements match
```

Use `-j` for machine-readable JSON output:

```bash
tinfoil attestation verify \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router \
  -j > verification.json
```

## Certificate Audit

Verify that a TLS certificate matches the enclave's attestation:

```bash
# From a live server
tinfoil certificate audit -s inference.tinfoil.sh

# From a PEM file
tinfoil certificate audit -c /path/to/certificate.pem
```

## Building from Source

```bash
git clone https://github.com/tinfoilsh/tinfoil-cli.git
cd tinfoil-cli
go build -o tinfoil
```

## Troubleshooting

- `PCR register mismatch`: The running enclave code differs from the source repo.

## Reporting Vulnerabilities

Email [security@tinfoil.sh](mailto:security@tinfoil.sh) or open an issue. We respond within 24 hours.
