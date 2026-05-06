# Tinfoil CLI

A command-line interface for verifying Tinfoil enclave attestations, making verified HTTP requests, and managing the lifecycle of Tinfoil Containers.

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
tinfoil proxy -p 8080
```

By default this connects to the public Tinfoil router for inference. To proxy a specific enclave, pass `-e` and `-r`:

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
  proxy -b 0.0.0.0
```

Add `-e <host> -r <owner/repo>` to target a specific enclave instead of the Tinfoil router.

Example `docker-compose.yml`:

```yaml
services:
  tinfoil-proxy:
    image: ghcr.io/tinfoilsh/tinfoil-cli:<version>
    command: >
      proxy
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
| `-e, --host` | public router | Enclave hostname (override to target a specific enclave; must be set together with `-r`) |
| `-r, --repo` | public router | Enclave config repo (override to target a specific enclave; must be set together with `-e`) |
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
  -H "Authorization: Bearer $TINFOIL_API_KEY" \
  -H "Content-Type: application/json" \
  -b '{"model": "deepseek-r1-0528", "messages": [{"role": "user", "content": "Hello"}]}'
```

Pass custom request headers with repeatable `-H, --header` flags. Headers are sent through the verified connection after enclave attestation succeeds.

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

## Container management

The `container`, `secret`, `ssh-key`, `registry`, and `domain` subcommands manage Tinfoil Containers through the same controlplane API the dashboard uses. See the [Tinfoil Containers docs](https://docs.tinfoil.sh/containers/overview) for the underlying concepts and the [CLI reference](https://docs.tinfoil.sh/containers/cli) for the full command surface.

### Logging in

Create an admin API key from the Tinfoil dashboard (Settings → API Keys → Admin keys). Admin keys are scoped to a single organization, so the CLI inherits that organization automatically.

```bash
tinfoil login                        # prompts for the key
tinfoil login --api-key admin_xxx    # non-interactive
tinfoil whoami                       # confirm the credential and show org context
tinfoil logout                       # delete saved credentials
```

Credentials are written to `~/.tinfoil/config.json` (mode 0600). Override on a per-command basis with `TINFOIL_API_KEY` and `TINFOIL_CONTROLPLANE_URL`.

### Containers

```bash
# Inspect what's deployed
tinfoil container list
tinfoil container get my-container
tinfoil container hosts             # which hosts your org may target

# Deploy
tinfoil container create my-container \
  --repo screenpipe/my-repo-container \
  --tag v1.2.3 \
  --variable LOG_LEVEL=info \
  --secret OPENAI_API_KEY \
  --custom-domain api.example.com

# Lifecycle
tinfoil container stop my-container
tinfoil container start my-container --tag v1.2.4
tinfoil container relaunch my-container --variable LOG_LEVEL=debug
tinfoil container delete my-container

# Updates
tinfoil container update status my-container
tinfoil container update accept my-container
tinfoil container update cancel my-container

# Auto-update (GitHub-connected containers)
tinfoil container auto-update my-container --on
tinfoil container auto-update my-container --off

# Open a verified proxy to a deployed container
tinfoil container connect my-container -p 8080
```

`container connect <name>` resolves the container's enclave domain and source repo, then runs a verified proxy locally — equivalent to `tinfoil proxy -e <domain> -r <repo>` but without copy-pasting either value.

### Secrets, SSH keys, registry credentials, custom domains

```bash
# Org secrets (used by containers via --secret)
tinfoil secret list
echo -n "$OPENAI_KEY" | tinfoil secret create OPENAI_API_KEY --value-file -
tinfoil secret set OPENAI_API_KEY --value-file ./key.txt
tinfoil secret delete OPENAI_API_KEY

# SSH keys for debug containers
tinfoil ssh-key create laptop --public-key-file ~/.ssh/id_ed25519.pub
tinfoil ssh-key list
tinfoil ssh-key delete laptop

# Private registry credentials
tinfoil registry list
tinfoil registry set ghcr --username myuser --token ghp_xxx
tinfoil registry set gcr --key-file ./gcp-sa.json
tinfoil registry set dockerhub --username myuser --token dckr_xxx
tinfoil registry delete ghcr

# Custom domains (TXT/CNAME instructions are printed on add/verify)
tinfoil domain add api.example.com
tinfoil domain verify api.example.com
tinfoil domain delete api.example.com
```

Pass `-o json` on any list/get to emit machine-readable JSON.

## Building from Source

```bash
git clone https://github.com/tinfoilsh/tinfoil-cli.git
cd tinfoil-cli
go build -o tinfoil
```

## Troubleshooting

- `PCR register mismatch`: The running enclave code differs from the source repo.

## Reporting Vulnerabilities

Please report security vulnerabilities by emailing [security@tinfoil.sh](mailto:security@tinfoil.sh).

We aim to respond to (legitimate) security reports within 24 hours.
