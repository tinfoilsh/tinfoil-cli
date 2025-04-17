# Tinfoil CLI

A command-line interface for making verified HTTP requests to Tinfoil enclaves and validating attestation documents.

## Installation

### Pre-built binaries

Download the latest release for your OS from the [Releases](https://github.com/tinfoilsh/tinfoil-cli/releases) page.

### Install Script

You can also install tinfoil CLI using our install script. This script automatically detects your operating system and architecture, downloads the correct binary, and installs it to `/usr/local/bin`.

Run the following command:

```sh
curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sh
```

Note: If you receive permission errors (for example, if you’re not running as root), you may need to run the command with sudo:

```sh
sudo curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sh
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
  attestation  Attestation commands (verify or audit)
  chat         Chat with a model
  embed        Generate text embeddings
  completion   Generate the autocompletion script for the specified shell
  help         Help about any command
  http         Make verified HTTP requests

Flags:
  -e, --host string           Enclave hostname
  -h, --help                  help for tinfoil
  -r, --repo string           Source repo

Use "tinfoil [command] --help" for more information about a command.
```

## Chat

The `chat` command lets you interact with a model by simply specifying a model name and your prompt. By default, the model used is `deepseek-r1:70b`.

### Using the Chat Command

#### With Default Model

```bash
tinfoil chat -k "YOUR_API_KEY" "Why is tinfoil now called aluminum foil?"
```

This command uses the default model `deepseek-r1:70b` and loads the enclave host and repo values from `config.json`.

#### With another model available in `config.json`

```bash
tinfoil chat --model llama3.2:1b --api-key "YOUR_API_KEY" "Why is tinfoil now called aluminum foil?"
```

#### Specifying a Custom Model

For custom models not included in `config.json`, supply the model name along with the `-e` and `-r` overrides:

```bash
tinfoil chat --model custom-model --api-key "YOUR_API_KEY" "Explain string theory" \
  -e custom.enclave.example.com \
  -r cool-user/custom-model-repo
```

If you omit `-e` or `-r` for a model that isn’t in the configuration, a warning will be displayed prompting you to specify these flags.

### Command Options

- `-m, --model`: The model name to use for chat. Defaults to `deepseek-r1:70b`.
- `-k, --api-key`: The API key for authentication.
- `-e, --host`: The hostname of the enclave. Optional if defined in the config file.
- `-r, --repo`: The GitHub repository containing code measurements. Optional if defined in the config file.


## Attestation

### Verify Attestation

Use the `attestation verify` command to manually verify that an enclave is running the expected code. The output will be a series of INFO logs describing each verification step.

Sample successful output:

```bash
$ tinfoil attestation verify \
  -e models.default.tinfoil.sh \
  -r tinfoilsh/default-models-nitro
INFO[0000] Fetching latest release for tinfoilsh/default-models-nitro
INFO[0000] Fetching sigstore bundle from v0.0.2 for latest version tinfoilsh/default-models-nitro EIF 906162aef9fb2d4731433421ae6050840a867ee4b7b9302ada6228a809e0cab5
INFO[0000] Fetching trust root
INFO[0000] Verifying code measurements
INFO[0000] Fetching attestation doc from models.default.tinfoil.sh
INFO[0001] Verifying enclave measurements
INFO[0001] Certificate fingerprint match: b3ca31564d143085005670b450ef3d64429aa1529c641ec897983f11c2726007
INFO[0001] Verification successful, measurements match
```

### Audit Attestation

You can also verify attestations at random and record a machine-readable audit log. Use the `attestation audit` command for this purpose.

By default the audit record is printed to stdout as JSON. To write it to a file, use the `-l/--log-file` flag:

```bash
tinfoil attestation audit \
  -e models.default.tinfoil.sh \
  -r tinfoilsh/default-models-nitro \
  -l /var/log/tinfoil_audit.log
```

The audit log record includes the timestamp, enclave host, code and enclave measurement fingerprints, and the verification status.

### Proxy

Use `tinfoil proxy` to start a local HTTP proxy that verifies connections and forwards them to the specified enclave.

```bash
tinfoil proxy \
  -r tinfoilsh/confidential-llama3-3-70b-64k \
  -e llama3-3-70b-64k.model.tinfoil.sh \
  -p 8080
```

### Docker

A docker image is available at `ghcr.io/tinfoilsh/tinfoil-cli`.

## Troubleshooting

Common error resolutions:

- `PCR register mismatch`: Running enclave code differs from source repo


## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to security reports within 24 hours and will keep you updated on our progress.