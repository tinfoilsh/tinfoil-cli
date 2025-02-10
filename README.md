# Tinfoil CLI

A command-line interface for making verified HTTP requests to Tinfoil enclaves and validating attestation documents.

## Installation

### Pre-built binaries

Download the latest release for your OS from the [Releases](https://github.com/tinfoilanalytics/tinfoil-cli/releases) page.

### Install Script

You can also install tinfoil CLI using our install script. This script automatically detects your operating system and architecture, downloads the correct binary, and installs it to `/usr/local/bin`.

Run the following command:

```sh
curl -fsSL https://github.com/tinfoilanalytics/tinfoil-cli/raw/main/install.sh | sh
```

Note: If you receive permission errors (for example, if you’re not running as root), you may need to run the command with sudo:

```sh
sudo curl -fsSL https://github.com/tinfoilanalytics/tinfoil-cli/raw/main/install.sh | sh
```

### Build from source

1. Ensure you have Go installed.
2. Clone the repository:

```bash
git clone https://github.com/tinfoilanalytics/tinfoil-cli.git
cd tinfoil-cli
```

3. Build the binary:

```bash
go build -o tinfoil
```

4. (Optional) Move the binary to your PATH:

```bash
sudo mv tinfoil /usr/local/bin/
```

## Command Reference

```text
Usage:
  tinfoil [command]

Available Commands:
  attestation Attestation commands
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  http        Make verified HTTP requests

Flags:
  -e, --enclave-host string   Enclave hostname (default "models.default.tinfoil.sh")
  -h, --help                  help for tinfoil
  -r, --repo string           Source repo (default "tinfoilanalytics/default-models-nitro")

Use "tinfoil [command] --help" for more information about a command.
```

## Verified HTTP Requests

Make requests to enclave endpoints with automatic attestation verification.

### GET Request

```bash
tinfoil http get "https://{ENCLAVE_HOST}/endpoint" \
  -e models.default.tinfoil.sh \
  -r tinfoilanalytics/default-models-nitro
```

### POST Request

```bash
tinfoil http post "https://{ENCLAVE_HOST}/endpoint" \
  -e models.default.tinfoil.sh \
  -r tinfoilanalytics/default-models-nitro \
  -b '{"input_data": "example"}'
```

Flags:

- `-e, --enclave-host`: The hostname of the enclave.
- `-r, --repo`: GitHub source repo containing code measurements.
- `-b, --body`: Request body (POST only)

### Streaming HTTP POST

To receive the response in a streaming fashion (for example, when using endpoints that return newline-delimited chunks), add the `--stream` flag:

```sh
tinfoil http post "https://models.default.tinfoil.sh/api/chat" \
  -e models.default.tinfoil.sh \
  -r tinfoilanalytics/default-models-nitro \
  --stream \
  -b '{"model": "llama3.2:1b", "messages": [{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": "Why is tinfoil now called aluminum foil?"}], "stream": true}'
```

## Attestation Verification

Validate that the enclave is running authorized code.

Sample successful output:

```bash
$ tinfoil attestation verify \
  -e models.default.tinfoil.sh \
  -r tinfoilanalytics/default-models-nitro
INFO[0000] Fetching latest release for tinfoilanalytics/default-models-nitro 
INFO[0000] Fetching sigstore bundle from v0.0.2 for latest version tinfoilanalytics/default-models-nitro EIF 906162aef9fb2d4731433421ae6050840a867ee4b7b9302ada6228a809e0cab5 
INFO[0000] Fetching trust root                          
INFO[0000] Verifying code measurements                  
INFO[0000] Fetching attestation doc from models.default.tinfoil.sh 
INFO[0001] Verifying enclave measurements               
INFO[0001] Certificate fingerprint match: b3ca31564d143085005670b450ef3d64429aa1529c641ec897983f11c2726007 
INFO[0001] Verification successful, measurements match
``` 

## Troubleshooting

Common error resolutions:

- `PCR register mismatch`: Running enclave code differs from source repo