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

Note: If you receive permission errors (for example, if you're not running as root), you may need to run the command with sudo:

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
  chat         Chat with a language model
  audio        Transcribe audio files using Whisper
  embed        Generate text embeddings
  completion   Generate the autocompletion script for the specified shell
  help         Help about any command
  http         Make verified HTTP requests

Flags:
  -e, --host string           Enclave hostname
  -h, --help                  help for tinfoil
  -r, --repo string          Source repo

Use "tinfoil [command] --help" for more information about a command.
```

## Chat

The `chat` command lets you interact with language models. Simply specify a model name and your prompt.

### Using the Chat Command

#### Basic Usage (running DeepSeek R1)

```bash
tinfoil chat -m deepseek-r1-70b -k "YOUR_API_KEY" "Why is tinfoil now called aluminum foil?"
```

This command loads the enclave host and repo values for the specified model from `config.json`.

#### Listing Available Models

To see all available chat models:

```bash
tinfoil chat --list
```

#### Specifying a Custom Model

For custom models not included in `config.json`, supply the model name along with the `-e` and `-r` overrides:

```bash
tinfoil chat -m custom-model -k "YOUR_API_KEY" "Explain string theory" \
  -e custom.enclave.example.com \
  -r cool-user/custom-model-repo
```

### Chat Command Options

- `-m, --model`: The model name to use for chat (required)
- `-k, --api-key`: The API key for authentication
- `-e, --host`: The hostname of the enclave (optional if defined in config)
- `-r, --repo`: The GitHub repository containing code measurements (optional if defined in config)
- `-l, --list`: List available chat models

## Audio Transcription

The `audio` command allows you to transcribe audio files using Whisper models.

### Using the Audio Command

```bash
tinfoil audio -f path/to/audio.mp3 -k "YOUR_API_KEY"
```

By default, this uses the `whisper-large-v3-turbo` model. You can specify a different Whisper model if needed:

```bash
tinfoil audio -m whisper-custom-model -f audio.mp3 -k "YOUR_API_KEY"
```

### Audio Command Options

- `-f, --file`: The audio file to transcribe (required)
- `-m, --model`: The Whisper model to use (defaults to whisper-large-v3-turbo)
- `-k, --api-key`: The API key for authentication
- `-e, --host`: The hostname of the enclave (optional if defined in config)
- `-r, --repo`: The GitHub repository containing code measurements (optional if defined in config)

## Embed

The `embed` command allows you to generate embeddings for text inputs. By default, it uses the `nomic-embed-text` model.

### Using the Embed Command

#### With Default Model

```bash
tinfoil embed "This is a text I want to get embeddings for."
```

This command uses the default model `nomic-embed-text` and loads the enclave host and repo values from `config.json`.

#### With Multiple Text Inputs

You can provide multiple text inputs to get embeddings for all of them:

```bash
tinfoil embed "First text" "Second text" "Third text"
```

#### Specifying a Custom Model

```bash
tinfoil embed -m custom-embed-model -k "YOUR_API_KEY" "Text to embed" \
  -e custom.enclave.example.com \
  -r cool-user/custom-model-repo
```

### Command Options

- `-m, --model`: The model name to use for embeddings. Defaults to `nomic-embed-text`.
- `-e, --host`: The hostname of the enclave. Optional if defined in the config file.
- `-r, --repo`: The GitHub repository containing code measurements. Optional if defined in the config file.

## Attestation

### Verify Attestation

Use the `attestation verify` command to manually verify that an enclave is running the expected code. The output will be a series of INFO logs describing each verification step.

Sample successful output:

```bash
$ tinfoil attestation verify \
  -e llama3-3-70b.model.tinfoil.sh \
  -r tinfoilsh/confidential-llama3-3-70b
INFO[0000] Fetching latest release for tinfoilsh/confidential-llama3-3-70b 
INFO[0000] Fetching sigstore bundle from tinfoilsh/confidential-llama3-3-70b for digest f2f48557c8b0c1b268f8d8673f380242ad8c4983fe9004c02a8688a89f94f333 
INFO[0001] Fetching trust root                          
INFO[0001] Verifying code measurements                  
INFO[0001] Fetching attestation doc from llama3-3-70b.model.tinfoil.sh 
INFO[0001] Verifying enclave measurements               
INFO[0001] Public key fingerprint: 5f6c24f54ed862c404a558aa3fa85b686b77263ceeda86131e7acd90e8af5db2 
INFO[0001] Remote public key fingerprint: 5f6c24f54ed862c404a558aa3fa85b686b77263ceeda86131e7acd90e8af5db2 
INFO[0001] Measurements match  
```

### Audit Attestation

You can also verify attestations at random and record a machine-readable audit log. Use the `attestation audit` command for this purpose.

By default the audit record is printed to stdout as JSON. To write it to a file, use the `-l/--log-file` flag:

```bash
tinfoil attestation audit \
  -e llama3-3-70b.model.tinfoil.sh \
  -r tinfoilsh/confidential-llama3-3-70b \
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