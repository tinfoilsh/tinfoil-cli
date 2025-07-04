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
curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sh
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
  infer        Run inference with a model (chat completion or audio transcription)
  chat         Chat with a language model
  audio        Transcribe audio files using Whisper
  embed        Generate text embeddings
  proxy        Run a local HTTP proxy
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

The `chat` command lets you interact with a model by simply specifying a model name and your prompt. You need to specify the model with the `-m` flag.

### Using the Chat Command

#### Basic Usage (running DeepSeek R1)

```bash
tinfoil chat -m deepseek-r1-70b -k "YOUR_API_KEY" "Why is tinfoil now called aluminum foil?"
```

This command loads the enclave host and repo values for the specified model from `config.json`.


#### Specifying a Custom Model

For custom models not included in `config.json`, supply the model name along with the `-e` and `-r` overrides:

```bash
tinfoil chat -m custom-model -k "YOUR_API_KEY" "Explain string theory" \
  -e custom.enclave.example.com \
  -r cool-user/custom-model-repo
```

If you omit `-e` or `-r` for a model that isn't in the configuration, a warning will be displayed prompting you to specify these flags.

### Command Options

- `-m, --model`: The model name to use for chat. Must be specified.
- `-k, --api-key`: The API key for authentication.
- `-e, --host`: The hostname of the enclave. Optional if defined in the config file.
- `-r, --repo`: The GitHub repository containing code measurements. Optional if defined in the config file.


## Embed

The `embed` command allows you to generate embeddings for text inputs. By default, it uses the `nomic-embed-text` model.

### Using the Embed Command

#### With Default Model

```bash
tinfoil embed -k "YOUR_API_KEY" "This is a text I want to get embeddings for."
```

This command uses the default model `nomic-embed-text` and loads the enclave host and repo values from `config.json`.

#### With Multiple Text Inputs

You can provide multiple text inputs to get embeddings for all of them:

```bash
tinfoil embed -k "YOUR_API_KEY" "First text" "Second text" "Third text"
```

#### Specifying a Custom Model

```bash
tinfoil embed -m custom-embed-model -k "YOUR_API_KEY" "Text to embed" \
  -e custom.enclave.example.com \
  -r cool-user/custom-model-repo
```

### Command Options

- `-m, --model`: The model name to use for embeddings. Defaults to `nomic-embed-text`.
- `-k, --api-key`: The API key for authentication.
- `-e, --host`: The hostname of the enclave. Optional if defined in the config file.
- `-r, --repo`: The GitHub repository containing code measurements. Optional if defined in the config file.


## Audio

The `audio` command allows you to transcribe audio files using Whisper. By default, it uses the `whisper-large-v3-turbo` model.

### Using the Audio Command

#### Basic Usage

```bash
tinfoil audio -k "YOUR_API_KEY" -f path/to/audio/file.mp3
```

This command uses the default model `whisper-large-v3-turbo` and loads the enclave host and repo values from `config.json`.

#### Specifying a Custom Model

```bash
tinfoil audio -m custom-whisper-model -k "YOUR_API_KEY" -f path/to/audio/file.mp3 \
  -e custom.enclave.example.com \
  -r cool-user/custom-model-repo
```

### Command Options

- `-m, --model`: The model name to use for transcription. Defaults to `whisper-large-v3-turbo`.
- `-k, --api-key`: The API key for authentication.
- `-f, --file`: The audio file to transcribe.
- `-e, --host`: The hostname of the enclave. Optional if defined in the config file.
- `-r, --repo`: The GitHub repository containing code measurements. Optional if defined in the config file.


## Attestation

### Verify Attestation

Use the `attestation verify` command to manually verify that an enclave is running the expected code. The output will be a series of INFO logs describing each verification step.

Sample successful output:

```bash
$ tinfoil attestation verify \
  -e llama3-3-70b-p.model.tinfoil.sh \
  -r tinfoilsh/confidential-llama3-3-70b-prod
INFO[0000] Fetching latest release for tinfoilsh/confidential-llama3-3-70b-prod 
INFO[0000] Fetching sigstore bundle from tinfoilsh/confidential-llama3-3-70b-prod for digest f2f48557c8b0c1b268f8d8673f380242ad8c4983fe9004c02a8688a89f94f333 
INFO[0001] Fetching trust root                          
INFO[0001] Verifying code measurements                  
INFO[0001] Fetching attestation doc from llama3-3-70b-p.model.tinfoil.sh 
INFO[0001] Verifying enclave measurements               
INFO[0001] Public key fingerprint: 5f6c24f54ed862c404a558aa3fa85b686b77263ceeda86131e7acd90e8af5db2 
INFO[0001] Remote public key fingerprint: 5f6c24f54ed862c404a558aa3fa85b686b77263ceeda86131e7acd90e8af5db2 
INFO[0001] Measurements match  
```

### JSON Output

You can also record the verification to a machine-readable audit log. Use the `attestation verify --json` command for this purpose.

```bash
tinfoil attestation verify \
  -e llama3-3-70b-p.model.tinfoil.sh \
  -r tinfoilsh/confidential-llama3-3-70b-prod \
  -j > file.json
```

The audit log record includes the timestamp, enclave host, code and enclave measurement fingerprints, and the verification status.

## Proxy

Use `tinfoil proxy` to start a local HTTP proxy that verifies connections and forwards them to the specified enclave.

```bash
tinfoil proxy \
  -r tinfoilsh/confidential-llama3-3-70b-64k \
  -e llama3-3-70b-64k.model.tinfoil.sh \
  -p 8080
```

## Docker

A docker image is available at `ghcr.io/tinfoilsh/tinfoil-cli`.

## Troubleshooting

Common error resolutions:

- `PCR register mismatch`: Running enclave code differs from source repo


## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to security reports within 24 hours and will keep you updated on our progress.