# Tinfoil CLI

A command-line interface for making verified HTTP requests to Tinfoil enclaves and validating attestation documents.

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
  audio       Transcribe audio files using Whisper
  certificate Audit enclave certificate
  chat        Chat with a language model
  completion  Generate the autocompletion script for the specified shell
  embed       Generate embeddings for the provided text input(s)
  help        Help about any command
  http        Make verified HTTP requests
  proxy       Run a local HTTP proxy
  tts         Convert text to speech using TTS models

Flags:
  -h, --help          Help for tinfoil
  -e, --host string   Enclave hostname
  -r, --repo string   Source repo
  -t, --trace         Trace output
  -v, --verbose       Verbose output

Use "tinfoil [command] --help" for more information about a command.
```

## Chat

The `chat` command lets you interact with a model by simply specifying a model name and your prompt. You need to specify the model with the `-m` flag. By default, responses are returned all at once (non-streaming), but you can enable streaming with the `-s` flag.

### Using the Chat Command

#### Basic Usage (running DeepSeek R1)

```bash
tinfoil chat -m deepseek -k "YOUR_API_KEY" "Why is tinfoil now called aluminum foil?"
```

You can use either the friendly name (`deepseek`) or the full name (`deepseek-r1-0528`).

#### Streaming Response

For real-time streaming of the response (tokens appear as they're generated):

```bash
tinfoil chat -m deepseek -k "YOUR_API_KEY" -s "Explain quantum computing"
```

#### Response Modes

- **Non-streaming (default)**: The complete response is returned all at once after generation is finished
- **Streaming (`-s` flag)**: Tokens are displayed in real-time as they're generated, providing a more interactive experience

All models are now accessed through the Tinfoil inference proxy. The `config.json` provides user-friendly aliases for all models:

- `llama` → `llama3-3-70b`
- `deepseek` → `deepseek-r1-0528`
- `terminus` → `deepseek-v31-terminus`
- `gpt-oss` → `gpt-oss-120b`
- `whisper` → `whisper-large-v3-turbo`
- `embed` → `nomic-embed-text`


#### Specifying a Custom Model

You can use any model name directly. For models requiring custom enclave settings, supply the `-e` and `-r` overrides:

```bash
tinfoil chat -m custom-model -k "YOUR_API_KEY" "Explain string theory" \
  -e custom.enclave.example.com \
  -r cool-user/custom-model-repo
```

If you omit `-e` or `-r` for a model that isn't in the configuration, a warning will be displayed prompting you to specify these flags.

### Command Options

- `-m, --model`: The model name to use for chat. Must be specified.
- `-k, --api-key`: The API key for authentication.
- `-s, --stream`: Stream response output (real-time token generation). Optional, defaults to false.
- `-l, --list`: List available chat models.
- `-e, --host`: The hostname of the enclave. Optional if defined in the config file.
- `-r, --repo`: The GitHub repository containing code measurements. Optional if defined in the config file.


## Embed

The `embed` command allows you to generate embeddings for text inputs. By default, it uses the `nomic-embed-text` model.

### Using the Embed Command

#### With Default Model

```bash
tinfoil embed -k "YOUR_API_KEY" "This is a text I want to get embeddings for."
```

This command uses the default model `nomic-embed-text`. You can also use the friendly name `embed`:

```bash
tinfoil embed -m embed -k "YOUR_API_KEY" "This is a text I want to get embeddings for."
```

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

This command uses the default model `whisper-large-v3-turbo` and accesses it through the Tinfoil inference proxy. You can also use the friendly name `whisper`:

```bash
tinfoil audio -m whisper -k "YOUR_API_KEY" -f path/to/audio/file.mp3
```

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


## TTS (Text-to-Speech)

The `tts` command allows you to convert text to speech using TTS models. By default, it uses the `kokoro` model.

### Using the TTS Command

#### Basic Usage

```bash
tinfoil tts -k "YOUR_API_KEY" "Hello, this is a test of text-to-speech synthesis"
```

This command uses the default model `kokoro` and saves the generated audio to `output.mp3`. You can also use the friendly name `tts`:

```bash
tinfoil tts -m tts -k "YOUR_API_KEY" "Hello world"
```

#### Specifying Voice and Output File

```bash
tinfoil tts -m kokoro -k "YOUR_API_KEY" --voice "af_sky+af_bella" -o "my_speech.mp3" "Custom text to speak"
```

### Command Options

- `-m, --model`: The model name to use for TTS. Defaults to `kokoro`.
- `-k, --api-key`: The API key for authentication.
- `--voice`: Voice to use for synthesis. Defaults to `af_sky+af_bella`.
- `-o, --output`: Output file path. Defaults to `output.mp3`.
- `-e, --host`: The hostname of the enclave. Optional if defined in the config file.
- `-r, --repo`: The GitHub repository containing code measurements. Optional if defined in the config file.


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
INFO[0001] Remote public key fingerprint: 5f6c24f54ed862c404a558aa3fa85b686b77263ceeda86131e7acd90e8af5db2 
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

## Proxy

Use `tinfoil proxy` to start a local HTTP proxy that verifies connections and forwards them to the specified enclave.

```bash
tinfoil proxy \
  -r tinfoilsh/confidential-model-router \
  -e inference.tinfoil.sh \
  -p 8080
```

### Command Options

- `-p, --port`: Port to listen on. Defaults to `8080`.
- `-b, --bind`: Address to bind to. Defaults to `127.0.0.1`.
- `-e, --host`: The hostname of the enclave.
- `-r, --repo`: The GitHub repository containing code measurements.
- `--log-format`: Logger output format (`text` or `json`). Defaults to `text`.

By default, the proxy binds to `127.0.0.1` (localhost only). To expose the proxy on all interfaces, use `-b 0.0.0.0`.

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
