# Tinfoil CLI

A command-line interface for working with Tinfoil enclaves: verify the code they run, make verified HTTP and SSH connections, and manage containers, persistent volumes, and sandboxes.

Available on [GitHub Releases](https://github.com/tinfoilsh/tinfoil-cli/releases).

## How it works

1. Reads the selected command, target, and local configuration.
2. Sends management operations to the Tinfoil controlplane, or verifies the target enclave before connecting to a workload.
3. Prints results, follows deployment progress, or keeps a connection open for local clients.

Client-facing documentation:

- [Installation, updates, HTTP requests, and attestation](https://docs.tinfoil.sh/sdk/cli-sdk)
- [Tinfoil Containers overview](https://docs.tinfoil.sh/containers/overview) and [CLI workflows](https://docs.tinfoil.sh/containers/cli)
- [Attested SSH profiles](https://docs.tinfoil.sh/containers/attested-ssh)
- [Standalone Tinfoil Proxy](https://docs.tinfoil.sh/local-proxy/cli), the replacement for `tinfoil proxy`

## Running locally

With the Go version declared in [go.mod](go.mod), run from the repository root:

```sh
go run . --help
```

## Architecture Overview

The CLI is a single Go package at the repository root, using Cobra for commands and the Tinfoil Go SDK for enclave verification.

- **[main.go](main.go)**: Command entry point and global flags.
- **[controlplane.go](controlplane.go)**: Management API client; [auth.go](auth.go) handles login and identity.
- **[attestation_verify.go](attestation_verify.go)**: Enclave verification commands.
- **[http.go](http.go)**: Verified HTTP request setup.
- **[container.go](container.go)**: Container lifecycle commands; [project.go](project.go) manages groups of instances.
- **[tunnel.go](tunnel.go)**: Verified TCP tunnels used by forwarding, SSH, and SCP.
- **[volume.go](volume.go)**: Persistent disk management; [storage_commands.go](storage_commands.go) prepares automatic unlock.
- **[sandbox.go](sandbox.go)**: Sandbox lifecycle and local key enrollment.

## Development

See [dev.md](dev.md) for source builds and operational workflows, including deployment, rollback, and recovery.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
