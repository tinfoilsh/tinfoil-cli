# Development

Use the Go version declared in [go.mod](go.mod). Run the commands below from the repository root.

## Build

```sh
GOWORK=off go build -o tinfoil .
./tinfoil --help
```

`GOWORK=off` uses this repository's dependencies even when a parent directory contains a Go workspace.

## Checks

On macOS, use a short temporary path owned by your primary group for socket and file-permission tests:

```sh
test_tmp=$(mktemp -d /tmp/tfc.XXXXXX)
chgrp "$(id -gn)" "$test_tmp"
export TMPDIR="$test_tmp"
```

Format edited Go files with `gofmt`, then run:

```sh
GOWORK=off go test ./...
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
```

To run a focused set of tests:

```sh
GOWORK=off go test -count=1 -run '^TestLoadConfig' ./internal/config
```

[CI](.github/workflows/test.yml) runs the test suite on pull requests.

## Optional integration tests

- Live attestation: set `RUN_TINFOIL_INTEGRATION=true` to enable the test against `inference.tinfoil.sh`.
- Perimeter integration: set `TINFOIL_MONITOR_TEST_SOURCE` to the absolute path of a Perimeter checkout. The test builds and starts a local Perimeter and requires the OpenSSH client.
