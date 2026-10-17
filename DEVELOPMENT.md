# Development

Use the Go version declared in [go.mod](go.mod). Run the commands below from the repository root.

## Build

```sh
export GOWORK=off
go build -o tinfoil .
./tinfoil --help
```

`GOWORK=off` uses this repository's dependencies even when a parent directory contains a Go workspace.

## Checks

Format edited Go files with `gofmt`, then run:

```sh
go test ./...
go vet ./...
```

To run a focused set of tests:

```sh
go test -count=1 -run '^TestLoadConfig' .
```

[CI](.github/workflows/test.yml) runs the test suite on pull requests.

## Optional integration tests

- Live attestation: set `RUN_TINFOIL_INTEGRATION=true` to enable the test against `inference.tinfoil.sh`.
- Monitor integration: provide a Monitor checkout at `../monitor` or set `TINFOIL_MONITOR_TEST_SOURCE` to its path. The test builds and starts a local Monitor and requires the OpenSSH client.
