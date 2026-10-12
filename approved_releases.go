package main

import _ "embed"

// These templates are copied byte-for-byte from verified releases. See
// releases/README.md before changing a default or its corresponding asset.

//go:embed releases/sandbox-v0.1.10.yml
var approvedSandboxTemplate []byte

//go:embed releases/monitor-v0.1.0-private.4.yml
var approvedMonitorTemplate []byte
