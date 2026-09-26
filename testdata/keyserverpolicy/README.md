# Keyserver policy reference

`policy.go` records `tinfoilsh/keyserver`'s `policy.go` at commit
`2ea68acda377b7f91389fad692bed9c46b915376`. Only the package declaration is
changed so CLI tests can import the otherwise non-importable `package main`.
No keyserver repository files are modified.

The release-policy tests call this snapshot's `LoadPolicy`, `Match`, and
`Authorize` against generated artifacts and the recorded v1/v2 YAML fixtures.
This verifies the policy wire contract, not live attestation or policy loading
on a deployed keyserver. The reference is test-only and is not linked into the
CLI executable.
