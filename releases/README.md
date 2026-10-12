# Approved release templates

The CLI embeds these exact release files so default creation and local config
verification work without GitHub access. The public CLI includes configuration
and immutable image references only; Monitor source and its image remain private.

| Workload | Release | Tag commit | Template SHA-256 |
|---|---|---|---|
| Monitor | `v0.1.0-private.4` | `3df94c60e389a13b3364571b73b4d5fadd5db9e6` | `80c640d7dd5e00ddfa601f25c57678d0ba71900796f5ec1bf141cda4a3400f8a` |
| Sandbox | `v0.1.10` | `7d68bfd7ce5f84e07159b0d156cbb5fa84f7ea50` | `9b367406954fdb3242abec6802ea92dd02c38c2ea6d189fc0479d5e41760f032` |

Both defaults use CVM `0.15.1-rc.3` with attestation digest
`e1c8d17c7d79663c365169a796eec06116f483825028fad5faddfe9839321217`.

To approve a new default:

1. Wait for both workload image publication and the Tinfoil release to succeed.
2. Verify release provenance, the template checksum, its exact tag commit, and
   the image digest. Check the runtime attestation digest independently.
3. Copy the release's `tinfoil-config.yml` byte-for-byte into this directory.
4. Update the corresponding default tag, embed directive, checksum test, and
   this provenance table in the same change.
5. Run CLI tests and verify that the controlplane's rendered config matches the
   embedded template with only the expected owner and storage values supplied.

An explicit Monitor `--template` still wins. Other Monitor revisions use the
locally cached template or the selected release's GitHub file; other sandbox
revisions fetch their own release template. Neither path substitutes the
controlplane's returned config for the independent template. A custom local
file or cached copy is trusted input, not an artifact whose release provenance
the CLI verifies automatically.
