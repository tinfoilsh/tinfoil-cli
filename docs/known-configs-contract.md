# Known-configs connection policy contract

Verification always needs a caller-owned expectation: `VerifyV3` pins a
repository or registry project the enclave must prove it runs, the SDKs
require their caller to supply that pin at construction, and the CLI's
`--repo` flag is the same contract per invocation. The known-configs store
is the stateful form of that expectation — a local **connection policy**:
what this user trusts, written down once and consulted on every
controlplane-resolved connect instead of retyped. Explicit `--repo` supplies
the expectation per invocation, `--dangerous` bypasses the check, and
bare-hostname tunnel targets are out of scope.

Local-config containers (`--config <file>`) are also out of scope: the
caller already holds the expectation as the config file itself, and
verification compares its exact-byte digest against the attestation
document. There is no controlplane-chosen name to gate and nothing for the
store to remember that the file does not state better. `--repo` is refused
for local containers; `--config` is required.

It matters most on controlplane-resolved paths (`container connect`, and
`forward`/`ssh`/`scp`/`attest-ssh` by container name or ID), where the CLI
otherwise builds the expectation from the controlplane's own response —
there, verification would pass for any validly endorsed config the
controlplane chose to serve. With the policy in place, the resolved config
must match an entry, or the command prompts or fails closed. An explicit
`--repo` supplies the expectation directly for that invocation: the resolved
config is checked against it instead of the store, and on success the
assertion is added to the store.

## File

`~/.tinfoil/known-configs.json`, overridable with `TINFOIL_KNOWN_CONFIGS`.
Hand-editable JSON, with one atomic write per operation. If a
`known-configs.yml` file exists, convert it to JSON before connecting; the CLI
will not silently replace it with an empty store.

```json
{
  "mode": "prompt",
  "record": "project",
  "allow": {
    "orgs": ["tinfoilsh"],
    "projects": ["tinfoilsh/confidential-api"],
    "pins": ["tinfoilsh/confidential-api@v1.2.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
  }
}
```

## Matching

A resolved reference (a registry config `org/project@revision[@sha256:digest]`
or a GitHub release `owner/repo@tag` — both fully supported forms) passes
when any allow entry covers it. An entry grants
exactly what it says:

- an org entry covers everything in the org
- a project entry covers any revision of the project
- a pin covers itself; a pin without digest covers any digest of that
  revision (the config endorsement binds revision to digest 1:1)

Matching is a prefix test at a `/` or `@` boundary; there are no partial-name
matches (`acme` never covers `acmecorp/...`). There are no precedence rules:
a broad entry subsumes narrower ones below it, like ssh known_hosts. The
`record` setting never reinterprets existing entries. Bucket shapes are
validated on load — a project pasted under `orgs` is an error, not a
surprise.

## Mode

What happens when a resolved config matches no entry:

- `prompt` (default): yes/no on a TTY, showing the full resolved reference;
  yes records at the `record` granularity and proceeds. No TTY → fail closed
  with the exact flags to re-run. There is deliberately no blind-accept
  flag: non-interactive callers state an expectation (`--repo`) or name the
  bypass (`--dangerous`).
- `frozen`: fail closed, never prompt, no automatic writes (journaling
  included). The file changes only through deliberate acts — hand-editing or
  an explicit `--repo` assertion, the flag equivalent of editing the file.

## Record

The granularity a prompt-yes (or create-time seed, or `--repo` assertion)
writes: `org`, `project` (default), or `pin`. Recording is inclusive going
down — an org-yes also records the project and the exact pin — so tightening
`record` later starts from everything already used. A `--repo` assertion
records at its own granularity, inclusive downward, without changing the
configured default. Tightening is completed by pruning: `tinfoil trust set
--record pin --prune` removes the broader entries (offered interactively;
the store printout names the command whenever broader entries survive).

## Journal

Every allowed connect records the exact resolved reference into `pins`
(sorted so a project's history groups; deduplicated). A connect allowed by an
existing grant announces a first sight with `New config journaled: …`; a
prompt-yes or `--repo` assertion prints `Recorded …` instead, and its
inclusive-downward recording includes the pin. `--dangerous` never writes — a
bypass must not become standing trust. In frozen mode nothing is journaled; a
first sight is still announced.

## Failure discipline

- Malformed JSON, duplicate or unknown fields, unknown mode/record, or an
  invalid bucket entry: error without prompting or changing the file. Fix the
  store before connecting, including when using an explicit `--repo`.
  `--dangerous` explicitly bypasses loading and checking the store.
- A missing file or `{}` is an empty store with default settings. An empty
  file or `null` document is invalid.
- Recording failures on a policy-passing connect warn; they do not block a
  connection that policy already allows.

## Session semantics

The expectation is frozen at session start. Re-verification (freshness
expiry, TLS pin change) runs against that frozen reference; a production
update therefore fails the live session closed. The trust decision point is
connect time — including every reconnect after an update — which is exactly
where the store gates.
