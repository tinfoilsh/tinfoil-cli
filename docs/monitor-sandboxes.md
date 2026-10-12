# Monitor and contained sandboxes

Unreleased. Monitor needs a runtime with non-admin SSH port mapping. Deploy
host and control-plane support before releasing this CLI. Backoffice separately
approves hosts for sandboxes and monitors; each create command uses its matching
pool. Configure disjoint pools to place them on separate hosts. Cross-host
sandboxes require tinfoild network-policy capability 3 and reach only the
Monitor's published SSH endpoint. The attested Monitor host key stays pinned.
A stopped or unavailable Monitor produces an error. Replacing a Monitor requires
an explicit sandbox restart and enrollment against the verified new Monitor.

## Setup

```sh
tinfoil monitor create personal --tag v0.1.0
tinfoil sandbox create work --tag v0.1.0 --monitor personal --ssh
ssh work
```

Both create commands use `POST /api/containers` with the corresponding
`tinfoilsh/confidential-agent-{monitor,sandbox}` repository and an explicit `--tag`.
Both require sandbox access in the active account. The release and rendered
config are saved at creation; restart keeps them pinned. Version changes require
explicit reprovisioning. Container stop/delete/deploy commands manage Monitor.

Monitor stores owner-encrypted state in the S3 bucket configured by the operator.
Creation assigns a prefix and renewable credentials. The CLI verifies the bucket
binding as part of the measured config and saves its storage ID. Monitor has no
attached state disk. Deleting its container retains the objects; recreating it
with the saved profile reuses that storage and preserves the minimum generation.

The CLI binds the hash of its local workspace key into the sandbox's measured
config before boot. It reproduces that config from the release template and
checks the owner binding before sending any keys. Start and restart retain the
binding; restore the saved workspace key on another device before enrolling.

Environment inputs can replace defaults in `tinfoil-config.yml`. Use
`--variable KEY=value` on sandbox commands for each override, including when
enrolling a sandbox configured in the dashboard. Repeat the same overrides when
connecting so the CLI can reproduce and verify the measured config. The owner
hash always comes from the local workspace key.

The CLI connects privately to the sandbox, attests it, and enrolls its keys and
Monitor configuration. The sandbox then starts reverse SSH.
The CLI verifies both workloads before sending keys and installs a pinned
OpenSSH ProxyJump profile. To verify again and rebuild the profile:

```sh
tinfoil attest-ssh --sandbox work --install
```

## Recovery

| Situation | Command |
|---|---|
| Failed provisioning | Correct the error and repeat create; no provisioning state is resumed |
| Lost enrollment reply | `tinfoil sandbox enroll work` |
| Stopped sandbox | `tinfoil sandbox start work` |
| Sandbox rebooted on its host | `tinfoil sandbox enroll work` |
| Monitor process restarted | `tinfoil monitor create personal` |
| Monitor VM restarted | `tinfoil monitor create personal --repin`, then restart its sandboxes |

Missing keys must be restored from a backup. The CLI does not regenerate them
for an existing sandbox.

## Backups and other devices

```sh
tinfoil monitor export personal personal-keys.json
tinfoil monitor import personal-keys.json
tinfoil monitor create personal
```

The export contains the Monitor owner secret, storage ID, minimum generation and its sandboxes' workspace,
login and agent keys. Keep it private. Import requires the same account and
refuses to overwrite different keys. Each device registers its own SSH key.

## Removing access

Clear a device's "Open sandbox routes" option or remove its identity in the
Monitor app to close its sessions and revoke access.

`tinfoil sandbox delete work` removes the VM, SSH profile and agent identity.
It retains the workspace volume and local keys. The volume remains billed
until explicitly deleted with `tinfoil volume delete`. Repeat an interrupted
delete to finish cleanup.

## Local files

| Path | Contents |
|---|---|
| `~/.tinfoil/monitors/<account hash>/<name>/` | Owner secret, device key and verified profile |
| `~/.tinfoil/sandboxes/<name>/` | Workspace, login and agent keys; Monitor binding |
| `~/.ssh/tinfoil/<name>.conf`, `<name>.known_hosts` | SSH profile and host-key pins |

Deleting a sandbox leaves its Monitor running. The Monitor continues to incur
normal container compute charges on its owner's infrastructure bill until stopped
or deleted. Deleting the user account cleans up both.

## Private Monitor development

Connect the private Monitor repository through the organization's GitHub App,
and save its GHCR pull credentials through the normal registry settings. Enable
sandbox and private-registry access for that organization. Pin the image and CVM
digests in the selected revision's `tinfoil-config.yml`, then run:

```sh
tinfoil monitor create personal --tag v0.1.0-dev.1 --template ./tinfoil-config.yml
```

The file must come from that revision. The CLI verifies the complete rendered
config before sending the owner secret and saves the verified template locally.
Subsequent starts can reuse it without public GitHub access. An imported profile
on another device needs the matching file again. Source code and the image may
remain private; the rendered measured config is published to the config registry.

For another revision, stop and delete the container while keeping the local
profile, then recreate the same name with the new tag and template plus `--repin`.
The saved storage ID, owner secret and minimum generation survive. Restart its
sandboxes after the Monitor's SSH host key changes.
