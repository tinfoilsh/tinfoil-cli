# Monitor and contained sandboxes

Monitor needs a runtime with non-admin SSH port mapping. Deploy
host and control-plane support before using these commands. Backoffice separately
approves hosts for sandboxes and monitors; each create command uses its matching
pool. Configure disjoint pools to place them on separate hosts. Cross-host
sandboxes require tinfoild network-policy capability 3 and reach only the
Monitor's published SSH endpoint. The attested Monitor host key stays pinned.
A stopped or unavailable Monitor produces an error. Replacing a Monitor requires
an explicit sandbox restart and enrollment against the verified new Monitor.

## Setup

```sh
tinfoil monitor create personal
tinfoil sandbox create work --monitor personal --ssh
ssh work
```

Both create commands use `POST /api/containers` with the corresponding
`tinfoilsh/confidential-agent-{monitor,sandbox}` repository. New resources default
to Monitor `v0.1.0-private.4` and sandbox `v0.1.10`; `--tag` overrides the release.
The CLI embeds these approved release templates, so first use does not need a
GitHub credential or a local template file. The organization still needs access
to the private Monitor repository and its registry image.
Both require sandbox access in the active account. The release and rendered
config are saved at creation; restart keeps them pinned. Version changes require
explicit reprovisioning. Container stop/delete/deploy commands manage Monitor.

Monitor stores owner-encrypted state in the S3 bucket configured by the operator.
Creation assigns a prefix and renewable credentials. The CLI verifies the bucket
binding as part of the measured config and saves its storage ID. Monitor has no
attached state disk. Deleting its container retains the objects; recreating it
with the saved profile reuses that storage and preserves the minimum generation.

The CLI binds an Argon2id verifier of its local workspace key into the sandbox's
measured config before boot. It reproduces that config from the release template and
checks the owner binding before sending any keys. Start and restart retain the
binding; restore the saved workspace key on another device before enrolling.

Environment inputs can replace defaults in `tinfoil-config.yml`. Use
`--variable KEY=value` on sandbox commands for each override, including when
enrolling a sandbox configured in the dashboard. Repeat the same overrides when
connecting so the CLI can reproduce and verify the measured config. The owner
binding always comes from the local workspace key.

The CLI connects privately to the sandbox, attests it, and enrolls its keys and
Monitor configuration. The sandbox then starts reverse SSH.
The CLI verifies both workloads before sending keys and installs a pinned
OpenSSH ProxyJump profile. To verify again and rebuild the profile:

```sh
tinfoil attest-ssh --sandbox work --install
```

## Supplying your own keys

The CLI generates secure random keys locally by default. To use an existing key
or a passphrase, read it from a file or use `-` for stdin:

```sh
tinfoil monitor create personal --owner-key-file ./monitor-key.txt
tinfoil sandbox create work --monitor personal --workspace-key-file ./workspace-key.txt
```

Passphrases must contain 16 to 4096 UTF-8 bytes. Spaces and newlines are part of
the secret. Existing canonical base64 keys are recognized, including a newline
at the end of an old key file. Saved credential JSON files can also be supplied.
Secrets are never passed as command-line arguments or sent to the controlplane.

New bindings use Argon2id v19 with 256 MiB, 3 iterations, 4 lanes, a random
32-byte salt, and a 32-byte verifier. The exact credential bytes unlock the
workspace or Monitor. Old SHA-bound deployments keep their original keys and
configuration. New credential records retain their verifier and salt; old key
files stay unchanged. Back up the saved files, including all SSH and agent keys.

To enroll an uncontained sandbox created in the dashboard, supply the same
workspace credential:

```sh
tinfoil sandbox enroll work --workspace-key-file ./workspace-key.txt
```

The CLI first checks the credential against the saved binding and reproduces
the complete release configuration. It then saves the credential and creates a
local login key if needed. A sandbox already enrolled with another login key may
need a restart before enrolling this device. For a contained sandbox, restore
its Monitor backup, which includes the existing login and agent keys.

A Monitor created in the dashboard can be adopted with `monitor create` and the
same `--owner-key-file`. A restored Monitor backup also preserves the minimum
state generation and the previously pinned host key.

For the Monitor app's owner field, enter your original supplied passphrase. For
a CLI-generated credential, open the local `owner.key` path printed by
`monitor create` and copy the JSON `key` field. That field is the encoded random
key the app accepts. A legacy `owner.key` contains that encoded key directly.
Do not paste the entire JSON record or its `argon2id` verifier. The CLI does not
print owner secrets during normal creation or recovery.

## Recovery

| Situation | Command |
|---|---|
| Failed provisioning | Correct the error and repeat create; saved keys are reused |
| Lost enrollment reply | `tinfoil sandbox enroll work` |
| Stopped sandbox | `tinfoil sandbox start work` |
| Sandbox rebooted on its host | `tinfoil sandbox enroll work` |
| Monitor process restarted | `tinfoil monitor create personal` |
| Monitor VM restarted | `tinfoil monitor create personal --repin`, then restart its sandboxes |

Restore missing keys from a backup, or supply the original credential when
adopting an uncontained dashboard sandbox. The CLI does not replace a saved
workspace key with a different one.

## Changing a sandbox release

Back up the Monitor bundle first. Record the current workspace volume ID, stop
the sandbox, and delete only its container. Keep its volume, local credential,
login key, and Monitor agent identity. Recreate the same sandbox name with its
retained volume:

```sh
tinfoil sandbox create work --monitor personal --volume WORKSPACE_VOLUME_ID
```

This uses the approved release, reuses the original keys, attaches the workspace
before launch on its existing host, and enrolls the new boot. Use `--tag` for a
specific release. If the local workspace credential is missing, restore the
backup first; an uncontained sandbox can also use its original
`--workspace-key-file`. The command refuses to generate a replacement credential
when reusing a volume, or to take a volume from another container.

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
tinfoil monitor create personal --tag v0.1.0-private.4 --template ./tinfoil-config.yml
```

For a nondefault revision, the file must come from that revision. The CLI verifies the complete rendered
config before sending the owner secret and saves the verified template locally.
Subsequent starts can reuse it without public GitHub access. An imported profile
on another device needs the matching file again. Source code and the image may
remain private; the rendered measured config is published to the config registry.

For another revision, stop and delete the container while keeping the local
profile, then recreate the same name with the new tag and template plus `--repin`.
The saved storage ID, owner secret and minimum generation survive. Restart its
sandboxes after the Monitor's SSH host key changes.
