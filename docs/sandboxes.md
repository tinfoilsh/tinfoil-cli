# Sandbox and Monitor CLI workflows

Log in with an admin API key for the intended account (`tinfoil login`, then `tinfoil whoami`). Status is available directly under each workload:

```sh
tinfoil sandbox status                 # list sandboxes
tinfoil monitor status                 # list Monitors
tinfoil sandbox status work            # configuration, boot details, bound Monitor
tinfoil monitor status personal --watch
```

`get`, `list` and `ls` alias `status` under both groups. With no name they list that resource kind. `status NAME --watch` prints changes until Ctrl-C, using the shared container poller. `--output json` exposes structured fields (watch prints successive snapshots). Status and list commands always fetch current account data.

Create using an explicit published release and an existing Ed25519 SSH public key:

```sh
tinfoil repo build info tinfoilsh/confidential-agent-monitor
tinfoil monitor create personal --tag VERSION
tinfoil sandbox create work --monitor personal --tag VERSION
tinfoil attest-ssh work --install
ssh work
```

Creation defaults to `~/.ssh/id_ed25519.pub` for a Monitor and its selected Monitor's measured owner for a sandbox. Override with `--owner-public-key FILE`; `--identity PATH` selects `PATH.pub` (or PATH if already a public file). Private/encryption keys stay local. Release discovery through `repo build info` needs organization repository access; public personal-account catalog discovery remains tracked work. Creation does not bypass the existing [connection policy](known-configs-contract.md).

A new workspace is 30 GiB (32.21 decimal GB). `--workspace ID|NAME` reuses an unattached, non-deleted disk of at least that size on its existing host, even without quota for another volume. Inspect disks with the existing `volume list/get` commands. Keep the original encryption credentials: an SSH key alone cannot recover the data. Compute is billed while running; storage remains billable until deleted.

Creation saves one immutable intent per account/controlplane before submitting. After Ctrl-C, a timeout or `--no-wait`, use `sandbox pending` / `sandbox resume` (or `monitor resume`). Resume validates measured identity, owner, release, Monitor and workspace bindings without an extra deploy or a blind repeat of an uncertain POST. `pending clear` explicitly forgets only the local record; all remote resources and saved keys remain. Inspect resource lists before clearing. A stale lock error names the lock file; remove it only after verifying no original process is still running.

Lifecycle and update conveniences reuse the existing container handlers:

```sh
tinfoil monitor start personal         # deploy the saved configuration; --no-wait is available
tinfoil monitor stop personal
tinfoil monitor delete personal        # retains the existing confirmation; --yes is available
tinfoil sandbox update work --tag VERSION
tinfoil monitor update personal --tag VERSION
```

These commands reject another resource kind or a debug VM before mutation. Updates review and recheck the same plan as `container update`, with automatic traffic switching (`--hold=false`). `--yes` approves the plan and any downtime; `--no-wait` skips following progress after acceptance. Neither bypasses the plan. Monitor deletion retains object storage; these commands do not provide an object-store restore workflow. Advanced configuration flags remain on `container`.

Existing `sandbox start/restart/stop/delete` retain their lifecycle and enrollment behavior; start/restart accepts `--no-enroll` for boot-only administration. Use `volume` for storage and `monitor open NAME` for the local panel. Rerun attestation/enrollment after reboot. Keep `monitor open` running while using its local URL.

See the [79-affordance tracker](sandbox-cli-parity.md) for existing capabilities, convenience changes, implementation gaps, and unverified deployment behavior.
