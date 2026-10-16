# Sandbox and Monitor commands

Log in to the intended account with `tinfoil login` and confirm it with `tinfoil whoami`.
Create from explicit published releases using an Ed25519 owner public key:

```sh
tinfoil monitor create personal --tag VERSION
tinfoil sandbox create work --monitor personal --tag VERSION
tinfoil attest-ssh work --install
ssh work
tinfoil monitor open personal
```

A sandbox can only use a Monitor you created, because pairing needs that Monitor's owner key and encryption credentials. Without `--monitor`, sandbox creation selects your only Monitor. Monitor creation defaults to `~/.ssh/id_ed25519.pub`; sandbox creation defaults to the selected Monitor's measured owner. `--owner-public-key FILE` overrides either; `--identity PATH` selects its public key. `--workspace ID|NAME` reuses an unattached workspace on its existing host. Controlplane validates capacity, placement and entitlements. Private and encryption keys stay local.

Creation uses the ordinary container workflow: submit once, then follow the returned deployment. `--no-wait` or `--output json` returns the initial response. After an error or interruption, inspect `sandbox status` / `monitor status` before retrying creation. Use `start` for an existing stopped or failed resource. There is no local pending record or resume command.

`status [NAME]` lists resources or shows details; `get`, `list`, and `ls` are aliases. `status NAME --watch` prints changes until Ctrl-C. Monitor `start/stop/delete` and both groups' `update --tag VERSION` share the container handlers. Updates use automatic traffic switching while retaining plan review, rechecking, and downtime consent; `--yes` accepts the plan and downtime. Sandbox `start/restart` also enrolls this machine; `--no-enroll` boots without unlocking.

Rerun `attest-ssh` after either VM reboots. Keep `monitor open` running while using its local panel URL. Back up the encryption credentials: an SSH key alone cannot recover storage. Moving a workspace requires its original owner and encryption credentials. Sandbox deletion keeps billable workspace storage; Monitor deletion retains object storage. Use `volume` for disk management.

The sandbox's network policy selects its Monitor. The CLI verifies that Monitor's
published configuration and attestation before enrolling credentials. Changing the
Monitor in the dashboard requires rerunning `tinfoil attest-ssh NAME --install`.

To launch without Monitor, choose **No Monitor** in the dashboard's Monitor step,
using a sandbox release that declares `NO_MONITOR`. This sets the measured value
`NO_MONITOR=1`, which requires no network policy. `attest-ssh` and `sandbox enroll/start/restart` use
direct SSH to the published port, retain attestation and workspace encryption,
and warn that network traffic is not being tunneled through Monitor. A local
shell environment variable cannot change an existing sandbox's mode.

Monitored deployments require compatible Monitor and sandbox images, a CVM runtime allowing the private TCP alias range, and host/Controlplane support for the restricted `10.254.0.1:22` alias to the selected Monitor. Direct deployments require public attestation and the published SSH port. Live provisioning, billing, storage allocation and cross-host production behavior require deployment testing. Local tests cover API requests, lifecycle recovery, credential custody, attestation rejection, and SSH integration.
