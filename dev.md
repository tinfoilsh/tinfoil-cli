# Development and operations

## Building from source

Use the Go version declared in [go.mod](go.mod). From the repository root:

```sh
go build -o tinfoil .
./tinfoil --help
```

For installation, CLI updates, HTTP requests, and attestation commands, see the [CLI documentation](https://docs.tinfoil.sh/sdk/cli-sdk). For native SSH profiles, see [Attested SSH](https://docs.tinfoil.sh/containers/attested-ssh).

The workflows below use the command names in this checkout. Run `tinfoil <command> --help` for the installed command reference.

## Logging in

Create an admin API key from the Tinfoil dashboard (Settings → API Keys → Admin keys). Keys select either an organization or personal context. `whoami` and `login` show the authenticated context and IDs, an organization name when supplied by the server, the credential source, and a locally masked key. Container management requires an organization context and the relevant permissions.

```bash
tinfoil login                        # prompts for the key
tinfoil login --api-key admin_xxx    # non-interactive
tinfoil whoami                       # confirm the credential and show org context
tinfoil logout                       # delete saved credentials
```

Credentials are written to `~/.tinfoil/config.json` (mode 0600). Override on a per-command basis with `TINFOIL_ADMIN_KEY`, `TINFOIL_CONTROLPLANE_URL`, or `TINFOIL_CONFIG` for an alternate config path. `TINFOIL_API_KEY` is also accepted as a fallback when it holds an `admin_` key; a `tk_` inference key in that variable is ignored so the saved login keeps working. `login --url` targets a different controlplane.

`TINFOIL_ADMIN_KEY` takes precedence over an admin key in `TINFOIL_API_KEY`, then the saved file. Saving a different key does not override the environment: login warns and shows the saved identity separately from the effective login. Logout deletes only the saved file; unset environment keys separately.

## First container from an existing image

Use a public config repository connected to the Tinfoil GitHub App, with `tinfoil-config.yml` pointing to your actual image. Secrets, custom domains, and volumes are optional unless your workload requires them.

1. Propose your config: `tinfoil repo config pr myorg/my-repo-container --file ./tinfoil-config.yml`.
2. **Merge that PR before publishing.** Check with `tinfoil repo pr status myorg/my-repo-container <number>`; an open PR is not the default-branch configuration.
3. Queue the release: `tinfoil repo build run myorg/my-repo-container --version v1.2.3`.
4. **Wait for both Tinfoil Release and Build & Publish to succeed.** The build command is nonblocking, not a deploy-ready signal. Use `tinfoil repo build status myorg/my-repo-container --version v1.2.3` and the printed GitHub Actions URL; then `tinfoil repo build info myorg/my-repo-container` to confirm that same tag is published. A Git tag alone is insufficient.
5. Create using that exact release: `tinfoil container create my-container --repo myorg/my-repo-container --tag v1.2.3`. **`--tag` is required**, not implicitly `latest`.
6. Once Running, use the printed verified HTTP request or `tinfoil container connect my-container`. `tinfoil container get my-container` shows connection guidance again.

## Containers

```bash
# Inspect what's deployed
tinfoil container list
tinfoil container get my-container
tinfoil container metrics my-container --time 24h
tinfoil container hosts             # which hosts your org may target

# Create (deploys immediately and follows progress until Running)
tinfoil container create my-container \
  --repo myorg/my-repo-container \
  --tag v1.2.3

# Create with a persistent volume (the config must declare it; see Volume management)
tinfoil container create my-db --repo myorg/my-db --tag v1.0.0 --volume my-db-data

# Stop, then deploy again (stopped or failed containers; saved config unless flags override it)
tinfoil container stop my-container
tinfoil container deploy my-container
tinfoil container deploy my-container --tag v1.2.4 --host gpu-host-2

# Update a running container (blue/green when possible; asks before causing downtime)
tinfoil container update my-container --tag v1.2.4
tinfoil container update my-container --tag v1.2.4 --hold              # hold for review
tinfoil container connect my-container --review                       # verify the held candidate, not production
tinfoil container update my-container --tag v1.2.2 --mark-latest=false   # roll back without changing the latest release
tinfoil container promote my-container                                 # switch traffic to the held version
tinfoil container cancel my-container
tinfoil container cancel my-container --rollback-latest

tinfoil container delete my-container                                  # prompts; --yes to skip

# Projects (every instance that shares one config repository)
tinfoil project list
tinfoil project get myorg/my-repo-container
tinfoil project update myorg/my-repo-container --tag v1.2.4 --hold
tinfoil project update myorg/my-repo-container --tag v1.2.4 --instance <container-id>
tinfoil project settings myorg/my-repo-container --hold-by-default
tinfoil project settings myorg/my-repo-container --hold-by-default=false

# Open a verified proxy to a deployed container
tinfoil container connect my-container -p 8080
```

A container is either running or it is not. `deploy` boots an enclave for a container that has none (stopped, failed, or stopping); `update` replaces the version a running container serves. There is no in-place restart: `update` with the same tag uses the same update strategy as a version change, while `stop` then `deploy` restarts it with downtime.

Single-GPU containers without persistent volumes update blue/green: the new version boots next to the current one and traffic switches when it is Running. Multi-GPU containers and containers with persistent volumes cannot run two copies, so `update` stops the current version first; the CLI describes the downtime and asks you to type `yes` (pass `--yes` in scripts). A target tag can also require replacement even when the current version supports blue/green. Project updates preflight the entire batch and list all affected instances before asking for confirmation. Holding for review is only available for blue/green updates. `--hold` is equivalent to `--hold=true`; `--hold=false` explicitly disables holding, including a project's default. `--hold-by-default=false` clears that project setting.

Omitting `--hold` inherits the project's default for both individual and project updates. Use equals syntax for explicit values (`--hold=false`, not `--hold false`). Updates first fetch a side-effect-free server plan and show current → target tag/resources, strategy, hold source, retained volumes, setting-name changes, and cost availability on stderr. Secret and variable values are never printed in the plan. `--yes` skips confirmations, not the plan; `--no-wait` skips following, not planning. JSON stdout remains the execution response. Execution still enforces downtime confirmation if conditions change after planning.

Failed plan entries or no eligible instances block project execution; skipped instances are listed before eligible instances proceed. Plans are snapshots, not capacity reservations. This CLI requires the backend identity, plan, and connection-descriptor endpoints; it does not silently update when planning is unavailable.

Project execution is restricted to the IDs eligible in the reviewed plan, even without `--instance`; skipped instances and instances created afterward are never added. After consent, the CLI rechecks that exact selection. Changes to the eligible set, resources, tag, hold policy, configuration-change names, or other reviewed fields require a new summary and fresh consent. `--yes` accepts the displayed changes automatically but still rechecks. The CLI stops after three review rounds and permits at most one retry after a server downtime refusal, always with a fresh plan. Skipped instances remain in the final combined results and make the command exit nonzero even if every executed update succeeds. The final recheck is not an atomic reservation: execution still relies on backend scope/state validation.

When the plan includes private-keyserver delivery metadata, it lists managed and external secret names separately. Private keyserver authorization and disk unlock are not verified by planning; no endpoint, credential, or secret value is displayed. Debug targets use managed secrets and explicitly report that the private endpoint is ignored. Delivery changes require renewed consent like other reviewed settings; plans without this optional metadata retain the managed-delivery behavior.

`--secret` selects only Tinfoil-managed secrets, never private names. On `container deploy` or `container update`, omission retains the saved selection; pass a single `--secret=""` to send `secrets: []` and explicitly clear it when migrating to private delivery. Do not combine an empty selection with named secrets. On create, omit `--secret` or pass `--secret=""`. Project updates cannot clear per-instance selections: migrate affected instances individually first. The guest obtains private names from measured workload, model, and volume declarations.

`create`, `deploy`, `update`, and `promote` follow the requested deployment and print each boot stage until it is Running or held for review, exiting non-zero if it fails, is stopped, is canceled, or is superseded. A queued deployment continues to be followed while the previous version stops. Pass `--no-wait` to return as soon as the request is accepted, or `-o json` for the initial response.

`container connect <name>` runs a verified proxy locally at `http://localhost:<port>`. `--review` explicitly selects an available blue/green candidate and pins verification to its release; it never falls back to production. Get/progress output distinguishes the production HTTPS URL from the review URL and prints the expected `repo@tag` plus a verified HTTP command. An explicit `--repo owner/name[@tag][@sha256:digest]` retains its verification semantics; review mode requires the candidate's repository and tag, with an optional additional digest pin.

Container create, deploy, update, and project update mark the deployed tag as the repository's latest GitHub release once it is running. Pass `--mark-latest=false` to leave the latest release unchanged, for example when rolling back.

Selecting an earlier release through `update --tag ... --mark-latest=false` rolls back code, not configuration history: current settings, current secret values, and retained volumes are used, not a historical snapshot. The plan names changes without exposing values. Leaving mark-latest enabled changes the repository-wide latest release and can affect other consumers; the CLI does not infer release age from arbitrary tag spelling.

`--volume <id|name>[:<mount name>]` on `create` and `deploy` attaches an existing unattached volume to a mount the repository's `tinfoil-config.yml` declares, then deploys the container. The mount name is optional when the config declares exactly one mount. On create, the volume's host becomes the container's host (an explicit `--host` must match). On deploy, the container must already be on that host unless `--host` moves it there. Once attached, later deploys reuse the disk; omit `--volume`.

Create validates the configuration and disk assignments before creating or replacing a container. Mounts with a `key_secret` require a disk; optional mounts may remain empty. With `--replace <container-id>`, selected disks may also be attached to that exact replacement target, never another workload. After replacement, the CLI attaches them to the new container and deploys it, preserving an explicit `--mark-latest` choice. If a follow-up step fails, the new container and successful attachments are not rolled back; the error identifies the retained container and recovery commands. A validation permission error requires an admin key authorized for `containers.validate`; the CLI does not bypass validation.

A name shared by a debug and a production container is ambiguous; the CLI lists both and asks for the ID.

`container cancel --rollback-latest` also requests restoring the repository's latest release to the container's current production tag. The controlplane selects that tag; no tag argument is accepted. The command requires the server to acknowledge the restoration request and report its tag, so an older server that only cancels the update returns an error. Restoration is queued; verify the latest release afterward.

## Volume management

Volumes are encrypted persistent disks that live on one container host and attach to a mount declared in a repository's `tinfoil-config.yml`. A volume can be attached to one stopped container at a time and keeps its data across stops, deploys, and updates.

Automatic unlock requires the keyserver configuration and the `key_secret` value in a secrets manager **outside Tinfoil**. Ordinary creation or attachment does not provision that secret or prove it can unlock. For customer-owned AWS Secrets Manager provisioning, use `project storage configure` once, then `volume create --auto-unlock`; existing disks use `volume auto-unlock configure --existing-secret` to reuse their original key. See the [auto-unlock workflow and contract](docs/volume-auto-unlock-contract.md) for required flags, reviewed config/policy publication, and recovery. `volume auto-unlock status <volume> --project owner/repo` reports local evidence only, never an observed unlock. Mounts without `key_secret` are optional/manual: the workload must initialize and unlock an attached disk itself. Do not treat attachment or container Running status as disk-readiness evidence.

```bash
# Inspect
tinfoil volume list                             # includes the org's storage quota
tinfoil volume get my-db-data

# Create (sizes take GiB/TiB or GB/TB; --host is optional when only one host is available)
tinfoil volume create my-db-data --size 16TiB --host gpu-host-1

# Attach to a stopped container, then deploy it
tinfoil volume attach my-db-data my-db          # --as <mount name> when the config declares several
tinfoil container deploy my-db

# Move a volume between containers
tinfoil container stop my-db
tinfoil volume detach my-db-data
tinfoil container stop my-other-db
tinfoil volume attach my-db-data my-other-db

# Rename or delete (delete erases the data and requires the volume to be detached)
tinfoil volume rename my-db-data --name archive-data
tinfoil volume delete archive-data              # prompts; pass --yes to skip
```

Volume names are not unique within an organization; when several volumes share a name, the commands ask for the volume ID.

Auto-unlock provisioning supports **AWS Secrets Manager only**. Each new disk gets a unique `<prefix>/volumes/<volume-uuid>/key` reference; existing disks must reuse their original key, never another disk's key. Setup checks local writes and AWS credential loading before allocation, but cannot prove secret-write permissions without a write. A later failure retains the disk and reports recovery instructions rather than deleting, recreating, or rotating it.

For the next release, run `volume auto-unlock configure` with the same disk and original secret ARN, the new `--tag`, the previous `--policy-file`, and fresh output paths. The prepared policy adds the new exact release approval while retaining the old one and reusing the same key; repeating it is idempotent. **The operator must explicitly remove obsolete approvals and reload the keyserver to revoke them.** No per-stop/deploy key generation or manual decrypt is required, and the CLI does not claim the external policy is loaded or the disk is unlocked.

## Sandboxes

Sandboxes are user-owned confidential VMs with persistent encrypted disks.

```bash
tinfoil sandbox create my-sandbox     # boots, enrolls keys, installs an ssh profile
ssh my-sandbox
tinfoil sandbox list
tinfoil sandbox ssh my-sandbox        # the tunnelled alternative
tinfoil sandbox stop my-sandbox       # keep the disk
tinfoil sandbox start my-sandbox
tinfoil sandbox restart my-sandbox
tinfoil sandbox enroll my-sandbox     # enroll with an existing permit
tinfoil sandbox delete my-sandbox     # erase the disk
```

`create`, `start`, and `restart` wait for the VM, verify its attestation, enroll local SSH and disk keys, and install a native ssh profile when the VM exposes a direct SSH port. The profile connects through `console.tinfoil.sh` on the allocated port, with the host key verified against the sandbox's domain. The CLI stores the local SSH and disk keys in `~/.tinfoil/sandboxes/<name>`. Back up `disk.key`; without it, the workspace cannot be opened.

`enroll` uses a permit issued elsewhere, such as the dashboard. Permits expire after five minutes and work once for one boot.
