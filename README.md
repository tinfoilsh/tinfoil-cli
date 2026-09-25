# Tinfoil CLI

A command-line interface for verifying Tinfoil enclave attestations, making verified HTTP requests, and managing the lifecycle of Tinfoil Containers.

[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/cli-sdk)

## Installation

```sh
curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sh
```

Or download a binary from the [Releases](https://github.com/tinfoilsh/tinfoil-cli/releases) page. A Docker image is also available at `ghcr.io/tinfoilsh/tinfoil-cli`.

### Updating

Re-run the install script to update to the latest release. The CLI checks for new releases at most once a day and prints a warning with the update command when one is available. Set `TINFOIL_NO_UPDATE_CHECK=1` to disable the check.

## Proxy

`tinfoil proxy` is deprecated. For a local verified proxy that lets any HTTP client use Tinfoil without a native SDK, use [tinfoil-proxy](https://github.com/tinfoilsh/tinfoil-proxy), available as a standalone binary or the Tinfoil Tray menu-bar app. `tinfoil container connect` (below) still runs a proxy scoped to one of your deployed containers.

## HTTP Requests

Make one-off verified requests directly, without running the proxy:

```bash
# GET
tinfoil http get https://inference.tinfoil.sh/health \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router

# POST
tinfoil http post https://inference.tinfoil.sh/v1/chat/completions \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router \
  -H "Authorization: Bearer $TINFOIL_API_KEY" \
  -H "Content-Type: application/json" \
  -b '{"model": "deepseek-r1-0528", "messages": [{"role": "user", "content": "Hello"}]}'
```

Pass custom request headers with repeatable `-H, --header` flags. Headers are sent through the verified connection after enclave attestation succeeds.

## TCP tunnels and SSH

Set `TINFOIL_TUNNEL_API_KEY` to an inference API key (`tk_...`), then forward a published workload port or connect with SSH:

```bash
tinfoil forward my-server -L 5432:5432
tinfoil forward --sandbox my-sandbox -L 6379:6379
tinfoil ssh my-server
tinfoil ssh my-server -- systemctl status
```

`-L` accepts `[bind:]<local-port>:<enclave-port>` and may be repeated. SSH arguments go after `--`; `-l` sets the remote user and `-p` the enclave-side port. The target is a container name or a bare enclave hostname. The tunnel key is validated by the enclave and is separate from the admin key used to log in, which is why it has its own variable (or `--api-key`). Both commands refuse a debug-mode enclave unless `--allow-debug` is passed.

## Attestation Verification

Verification requires the expected workload: an explicit `--enclave` needs `--repo owner/name[@tag][@sha256:digest]`, and a bare `owner/name` accepts any release the freshness witness currently endorses. Hardware-only verification is no longer an authorization path. JSON output includes the verified `crypto_material` and `freshness_expires_at`.

### Native SSH profiles

Workloads that declare an `attested-keys` entry named `host-ssh` and serve it as their sshd HostKey can be reached with plain `ssh` once the key is verified. The target is a container name or a bare enclave hostname, as with `tinfoil ssh`:

```bash
tinfoil attest-ssh ubuntu-test --install
ssh ubuntu-test
```

For a container with a published SSH port, the profile connects to `console.tinfoil.sh` on the allocated port. Attestation uses the enclave's hostname; the console endpoint only forwards encrypted SSH traffic.

Bare hostname targets connect directly on port 22 by default and require `--repo`. Use `--ssh-host` and `--ssh-port` to select a different SSH endpoint:

```bash
tinfoil attest-ssh enclave.example.com --repo owner/workload --name dev \
  --ssh-host ssh.example.com --ssh-port 2222 --install
ssh dev
```

`--install` writes `~/.ssh/tinfoil/<name>.conf` and its pinned `<name>.known_hosts`. If `~/.ssh/config` is missing a top-level `Include tinfoil/*.conf` line, the command asks whether to add it (`--yes` adds it without prompting; non-interactive runs without `--yes` leave the config unchanged and print the line to add). Without `--install`, the command prints the profile and pin. The pin is the key verified at install time; a CVM reboot rotates it, so rerun the command after one. `--user` and `--identity` select the login user and client key.

Manually verify that an enclave is running the expected code:

```bash
tinfoil attestation verify \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router
```

```
INFO[0001] Verified tinfoilsh/confidential-model-router at f2f48557c8b0...; TLS key 5f6c24f54ed862c4...
```

Use `-j` for machine-readable JSON output:

```bash
tinfoil attestation verify \
  -e inference.tinfoil.sh \
  -r tinfoilsh/confidential-model-router \
  -j > verification.json
```

## Container management

The `container`, `project`, `volume`, `model`, `repo`, `secret`, `ssh-key`, `registry`, and `domain` subcommands manage Tinfoil Containers through the same controlplane API the dashboard uses. See the [Tinfoil Containers docs](https://docs.tinfoil.sh/containers/overview) for the underlying concepts and the [CLI reference](https://docs.tinfoil.sh/containers/cli) for the full command surface.

### Logging in

Create an admin API key from the Tinfoil dashboard (Settings → API Keys → Admin keys). Keys select either an organization or personal context. `whoami` and `login` show the authenticated context and IDs, an organization name when supplied by the server, the credential source, and a locally masked key. Container management requires an organization context and the relevant permissions.

```bash
tinfoil login                        # prompts for the key
tinfoil login --api-key admin_xxx    # non-interactive
tinfoil whoami                       # confirm the credential and show org context
tinfoil logout                       # delete saved credentials
```

Credentials are written to `~/.tinfoil/config.json` (mode 0600). Override on a per-command basis with `TINFOIL_ADMIN_KEY`, `TINFOIL_CONTROLPLANE_URL`, or `TINFOIL_CONFIG` for an alternate config path. `TINFOIL_API_KEY` is also accepted as a fallback when it holds an `admin_` key; a `tk_` inference key in that variable is ignored so the saved login keeps working. `login --url` targets a different controlplane.

`TINFOIL_ADMIN_KEY` takes precedence over an admin key in `TINFOIL_API_KEY`, then the saved file. Saving a different key does not override the environment: login warns and shows the saved identity separately from the effective login. Logout deletes only the saved file; unset environment keys separately.

### First container from an existing image

Use a public config repository connected to the Tinfoil GitHub App, with `tinfoil-config.yml` pointing to your actual image. Secrets, custom domains, and volumes are optional unless your workload requires them.

1. Propose your config: `tinfoil repo config pr myorg/my-repo-container --file ./tinfoil-config.yml`.
2. **Merge that PR before publishing.** Check with `tinfoil repo pr status myorg/my-repo-container <number>`; an open PR is not the default-branch configuration.
3. Queue the release: `tinfoil repo build run myorg/my-repo-container --version v1.2.3`.
4. **Wait for both Tinfoil Release and Build & Publish to succeed.** The build command is nonblocking, not a deploy-ready signal. Use `tinfoil repo build status myorg/my-repo-container --version v1.2.3` and the printed GitHub Actions URL; then `tinfoil repo build info myorg/my-repo-container` to confirm that same tag is published. A Git tag alone is insufficient.
5. Create using that exact release: `tinfoil container create my-container --repo myorg/my-repo-container --tag v1.2.3`. **`--tag` is required**, not implicitly `latest`.
6. Once Running, use the printed verified HTTP request or `tinfoil container connect my-container`. `tinfoil container get my-container` shows connection guidance again.

### Containers

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

### Model weights

The `model` subcommand wraps Hugging Face model weights into verified artifacts that GPU containers load with integrity checking (see the [Models docs](https://docs.tinfoil.sh/containers/models)):

```bash
# Wrap a model on a host and wait for the tinfoil-config.yml block
tinfoil model wrap google/gemma-4-31B-it --host gpu-host-1 --wait

# Gated or private repos
tinfoil model wrap meta-llama/Llama-4-8B --host gpu-host-1 --hf-token-file ./hf.token

# Update to the latest (or a specific) revision — only changed files are re-downloaded
tinfoil model update google/gemma-4-31B-it --host gpu-host-1 --wait

# Inspect wrap jobs
tinfoil model list
tinfoil model status gpu-host-1 <job-id>          # add --logs for wrap logs

# Delete a wrap job (also removes the weights once nothing references them)
tinfoil model delete gpu-host-1 <job-id>
```

### Repository config and releases

The `repo` subcommand acts through the Tinfoil GitHub App installed on the config repository:

```bash
# Read tinfoil-config.yml from the default branch
tinfoil repo config get myorg/my-repo-container
tinfoil repo config get myorg/my-repo-container --raw > tinfoil-config.yml

# Open a pull request with a locally edited config, then track it
tinfoil repo config pr myorg/my-repo-container --file ./tinfoil-config.yml --body "Bump memory"
tinfoil repo pr status myorg/my-repo-container 42

# Inspect tags and trigger the Tinfoil Release workflow
tinfoil repo build info myorg/my-repo-container
tinfoil repo build run myorg/my-repo-container --version v1.2.4
tinfoil repo build status myorg/my-repo-container --version v1.2.4
```

### Secrets, SSH keys, registry credentials, custom domains

```bash
# Org secrets (used by containers via --secret)
tinfoil secret list
tinfoil secret get OPENAI_API_KEY               # metadata only; the value is never returned
echo -n "$OPENAI_KEY" | tinfoil secret create OPENAI_API_KEY --value-file -
tinfoil secret set OPENAI_API_KEY --value-file ./key.txt
tinfoil secret delete OPENAI_API_KEY

# Repository secrets
tinfoil repo secret list myorg/my-repo-container
tinfoil repo secret get myorg/my-repo-container OPENAI_API_KEY
tinfoil repo secret create myorg/my-repo-container OPENAI_API_KEY --value-file ./key.txt
tinfoil repo secret set myorg/my-repo-container OPENAI_API_KEY --value-file ./key.txt
tinfoil repo secret delete myorg/my-repo-container OPENAI_API_KEY

# SSH keys for debug containers
tinfoil ssh-key create laptop --public-key-file ~/.ssh/id_ed25519.pub
tinfoil ssh-key list
tinfoil ssh-key delete laptop

# Private registry credentials
tinfoil registry list
tinfoil registry set ghcr --username myuser --token ghp_xxx
tinfoil registry set gcr --key-file ./gcp-sa.json
tinfoil registry set dockerhub --username myuser --token dckr_xxx
tinfoil registry delete ghcr

# Custom domains (TXT/CNAME instructions are printed on add/verify)
tinfoil domain add api.example.com
tinfoil domain verify api.example.com
tinfoil domain delete api.example.com
```

Pass `-o json` on any list/get to emit machine-readable JSON.

## Volume management

Volumes are encrypted persistent disks that live on one container host and attach to a mount declared in a repository's `tinfoil-config.yml`. A volume can be attached to one stopped container at a time and keeps its data across stops, deploys, and updates.

Automatic unlock requires the keyserver configuration and the `key_secret` value in a secrets manager **outside Tinfoil**. Creating or attaching a disk does not provision that secret or prove it can unlock. Mounts without `key_secret` are optional/manual: the workload must initialize and unlock an attached disk itself. Do not treat attachment or container Running status as disk-readiness evidence.

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
tinfoil volume attach my-db-data my-other-db

# Rename or delete (delete erases the data and requires the volume to be detached)
tinfoil volume rename my-db-data --name archive-data
tinfoil volume delete archive-data              # prompts; pass --yes to skip
```

Volume names are not unique within an organization; when several volumes share a name, the commands ask for the volume ID.

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

## Building from Source

```bash
git clone https://github.com/tinfoilsh/tinfoil-cli.git
cd tinfoil-cli
go build -o tinfoil
```

## Troubleshooting

- `PCR register mismatch`: The running enclave code differs from the source repo.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
