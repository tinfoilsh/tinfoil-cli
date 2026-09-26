# Volume auto-unlock CLI contract

Stack: CLI parent PR #129 (`feat/container-lifecycle-vocabulary`, `0c666be`).
Guest and controlplane companion PR links will be added when available.

## Commands

One-time local setup (does not deploy a keyserver or change its policy):

```sh
tinfoil project storage configure owner/repo \
  --keyserver-url https://keys.example.com \
  --aws-region us-east-2 --aws-prefix tinfoil --aws-profile customer
```

The positional argument also accepts an existing project ID. An explicit
`owner/repo` works before the first instance/project exists: the CLI verifies
organization identity and access using the controlplane's repository config
read endpoint, without allocating a namespace or project. Repository names
are normalized to lowercase. Missing required values prompt only on a TTY;
noninteractive callers must supply them. `--aws-profile` is optional (standard
AWS credential chain); optional `--domain` saves an exact deployment domain.
Reconfiguration with different metadata is refused rather than silently
redirecting an existing project's key custody.

```sh
tinfoil volume create app-data --size 30GiB --host HOST --auto-unlock \
  --project owner/repo --mount data --tag v1.2.3 --domain app.example.com \
  --config-file tinfoil-config.yml --config-out prepared-config.yml \
  --policy-out prepared-policy.yml

tinfoil volume auto-unlock configure VOLUME_ID \
  --project owner/repo --mount data --existing-secret ORIGINAL_SECRET_NAME_OR_ARN \
  --tag v1.2.3 --domain app.example.com \
  --config-file tinfoil-config.yml --config-out prepared-config.yml \
  --policy-out prepared-policy.yml

tinfoil volume auto-unlock status VOLUME_ID --project owner/repo
```

`--mount` is the logical name in top-level `volumes`, not a filesystem path.
It must already be declared in the input config. `--domain` may instead come
from the project storage profile. Exact domain and release tag are mandatory
before allocation; there is no guessed instance domain or wildcard approval.
Use a known deployment/custom domain if an instance does not yet exist.
`--policy-file` optionally reads an existing policy to prepare an additive
copy. Without it the output is a standalone fragment for manual review/merge,
not a replacement for the keyserver's full policy. Outputs must be different
from input files and cannot overwrite different existing contents.

## Measured configuration and policy

The prepared YAML preserves unknown fields and comments using YAML nodes.
Only a missing `keyserver-url` and a missing selected volume `key-secret`
are added. Conflicting existing values are refused. New disks use a unique
reference `VOLUME_<UUID_WITH_UNDERSCORES>_KEY`. Existing disks retain any
already declared reference and require the operator's explicit original
secret name/ARN; key validation alone cannot prove a key matches disk data.

```yaml
keyserver-url: https://keys.example.com
volumes:
  - name: data
    key-secret: VOLUME_<UUID_WITH_UNDERSCORES>_KEY
```

Policy wire schema matches the existing private keyserver:

```yaml
workloads:
  volume-<UUID>:
    repo: owner/repo
    tag: v1.2.3
    domain: app.example.com
    secrets:
      VOLUME_<UUID_WITH_UNDERSCORES>_KEY:
        path: volumes/<UUID>/key
        field: value
```

The keyserver must run with `BACKEND=aws`, the profile's `AWS_REGION`, and
`AWS_SECRETS_PREFIX` matching `--aws-prefix`. The AWS name is
`<prefix>/volumes/<UUID>/key`. Explicit existing names must be under that
prefix; an ARN is resolved to its actual name before deriving the policy
path. With an empty prefix, the full secret name is the policy path.
Same repo/tag entries cannot authorize multiple domains on this keyserver.
When merging a policy, reuse the one matching workload only if its exact
domain matches; duplicate pins, missing domain, changed mappings, and
wildcards are refused. Distinct deployment domains need distinct released
config tags (or independently operated keyservers), not duplicate entries.

## Custody and failure recovery

AWS Secrets Manager is the only provisioning backend in this version.
Vault and file provisioning are not supported. The customer owns the AWS
account, IAM policy, durability/backups, keyserver, TLS, policy deployment,
and key retention. Disable rotation for volume secrets: the original key
must survive every stop, deploy, and release change. The CLI never formats,
deletes, recreates, or rotates a disk/secret as recovery.

Only a newly allocated volume may generate a key: 64 bytes from Go
`crypto/rand`, encoded with `base64.StdEncoding`. AWS `SecretString` contains
exactly `{"value":"<base64>"}`. No key values go to the controlplane, GitHub,
config, policy, receipt, CLI output/logs, or command arguments. AWS SDK v2
authentication is loaded only during an explicit provisioning command.
Errors are sanitized; AWS request/response logging is disabled.

Writes use `CreateSecret`, never Put/Update/upsert. A deterministic per-volume
name, volume UUID version token, and scope/volume provenance tags support
read-only recovery after an uncertain create response. A durable receipt is
written before attempting secret creation. Recovery reads the original
secret and checks provenance/version; it never generates another key.
After partial failure, the error retains the allocated volume ID and phase.
Use `auto-unlock configure` with that ID and the reported existing secret
reference, not another `volume create`. If the first key never reached AWS,
setup remains incomplete and requires operator investigation; the CLI does
not manufacture a replacement for an existing disk. If allocation itself
has an uncertain response, inspect `volume list` before any retry.

Local metadata lives in a separate `storage/` directory beside the effective
CLI config path (directory 0700, JSON files 0600). Profiles are scoped by
normalized controlplane URL, authenticated organization ID, and canonical
repository; receipts additionally bind the volume UUID. Login/logout does
not rewrite this directory or extend the credential JSON schema.

## Review, publish, authorize, deploy

1. Review the prepared config and policy. No remote policy write API exists.
2. Propose the config with the existing command
   `tinfoil repo config pr owner/repo --file prepared-config.yml`; review and
   merge the PR. Never publish secret values.
3. Publish the **new measured config** under the exact policy tag using
   `tinfoil repo build run owner/repo --version v1.2.3`. Wait for both release
   workflows and a published release (`repo build status` / `repo build info`).
   Editing YAML changes measurements; an old tag does not cover the edit.
4. Independently review/merge/install the policy on the customer keyserver
   and restart it with that file using the customer's deployment process.
   The CLI neither applies policy nor asserts it has been loaded.
5. Create/attach/deploy through the normal lifecycle commands, selecting the
   same repo/tag/domain and original disk. Private-keyserver deployments use
   `--secret=""` to clear Tinfoil-managed selections. No per-boot decrypt
   command is required; the guest fetches the original key at boot and must
   complete its mount stage before workloads start.

Status reports local configuration evidence only: `CONFIGURED_LOCAL` means
the saved config/key-secret/policy metadata and artifacts agree, always with
`awaiting publication/policy load; unlock not observed`. It does not mean
unlocked, running, or remotely approved. Changed/missing artifacts are stale.
A teammate without this local profile sees unknown, not locked or key loss.
This version does not implement attested guest mount observation; attachment,
controlplane lifecycle status, and keyserver HTTP health are not unlock proof.
