# Sandboxes tab → CLI affordance tracker

Reference: **websites-monorepo upstream `main`, `58bd651033d938d000a53dcd703ea4c0b0512c36`**, fetched October 14, 2026. This is the committed upstream tree, not the local dashboard feature branch. CLI starting point: `821c64fc257f8aca8ec5d62355c665c620e03e5b`, branch `codex/cli-owner-upstream-main` in `features/muse-at-home/cli`. The initial checkout had no staged, unstaged, or untracked work.

Scope: every interaction, validation, recovery path, and account boundary in the Sandboxes tab. Distinguish existing CLI behavior from a missing convenience and from missing workflow behavior. Generic commands count as existing capabilities; a missing sandbox/Monitor entry point does not mean their underlying behavior is absent. Status must have sandbox and Monitor conveniences. Browser layout, focus and clipboard interactions need terminal equivalents. Live deployment verification is separate.

Source abbreviations (all at the pinned upstream commit):

- [Tab](https://github.com/tinfoilsh/websites-monorepo/blob/58bd651033d938d000a53dcd703ea4c0b0512c36/apps/dashboard/src/app/components/SandboxesTab.tsx): lists, forms, account scope, pricing, pending records, actions.
- [Row](https://github.com/tinfoilsh/websites-monorepo/blob/58bd651033d938d000a53dcd703ea4c0b0512c36/apps/dashboard/src/app/components/sandboxes/AgentRow.tsx): details, connection commands, actions, progress/errors.
- [Create](https://github.com/tinfoilsh/websites-monorepo/blob/58bd651033d938d000a53dcd703ea4c0b0512c36/apps/dashboard/src/app/components/sandboxes/create.ts): measured keys/bindings, storage validation, create/resume.
- [Lifecycle](https://github.com/tinfoilsh/websites-monorepo/blob/58bd651033d938d000a53dcd703ea4c0b0512c36/apps/dashboard/src/app/components/sandboxes/lifecycle.ts), [States](https://github.com/tinfoilsh/websites-monorepo/blob/58bd651033d938d000a53dcd703ea4c0b0512c36/apps/dashboard/src/app/components/sandboxes/utils.ts).
- [Releases](https://github.com/tinfoilsh/websites-monorepo/blob/58bd651033d938d000a53dcd703ea4c0b0512c36/apps/dashboard/src/app/components/sandboxes/releases.tsx), [Public catalog](https://github.com/tinfoilsh/websites-monorepo/blob/58bd651033d938d000a53dcd703ea4c0b0512c36/apps/dashboard/src/app/api/sandboxes/releases/route.ts).
- [Review](https://github.com/tinfoilsh/websites-monorepo/blob/58bd651033d938d000a53dcd703ea4c0b0512c36/apps/dashboard/src/app/components/containers/UpdateReviewDialog.tsx).

Status: **Existing** = supported at the starting point; **Convenience** = a new entry point reusing existing behavior; **Implemented** = new workflow/detail behavior in this pass; **Partial** / **Gap** = remaining work; **Equivalent** = terminal interaction substitutes for a browser interaction. “Implemented” does not mean all underlying primitives are new.

The first draft overcounted missing command names as missing capabilities. Status, Monitor lifecycle and managed update conveniences now share existing handlers, rendering and polling. The separate lifecycle/update implementations and the additional SSH, volume and release command trees are removed. Managed creation/recovery remains a distinct workflow.

| Area | Already available | What this pass adds |
| --- | --- | --- |
| Status | `container list/get`, status model, rendering and polling; `sandbox list` | `sandbox status`, `monitor status`, watch, missing boot/error details |
| Lifecycle | `sandbox start/restart/stop/delete`; generic `container deploy/stop/delete` for Monitors | `monitor start/stop/delete` reuse the generic handlers with type checks; shared restart configuration guard; `--no-enroll` |
| Updates | `container update --tag VERSION --hold=false`, read-only plan and consent/recheck | `sandbox update` / `monitor update` reuse the generic handler, defaulting to automatic traffic switching |
| Storage | `volume list/get/create/attach/detach/delete`, volume lookup and local custody | Managed creation preflight/reuse; no new volume command tree |
| Releases | `repo build info OWNER/REPO`, release tags, notes and prerelease metadata | None; new creation requires explicit `--tag` |
| Connections | `attest-ssh NAME --install`, `sandbox enroll`, native SSH, `monitor open` | Status prints the existing connection commands |
| Creation | Generic `container create`, variables and sandbox network policy; atomic storage writer/locks and account scope | Managed request assembly, public-key defaults, preflight and persisted interruption/reconciliation workflow |

## Discover and inspect

| ID | Dashboard affordance / acceptance criterion | CLI mapping and status | Source |
| --- | --- | --- | --- |
| D01 | Separate sandbox and Monitor lists; exclude debug and unrelated VMs | Convenience: `sandbox status` / `monitor status` list their kind; `get/list/ls` are aliases; generic and filtered lists share one implementation | Tab |
| D02 | Show names and distinguish all lifecycle states, including unknown | Convenience: existing labels/model plus explanations in managed `status` | Row, States |
| D03 | Refresh now, automatic 5-second refresh, loading/empty/error states | Partial existing list refresh by rerun; `status NAME --watch` reuses polling; continuous whole-list watch remains | Tab |
| D04 | Never act on stale data after refresh errors | Existing fresh API reads per command; no cached fallback | Tab |
| D05 | Expand/collapse independently of copy/menu actions | Convenience: `status NAME` (alias `get`) versus no-argument status/list | Row |
| D06 | Explain running versus actually connected/unlocked | Implemented explanations and existing connection instructions in managed `status` | Row, States |
| D07 | Show sandbox's Monitor name/state; explain stopped/missing/other-account Monitor | Implemented `sandbox status NAME` resolves measured Monitor; explains stopped/missing/unpublished bindings | Row |
| D08 | Show measured configuration reference and current version | Implemented existing shared detail output now preserves release alongside config reference | Row, Releases |
| D09 | Flatten nested boot stages with name, detail, and status | Implemented shared detail rendering flattens nested stages and preserves detail in JSON | Row |
| D10 | Prefer last deployment attempt error for stopped/failed resources | Implemented model, detail rendering and lifecycle errors prefer last attempt for stopped/failed resources | Row |
| D11 | Translate approval/expiry/handoff errors, retaining raw technical details | Implemented managed `status` advice alongside the existing raw error | Row, States |
| D12 | Show action-specific progress/errors even after dialog closes | Implemented stderr progress, persistent `pending` and actionable recovery errors | Tab, Row |

## Create and recover

| ID | Dashboard affordance / acceptance criterion | CLI mapping and status | Source |
| --- | --- | --- | --- |
| C01 | Create Monitor with measured owner and provisioned object storage | Implemented `monitor create NAME`, including `object_storage: {}` | Tab, Create |
| C02 | Create sandbox with fresh instance UUID, measured owner/Monitor binding, private fixed TCP alias | Implemented `sandbox create NAME`, with immutable measured instance and private Monitor alias | Tab, Create |
| C03 | Validate lowercase DNS-style name, ≤63 characters, alphanumeric ends | Implemented creation-only validation; legacy credential names remain supported | Tab |
| C04 | Prevent name collision with every VM kind in the account | Implemented account-wide list preflight; resume checks measured identity before adoption | Tab |
| C05 | Select Monitor by identity and show non-running state | Implemented `--monitor ID\|NAME`; missing selection fails instead of being replaced | Tab |
| C06 | Default Monitor; allow stopped Monitor and warn service access must wait | Implemented automatic selection only when exactly one Monitor exists; stopped Monitor allowed with guidance | Tab |
| C07 | Prefill owner from selected Monitor's measured configuration; allow override | Implemented measured Monitor owner default; `--owner-public-key FILE` overrides it | Tab, Create |
| C08 | Accept only valid Ed25519 public keys, reject private material, show fingerprint | Implemented one Ed25519 public key, no private material/options/multiple keys; prints SHA256 fingerprint | Create |
| C09 | Create with public key only; keep private/encryption keys local; choose identity later | Implemented public-only creation; inherited `--identity` selects identity public file and later owner authentication | Tab |
| C10 | New workspace defaults to 30 GiB (32.21 decimal GB) | Implemented API-managed new workspace default, documented as 30 GiB / 32.21 GB | Tab |
| C11 | Read current capacity/capability/pricing; fail closed if unavailable | Implemented current volume capability, capacity and rate/exemption checks before create POST | Tab |
| C12 | Show standard compute rates, account-adjustment caveat, storage rate/exemption/capacity | Partial live storage rate/exemption/capacity and compute billing guidance; standard CPU/RAM rate display remains | Tab |
| C13 | Enumerate existing workspace names/IDs/sizes and reasons ineligible | Partial existing `volume list/get` enumerate IDs/names/sizes; creation checks eligibility; eligibility list presentation remains | Tab |
| C14 | Reuse unattached, non-deleted workspace ≥30 GiB on its existing host | Implemented `--workspace ID\|NAME`, rechecked immediately before create; server retains volume host | Tab, Create |
| C15 | Reuse remains available without new-storage quota/capability; no automatic detach | Implemented reuse independent of new-volume quota/capability; no detach request | Tab, Create |
| C16 | Warn original encryption credentials are required; SSH key alone cannot recover data | Implemented creation/reuse instructions plus existing enrollment credential enforcement | Tab |
| C17 | Save immutable intent before POST, including instance and workspace IDs | Implemented atomic public intent before POST using existing storage writer | Create |
| C18 | Preserve pending operation across process/modal closure, timeout, or lost reply | Implemented account-scoped `pending`, `resume`, Ctrl-C and `--no-wait`; uncertain submission never blindly repeats POST | Tab, Create |
| C19 | Reconcile existing name/ID using measured owner, tag, instance and Monitor binding | Implemented immutable measured owner/tag/instance/Monitor checks on reconciliation and final detail | Create |
| C20 | Save returned ID; detect deletion; verify final workspace and network binding | Implemented persisted ID, deletion failure, final workspace and private alias validation | Create |
| C21 | One pending creation per account; reserve its name; prevent duplicate concurrent submits | Implemented shared per-account pending file and existing storage lock; duplicate submit blocked | Tab |
| C22 | Show pending name, kind, version and progress; locked inputs while resuming | Implemented `pending` table/JSON; `resume` accepts no replacement creation inputs | Tab |
| C23 | Corrupt pending record blocks new creation; explicit clear keeps remote resources | Implemented validation blocks new create; explicit `pending clear` works on corrupt records | Tab |
| C24 | Clear pending record without deleting VM, disk, keys or object storage | Implemented confirmed local-only `pending clear`; retains remote resources and credentials | Tab |
| C25 | Wait through publication and boot without an extra deploy; stop on failed/stopped | Implemented create POST plus existing poller; no deploy; failures/stops keep recovery record | Create |
| C26 | Cancellation/account change leaves resumable original-account intent | Equivalent immutable authenticated client, scoped intent and cancelable requests/polling | Tab |
| C27 | Create errors retain form/intent and offer retry/recovery instructions | Implemented pending record survives error with inspect/resume instructions | Tab |
| C28 | Submit/Done/cancel, validation errors, keyboard focus and busy controls | Equivalent flags/help, stderr, exit codes, Ctrl-C and operation lock | Tab |

## Release selection and updates

| ID | Dashboard affordance / acceptance criterion | CLI mapping and status | Source |
| --- | --- | --- | --- |
| V01 | List compatible published releases; omit drafts/no config asset | Partial existing `repo build info OWNER/REPO`; public personal-account catalog/config-asset filtering remains | Releases, Public catalog |
| V02 | Label stable/latest/prerelease; link release notes | Existing `repo build info` shows published tags, prerelease metadata, latest tag and release-note links | Releases |
| V03 | Use newest stable for new resources only | Gap automatic newest-stable selection; managed create currently requires explicit `--tag` | Releases |
| V04 | Explicit tag/manual fallback works when catalog/private source unavailable | Existing generic `--tag`; managed create also accepts explicit tag without catalog discovery | Releases |
| V05 | Refresh catalog, retain explicit/manual selection, expose fetch errors | Existing rerun `repo build info`; explicit tag stays selected | Releases |
| V06 | Organization Monitor catalog uses authenticated repo tags; no public private-token proxy | Partial existing organization-authenticated repo commands; exact dashboard catalog adapter deferred | Releases |
| V07 | Inspect current and available versions in any lifecycle state | Convenience current version in sandbox/Monitor `status`; existing repo command inspects releases in any state | Releases |
| V08 | Update only running resource with no in-flight deployment; recheck target identity/config/tag | Partial existing generic update/API guards; explicit managed target/config recheck remains | Tab |
| V09 | Read-only plan before mutation; reject wrong target/tag/malformed plans | Partial existing shared read-only plan and ID/schema checks; requested-tag/resource strictness remains | Review |
| V10 | Review current→target version/CPU/memory/GPU and replacement/blue-green strategy | Existing shared plan output | Review |
| V11 | Review variables/secrets/SSH keys/settings, refreshed secrets and secret-delivery notice | Existing shared plan output | Review |
| V12 | Explain retained volumes and whether cost estimate exists | Existing shared plan output | Review |
| V13 | Require downtime consent; cancel without mutation | Existing generic update confirms downtime and permits cancellation; no new confirmation system | Review |
| V14 | Re-fetch plan before submit; reset consent if plan changes; retry unavailable plan | Existing shared plan recheck/retry | Review |
| V15 | Automatic takeover (no hold selector in Sandboxes tab) | Convenience: `sandbox update` / `monitor update` use the existing handler with `hold=false` | Tab, Review |
| V16 | Surface progress and server errors; never repeat mutation on failed plan | Convenience: managed update commands share the existing plan, follower and failure handling | Tab, Review |

## Lifecycle and connection

| ID | Dashboard affordance / acceptance criterion | CLI mapping and status | Source |
| --- | --- | --- | --- |
| L01 | Start stopped sandbox | Existing `sandbox start`; added `--no-enroll` for boot-only administration | States, Lifecycle |
| L02 | Stop running/failed sandbox, retaining workspace | Existing `sandbox stop` | States, Lifecycle |
| L03 | Restart running/failed sandbox; wait for stop before deploy | Implemented small shared stop/follow configuration guard; restart itself already existed | Lifecycle |
| L04 | Delete running/stopped/failed sandbox; retain disk and explain continuing charges | Existing `sandbox delete --yes`; retained credentials | Tab, States |
| L05 | Start/stop/restart/delete Monitor with same state matrix | Partial: `monitor start/stop/delete` reuse existing generic handlers; restart is composed from stop, wait for stopped status, then start; exact managed state matrix remains | States, Lifecycle |
| L06 | Stop/restart/delete confirmation and cancellation | Equivalent explicit CLI invocation; existing delete/downtime prompts support `--yes`; no new prompts for stop/restart | Tab |
| L07 | Monitor action warns which bound sandboxes lose service access | Gap automatic affected-sandbox summary; bindings are already available via container list JSON | Tab |
| L08 | Monitor stop retains state; deletion retains object storage with no restore flow promised | Existing retention behavior; object-storage/no-restore guidance documented here | States |
| L09 | Disable mutations during transient/unknown states; inspect/update catalog still available | Partial existing server validation and unrestricted read commands; managed action matrix remains | States |
| L10 | Validate measured sandbox binding and private Monitor TCP alias before start/restart | Existing `validateSandboxNetwork` | Lifecycle |
| L11 | Abort restart if name/repo/config/tag changes while stopping | Implemented shared stop guard on ID/name/repo/tag/config plus unexpected status | Lifecycle |
| L12 | Copy/select connection command, successful copy feedback, clipboard failure fallback | Convenience printable existing connection commands in managed `status`; no clipboard dependency | Row |
| L13 | Attest, unlock Monitor and sandbox, enroll, install SSH profile; reconnect after either reboot | Existing `attest-ssh NAME --install`, `sandbox enroll` and native SSH; no new connection implementation | Row |
| L14 | Open local Monitor panel, print URL, explain process must stay running | Existing `monitor open NAME` | Row |
| L15 | Install CLI link, login with current-account admin key, identity selection instructions | Existing README/login/help | Tab |

## Account and presentation boundaries

| ID | Dashboard affordance / acceptance criterion | CLI mapping and status | Source |
| --- | --- | --- | --- |
| A01 | Personal/organization context; exclude other accounts' resources and credentials | Existing API key context + scoped resource storage | Tab |
| A02 | Pending creation isolated by user, organization and control plane | Implemented pending scope includes authenticated user/org/controlplane and validates saved scope | Tab |
| A03 | Account change aborts in-flight work; stale responses cannot mutate new account | Equivalent immutable authenticated client and validated pending scope; no browser account-switch state | Tab |
| A04 | Subscription gate blocks create/start/restart/update but permits stop/delete/read | Partial API enforces subscription/entitlement; CLI does not yet preflight an active subscription | Tab |
| A05 | Account entitlement controls access to tab | Equivalent API authorization; server remains authoritative | Tab/client |
| A06 | Independent errors/loading/retry for resource list, volumes, owner lookup, releases and plan | Existing separate commands/API errors; managed creation adds persistent recovery instructions | Tab |
| A07 | Accessible labels/status, focus restoration, responsive layout, independent menu buttons | Equivalent Cobra help, plain text/JSON, stderr progress, exit codes and no clipboard dependency | Tab, Row |
| A08 | No silent destructive cleanup; preserve workspace, storage credentials and grants | Implemented local-only pending clear; existing sandbox/Monitor deletion and credential retention remain | Tab, States |

## Implementation and verification

The bounded implementation is creation/recovery plus sandbox/Monitor status, lifecycle and update conveniences and small fixes to shared detail/polling code. Command wrappers reuse the existing handlers and flags, check resource kind before mutation, and keep flag metadata separate. Sandbox enrollment stays in its existing lifecycle path. Lifecycle/update/volume/SSH operations retain their existing owners. Automatic release selection, whole-list watching, subscription preflight and the other Partial/Gap entries remain tracked, not claimed complete.

Creation uses the dashboard upstream request shape and reuses measured-environment parsing, volume lookup, account scope, atomic file writing/locking and the existing poller. The pending record is new because generic create has no durable managed-creation intent. Existing v2/v3 credentials and legacy named directories remain supported; there are no migrations for unshipped creation designs.

Review baseline: CLI PR #139 targets `main` at `7bad5ea65c67db91032e379cdf4c14ee9cdd6f10`; these changes are compared separately against starting HEAD `821c64f`. Review includes staged, unstaged and untracked files. Do not use local CLI main or the local dashboard feature branch as the behavior reference.

Local checks cover create/reconcile request contracts, uncertain replies without duplicate POST, measured binding and workspace mismatches, public-only creation, account scope, quota/reuse, cancellation, status filtering/watching, and restart configuration changes. Command-path tests cover Monitor lifecycle requests, wrong-kind/debug rejection, alias flag metadata, and managed updates retaining plan review/recheck, automatic switching and downtime consent. Production/test/documentation sizes are reported separately. No committed test coverage is removed to reduce implementation size.

Live CVM creation, object-store allocation, workspace placement, billing entitlements, and production update/SSH behavior remain unverified. Local API fixtures and OpenSSH/Monitor process tests do not establish deployed end-to-end parity.
