# Bounded pilot enrollment runner

`kaiba-pilot-enrollment-runner` lets an owner launch one reviewed enrollment job
with sudo. It sequences the host/device commands, observes their postconditions,
retains durable progress and emits a small status file for an unprivileged
observer. It is intended for the next Mako pilot enrollment; this implementation
has not enrolled Mako or changed the running Ace deployment.

The runner and command adapter are implemented and covered by a subprocess
rehearsal. The **Mako-specific deployment packet and operation hooks still need
preparation and review** against fresh target observations, current authority
records, deadlines and serving state. Merging this code does not authorize those
operations. Existing pilot admission decisions, credential protocols and hardware
qualification requirements are unchanged.

## One owner interaction

Prepare all public software, connectivity, scoped SSH access, issuer grants,
backup destination and postconditions before asking the owner to launch the job.
The authority storage must already be unlocked. If locked, the owner first uses
its existing FIDO unlock procedure. Enrollment uses the pilot software issuer;
it does not require a YubiKey boot-image signing ceremony.

The reviewed command has this form (placeholders are deliberately not runnable):

```sh
sudo /nix/store/REVIEWED-RUNNER/bin/kaiba-pilot-enrollment-runner run \
  --packet /var/lib/kaiba-enrollment-packets/REVIEWED/packet.json \
  --sha256 REVIEWED_PACKET_SHA256 \
  --retain-recovery-passphrase
```

The owner enters the saved backup recovery passphrase locally, once. The option
explicitly consents to retaining it for this process's lifetime through the
backup step. There is no password/PIN argument, environment variable, credential
file or chat input. The runner disables core dumps and dumpability, requires no
swap, and reads the terminal without echo directly into an mlocked anonymous
page excluded from core dumps. It supplies a pipe only to the initial read-only
recovery-credential check and the final backup executor. It zeroes the page after
backup completion and on normal/error/signal exits. A terminated process loses
this credential; resuming before backup needs a new local prompt. Root remains
trusted, as do the reviewed credential-check and backup executors.

The credential check must verify the existing recovery slot before any device
mutation. A wrong passphrase stops there, with no automatic guessing or fallback
to a token. A FIDO/PIV PIN must never be supplied as the backup credential.

Subprocesses have no controlling terminal and no inherited interactive input.
All later operations must be noninteractive. No passwordless general root shell,
agent-readable credential cache or persistent sudo grant is installed.

## Fixed sequence and completion

Every execution step requires an independent postcondition probe. An exit code
of zero alone is insufficient.

| Step | Required packet-specific operation and postcondition |
| --- | --- |
| Preflight | Read-only target authentication, encrypted storage and workload inventory, host/authority/SSH identities, current grants and certificate validity, backup destination/free space, baseline Ace membership and serving policy. Must recognize an approved partial run on resume. |
| Check credential | Read-only test of the existing backup recovery credential; no token fallback, no storage format or keyslot change. |
| Prepare authority | Coordinate the existing supervisor, scope Mako access and verify both source readers. Retain Ace's identity and a recoverable serving baseline. |
| Prepare device | Install only the approved client/account/protected directory, with ownership and executable-path checks before any key creation. |
| Initialize device | Generate exactly one Mako key on Mako; retain the public binding, never export its private key. |
| Start enrollment | Submit the exact approved record references and public key with a stable idempotency key; retain the assigned identity and challenge. |
| Submit bootstrap | Verify the bound proof; obtain at most the authorized credential from the issuer. Probe the existing issuer/fleet result after any lost reply. |
| Install credential | Install the exact staged credential matching the generated key. |
| Prove installed | Prove possession from a new client process, then read authoritative verification state. |
| Activate | Activate only the verified approved tuple and qualification gaps. |
| Verify access | Authenticated own-state access with exact identity/credential continuity. |
| Test isolation | Execute the explicitly approved Ace/Mako own-record and other-record tests; one device's evidence does not qualify the other. |
| Test restart | Execute only the packet's stated restart scope and observe identity continuity. Process restart must not be reported as an OS or cold boot. |
| Backup | Quiesce writers, preserve current records/configuration, copy encrypted authority to the pinned USB, verify readback/recovery/filesystem/database consistency, unmount USB and restore the original protected mount. No blind overwrite of a prior backup. |
| Resume serving | Install the reviewed updated serving baseline, resume the approved scope/deadline and verify access. A failed backup cannot reach this step. |
| Remove temporary access | Remove only job-owned temporary access; preserve the approved ongoing serving rules and report verified cleanup. |

An exclusive journal lock prevents two local runners. Before each operation the
runner fsyncs a one-use intent. Completed responses bind the packet digest, run,
target, step and stable operation ID; resume validates these bindings. It never
repeats a step with an existing intent. It invokes the read-only reconciliation
probe, continuing only if that probe establishes the exact operation completed.
Unknown or partially applied results stop for review. This version deliberately
does not automatically resubmit even an idempotent enrollment request.

On failure after a step was attempted, the separately reviewed `safe-stop` hook
runs. It is idempotent cleanup, **not rollback of membership or issuance**. It must
stop unsafe serving and remove job-owned temporary access without restoring a
stale database or the old serving baseline after new writes. Cleanup may run
for at most 60 seconds after the execution deadline, with unchanged input and
host guards. A failure before any step does not stop existing services.

The `resume` command uses the same packet/hash and journal within the same boot
and authorization window. It does not create renewed authority. Changed inputs,
an expired window, a host reboot, or an unresolved mutation needs a separately
reviewed continuation. No automatic process restart or mutation retry is installed.

## Reviewed packet and adapter

The packet is root-owned, single-link mode 0600 in root-controlled directories.
It has exactly these fields:

- `schema_version`: `kaiba.pilot-enrollment-run/v1alpha1`.
- `run_id`, `asset`: bounded lowercase labels.
- `target_digest`: SHA-256 of the exact authenticated target binding.
- `issued_at`, `expires_at`: UTC window no longer than twelve hours.
- `host_boot_id`: the management host's current boot.
- `state_directory`: a new root-private journal directory under a trusted parent.
- `progress_file`, `observer_uid`: an explicitly selected local status-file path
  and reader. Progress includes a timestamp and runner PID; a stale file after
  a crash is not a live-service observation. Its directory remains root-controlled; the reader needs directory
  traversal. Status is output only, never execution authority.
- `adapter`: `{ "path": "/nix/store/.../bin/...", "sha256": "..." }`.
- `context`: the root-private reviewed adapter configuration path and SHA-256.
- `step_timeout_seconds`: 1–1800; the job deadline further limits each call.

`validate` checks structure, hashes and local guards without prompting or calling
an executor. It does not claim remote preflight passed. Approved input hashes
are checked again before every adapter call.

The packaged `kaiba-pilot-enrollment-adapter` dispatches an exact command list.
Its context is `kaiba.pilot-enrollment-adapter/v1alpha1`, with `run_id`,
`target_digest`, `inputs` (fixed public/private-metadata files and hashes, never
secret files), and `operations`. Every fixed step plus `preflight`,
`check-credential` and `safe-stop` has `execute` and `probe` command definitions.
Preflight's `execute` is null. Each command is an `argv` array and SHA-256 of its
resolved immutable Nix executable. Script/configuration inputs referenced by
arguments must also be bound by immutable store paths or `inputs` hashes.

Commands receive one bounded JSON request on stdin, including `action`, `step`,
`run_id`, `target_digest`, `operation_id` and the context binding. They emit only
`{"outcome":"complete"}`, `unknown` or `blocked`. Execute success is followed
by the probe; reconciliation invokes the probe alone. Probes must be read-only
and check target, key, records and exact current postconditions, not just the
presence of a marker. Detailed non-secret diagnostics belong in the hook's
private journal. Raw stdout/stderr are not persisted or forwarded by the runner.
The two credential-consuming commands receive `--recovery-key-fd N`, a one-use
pipe, and must pass it directly to the approved recovery verifier without logging,
copying to files, or reading the terminal. Probes receive no credential descriptor.

A packet author must review command effects, transitive code/input dependencies,
SSH host-key pinning, authority trust and postconditions. **This is not a sandbox
for untrusted root commands.** The runner does not turn arbitrary commands into
valid enrollment evidence, grant admission, or verify hardware facts itself.
Do not wrap the old whole-ceremony scripts as individual steps: extract their
bounded operations/probes, remove nested TTY/password prompts, and preserve their
existing host/device checks and reconciliation rules.

## Validation and remaining live work

```sh
python3 -B -m unittest discover -s tests/pilot-enrollment-runner -v
nix build .#checks.x86_64-linux.pilot-enrollment-runner
# The same check runs natively on aarch64-linux in CI.
```

The subprocess rehearsal exercises a durable synthetic authority, lost replies,
exactly-once dispatch, a backup snapshot, secret descriptor isolation, deadlines,
output bounds and cross-target response rejection. Terminal tests verify echo
suppression and restoration. These are runner/adapter tests, not a new real-fleet
integration or hardware qualification. Existing fleet/client lifecycle tests
remain responsible for actual protocol behavior. The Nix check builds no kernel,
image or VM and grants no live execution authority.

Before the Mako run: refresh its observations and access, prepare all exact hooks
and their real-service rehearsal, review the bounded effects on the already-live
Ace authority, then ask once for the completed execution packet. No Mako device,
authority record, signing token or current service was changed by this software PR.

## Initial enrollment protocol hook

`protocol.py` implements the seven protocol steps from device initialization
through verified own-state access. A reviewed host adapter supplies its fixed
Mako client dispatcher; the module performs bounded HTTPS/mTLS requests with
explicit trust roots, separate station/operator credentials, no redirects and
no automatic retries. It checks the approved record references, target, public
key and assigned identity before continuing. It cannot fetch a device private key.

The hook keeps a separate owner-only public journal bound to the exact plan.
Its own one-use intents prevent an accidental direct invocation from repeating
a mutation, even outside the outer runner. Read-only probes use client status,
client self-read and authority GET requests. A lost initial response without a
saved enrollment identifier remains unresolved; the hook never repeats creation
to rediscover it. A retained identifier permits observation of completed proof or
activation without repeating key use or issuance.

This is a library for the reviewed host adapter, not an independently runnable
Mako packet. Device setup, SSH transport and encrypted backup have library implementations
below. Authority deployment and serving controls still need packet-specific
integration and approval. The actual protocol library and HTTPS
transport are exercised against disposable fleet services in the companion fleet
rehearsal; its device dispatch substitutes only the storage observation.

`recovery.py` supplies the backup hooks' noninteractive recovery-slot operations:
one passphrase check against slot 0, or one read-only opening of the encrypted
copy. It forwards only the inherited pipe descriptor to cryptsetup, disables
external-token fallback and never formats storage or changes slots. It closes
the descriptor on success or failure and does not retry. The native check verifies
both correct and incorrect synthetic credentials against a disposable LUKS image
and confirms its header is unchanged. Image identity, USB handling, quiescence,
mount verification and restored filesystem/database checks remain the reviewed
host backup hook's responsibility.

## Device-side host hook

`kaiba-pilot-enrollment-device` provides bounded setup and initial client dispatch
on the reviewed NixOS target. A root-controlled, hash-bound plan pins the board
and NVMe digests, boot ID, current and booted systems, LUKS UUID/partition,
client binary and full public client configuration. Every call checks the plan's
execution window, disabled swap and the block ancestry from `/var/lib` through
that exact LUKS mapping to the selected partition.

Setup requires the pilot account/group and all four installation directories to
be absent. It records intent before creating them, installs the exact client and
public configuration, and verifies an ext4 bind mount with `nosuid,nodev,noexec`.
Only the dedicated client user owns its mode-0700 credential directory. Tools,
inputs and operation metadata are separate root-controlled directories. Inputs
are group-readable through a traversable parent; no logs or backups are placed
inside the client's strict state directory.

The only mutation commands are `init`, `bootstrap`, `install` and
`prove-installed`. Each has a durable one-use intent. A lost reply does not permit
another invocation. `status`, `self` and `probe-prepare` are observations. Setup
and client operations do not reboot, change the OS, configure services, format
storage or access OTP/firmware mechanisms. Account and bind-mount persistence
across a NixOS switch/reboot is not established by this hook.

This executable must be delivered through the packet's authenticated SSH path;
shipping it does not grant general root access. The host still must bind the SSH
principal/host key and exact plan, then call only approved steps. The SSH library
can deliver the reviewed modules and plan in memory without a remote helper file.
Unit tests use synthetic sysfs trees and temporary directories, substituting
privileged account/mount/process actions. They do not claim live root deployment
qualification. The complete owner packet remains pending host backup, authority
transition and serving integration.

## Authenticated SSH dispatcher

`transport.Device` supplies the device callback for the protocol library. The
reviewed host adapter pins an immutable OpenSSH executable, target, principal,
private-key path/owner, public known-hosts file and digest, and the target's
immutable Python interpreter. Public host keys must be in the Nix store or a
root-controlled directory. It checks identity-file permissions without reading
private-key bytes; OpenSSH loads the key.

Each invocation disables SSH configuration files, agents, interactive prompts,
forwarding, proxy commands and connection reuse. It sends the bundled device
hook and exact plan over authenticated SSH stdin to noninteractive sudo/Python.
The response binds a fresh nonce and the entire request. Input/output sizes and
elapsed time are bounded. Failed or lost responses never trigger a retry;
remote mutation may have happened and must be reconciled using the device
journal. The `observe` action runs only the device's read-only host guard.

This transport assumes the separately approved SSH principal can execute the
reviewed root helper. It neither installs that access nor turns a general sudo
account into a restricted account. Packet approval must cover the delivered
code and every allowed device action.

## Encrypted backup host hook

`backup.Backup` implements the stopped-writer backup on the existing Ubuntu pilot
host. Its plan pins the host boot, deadline, LUKS UUID, USB serial/UUID/sizes,
immutable cryptsetup/PostgreSQL tools and hashes of preserved deployment inputs.
The host adapter must first stop all pilot writers and save the updated serving
and deployment configuration inside the encrypted authority filesystem.

The hook checks the original mapping and mount, clean database shutdown, absent
swap and unmounted destination. It records one-use intent, snapshots filesystem
content/ownership/modes/xattrs in memory, unmounts the source, creates a new
exclusive encrypted copy and verifies its readback. It consumes the inherited
recovery pipe once to open that copy read-only, compares the restored filesystem,
and runs offline PostgreSQL checksum checks. It then closes the copy, unmounts
the USB and remounts the original protected filesystem, leaving services stopped.
A prior attempt or existing destination prevents execution; failures preserve
state for reconciliation. Serving may resume only through the separate reviewed
host step after this hook's result and current postconditions are verified.

Tests exercise transport bounds and response binding, and the backup's real
file-copy/comparison logic with substituted privileged operations. They cover
wrong credentials, mismatched restored content and repeated attempts. These
checks do not qualify actual USB/mount handling or demonstrate restored service
startup. The complete Mako packet still needs authority/grant transition,
isolation/restart checks, safe-stop, backup result probing and serving handoff
integrated and reviewed together before live execution.

## Host issuer-grant transition

`issuer_refresh.Refresh` runs the bounded administrative transition on the
existing Ubuntu pilot host. Before invoking it, the reviewed host adapter must
install the fresh observation/admission records, initialize the upgraded issuer
using its unchanged config, then stop the serving supervisor, Fleet and issuer.
PostgreSQL and both record authorities remain available. This hook does not
perform that deployment or initialize tables by itself.

The plan pins the current host boot/window, exact upgraded issuer/unit, old
configuration bytes/scope, replacement bytes, target and Fleet certificate digest.
It rejects changes to the peer grant, credential lifetime or lifecycle settings.
It verifies the encrypted mount through the existing host storage guard, disabled
swap, stopped writers and systemd's loaded executable. A read-only result probe
can also run after serving resumes; any running issuer must use the pinned binary.

The transition archives its public plan and old/new configurations inside the
encrypted authority filesystem. It obtains semantic digests from the real
issuer's `plan` command instead of reimplementing its typed canonicalization,
then binds those values into a retained request. The approval digest covers the
reviewed host plan and exact input bytes. Fleet's reader uses the same pinned
public trust roots as the issuer, with its own certificate and key.

For `apply` only, a short-lived privileged feeder reads the designated Fleet
identity into an inherited pipe and exits. The administrative issuer child runs
with the issuer UID/GID and no supplementary groups, preserving PostgreSQL peer
authentication. No private bytes enter the parent, arguments, environment or
journal, and no credential file permissions change. This requires Fleet's
inherited-identity support; it is not a fallback to widening key access.

A durable intent precedes the single apply. The exact returned commit must match
read-only inspection before the new config is installed atomically. Lost replies,
partial attempts or mismatches stop without replay or rollback. Probes check the
current config and retained database transition, not merely a completion marker.
A confirmed transition does not mean services are ready, a device is enrolled or
a final backup exists; those remain separate owner-packet steps.

Tests exercise ordering, retained-state reconciliation, peer/lifecycle rejection,
real ephemeral pipe transfer and bounded child I/O. Privileged service/ownership
operations are substituted. Complete host deployment, actual UID/database access,
Ace/Mako isolation and serving/backup integration still require the reviewed
single-launch packet and its rehearsal.

## Host authority deployment

`deployment.Deployment` prepares the existing Ubuntu authority before device
setup. Its plan binds the host boot and bounded window, all six service-unit
preimages, immutable controller/storage guard, exact issuer binary replacement,
observation/admission file preimages and replacements, peer enrollment ID and
nested issuer-refresh plan. File targets are limited to the two readers' config,
records and evidence; the issuer grant change uses the separate refresh hook.

Execution preserves public preimages in encrypted storage, stops guarded serving,
and replaces only the issuer unit's executable. It starts the upgraded issuer
against the unchanged config to initialize additive tables, verifies the actual
process and loopback listener, then stops it before installing reviewed records.
The record readers start before the grant transition. Fleet and the issuer start
only after that transition is confirmed. The existing peer's authenticated
membership response must remain exactly unchanged throughout preparation.

Each mutation has a durable one-use intent. Reconciliation checks current unit
bytes, service state, exact installed records, issuer transition and peer response.
It does not trust a saved success marker. The outer runner must call `safe_stop`
after an attempted mutation fails; cleanup stops children without rolling back
configuration after a potentially committed grant change. Cleanup remains possible
when encrypted storage is unavailable, within the runner's bounded cleanup window.

The module is a host hook, not a standalone enrollment command. Tests exercise
ordering, file preservation, failure after grant commit, refusal to replay and
peer drift with substituted privileged service operations. Live deployment is
still pending. The complete owner packet must integrate this hook with device
setup, isolation/restart checks, verified backup and two-device serving before it
is approved or run. This change does not enroll Mako or alter Ace's deadline.
