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
