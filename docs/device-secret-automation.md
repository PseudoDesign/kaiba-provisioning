# Device-secret experiment automation

The next Slice B work is a bounded two-boot experiment, reusing the existing
OTP-derived LUKS implementation and keeping human actions at physical and
execution-authority boundaries. The existing owned Pi does not enter the
fresh-board seven-operation workflow. This plan grants no hardware authority.

## Delivery sequence

| Piece | Deliverable and acceptance | Status |
| --- | --- | --- |
| 1. Host capture runner | Passive UART collection, boot-relative observation windows, private durable checkpoints, two-phase ordering, simulation isolation, restart/failure tests, and native packages. | Implemented; exercised with synthetic transcripts and pseudo-terminals, not the Pi. |
| 2. Signed target harness | Reuse the pinned derivation and LUKS integration; implement exact target observations, a disposable volume, key cleanup and approved lock checks; create then reopen across isolated cold boots. | [Implemented in the target harness](device-secret-target-harness.md); software and VM tests only. Image selection, signing and physical operation remain pending. |
| 3. Execution packet and staging | Exact artifacts, selected target/slot/volume, separate authority scopes, backups, one-shot privileged staging/readback, recovery route, capture plan and reviewed report projection. | Planned; complete and review this before live execution. |

The later copied-media demonstration uses the original and a functioning
comparable board. It remains part of the protected-state milestone. Full fleet
admission and qualification of every allowed recovery/image path are not supplied
by two successful target-report captures.

### Reuse and compatibility decisions

Review of `nix-pseudo-design` at
[`82c39216`](https://github.com/PseudoDesign/nix-pseudo-design/tree/82c39216c933a038058de0024b7e5dc085b31d63)
found shared salt, initrd and LUKS installation plumbing. Its checked-in hosts
select `legacy-hkdf-v1`; that path reads the raw OTP key. The firmware-HMAC path
is available in its pinned `nixos-raspberrypi` dependency at
[`d3360e0b`](https://github.com/ams-tech/nixos-raspberrypi/tree/d3360e0b4b9ed0f7ccba5120cecb36dc886864e2).
This is source review, not an observation of those running hosts.

The [target harness](device-secret-target-harness.md) now adapts that code with these explicit decisions and remaining gates:

- Replace its `key_id < num_keys` check with the actual one-based API, matching
  our [one-slot observation](observations/2026-09-17-device-secret-metadata.md).
  The new helper and whole-workflow VM test accept count 1 with slot 1.
- Pin the firmware API and use `kaiba-firmware-hmac-counter-v1`: the upstream
  one-block counter encoding with purpose/NUL/nonce as its public salt. This is
  an explicit experiment scheme; it does not change existing host keyslots.
- Resolve slot suitability and the allowed signed-image/recovery set before
  programming a usable secret. Preserve occupied slots and existing hosts.
- The target module requires raw-read and key-write boot restrictions and adds
  memory-only derivation plus HMAC/signing closure. Generation and usage-write
  lock bits are observed; irreversible negative-write probes are not implemented.

Slot and authorized-image decisions still block selection/signing of a hardware
experiment and secret operations. Software harness and image-constructor work
proceeds without choosing an eligible physical board.

## Bounded hardware session, once prepared and approved

Prepare and test everything before the operator session. One review packet
contains the distinct signing, media-write, and any OTP scopes; existing grants
remain separate and cannot be inferred from a runner plan or a READY response.
Resolve recoverability and the approved disposable storage extent before staging.

The intended sequence is:

1. Perform the approved signing interaction and launch the future fixed,
   privileged staging executor once. It verifies identities, captures backups,
   stages only the reviewed extents, performs independent readback and records
   durable one-use intents. It is not an unrestricted sudo command service.
2. Fit the NVMe once and disconnect network/data paths. The operator confirms
   the Pi has been fully off for ten seconds. Arm passive UART, then apply only
   the separate supply. The target harness creates the disposable encrypted
   record and runs the approved checks.
3. After the first capture, remove all power. Confirm the same isolation and
   off interval, arm the second capture and power on. The same image reopens
   the existing record and repeats the relevant restrictions and cleanup checks.
4. Follow the prepared physical return-to-SD route and verify management/root
   health. Restore host guards as appropriate. Retain private raw evidence and
   prepare the explicit public report from reviewed fields.

Secret programming is a separate, explicitly authorized one-shot operation;
it is never part of repeatable test boot logic. An ambiguous result stops for
reconciliation. Manual power remains operator-reported; UART activity and a new
boot ID cannot establish a cold-power interval or physical network isolation.
Relay automation needs separate qualification and is not a prerequisite here.

## Host runner

Build and check on the current native architecture:

```console
nix build --no-link .#kaiba-device-secret-runner
nix develop --command scripts/check.sh contracts device-secret-runner
```

`kaiba-device-secret-runner` provides `init`, `status`, `rehearse`, and `run`.
Run directories must be absolute, owner-only paths on persistent storage.
Use a new directory per experiment; do not delete journal files to retry.

```console
kaiba-device-secret-runner init --state /absolute/private/run \
  --plan /absolute/reviewed-plan.json --mode simulation
kaiba-device-secret-runner rehearse --state /absolute/private/run \
  --tape /absolute/create-simulation.json
kaiba-device-secret-runner status --state /absolute/private/run
kaiba-device-secret-runner rehearse --state /absolute/private/run \
  --tape /absolute/reopen-simulation.json
```

The tests contain complete generated synthetic plan/tape examples and exercise
the CLI across separate processes. Simulation state cannot be consumed by
`run`, and `rehearse` cannot add fixtures to UART state. Do not present simulated
results as physical observations.

For a future approved hardware session, initialize a separate `--mode uart`
directory from the finalized plan and use `run --state /absolute/private/run`.
It requires a terminal for each off/isolation READY acknowledgement, opens the
two matching UART selectors read-only at 115200 8N1, flushes stale input and
announces `CAPTURE_ARMED` before asking for power. No subsequent powered reply
is required: the valid bound `started` record begins the observation window.

There are separate bounded waiting and observation intervals. All pre-marker
bytes are retained, and a missing marker ends as unknown, not successful boot.
The collector continues for the full observation window after the `complete`
record, so later contradictory events cannot be hidden by early success.
The private raw capture is bounded and synchronized as it is collected.
Terminal settings are restored on normal completion and handled interruptions.
SIGKILL, host power loss and disconnected hardware can prevent cleanup; retained
active state then requires review and never automatically repeats the phase.

The runner performs no signing, media staging, power operation, UART payload
write, SSH login, firmware call, control transaction, or audit submission.
It does not need root merely to collect from an already permitted UART.
The privileged staging executor is a separate planned component.

## Experimental plan and reporting protocol

These are versioned development formats, not additions to fleet admission or
the authority's evidence schemas. The host binds an experiment ID, target
reference, source revision, observed boot-image/root digests, selected one-based
slot, volume UUID and public nonce digest. The plan also contains the two UART
selectors and exact capture bounds. It contains no secret, executable command,
arbitrary actuator or execution-authorized flag. It is not itself an approval.

Each target record is one bounded line beginning `KAIBA_DEVICE_SECRET_EVENT=`,
followed by canonical JSON: sorted keys, compact separators and no extra fields.
It carries those bindings, the event schema, phase, fresh boot UUID, sequence,
check name and boolean `passed`. The event schema is
`kaiba.device-secret-experiment-event/v1alpha1`; the exact fields and order of
required checks are defined in [the runner](../scripts/device-secret/runner.py).
The initial plan schema is `kaiba.device-secret-experiment-plan/v1alpha1`.

The two phases are `create` and `reopen`. Their required sequence is: `started`,
`raw_read_blocked`, `legacy_read_blocked`, `key_write_locked`, `same_input`,
`domain_separation`, `nonce_separation`, `volume_created` or `volume_reopened`,
`hmac_closed`, `signing_closed`, `locks_cannot_clear`, and `complete`.
The target harness must derive the observations from actual checks; merely
echoing expected plan values cannot establish them. Boot-image observations
must use runtime facts rather than embedding a self-referential image hash.

The target image suppresses competing console output during its bounded record
writes; actual UART behavior remains to be observed. The host accepts ordinary console prefixes and CRLF,
but malformed/interleaved records, duplicate fields/events, changed bindings,
failed or missing checks, a repeated boot UUID, byte exhaustion or cleanup
failure stop the run. It does not silently reconstruct a success marker.
Raw captures can contain unexpected target output and remain private; only
the closed result fields are candidates for a later reviewed public projection.

Completed phases retain raw hashes and are verified again when state is opened.
The next unstarted phase can resume after host-process restart. An active phase,
or an interrupted atomic checkpoint, stops for review. The runner has no reset,
skip, force, or automatic retry command. Local state assumes a trusted operator;
its hashes detect inconsistency, not malicious station-root modification.

Results say `matched-target-report`, not hardware-qualified. Both
`hardware_qualified` and `execution_authority` remain false, including for live
UART capture. Independent media readback, physical isolation, slot/image review,
and the [mechanism acceptance conditions](device-secret-feasibility.md#bounded-mechanism-experiment)
remain necessary. Successful software rehearsals do not close Slice B.
