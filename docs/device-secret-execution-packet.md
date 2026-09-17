# Device-secret execution packet and media recovery

The third piece of the [automation plan](device-secret-automation.md) now has
file-only packet construction, a fixed privileged media executor, and a private
report projector. Software tests cover staging, interruption and restoration;
the real Pi/USB enclosure and secret operations have not been exercised by this
change. No selected physical packet, new signing grant, or hardware approval is
included in this change.

## Preparation before the operator session

Use a clean selected source commit. The constructors take explicit inputs and
have no default physical board, slot, disk or signing candidate. An experiment
configuration contains public bindings only; do not put secrets, PINs, private
keys, backup bytes or raw captures in the Nix store.

1. Resolve and retain the slot-suitability review, authorized-image review and
   physical recovery route. The current slot-1 usage value of zero does not prove
   an empty key. Preserve existing contents and usage. The earlier inspection
   image reported no crypto locks, so its continued authorization is relevant to
   the storage boundary. Neither an experiment success nor a disposable record
   resolves that image exposure for fleet use.
2. Build `lib.mkRpi5DeviceSecretExperiment` with the proposed public experiment
   configuration, expected customer-key hash and exact source revision. Build it
   on native ARM. Without a local ARM builder, use the [public candidate export](device-secret-native-export.md)
   workflow. It accepts only the experiment bindings and keeps physical host
   selectors local. The target remains the [bounded harness](device-secret-target-harness.md),
   without generation or OTP usage writes.
3. Build `lib.mkRpi5DeviceSecretSigningPlan` with `system`, that `candidate` and
   `sourceDateEpoch`. This reuses the native single-image signing contract. Its
   reviewed manifest additionally binds the checked experiment configuration.
   Present the exact plan and image for signing approval through the existing
   [native signing procedure](native-offline-handoff.md#separate-single-image-signing-scope).
4. After that approved ceremony, use `lib.mkRpi5VerifiedNativeOfflineSigning` to
   authenticate its approval, result and receipt. An existing signature for a
   different image cannot replace this step.
5. Build `lib.mkRpi5DeviceSecretExecutionPacket` with `system`, `verifiedSigning`,
   `targetSizeBytes`, `host`, `captureSettings`, and store-backed `slotReview`,
   `imageReview`, `recoveryReview` files. This copies public artifacts and review
   text only. The reviews' digests bind their content; they do not prove review
   correctness or grant execution authority.
6. Build `lib.mkRpi5DeviceSecretMediaExecutor { system; packet; }` and
   `lib.mkRpi5DeviceSecretReport { system; packet; }`. Retain their exact immutable
   store paths using persistent `--out-link` locations (GC roots), including the
   packet and signing outputs. A text copy of a store path does not prevent garbage
   collection. Review the generated `review.md`, `packet.json`, and the executor's
   `describe` output before authorizing any device operation.

[The composition example](../examples/device-secret-handoff.nix) exposes the unsigned
candidate/signing plan before a ceremony, and the packet/executor/report only
after the authenticated public signing results are supplied.

The packet's `host` object has exactly these fields:

| Field | Required observation |
| --- | --- |
| `hostname`, `machine_id_sha256` | Hostname and SHA-256 of the 32 hexadecimal `/etc/machine-id` characters, excluding newline |
| `disk_by_id`, `enclosure_by_id` | Distinct `/dev/disk/by-id/` selectors resolving to the same whole USB disk |
| `disk_serial`, `enclosure_serial` | Exact `ID_SERIAL_SHORT` and `ID_USB_SERIAL_SHORT`; disk serial must match the target configuration's hash |
| `usb_vendor`, `usb_product` | Exact four-digit lowercase USB vendor/product IDs |
| `state_directory` | A unique `/var/lib/kaiba-device-secret-NAME` directory on an independent persistent host filesystem |

The closed `captureSettings` object supplies `uart_by_id`, `uart_by_path`,
`idle_timeout_seconds`, `observation_seconds`, and `maximum_bytes`, using the
existing runner's bounds. The packet derives all other capture bindings from
its signed input and experiment configuration; it does not accept independently
supplied boot/root hashes.

## Exact media scope

The authenticated native handoff supplies the outer FAT with `boot.img`,
`boot.sig`, and `boot_ramdisk=1`, plus the verity root/tree and original three
partition definitions. The packet adds one 65 MiB Linux-LUKS partition after
the aligned hash partition. Its PARTUUID is the target configuration's distinct
`partition_uuid`. Both GPT copies are regenerated and checked on a sparse regular
file. No device node is opened during a Nix build.

The six writes are primary GPT, 128 MiB outer boot FAT, root bytes, hash-tree
bytes, the zeroed 65 MiB experiment extent, and secondary GPT at the actual disk's
last sectors. The packet lists exact offsets, lengths and SHA-256 values. Unwritten
gaps and partition tails are untouched. The target harness requires the entire
disposable extent blank; it will not erase or adopt an existing volume itself.

All six spans are backed up before staging, including both previous GPT copies
and all existing bytes overlapped by the new experiment extent. Backup hashes
are checked against independent source readback. A completed backup is checked
again before every write action. Backups are private, root-owned regular files,
mode `0600`, under a `0700` directory on ext4, XFS or Btrfs. They are never part of
Git, the packet, a Nix derivation, or the public report.

Restoration returns the bytes present immediately before this staging attempt.
It cannot recover historical data already lost before that backup. In particular,
the old lost filesystem preimages are not replaced by the retained verity-test
block backups. Fresh full-span backups remain mandatory.

## One bounded privileged executor

`kaiba-device-secret-media` accepts one verb only. Its packet and dependencies
are fixed in its Nix wrapper; there are no device, offset, payload, command,
force, reset or retry flags.

| Command | Effect |
| --- | --- |
| `describe` | No hardware access; prints packet and executor/runtime digests for review |
| `status` | Reports which private intent/completion records exist; presence is not a new pass claim |
| `backup` | One authorized full-span backup, with private-file and independent device readback |
| `stage` | Uses or creates that backup, checks unchanged prestate, then writes and reads back the six spans once |
| `verify` | Read-only full-span comparison after completed staging and before target boots change the disposable extent |
| `restore` | Explicit one-use restoration of all six preimages, also available after an uncertain partial stage |

The executor checks root ownership, host identity, both disk selectors and USB
identifiers, whole-disk geometry and current attachment sequence. It rejects
mounts in visible namespaces, swap and holders. Automount must already be stopped
and runtime-masked, and the disk must start read-only. The executor changes neither
service configuration nor mount state. It does not open the Pi, UART, network,
firmware or signing interfaces.

Each action has a durable exclusive intent written before it starts. An action
with an intent cannot run again, even after process or host restart or renewed
authority. Stage writes payloads first and GPT last, with synchronization; that is
not an atomic disk transaction. Every exit from the write window attempts to
restore the read-only guard. Independent verification opens a fresh exclusive
read descriptor and flushes/invalidate caches before hashing every complete span.
SIGKILL, host power loss, removal, or kernel/device failure may prevent cleanup;
an absent completion means stop and reconcile. No failure triggers automatic
restoration or a second write attempt.

Before the session, the operator prepares the automount guard and the private
state directory under the reviewed host procedure. The same directory holds a
root-owned `0600` `authorization.json`, installed only after actual review:

```json
{
  "schema_version": "kaiba.device-secret-media-authorization/v1alpha1",
  "packet_sha256": "REPLACE_FROM_DESCRIBE",
  "executor_sha256": "REPLACE_FROM_DESCRIBE",
  "reviewer_reference": "reviewer:NAME",
  "approved_at": "REPLACE_WITH_ACTUAL_UTC_APPROVAL_TIME",
  "expires_at": "REPLACE_WITH_UTC_EXPIRY_WITHIN_24_HOURS",
  "actions": ["backup", "stage", "restore"]
}
```

This is a local execution record under a trusted root/operator, not a control-plane
approval, signature, or independent audit authority. Creating this JSON does not
obtain the user's approval. The executor checks its exact packet and source/runtime
binding, action list, attribution and validity period. The intended single `stage`
invocation needs both backup and stage authority. Restoration is separately
invoked when authorized, and expiry requires renewed approval rather than a retry.
Signing, target secret calls, physical power/media changes and publication remain
separate scopes; this record covers none of them.

## Physical session and report

After approved staging/readback, fit the NVMe once. For each of the two boots,
confirm ten seconds fully off and disconnected Ethernet/PoE/USB data, arm the
[passive runner](device-secret-automation.md#host-runner), then apply only the
separate supply. The runner detects the bound start event and does not require
another powered acknowledgement. Recover by the reviewed physical removal of
NVMe and inspection-SD route, not the unavailable boot menu. Verify inspection
root health before restoring host guards. Keep the enclosure detached when
restoring automount.

Run `kaiba-device-secret-report /private/capture-state /new/private-draft.json`
as the capture owner. It checks the runner's retained plan, result and raw-capture
hashes, and requires exact agreement with the packet. It produces a new `0600`
report with source/image hashes, mode, completed checks and capture hashes/lengths.
It omits raw serial text, device/enclosure identifiers, nonce, volume UUID and
boot IDs. Simulation remains simulation. Interrupted captures remain in need of
review; absent checks are not invented. Physical isolation, media readback and
slot/image suitability remain separate review items, and hardware qualification,
fleet admission and publication are never asserted by this command.

Review this private draft before publishing an explicit projection. Keep the
original raw evidence and backups on malak as previously requested.

## Checks and remaining gate

```console
nix develop --command scripts/check.sh contracts \
  device-secret-execution device-secret-execution-vm
```

Regular-file tests cover GPT checksums/partition bindings, all-span restoration,
untouched gaps, interrupted intents, authorization mismatch/expiry, corrupted
backups, changed prestate, short writes, readback failure, duplicate inputs and
report redaction/simulation isolation. A Linux loop-device VM rejects mounted media, exercises the
production exclusive write/readback path and read-only guard, and restores a
pre-existing ext4 filesystem with a test record, with an explicitly
separate synthetic selector. It does not qualify USB identity or the physical
enclosure. Native ARM CI additionally builds the new experiment signing plan.

The synthetic outputs from these software checks are not a selected physical packet.
That requires fresh inventory, the three substantive reviews, exact native build
and signing results, and separate execution authority. The current undefined
slot and older inspection image remain unresolved inputs. No secret has been
read, derived, generated or qualified by these software checks. Copied-media
confidentiality still needs the original and a functioning comparable board.
