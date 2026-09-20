# Remote LUKS development

The storage development helper creates an encrypted private test record, closes
the mapping, and reopens and authenticates that record after an authenticated
soft reboot. It runs from RAM on the existing signed inspection system. Updating
the helper requires no new boot-image signature. The native package, bounded host
runner and synthetic-firmware LUKS VM tests are implemented; physical storage
execution and qualification remain pending.

This is the next development step after the [remote HMAC checks](device-secret-development.md).
It reuses the [counter KDF and LUKS implementation](device-secret-target-harness.md#reuse-and-derivation-decision).
It does not implement a new unlock scheme or modify the qualification harness's
acceptance rules. The [rejection-evidence decision](device-secret-rejection-evidence.md)
remains open independently of storage development.

## Bounded operations

Only a separately selected, backed-up, disposable **65 MiB partition** is eligible.
Its GPT PARTUUID, disk-serial digest, exact byte size and 512-byte sector size are
checked before writes; it must be writable, unmounted and have no device-mapper
holders. No device path, arbitrary extent, existing volume, format-only command,
partitioner, restore or retry switch is exposed.

The helper accepts `create` or `reopen` with an exact configuration and expected
boot ID. It validates board identity, signed boot image and a read-only verity
root. Network access is permitted for this development path. The qualification
harness still requires network isolation. Memory is locked, swap must be absent,
and core dumps are disabled before any secret operation.
The kernel's `crypt` and `linear` device-mapper targets must already be available;
a read-only capability query rejects missing targets before on-media intent or
firmware operations. Module preparation belongs to the reviewed bench setup.

Each phase performs at most two HMAC derivations and two volatile lock writes:

1. Verify slot count, device-key type and the selected usage; reject already
   closed HMAC/signing operations. Record an on-media intent before mutation.
2. Apply and read back READ/GEN/USAGE runtime locks. Derive the LUKS passphrase
   and private-record MAC key using the existing distinct purposes and public
   per-volume nonce.
3. Create a LUKS2 container and random authenticated private record, or reopen
   the same container read-only and authenticate the record. Creation requires
   the entire partition to be zero beforehand. Reopen never reformats it.
4. Wipe application key buffers, close all five runtime locks and read back their
   status. Complete the journal and remove all mappings. A cleanup failure fails
   the operation and stops the host session.

The same shared storage code supplies the 1 MiB journal area, 64 MiB LUKS area,
fixed mapping names and interrupted-attempt detection. The journal binds the
complete configuration, boot-image digest and verity root. Its create/reopen
records require different boot IDs. Development uses its own configuration
schema, so its journal cannot be substituted for a qualification journal.
Removing the helper's temporary linear mapping uses the pinned libdevmapper's
bounded busy-device handling (at most 25 waits of 200 ms). This handles transient
udev readers during teardown only. A persistent holder still fails cleanup;
deferred deletion and retries of firmware, format or unlock operations are not used.

There is no private-key read, signing, generation, OTP/usage write, lock-clear
attempt or post-closure crypto probe. Runtime lock status is recorded separately
from behavioral lock qualification. `hardware_qualified` and
`lock_rejection_qualified` are always false, including after successful storage
verification. The existing failed HMAC rejection record remains failed.

## Build and native export

```console
nix build --no-link .#kaiba-device-secret-storage-session
nix develop --command scripts/check.sh contracts device-secret-storage-development device-secret-storage-development-vm
```

Native ARM CI exports `device-secret-storage-development-<commit>-aarch64-linux`
with a standalone static musl executable and `build.json`. The manifest binds the
repository, source commit, CI run/attempt, architecture, store path and executable
SHA-256. Verify those bindings and successful checks before selecting a helper
for a private session. No selected board, drive or nonce is sent to CI.

The helper statically links libcryptsetup, OpenSSL, device-mapper and Jansson.
The package privately renames Jansson's `json_object_get` symbol to avoid its
static-link collision with libcryptsetup's json-c dependency. The qualification
package retains its original library ABI. Tests check that the production helper
has no dynamic loader or synthetic transport and exercise the actual static
storage implementation with separately compiled synthetic firmware in a VM.

## Prepare a storage session

The host command is `kaiba-device-secret-storage-session`. Its closed
`kaiba.device-secret-storage-session/v1alpha1` configuration contains the
[development session fields](device-secret-development.md#one-reviewed-development-session)
with these exact differences:

| Field | Required value |
| --- | --- |
| `schema_version` | `kaiba.device-secret-storage-session/v1alpha1` |
| `checks` | `["create", "reopen"]`, in that order |
| `max_runs`, `max_reboots` | `2`, `1` |
| `slot_id` | `1`, separately reviewed as suitable for the experiment |
| `helper_sha256` | Digest of the verified native storage helper |
| `storage` | The closed configuration below |

`storage` uses the existing [12 target configuration fields](device-secret-target-harness.md#image-and-public-bindings),
but its schema is `kaiba.device-secret-storage-development/v1alpha1`.
It contains `scheme`, `experiment_id`, `target_reference`, `source_revision`,
`volume_uuid`, `partition_uuid`, `board_serial_sha256`, `disk_serial_sha256`,
`nonce_hex`, `slot_id` and `expected_usage`. Board/slot/usage must agree with the
outer session. Use the existing `kaiba-firmware-hmac-counter-v1` scheme and a new
random public 32-byte nonce. Initialization never selects or prepares a drive.

After review of the exact artifact, slot, partition, backups and bounded actions:

```console
kaiba-device-secret-storage-session init \
  --state /absolute/private/storage-session --config /absolute/private/storage-session.json
kaiba-device-secret-storage-session create \
  --state /absolute/private/storage-session --helper /absolute/private/verified-storage-helper
kaiba-device-secret-storage-session reboot --state /absolute/private/storage-session
kaiba-device-secret-storage-session reopen \
  --state /absolute/private/storage-session --helper /absolute/private/verified-storage-helper
```

Initialization is local and grants no authority. The runner permits precisely
create → authenticated soft reboot → reopen. It reuses strict SSH authentication,
image/firmware/kernel/verity/power preflight, and UART authentication of the new
SSH key. A separate durable host intent precedes each action. It uploads the
hash-checked ARM64 helper and public configuration to a private root-owned tmpfs
directory. The helper rechecks the boot ID and claims a boot-local one-shot marker.

Timeouts, interruption, malformed output, unexpected stderr, incomplete cleanup
or a failed result stop all further actions. `status` remains available. Neither
resetting a directory nor replacing a configuration authorizes a retry. Preserve
the journal and evidence for reconciliation. A fresh session cannot reopen an
unfinished on-media attempt; recovery is a separate reviewed operation.

Results use `kaiba.device-secret-storage-result/v1alpha1`, with the boot, image,
root, volume and nonce-hash bindings, phase, outcome, stop reason, storage and
lock-cleanup booleans, and the firmware outcome/tag/errno captured before cleanup.
Keys, derivation outputs and record plaintext never enter output, argv, environment
or host files. The host stores only these results and operation metadata. The VM
fixture reports `mode: synthetic-development`, which the production host runner
rejects. These records assume a trusted operator; they are not independent audit
evidence.

## Before physical use

Finish outstanding media restoration and host cleanup first. Establish the
[management SD boot and recovery route with NVMe installed](device-secret-development.md#permanent-bench-setup-next-stages),
then prepare the reserved test partition and its backup under an exact execution
packet. This software does not change boot configuration, install itself, prepare
media, or operate hardware automatically.

Remote create/reopen can establish development functionality across a soft
reboot. Offline cold-power reopen, boot-time restrictions, behavioral lock tests,
authorized recovery images and copied-media confidentiality on a functioning
comparable board remain separate qualification work. Keep development iteration
on the existing inspection system; sign a qualification candidate after the
implementation stabilizes.
