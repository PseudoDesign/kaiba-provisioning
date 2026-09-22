# Protected credential storage development

`kaiba-enrollment-storage` prepares a small encrypted filesystem for the
[development enrollment client](device-enrollment-client.md). It reuses the
firmware-HMAC counter KDF, runtime observations, memory protection, partition
guards and one-use journal from the existing storage experiment. The new
filesystem path is software under test; no physical execution or fleet
qualification is claimed.

The operational P-256 key is generated independently by the enrollment client
inside this filesystem. The firmware HMAC derives only the LUKS passphrase,
using the distinct `kaiba:enrollment-storage:luks2:v1` purpose and a new public
nonce. No unlock key enters output, arguments or environment. There is no key
import/export, raw OTP read, signing, generation or usage-write operation.

## Bounded lifecycle

The supported experiment is **create → close → restart → reopen → close**.
There are exactly two successful opens on different kernel boots. Each open
permits at most one HMAC derivation and two volatile lock writes. Close performs
no firmware call. There is no reset, automatic retry, third open, formatting
override, repair mode, reboot command or partition-selection command.

Select and back up a separate disposable 65 MiB GPT partition under an exact
execution packet. Existing test partitions and their journals are not eligible
for reformatting by this helper. It checks the partition UUID, NVMe serial
digest, exact size and sector geometry, mount/holder absence and write access.
Create additionally requires every byte to be zero. No partitioner or media
preparation is included.

Both opening phases require the expected board and boot ID, pinned inspection
boot image, read-only verity root, firmware and kernel. The complete configuration
and runtime binding are included in the public journal binding. Changing the
runtime file does not let a volume reopen under a different profile.

Before HMAC, the helper requires absent swap, disabled core dumps/dumpability
and locked process memory. It records intent, applies READ/GEN/USAGE restrictions,
derives the passphrase and opens LUKS2. It wipes application key buffers and
closes all five volatile operations **before** formatting or mounting the
filesystem. The sole active LUKS keyslot must be slot zero. Reported runtime
lock closure is not behavioral lock qualification.

Create builds an ext4 filesystem with the configured volume UUID. Reopen runs
a read-only filesystem check and rejects an unclean or mismatched filesystem;
it never repairs or reformats it. The fixed mount is
`/run/kaiba-enrollment-storage/volume`, with `nosuid,nodev,noexec` and owner-only
permissions. Client state belongs in its `credentials` directory. These paths
are absent below the empty mountpoint when the filesystem is closed.

Close verifies the current mount, device-mapper UUID and backing relationship,
partition identity, session and journal before unmounting. It records a separate
close intent, unmounts normally, removes the mappings, and only then completes
that phase's journal. It never forces an unmount. A busy mount, cleanup failure,
timeout or uncertain write requires review; do not rerun the command. A reboot
before successful close leaves an incomplete journal and blocks reopen.

This is a two-boot development experiment, not a normal persistent-volume
service. Automatic startup, arbitrary further reopens, power-loss recovery and
shipping permitted-image/credential lifecycle integration remain unimplemented.

## Inputs and package

Build natively:

```console
nix build .#kaiba-enrollment-storage
nix build .#checks.x86_64-linux.enrollment-storage .#checks.x86_64-linux.enrollment-storage-vm
```

The portable package contains `bin/kaiba-enrollment-storage`,
`libexec/mke2fs` and `libexec/e2fsck`, all static executables. Preserve this layout
when uploading a reviewed bundle to the existing inspection system. The helper
pins the complete filesystem-tool bytes at build time, checks them before any
firmware or media mutation, and executes them without a shell or PATH lookup.
It does not require a new boot-image signature to iterate in that development
system. Hardware execution authority is separate from building or uploading.

The storage configuration has the same twelve fields as
[remote storage development](device-secret-storage-development.md), with
`schema_version: kaiba.enrollment-storage-development/v1alpha1`. Supply a
separate closed runtime JSON object with these five fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | `kaiba.enrollment-storage-runtime/v1alpha1` |
| `kernel_release` | Exact expected kernel release |
| `firmware_version` | Exact expected bootloader revision |
| `boot_image_sha256` | Expected signed inspection image, 64 lowercase hex digits |
| `verity_root_hash` | Expected root hash, 64 lowercase hex digits |

The command form is:

```console
kaiba-enrollment-storage create CONFIG.json RUNTIME.json --expected-boot-id UUID
kaiba-enrollment-storage close CONFIG.json RUNTIME.json --expected-boot-id UUID
# After a separately authorized and authenticated restart:
kaiba-enrollment-storage reopen CONFIG.json RUNTIME.json --expected-boot-id NEW_UUID
kaiba-enrollment-storage close CONFIG.json RUNTIME.json --expected-boot-id NEW_UUID
```

Run the enrollment client between open and close. Its public configuration must
include `protected_volume_uuid` matching this volume. A boot-based enrollment
configuration without that binding is rejected. Every initialization/open of
client state checks the pinned directory's actual ext4 mount, writable
`nosuid,nodev,noexec` flags, matching LUKS2 device-mapper UUID and absent swap.
It rejects a plain directory, tmpfs fallback, missing mount or wrong volume.
The process-only software rehearsal may omit this binding explicitly.

## Evidence and remaining work

Each result records its development mode, experiment/source, boot/image/root,
volume and nonce-hash bindings, operation outcome and original firmware
diagnostic. Cleanup failure is separate from the original stop reason. An open
result means the encrypted filesystem remains mounted and its journal awaits
close. Close does not perform fresh firmware lock readback and reports that
distinction. `hardware_qualified` and `production_enrollment` are always false.

The VM uses synthetic firmware with actual LUKS, ext4 and the packaged client.
It covers key/certificate continuity across a VM restart, mount/volume mismatch,
no plaintext fallback, missing memory/swap protection, HMAC and cleanup errors,
incomplete/consumed journals and a busy close. Software tests do not establish
Pi boot-time restrictions, cold power, copied-media rejection or resistance to
privileged development/recovery software.

Before physical use, retain successful native checks and prepare an exact
volume/backup/execution/recovery packet. Authenticated station orchestration and
an explicit isolated development enrollment policy are still needed for the
full device enrollment campaign. Production roots, final debug/EEPROM settings,
CA deployment and FA-01–FA-08 remain independent admission conditions.
