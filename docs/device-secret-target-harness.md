# Device-secret target harness

This implements the target side of the [two-boot experiment](device-secret-automation.md).
It is experimental software, with synthetic firmware tests and real LUKS software
integration tests. It has not run on the Pi. Firmware-HMAC feasibility, copied-media
confidentiality and fleet admission remain pending. The existing native offline
candidate does not enable this harness.

## Scope and execution boundary

`kaiba-device-secret-target` is a bounded secret-operation and disposable-storage
test. It is separate from the read-only capabilities/metadata tools. Its execution
needs the future exact review packet: selected board and slot, authorized image
set, signing, storage extents, backups, recovery and permitted firmware calls.
Building the helper, enabling a Nix module, a host-runner plan, or `READY` does not
provide that authority. Do not run it on the inspection Pi.

The executable has no OTP generation, raw OTP write, usage write, key export,
arbitrary mailbox, reset, retry or force operation. It does issue negative secret
reads, HMAC and signing calls, volatile lock changes and bounded media writes
when explicitly launched in the prepared image. Unexpectedly returned secret
bytes are discarded and wiped. No production identity or existing LUKS volume
is used.

The current inventory reports slot 1 with undefined usage. That does not establish
slot suitability or whether a usable key is present. Reviewing the selected slot
and the allowed older/recovery images remains necessary before selecting a board
or authorizing secret operations. No such selection is made here.

## Reuse and derivation decision

The experiment chooses `kaiba-firmware-hmac-counter-v1`, adapting the one-block
`firmware-hmac-v1` construction from
[`nixos-raspberrypi` d3360e0b](https://github.com/ams-tech/nixos-raspberrypi/blob/d3360e0b4b9ed0f7ccba5120cecb36dc886864e2/pkgs/raspberrypi/rpi-otp-derived-key.nix).
The implementation uses C buffers and libcryptsetup rather than shell variables
or key files. It preserves the upstream counter-KDF byte encoding; a known-message
test checks that encoding independently. It does not migrate the existing hosts'
legacy keyslots.

For a 32-byte random public nonce:

```text
salt = ASCII(purpose) || 00 || nonce
message = 00000001 || ASCII("rpi-otp-derived-key:firmware-hmac-v1:raw") || 00
          || SHA256(salt) || 00000100
key = firmware HMAC-SHA256(selected slot, message)
```

The LUKS purpose is `kaiba:protected-state:luks2:v1`; the private-record MAC uses
`kaiba:protected-state:canary:v1`. A third purpose and an altered nonce test
separation. The versioned scheme is an explicit change from the earlier proposed
direct `purpose || NUL || nonce` HMAC. Production profile adoption is still a
decision gate. Neither a public nonce nor a board serial is a replacement secret.

The selected slot is one-based: `1 <= slot <= reported count`. This initial
experiment accepts only slot 1 because the two legacy read requests are bound to
its mapped words. Expected usage may be undefined (0) or user-defined (8–14), and the actual
value must match. Undefined usage does not mean blank or eligible: reuse needs
the same separate slot/ownership review. The harness does not require an OTP
usage write just to run an experiment. Reserved usage, missing locks, unsupported
operations and malformed replies stop execution.

## Image and public bindings

The flake exports `lib.mkRpi5DeviceSecretExperiment`, taking `experiment`,
`expectedCustomerKeyHash`, and `sourceRevision`. It reuses the native ARM signed
boot/dm-verity image construction and returns unsigned artifacts. There is no
default selected experiment image, new signing grant or media handoff. The
signing/staging packet is the next piece of work.

The [September EEPROM candidate](rpi5-eeprom-crypto-update.md) supplies the
upstream-declared fine-grained locks. Its signing, installation and physical
qualification remain pending; the old May candidate predates these locks.

The default-disabled `device-secret-experiment` module enables boot-time
`lock_device_private_key=1` and `lock_device_key_write=1`. It retains a read-only
verified root, disables development access and network time, requires no swap or
core dumps, uses volatile logging, and runs one non-restarting service after the
existing boot-evidence check. It suppresses competing console output during
records; the host still rejects malformed/interleaved frames.

The closed `kaiba.device-secret-target/v1alpha1` configuration contains:

| Field | Binding |
| --- | --- |
| `schema_version`, `scheme` | Exact supported versions |
| `experiment_id`, `target_reference` | Public experiment identifiers |
| `source_revision` | Image source commit; must agree with the image constructor |
| `volume_uuid`, `partition_uuid` | Distinct canonical UUIDs for the new LUKS volume and disposable partition |
| `board_serial_sha256` | SHA-256 of the Pi's 16 lowercase hexadecimal serial characters, excluding its final NUL |
| `disk_serial_sha256` | SHA-256 of the sysfs disk serial after trimming trailing space, tab and newline |
| `nonce_hex` | Exactly 32 public bytes in lowercase hex |
| `slot_id`, `expected_usage` | Reviewed slot and exact required existing usage |

There is no execution-authorized flag. Configuration validation uses
`--check-config CONFIG`, which performs no firmware or media operation.
The image service uses the distinct `--run-reviewed-experiment CONFIG` command.

At runtime the helper observes the bootloader's signed/boot-image properties,
the actual mounted read-only verity mapping and root hash, board serial and a
fresh kernel boot UUID. Whole-image and root digests are observed, avoiding an
image hash embedded in itself. The host compares those observations with its
independent finalized plan. Software link-state checks supplement the operator's
physical isolation record; they do not prove a cold-power interval or absence
of every network path.

## Disposable storage and interruption handling

The target requires one unmounted 65 MiB partition with 512-byte logical sectors,
selected by PARTUUID and parent disk serial. It rejects existing holders and
mounted media. The first MiB contains four 4 KiB journal blocks; a temporary
linear mapping confines LUKS to the remaining 64 MiB. The entire partition must
be zero before the first creation. Preparing this extent and any GPT change is
part of the separately reviewed staging executor, not this helper's discovery.

The journal binds the canonical configuration, observed boot image/root hashes,
stage and boot UUID. Every transition requires a blank destination block,
write, fsync and readback. Creation and reopening each have a separate intent
and completion block. Creation uses LUKS2/AES-XTS with a random independent volume
key and one keyslot; its 256-bit derived passphrase uses a fixed PBKDF2 cost for
this bounded experiment. That is not a production passphrase policy.

Inside the opened mapping the helper writes a random private test record with a
separately derived HMAC. It verifies that authenticated record immediately and
again after reopening read-only on a different boot. Neither its plaintext nor
a reference derivation output is retained outside the encrypted payload. All
mappings must close successfully. A boot-local one-use marker and persistent
intent blocks prevent same-boot repetition, partial-format retries and a third
experiment boot. An interrupted or inconsistent journal needs review; it is
never reformatted automatically.

This journal is an interruption guard under a trusted prepared image. It is not
an offline rollback mechanism, authenticated audit log or admission authority.
Independent staged-media readback and the later original/comparable-board test
remain required.

## Firmware checks and evidence limits

The helper uses the pinned mailbox layouts through the explicitly selected
`/dev/vcio` endpoint. It has a fixed operation set and no transport fallback.
All process memory is locked before secret calls; swap and core dumps must be
disabled. Key material stays in process/library memory, is passed directly to
libcryptsetup, and is explicitly cleared. No secret is sent through argv,
environment, temporary key files, the Nix store, serial records or reports.
This does not establish erasure of firmware/kernel internal buffers or protection
against privileged code, physical RAM access or an authorized kernel compromise.

The event sequence matches the host runner. Its meanings are:

- `raw_read_blocked`: a valid crypto private-key rejection with the specific
  firmware `KEY_LOCKED` error. Transport failure or unsupported operations do not
  count as lock evidence.
- `legacy_read_blocked`: explicit rejection from `GET_USER_OTP`, private block 3,
  words 0–7, plus the documented whole-mailbox rejection of the dedicated legacy
  private-key read. The pinned driver's `EINVAL` is accepted for that dedicated
  request only alongside the other rejection and lock/positive-operation checks.
  The exact reply assumptions remain to be tested on the selected firmware;
  a differing encoding stops this experiment rather than counting as a pass.
- `key_write_locked`: observed generation/usage lock bits before derivation.
  It does **not** attempt irreversible generation or usage writes and does not
  claim behavioral qualification of those write operations.
- `same_input`, `domain_separation`, `nonce_separation`: in-memory comparisons
  of successful firmware derivations, with no output values logged.
- `volume_created` / `volume_reopened`: successful real LUKS operation and
  private-record authentication, followed by closing the decrypted mapping.
- `hmac_closed`, `signing_closed`: operations succeed in the permitted phase,
  then return the specific locked error after closure.
- `locks_cannot_clear`: a clearing request leaves every required lock bit set.
  Failure triggers a bounded attempt to close locks and stops the run.

The legacy mapping and error conventions come from the pinned
[Pi 5 device tree](https://github.com/raspberrypi/linux/blob/c8c7494100e99ee05b11aaa4f0588a223a63d1af/arch/arm64/boot/dts/broadcom/bcm2712-rpi.dtsi),
[nvmem driver](https://github.com/raspberrypi/linux/blob/c8c7494100e99ee05b11aaa4f0588a223a63d1af/drivers/nvmem/raspberrypi-otp.c),
[mailbox driver](https://github.com/raspberrypi/linux/blob/c8c7494100e99ee05b11aaa4f0588a223a63d1af/drivers/char/broadcom/vcio.c), and
[EEPROM history](https://github.com/raspberrypi/rpi-eeprom/blob/2fee426f27b6c54d3f5b6f36efd9a2fe1286a45d/firmware-2712/release-notes.md).

A failed check emits a diagnostic line before its failed event. It contains the
fixed check name, last firmware outcome, most recent mailbox tag and that call's
numeric `errno` (zero when the call did not fail). These transport fields help
distinguish permission, invalid-request and timeout errors; they are not proof of
a firmware lock. Diagnostics issue no additional mailbox request and include no
request/response buffers, keys or derived outputs. The helper still stops and
performs its bounded cleanup after a failed check; another attempt requires review.

## Software verification and next gate

```console
nix develop --command scripts/check.sh contracts \
  device-secret-target device-secret-target-eval device-secret-target-luks-vm
```

Tests use a separately built synthetic firmware transport. Its binary identifies
itself as a test and emits `KAIBA_DEVICE_SECRET_TEST_EVENT`, which the production
reader does not recognize as evidence. The VM test explicitly adapts these
fixture records to check encoder/reader compatibility. No runtime switch can
enable this transport in the production binary.

Software tests cover the one-slot case, counter encoding, typed rejections,
malformed/short replies, unexpected key bytes, closed configuration, actual LUKS
creation and reopening across VM restarts, wrong simulated board key, closure
failures, consumed intents and removal of mappings. They do not exercise real
firmware or establish copied-media protection on comparable hardware.

The [execution-packet constructors and one-shot staging/recovery executor](device-secret-execution-packet.md)
now prepare the file-only handoff. Next, resolve slot/image suitability, select the
exact immutable image and present its concrete execution packet and backup scope. Physical mechanism results and any failed assumptions
then determine the feasibility decision described in the
[active mechanism plan](device-secret-feasibility.md#bounded-mechanism-experiment).
