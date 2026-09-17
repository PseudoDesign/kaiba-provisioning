# Device-secret feasibility: pending physical investigation

This is the protected-storage mechanism investigation in
[Slice B](implementation-staging.md). Offline-image work proceeds independently.
No device secret has been programmed, read, derived or qualified by this change.
Persistent state and copied-media protection remain unimplemented.

## Pinned inputs and established software work

| Input | Selected source | What remains to observe |
| --- | --- | --- |
| Pi platform | `nixos-raspberrypi` `7e39508bcf9c1da82cf11c1e22f74f9d9fd0fe10` | Exact running kernel and mailbox device availability/permissions |
| EEPROM candidate | `rpi-eeprom` `05d94be4554ce44a057bfce8d0dd37d951703dab`, Pi 5 image `2026-05-26`, revision `086b83e3` | Installed EEPROM identity and actual API/lock behavior |
| Firmware crypto | `raspberrypi/utils` `292dbe7e35296e556d839a0b9ae2ca957ac8c961` | Hardware support for every required operation |

The EEPROM release history contains the crypto API, key usage, raw-OTP lock
fix and invalid-HMAC-key fix. That is source support, not a board result. The
separate boot-firmware bundle revision is not an EEPROM version observation.
The platform's general utils package lacks GnuTLS and can omit the crypto
subdirectory. `kaiba-rpi5-fwcrypto` explicitly builds that pinned subdirectory
with GnuTLS, including its library and upstream CLI.

Sources: [pinned EEPROM history](https://github.com/raspberrypi/rpi-eeprom/blob/05d94be4554ce44a057bfce8d0dd37d951703dab/firmware-2712/release-notes.md),
[pinned crypto documentation](https://github.com/raspberrypi/utils/blob/292dbe7e35296e556d839a0b9ae2ca957ac8c961/rpifwcrypto/README.md),
[API definitions](https://github.com/raspberrypi/utils/blob/292dbe7e35296e556d839a0b9ae2ca957ac8c961/rpifwcrypto/rpifwcrypto.h).

## Non-secret baseline

Build on the station or native ARM builder; building performs no hardware I/O:

```console
nix build .#kaiba-device-secret-capabilities .#kaiba-rpi5-fwcrypto --no-link
nix develop --command scripts/check.sh contracts device-secret-capabilities
```

On the selected Pi, during an authorized observation session, the dedicated
probe can query the count and one explicitly selected, one-based slot:

```console
kaiba-device-secret-capabilities
kaiba-device-secret-capabilities --key-id 1
```

The example selects slot 1 only for metadata observation. It does not establish
that this slot is free or suitable for Kaiba; preserve any existing usage.
The default probe links only count/status/usage query APIs. It cannot generate keys,
read a public or private key, derive, sign, change usage, or change locks.
Unavailable/unsupported results remain unavailable; all responses retain
`feasibility: pending`. The upstream CLI is broader and is not the default
probe. Its presence does not authorize its operations.

Record the board class/revision, current signed-image digest, installed EEPROM
version/hash, kernel release, helper revision, permissions on `/dev/vcio_crypto`
and `/dev/vcio`, and probe result. Inspect only those public identity and
configuration fields. Do not run OTP dumps, private-key commands, raw mailbox
commands, or broad firmware-log collection. Do not infer support on another
board class or key ID. The library prefers `/dev/vcio_crypto` and falls back
to `/dev/vcio`; record the paths available in the actual environment.

### Pinned-kernel metadata limitation

The pinned Linux source `c8c7494100e99ee05b11aaa4f0588a223a63d1af`
([restricted mailbox allowlist](https://github.com/raspberrypi/linux/blob/c8c7494100e99ee05b11aaa4f0588a223a63d1af/drivers/char/broadcom/vcio.c))
permits count and status through `/dev/vcio_crypto`, but omits the library's
`GET_CRYPTO_KEY_USAGE` tag `0x0003009c`. The pinned library falls back to
`/dev/vcio` only when opening the restricted node fails, not when an ioctl is
rejected. When the restricted node is available, a successful count/status
with failed usage therefore does not establish lack of firmware support.
The probe must retain its partial result and unknown usage.

The assumption that these two pins provide a complete slot inventory through
the default endpoint is false. A kernel patch is unnecessary for the metadata
observation: explicitly select the dedicated companion below during an
authorized read-only session. Until usage is observed, slot selection and secret
programming remain blocked. This compatibility limitation does not block native
offline boot experiments and does not decide HMAC or storage feasibility.

### Explicit metadata-only companion

The same package includes `kaiba-device-secret-metadata`. It requires root and
opens only the existing `/dev/vcio` node. It does not change its permissions or
try another interface. This is a deliberate operator selection, never a fallback
from a failed default probe:

```console
sudo kaiba-device-secret-metadata --key-id 1
```

Only three fixed mailbox tags are implemented: count (`0x0003008f`), slot status
(`0x00030090`), and slot usage (`0x0003009c`). The only optional input is a
one-based slot ID. No arbitrary device path, tag, message, key read, cryptographic
operation, programming or lock command is accepted. Other `GET`-prefixed firmware
tags can generate keys or perform cryptography; their names do not make them
read-only. Opening the mailbox read-only also does not itself restrict ioctls;
the companion's fixed query set provides that restriction.

The companion uses the pinned library's message layout without linking its
general crypto implementation. It checks the node, response headers, lengths,
error bits and value bounds. Rejected queries are not retried. Failed fields
remain null or unavailable, and `feasibility` remains `pending`. JSON and
`--version` identify `transport: vcio-metadata-only`; the default probe identifies
`rpifwcrypto-default`. Record the selected transport and actual node permissions
with the baseline. A usage value of zero does not prove that a slot is blank.
Preserve existing slot contents and usage.

The companion is statically linked using a same-CPU musl build so it can run
from volatile storage on the existing inspection image. It needs no new kernel,
boot image, signing ceremony or persistent installation. Native ARM CI runs the
contract tests and exports the executable with its source commit, platform,
store path and SHA-256 in a `device-secret-metadata-<commit>-aarch64-linux`
artifact. Bind the downloaded artifact to the expected repository, successful
CI run and exact source revision, verify its hash, and use the already-verified
inspection SSH identity before executing it. CI establishes build and software
behavior only; physical metadata results must be recorded separately.

Focused checks exercise exact query buffers/order, root and device checks,
rejected queries, malformed replies, unavailable fields and command rejection.
They do not call hardware or establish secret/lock behavior. No secret operation
is authorized by building, downloading or running this metadata companion.

## Recorded read-only inventory

The [2026-09-17 observation report](observations/2026-09-17-device-secret-metadata.md)
and [public JSON projection](observations/2026-09-17-device-secret-metadata.json)
record successful count, status and usage queries on the owned development Pi 5
through the metadata companion. The metadata-access blocker is resolved without
a kernel patch. Slot suitability, the authorized-image boundary, HMAC and lock
behavior, and protected-storage qualification remain pending.

## Proposed mechanism and authority gate

Use a dedicated device key only after reviewing the slot's current status,
usage and the exact secret-programming operation. Never overwrite an occupied
slot or repeat customer-root ownership programming. Key generation and OTP
usage writes need a separate irreversible-action plan; neither is included in
the read-only probe.

The proposed derivation message is the ASCII domain
`kaiba:protected-state:luks2:v1`, one NUL separator, and exactly 32 random public
per-volume nonce bytes. Store the nonce as public volume metadata. It is not a
secret, and neither the board serial nor a disk ID replaces the OTP secret.
Pass the 32-byte HMAC output directly to a future LUKS2 keyslot operation through
a private descriptor; LUKS generates its own independent volume key. No derived
value belongs in argv, environment, files on removable media, logs, receipts,
the Nix store, or Git. There is no LUKS implementation in this PR.

The signed early-boot experiment must set `lock_device_private_key=1` and
`lock_device_key_write=1` before untrusted userspace. After the needed derivation,
close HMAC and unused signing operations. READ/GEN/SIGN/HMAC/USAGE locks reset at
reboot; normal and recovery images must reapply them. Upstream does not claim
protection against privileged code or an authorized-kernel compromise.

Before any usable secret is programmed, resolve the authorized-image set.
Older images under the development customer root can still boot and may
provide root-equivalent development access or omit these locks. Either use a
separately approved isolated sacrificial board for mechanism tests or explicitly
resolve that image/recovery exposure. The offline rollback decision does not
waive the storage boundary. No production identity is used in this experiment.

## Bounded mechanism experiment

Prepare a signed test image and an exact operation/slot plan after the baseline.
Use disposable secret material. Disable swap, core dumps and persistent logs;
keep result buffers in locked memory and clear them after comparison. Negative
secret-read probes must discard and clear unexpectedly returned bytes without
printing or retaining them. Such a return is a failure, never an evidence value.

| Case | Required observation |
| --- | --- |
| API and selected slot | Exact pinned running platform supports the selected metadata and HMAC operations; slot usage is compatible. |
| Boot read/write restrictions | Signed configuration applies raw-read, generation and usage-write restrictions before the experiment. |
| Purpose and nonce separation | Same input reproduces the result; changing domain or nonce changes it. Compare in memory and emit only booleans. |
| Cold-boot repeatability | A disposable authenticated-encryption canary created with the derived test key reopens after an offline cold boot. Retain ciphertext/public nonce only, never a reference HMAC output. |
| Operation closure | HMAC and unused signing succeed only in the permitted phase and reject after closure. |
| Raw-read paths | Both crypto private-key access and applicable legacy user-OTP read paths reject after boot locks. Capture return codes only. |
| Lock lifetime | Attempts to clear locks within a boot reject; the next normal/recovery boot reapplies them before any secret use. |
| Authorized images/recovery | Every image allowed for the intended storage profile preserves the defined secret boundary, or the unresolved image set blocks adoption. |

One immutable experiment record binds source, target reference, installed
firmware, signed image, public derivation inputs, approval reference, operation
names and outcomes. Raw transcripts remain private. Only explicit allowlisted
public fields and booleans/error codes may be retained; omit raw mailbox
buffers, key contents, HMAC values and canary plaintext.

The go decision requires all applicable mechanism cases on the actual selected
platform. A failed assumption identifies the implementation/profile decision
it blocks and completes that investigation report. Missing access, approval,
measurements, or an untested legacy read path leaves feasibility pending.
A compiled harness or successful build cannot make the go decision.

## Decisions and later milestone

| Decision | Resolving observation | Blocks |
| --- | --- | --- |
| Installed firmware supports the mechanism | Baseline plus bounded operation tests | Choosing this unlock mechanism |
| Slot and authorized-image set are suitable | Usage inventory and image/recovery review | Secret programming |
| Read restrictions and operation closure hold | Positive and negative lock tests | Protected-state implementation using this mechanism |
| Normal/recovery boot can derive safely offline | Cold-boot canary reopen and lock reapplication | Persistent-state integration |

Full LUKS lifecycle, recovery/keyslot handling and leakage review are the next
protected-state milestone. Copied-media confidentiality stays pending until
the original board reopens a private record offline and a functioning
comparable board cannot decrypt it or use the original identity.
