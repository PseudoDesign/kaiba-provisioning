# Device-secret feasibility: observed development path, qualification pending

This is the protected-storage mechanism investigation in
[Slice B](implementation-staging.md). The candidate now has an
[original-device offline create/cold-reopen observation](observations/2026-09-20-offline-storage.md),
an [HMAC closure observation](observations/2026-09-20-hmac-lock-rejection.md), and
[remaining development lock observations](https://github.com/PseudoDesign/kaiba-provisioning/blob/de56f51b4d9d4c8ed25ed77451d4a15fae5e8ac7/docs/observations/2026-09-20-remaining-lock-rejection.md).
The last link pins the reviewed public report revision while its documentation
PR is separate from this status update.

These results support continued engineering of the firmware-HMAC/LUKS candidate
on the selected development platform. They are not a production adoption decision,
a strict qualification-harness pass, or fleet admission. Production persistent
state, copied-media confidentiality, the permitted-image boundary and recovery
still need the decisions and demonstrations below.

The [remote development workflow](device-secret-development.md) provides
RAM-resident checks; the [remote storage helper](device-secret-storage-development.md)
and [offline storage service](device-secret-offline-storage.md) provide bounded
experimental storage paths. Use these existing routes for focused experiments.
A new kernel, image signature or media move is not automatically required for
a helper change. The [strict target harness](device-secret-target-harness.md)
remains a separate contract; observations from development helpers do not turn
its failed or unperformed cases into passes.

## Current evidence and remaining gates

| Area | Established observation | Still open |
| --- | --- | --- |
| Native offline boot and integrity | Pristine offline boot/local action and selected physical verity rejection cases have reports linked from Slice B. | Applicability to the final profile and complete boot/recovery qualification. |
| Original-device encrypted state | A private test record was created and reopened after an isolated cold boot. | Production volume/keyslot lifecycle, identity use, fallback and leakage review. |
| HMAC closure | Paired kernel error/payload observation retained alongside the original failed Linux call. | Adoption of this evidence method in the final profile; full permitted-image coverage. |
| Crypto and legacy reads, signing closure | The bounded development sequence completed with scoped rejection observations. Signing control used explicit DER compatibility, not cryptographic verification. | Strict qualification and final profile acceptance; no device-identity proof is implied. |
| Lock clearing | Immediate status readback after a failed clearing request showed all locks still set before cleanup. | Reapplication and secret protection across every permitted normal/recovery image. Generation/usage were observed as bits, not tested by irreversible writes. |
| Copied media | Original-device offline reopen provides one prerequisite. | A functioning comparable board must fail to decrypt the copied private record or use the original identity; an unbootable board or unsupported API is not a pass. |

The selected offline-storage and lock-observation sequences are complete. Slice B's final mechanism
qualification remains open; do not keep treating every observed case as unrun,
and do not infer that the final protection boundary has passed.

## Pinned inputs and established software work

| Input | Selected source | What remains to observe |
| --- | --- | --- |
| Pi platform | `nixos-raspberrypi` `7e39508bcf9c1da82cf11c1e22f74f9d9fd0fe10` | Applicability of the recorded running platform to the final profile |
| EEPROM candidate | `rpi-eeprom` `2fee426f27b6c54d3f5b6f36efd9a2fe1286a45d`, Pi 5 image `2026-09-12`, revision `a8698392` | Final-profile applicability beyond the scoped running-platform observations |
| Firmware crypto | `raspberrypi/utils` `292dbe7e35296e556d839a0b9ae2ca957ac8c961` | Qualification of the required operations and any development compatibility rules for the final profile |

The [EEPROM update](rpi5-eeprom-crypto-update.md) replaces the May candidate,
which predates the June 17 fine-grained locks required by the harness. The later
observation records identify the running platform; full EEPROM/protection
qualification remains pending. The selected history
contains the crypto API, key usage, raw-OTP lock fix, invalid-HMAC-key fix and
fine-grained read/generate/sign/HMAC/usage locks. That is source support, not a board result. The
separate boot-firmware bundle revision is not an EEPROM version observation.
The platform's general utils package lacks GnuTLS and can omit the crypto
subdirectory. `kaiba-rpi5-fwcrypto` explicitly builds that pinned subdirectory
with GnuTLS, including its library and upstream CLI.

Sources: [pinned EEPROM history](https://github.com/raspberrypi/rpi-eeprom/blob/2fee426f27b6c54d3f5b6f36efd9a2fe1286a45d/firmware-2712/release-notes.md),
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
a kernel patch. Later scoped HMAC, storage and lock observations are summarized
above. Production slot suitability, the authorized-image boundary and final
protected-storage qualification remain pending.

## Proposed mechanism and authority gate

Use a dedicated device key only after reviewing the slot's current status,
usage and the exact secret-programming operation. Never overwrite an occupied
slot or repeat customer-root ownership programming. Key generation and OTP
usage writes need a separate irreversible-action plan; neither is included in
the read-only probe.

The experimental implementation selects `kaiba-firmware-hmac-counter-v1`,
reusing the pinned upstream one-block counter KDF. Its salt is the ASCII purpose
`kaiba:protected-state:luks2:v1`, one NUL separator and 32 random public per-volume
nonce bytes. The [harness document](device-secret-target-harness.md#reuse-and-derivation-decision)
specifies the complete byte encoding. This explicitly replaces the earlier
proposed direct purpose/nonce HMAC for the experiment; production profile
adoption remains a decision. Existing host keyslots are unchanged.

The 32-byte firmware result passes directly in memory to libcryptsetup; LUKS
generates an independent volume key. No derived value belongs in argv,
environment, files on removable media, logs, receipts, the Nix store, or Git.
A public nonce, board serial or disk ID does not replace the OTP secret.

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

The [automation plan and host runner](device-secret-automation.md) reduce the
operator session to prepared execution and physical steps. The passive runner
and software rehearsal are implemented. The [target harness and unsigned image
constructor](device-secret-target-harness.md) are now implemented and tested in
software. The [packet and staging/recovery tooling](device-secret-execution-packet.md)
is also implemented. The development observations above came from their specific
reviewed procedures, not from a blanket pass of every harness case. Neither a
capture plan nor a matched target report grants execution authority or qualifies
this mechanism.

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

For HMAC failures, the [rejection-evidence decision](device-secret-rejection-evidence.md)
separates Linux API observations from firmware-payload validation. Its local
assessment can describe saved development results without repeating hardware
operations; it does not mark the operation-closure case above as passed.

## Decisions and later milestone

| Decision | Resolving observation | Blocks |
| --- | --- | --- |
| Adopt the observed engineering mechanism in a final profile | Map the scoped operation evidence and explicit compatibility limits to profile requirements | Production mechanism adoption |
| Slot and authorized-image set are suitable | Usage inventory and image/recovery review | Secret programming |
| Final read restrictions and operation closure | Accept an evidence method and cover all permitted images, retaining scoped positive/negative results | Production protection qualification |
| Normal/recovery boot can derive safely offline | Reuse original-device cold reopen; qualify lock reapplication and recovery routes | Production persistent-state integration |

Full LUKS lifecycle, recovery/keyslot handling and leakage review are the next
protected-state milestone. Copied-media confidentiality stays pending until
the original board reopens a private record offline and a functioning
comparable board cannot decrypt it or use the original identity.

## Next protected-state milestone: prepare before copying

The [copied-storage development helper](copied-storage-comparison.md) supplies
RAM-backed comparisons of a completed fixture, independent local LUKS controls
and a disposable record-derived identity challenge. Its software results do not
complete the physical steps below or qualify a production fleet identity.

1. Record a read-only baseline for each board: model, functioning boot and storage
   access, installed firmware/kernel, ownership root, slot metadata, and applicable
   recovery route. Do not assume the second board is unfused, disposable, or has an
   empty key slot. Do not route the already-owned original through fresh ownership.
2. Define the permitted normal, maintenance and recovery images and their secret
   exposure boundary. Existing development-root images are not automatically safe
   for production storage. Select provisioning, keyslot/fallback handling, loss,
   replacement and credential retirement behavior before implementing that path.
3. Prepare a disposable private-record fixture and a scoped identity challenge.
   Bind exact artifacts, public KDF inputs and a repeatable original-device offline
   reopen. Define which storage bytes, headers, nonces and credential material the
   copy must contain; an incomplete copy cannot establish the intended boundary.
4. Establish independent positive controls on the comparable board so failure is
   attributable to device-bound protection rather than broken hardware, boot,
   firmware, storage access or cryptographic tooling. Any secret provisioning for
   that control needs its own explicit authority; metadata alone is insufficient.
5. Prepare exact source/destination media identities, private backups, bounded
   copy/readback operations, stop conditions and recovery. Only then authorize and
   run the original/copy comparison. No copy, write, key operation or power action
   is authorized by this planning document.

Passing the comparison will establish only its stated copied-storage/identity
boundary. It does not replace qualification of all authorized images, final debug
and EEPROM protections, recovery, enrollment or the admission evidence method.
The [per-device boot-root plan](per-device-boot-root-plan.md) remains a separate
planned custody/update track; neither its TPM option nor device-local signing is
an implemented prerequisite silently added to the current experiment.
