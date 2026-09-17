# Native offline signing and physical-attempt handoff

This is the execution package for the [native offline candidate](native-offline-candidate.md)
in [Slice B](implementation-staging.md). It prepares signing and media inputs.
The [2026-09-16 observation](observations/2026-09-16-native-offline-positive.md)
records one pristine native offline boot and verified return to inspection SD.
The [2026-09-17 verity procedure](observations/2026-09-17-native-verity.md) adds the
two scoped corruption results, pristine restoration, positive control and SD
return, including an explicit late-read console-interleaving review. Device-secret
feasibility and full fleet qualification remain pending.
Nothing here admits the device to a fleet or repeats fresh-board qualification.

## Separate, single-image signing scope

Build from a selected clean commit on a native ARM64 builder:

```console
nix build --no-link --print-out-paths .#kaiba-rpi5-native-offline-signing-plan
```

Retain that exact commit and store output. Do not use a moving branch or a CI
synthetic merge commit as the signing candidate. The plan contains `boot.img`,
`public.pem`, `release-intent.json` and `plan.json`. Its `input` output contains
the canonical public signing-input manifest. That manifest binds the unsigned
artifact and review-file digests, exact boot/root/tree bytes, signed root hash,
and NVMe partition GUIDs. The constructor verifies the actual verity tree and
root arguments before emitting the plan. Source labels alone are not provenance.

The new `native_offline_boot` intent and approval contracts authorize exactly
one `rpi5.boot_image`. Provisioner, verifier and five-input release approvals
are rejected, even for identical image bytes. EEPROM, owned recovery and OTP
roles are excluded. No unchanged firmware image needs to be signed or rewritten.

The workstation package `kaiba-rpi5-native-offline-development-signing` exposes
`kaiba-rpi5-native-offline-signing`, the existing gate, receipt verifier and
fixed YubiKey backend. It has no runtime socket/key/provider selection and
exposes no generic five-role signing client. Existing PIN, touch, gate registry,
expiry, one-use grant, receipt attestation and incomplete-attempt rules apply.
The historical minimum is one artifact signature plus one receipt attestation;
this is not a promise of an upper bound on private-key operations.

The native command supports:

| Command | Purpose |
| --- | --- |
| `validate-plan --plan /absolute/plan` | Validate public plan/image/key bindings. |
| `validate-unsigned --plan /absolute/plan --manifest /absolute/input/manifest.json` | Validate the exact public native input manifest. |
| `author --plan /absolute/plan --reviewer-id reviewer:NAME --approved-at UTC --expires-at UTC --output /absolute/new-authorization` | After actual review, create one attributed approval and exact grant; maximum lifetime 24 hours. |
| `validate-authorization --plan /absolute/plan --approval /absolute/approval.json --registry /absolute/signing-grants.json` | Verify the exact native approval and one-grant registry. |
| `sign --plan /absolute/plan --output /absolute/new-signed` | Request the image signature from the installed approval gate. |
| `finalize --plan /absolute/plan --signed /absolute/signed --approval /absolute/approval.json --registry /absolute/signing-grants.json --receipt-export /absolute/signing-receipts.json --output /absolute/new-verified` | Verify the boot signature, result, approval and authenticated gate receipt together. |

Authoring an approval record does not obtain review or install authority. Before
authoring, present the exact source, plan/input/image digests, key/policy bindings,
and operation scope for approval. Install only the resulting exact registry
through the existing signing-host procedure. Obtain its authenticated receipt
export after signing. Do not repurpose a verifier/provisioner deployment bundle
or historical grant for this command. Runtime installation is a separately
reviewed host change; the software builds perform neither installation nor signing.

The [Ubuntu installer and static preflight](../deploy/ubuntu-signing-gate/README.md)
accept the native runtime as one closed profile and reject packages containing
multiple profiles. Build the native runtime and `ubuntu-signing-gate-deployment`
from the same selected clean commit, retain their exact store paths and hashes,
and review the host replacement before installation. Installation remains inert;
it creates neither an approval nor a PIN source and does not start the gate.

## Verified outer FAT and exact media spans

`lib.mkRpi5VerifiedNativeOfflineSigning` accepts the typed signing plan plus
store-backed public authorization, signed result and receipt export. It reruns
the authenticated finalizer. `lib.mkRpi5NativeOfflineMediaHandoff` accepts that
verified output and an explicitly observed `targetSizeBytes`. The repeatable
composition is [examples/native-offline-handoff.nix](../examples/native-offline-handoff.nix).

The outer FAT partition contains exactly `boot.img`, `boot.sig` and a
`config.txt` containing `boot_ramdisk=1`. It is formatted, extracted and compared
before inclusion. The inner boot ramdisk must never be written as this partition.

The media package describes five disjoint writes: primary GPT, 128 MiB outer
boot FAT, root data, root hash tree, and backup GPT at the **observed device's
last sectors**. Partitions start on 1 MiB boundaries. Every write has an offset,
length and digest; both root PARTUUIDs match the signed boot arguments. The
package also carries the verified signing output, public review and two
root-corruption offsets with pristine/altered block digests. It creates only
regular files. It is not accepted by the existing full-release media writer.

The fixed existing hardware configuration allows `/dev/nvme0n1` only on
`kaiba-rpi5-provisioner`, booted from the separate SD provisioner. On `malak`,
that node is the protected system SSD. Do not transplant the selector to malak.
No SD write is included. No private-state volume is created. Unwritten partition
tails and disk gaps are not sanitized by this package.

Before requesting media execution, attach fresh, narrowly scoped observations:

- Board reference and customer-key identity; installed EEPROM revision/hash;
  selected source, signed boot/root/tree and native plan bindings.
- Exact host, NVMe identity, byte capacity and 512-byte logical sector size;
  absence of target mounts, swap, holders and active use. No other medium may
  expose duplicate root PARTUUIDs during boot. The fixed hostname/node alone
  does not authenticate a board or disk.
- Digested, independently stored preimages for **every** planned write span,
  including both original GPT regions. Retain the original layout, all old data
  overlapped by the new layout, and a verified SD restoration route.
- Exact executor/version and the bounded write/readback procedure. This PR
  supplies no block-device writer or permission to run raw writes. Any new
  executor must enforce these bounds and stop on uncertain writes.

The plan's `execution_authorized`, `physical_staging_ready` and
`hardware_observed` remain false. Fresh inventory, reviewed backups and explicit
execution authority are separate inputs; generating a valid plan cannot imply them.

## Bounded physical experiment

Use the already-owned board. Retain UART captures privately and only allowlisted
public references/results in the experiment report. The public report binds the
actual board, installed EEPROM/kernel, source, signed image, media readback,
network isolation, clock observation, and each corruption offset/digest.

1. After the separately authorized writes, read back and hash every complete
   written span. Stop on any mismatch. Cold-power the board with Ethernet,
   Wi-Fi and USB network paths unavailable. Record that no network time is
   supplied; a plausible RTC value alone does not prove a time dependency.
2. Require the expected signed-boot/image observations, read-only verity mapping,
   expected `/etc/os-release` digest and `KAIBA_NATIVE_OFFLINE=pass`, then the
   pristine probe success. Match the intended NVMe boot; any SD/network fallback
   is a failed or inconclusive attempt, never a candidate pass.
3. Power off, return to the separate provisioner and apply only the specified
   startup-superblock alteration under the approved tamper scope. Retain the
   original hash tree. Read back the changed block and cold boot offline. Require
   explicit kernel verity rejection; a timeout or generic boot failure is insufficient.
4. Restore and read back the pristine candidate. Separately alter the designated
   allocated probe block before cold boot, retaining the original hash tree.
   Require the successful local action before the first probe read, then an I/O
   rejection **and** a kernel verity-corruption diagnostic. Earlier read-ahead or
   an unidentifiable failure makes this case inconclusive; investigate before retrying.
5. Restore/read back pristine bytes and repeat the positive control. Preserve a
   final inventory and restoration outcome. Stop on mismatched device identity,
   uncertain writes or unexplained evidence; do not automatically retry operations.

The firmware-HMAC investigation is a separate operation/slot/lock experiment.
No secret generation, HMAC, signing, OTP usage change, EEPROM update or final
debug-lock operation is included in this boot attempt. Slice B completes only
after actual offline/integrity observations and a supported secret mechanism or
a documented failed assumption with the decision it blocks. Missing evidence
remains pending; copied-media confidentiality needs the later two-board test.

## Software validation

```console
nix develop --command scripts/check.sh contracts native-offline-handoff
nix develop --command scripts/check.sh fast
```

The handoff check uses a disposable fixture key, authenticated fixture receipts,
small ext4/verity images, and regular files. It constructs the actual plan,
finalizer, FAT and GPT package, reconstructs a disk from its spans, and independently
checks GPT, FAT readback and corruption block digests. Go tests cover scope
separation, malformed inputs, changed identities, approvals, receipts and
finalization failures. Native ARM CI additionally builds the actual candidate's
signing plan. None of these checks is a physical hardware result.
