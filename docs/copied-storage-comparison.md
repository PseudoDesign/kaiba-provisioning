# Copied-storage development comparison

The comparison helper tests a completed development fixture on its original
board and a functioning comparable board. It uses a complete, hash-bound **65 MiB
copy in RAM**, including all four completed journal blocks, the LUKS2 headers,
keyslot area and encrypted data. The source NVMe and the second board's storage
remain installed. The helper has no physical-disk, media-copy, reboot or boot-image signing
command. Software implementation and synthetic tests are separate from hardware
execution, which remains pending.

This complements the [original-device offline observation](observations/2026-09-20-offline-storage.md)
and [device-secret feasibility work](device-secret-feasibility.md). It never
reopens a consumed create/reopen workflow or modifies its journal. The older
storage helpers retain their existing rejection rules.

## One bounded run on each board

The standalone static helper runs under trusted development administration.
The original board uses the existing signed inspection OS; the comparison board
may use an explicitly reviewed development OS. This is not the qualified boot
profile, and the executable uploaded into RAM is outside the signed root.
The helper checks the exact board serial hash, kernel, running EEPROM revision
and expected boot ID. The host execution packet must also bind SSH identity,
helper provenance, image/root observations, power state and execution authority.

Before firmware operations it requires root, no swap, disabled core dumps and
locked process memory. It accepts only a root-owned private regular file on
tmpfs, exactly 68,157,440 bytes long, matching its reviewed SHA-256. It validates
all four journal records against the original source configuration, boot image
and verity root. The create and reopen boot IDs must differ. Missing/incomplete
journals, extra keyslots, wrong volume parameters, missing drivers and mismatched
copies fail before secret use. Original and comparison roles require matching
and different board hashes respectively.

Each invocation permits at most **three HMAC calls and two volatile lock writes**:

1. Check slot 1's metadata and explicitly reviewed usage. Apply READ/GEN/USAGE
   restrictions and verify their reported state.
2. Reuse the existing `kaiba-firmware-hmac-counter-v1` LUKS and record-MAC purposes
   with the source fixture's public nonce. Reject zero/equal results, then repeat
   the LUKS derivation once and compare it in memory. Derived values stay in memory.
3. Format a fresh 64 MiB **tmpfs-only** LUKS control with the local derived key,
   write/authenticate a random record, close it, then reopen it read-only and
   authenticate the same record. No failed control counts as copy protection.
4. Check the source passphrase once with libcryptsetup's mapping name set to
   NULL, so device-mapper permission failures cannot masquerade as a wrong key.
   On the original board, additionally activate one read-only mapping and
   authenticate the record. On the comparison board, only the exact
   wrong-passphrase result (`-EPERM`) is accepted. An
   unsupported firmware API, malformed header, I/O error or unexpected successful
   unlock fails the run.
5. Wipe application key buffers, close and read back all five volatile locks,
   remove mappings/loop devices and the temporary control, and verify that the
   full source-copy hash is unchanged. Cleanup failure fails the run.

The source loop device and decrypted source mapping are read-only. Only the
temporary control is formatted or written. Libcryptsetup logging is suppressed;
the result contains public bindings, booleans and error codes, not plaintext,
passphrases, volume keys or firmware response buffers. The one-shot marker in
`/run` prevents another invocation in the same boot. The host must preserve a
durable intent before execution; removing a marker or preparing a new directory
does not authorize a retry. A timeout or interrupted/failed run stops the session.
Loop cleanup makes one detach request and waits at most five seconds for existing
udev readers to release it. A persistent holder fails cleanup; there is no repeated
detach, firmware call, format or unlock attempt.

If an HMAC call has a transport failure, the helper preserves its original
diagnostic and makes at most one read-only last-error query before cleanup can
clear that global value. It emits one `KAIBA_COPIED_STORAGE_LAST_ERROR` line on
stderr with the query outcome, errno, availability and scalar value; no request,
response or key bytes are logged. Interrupted calls do not make this extra query.
Executors must retain this separate metadata alongside the unchanged failed JSON
result and allow only that exact diagnostic format when handling a failed run.
The value is not correlated proof of the failed transaction. Neither a last-error
code nor `EINVAL` counts as a working second-board control or copied-key rejection.

## Disposable identity challenge

The existing private record contains 128 random bytes. After authenticating the
record on the original board, the helper hashes
`kaiba:copied-storage:fixture-identity:v1`, a NUL byte and those 128 bytes to
obtain an Ed25519 seed. It signs one reviewed fresh 32-byte public challenge and
exports only the public key and signature. It verifies the signature internally;
the independent file-only assessor verifies it again using the public key.
No private identity bytes are added to the source volume or exported.

This is a **disposable fixture identity derived from encrypted record material**.
It demonstrates that the comparison board cannot access that fixture's identity
through the selected copied container. It is not a fleet credential, a firmware
signing test, a non-exportable production signer or enrollment proof. A new
fixture or purpose defines another identity. Production identity generation,
credential installation, lifecycle and permitted-image/recovery qualification
remain separate work.

## Configuration and assessment

Build and test without contacting hardware:

```console
nix build --no-link .#kaiba-copied-storage .#kaiba-copied-storage-assess
nix develop --command scripts/check.sh contracts copied-storage copied-storage-vm
```

The helper accepts:

```console
kaiba-copied-storage --check-config comparison.json source-storage-config.json
kaiba-copied-storage run comparison.json source-storage-config.json /dev/shm/private/copy.img \
  --expected-boot-id REVIEWED-BOOT-UUID
```

The closed `kaiba.copied-storage-comparison/v1alpha1` configuration has exactly:
`schema_version`, `scheme`, `role` (`original` or `comparison`),
`board_serial_sha256`, `kernel_release`, `firmware_version`, `image_sha256`,
`source_boot_image_sha256`, `source_verity_root_hash`, `challenge_hex` and
`expected_usage`. Digests/challenge are nonzero lowercase hex; the firmware
revision is 40 characters and other digests/challenge are 64. Usage is zero or
8–14. Slot 1 is fixed; usage zero does not prove that the slot is available.
The separate source configuration is the exact completed remote or offline
development storage configuration; its contents are bound by the journal.

Prepare an assessment plan **before** execution. Its schema is
`kaiba.copied-storage-assessment/v1alpha1`. Shared fields are `image_sha256`,
`source_boot_image_sha256`, `source_verity_root_hash`, `volume_uuid`, `nonce_hex`,
`challenge_hex` and `firmware_version`. Each of `original` and `comparison` contains
`board_serial_sha256`, `kernel_release`, `boot_id` and `expected_usage`.

```console
kaiba-copied-storage-assess --plan assessment.json \
  --original original-result.json --comparison comparison-result.json
```

The assessor rejects synthetic results, mismatched copies/boards/challenges,
missing positive controls, non-wrong-key failures, invalid signatures, changed
input, failed cleanup and overstated qualification. Success is
`matched-development-comparison`, with `hardware_qualified`,
`fleet_identity_qualified`, `lock_rejection_qualified` and
`execution_authority` all false. Results assume a trusted station and OS;
they are not independently authenticated audit evidence.

## Physical execution packet remains required

Before execution, bind the helper's successful native CI export and hash; verify
both board baselines and the source fixture's completed offline evidence; obtain
an exact full-copy hash without changing the source; resolve each development
slot's permitted use and the development-image exposure; and prepare the bounded
private ciphertext transfer, tmpfs space, swap/core/log policy, module preparation,
any necessary reboot and cleanup. The original slot may still be closed from a
completed prior experiment. Do not clear locks to avoid a reviewed reboot.
The second board's own NVMe is not an output or a prerequisite for this route.

The same packet must preserve source/copy evidence, enforce one attempt per board
and describe recovery if a board does not return. A software build or assessment
does not authorize those operations. Raw captures/ciphertext stay private; any
public observation is a separately reviewed projection. This comparison does not
establish a cold/offline condition on the second board, qualify every permitted
image or recovery route, or complete fleet admission.
