# Remote device-secret development

Use the already signed inspection SD to investigate firmware API behavior before
building another qualification image. The development helper runs from RAM over
the existing authenticated SSH connection. Changing its executable does not
require another boot-image signature, NVMe installation, media write, or firmware
update. This is development execution under the inspection image's existing
root-equivalent access; uploaded code is outside its verified root.

The native helper and host session runner are implemented and covered by synthetic
checks. Their physical operation remains to be observed. They do not establish
boot-time lock application, offline operation, LUKS persistence, copied-media
protection, or fleet admission. The [qualification harness](device-secret-target-harness.md)
and its offline-image restrictions remain unchanged.

## Available checks

| Check | Operations and result |
| --- | --- |
| `inspect` | Count, selected slot status and usage only. No private read, cryptography, or lock mutation. |
| `read-lock` | Require the selected development slot/usage, set and verify the three runtime READ/GEN/USAGE locks, perform one crypto private-read negative probe, and close/verify all five volatile locks. |
| `hmac` | Apply the same runtime locks, compare two HMACs of a fixed public message, compare a different public message, close/verify all locks, and check one post-closure HMAC rejection. At most four HMAC calls. |

Each mutating check makes at most two volatile status writes, including failure
cleanup. Neither check programs a key or usage value. The executable has no
signing, legacy-read, arbitrary-tag, arbitrary-payload, key-export, block-device,
LUKS, or power command. Unexpected key material stays in locked process memory and
is wiped without printing it. Swap/core dumps must be disabled. Results contain
public metadata, boolean comparisons, typed outcomes and mailbox tag/errno only.

The helper shares the qualification harness's mailbox implementation. In
`read-lock`, a transport failure is recorded first, followed by one separate
last-error query when possible. An `EINVAL` and even a subsequent `KEY_LOCKED`
error do **not** turn the failed read into a successful protection check. The
kernel may reject the whole property call without copying its response to user
space; last-error state alone cannot distinguish that from all other failures.
Unexpected/malformed responses remain failed, and cleanup success is separate.

Locks persist within a boot. A second mutating check on an already closed slot
stops. Start an explicitly authorized soft reboot between checks that need an
open HMAC operation; do not attempt to clear locks. A soft reboot is useful for
API development, but supplies no evidence of a cold-power interval.

## Build and native handoff

```console
nix build --no-link .#kaiba-device-secret-development-session
nix develop --command scripts/check.sh contracts device-secret-development device-secret-target device-secret-runner
```

The helper is a same-architecture static musl executable. Native ARM CI checks
and exports it independently of the full image-build lane as
`device-secret-development-<commit>-aarch64-linux`, containing the executable and
`build.json`. That manifest records repository, exact source revision, run/attempt,
platform, store path and executable SHA-256. No selected device data is submitted
to CI. Verify the expected repository/revision, successful check and downloaded
bytes before placing the digest into a private session. The session runner also
rejects non-ARM64 ELF files and a changed executable digest.

The regular CI checks still apply; this export is neither a signed boot image
nor permission to operate hardware. A source revision can differ between PR
merge CI and the branch head, so retain the actual artifact's revision.

## One reviewed development session

Agree the selected development key, checks, maximum attempts/reboots, expiry,
and existing inspection-image exposure once for a bounded session. Programming,
new boot signatures, persistent media changes and qualification remain separate
scopes. An ambiguous action still requires review, but normal remote execution
needs no host sudo, YubiKey touch, keyboard, or manual SSH-key acceptance.

Keep the session and captures private on the station. The closed JSON format is
`kaiba.device-secret-development-session/v1alpha1` and requires exactly:

| Fields | Binding |
| --- | --- |
| `address`, `user` | Exact IPv4 address and SSH user; no hostname, shell expression, or SSH options |
| `identity_file`, `known_hosts` | Absolute client-key path and an existing independently authenticated pin; one exact address/Ed25519 entry |
| `board_serial_sha256`, `boot_image_sha256` | Expected board and signed inspection image, lowercase SHA-256 without prefix |
| `firmware_version`, `kernel_release` | Exact 40-character firmware revision and kernel release |
| `helper_sha256` | Exact downloaded executable SHA-256 |
| `slot_id`, `expected_usage` | One-based slot, and zero or a user-defined usage (8–14); usage zero does not establish an empty key |
| `checks` | Nonempty unique subset of `inspect`, `read-lock`, `hmac` |
| `max_runs`, `max_reboots` | 1–32 checks and 0–16 soft reboots, bounded by the actual approval |
| `expires_at` | UTC ISO timestamp ending in `Z`, at most 24 hours from initialization |
| `uart_by_id`, `uart_by_path` | Exact matching `/dev/serial/by-id/` and `/dev/serial/by-path/` selectors |

```console
kaiba-device-secret-development-session init \
  --state /absolute/private/new-session --config /absolute/private/reviewed-session.json
kaiba-device-secret-development-session run \
  --state /absolute/private/new-session \
  --helper /absolute/private/kaiba-device-secret-development --check inspect
kaiba-device-secret-development-session run \
  --state /absolute/private/new-session \
  --helper /absolute/private/kaiba-device-secret-development --check read-lock
kaiba-device-secret-development-session reboot --state /absolute/private/new-session
```

Initialization is file-only and grants no authority. Each check verifies the
SSH pin, board/image/firmware/kernel, healthy read-only verity root, tmpfs, no swap
and no *current* power/thermal flags. Historical flags are retained in the
attempt record and are not represented as a clean qualification preflight. The
runner records a durable intent before uploading/executing anything. It verifies
the helper hash again on the Pi, rechecks the boot identity inside the helper,
and removes the executable on normal exit. No secret bytes are exported.

For an authorized reboot, the runner arms the existing passive UART reader
first, issues one reboot, collects 120 seconds of bounded private output, and
matches the new SSH key against exactly one UART fingerprint and expected
signed-image marker. It then repeats the read-only preflight and checks that the
boot ID changed before accepting the new pin. Old pins and captures are retained.
It never accepts `ssh-keyscan` alone as authentication.

Failed checks, missing/invalid responses, timeouts and interrupted actions block
further execution in that session. `status` remains available. There is no reset,
force or automatic retry. Preserve the session, reconcile its result and actual
lock state, then prepare a newly reviewed session within the remaining human
authority. Creating a fresh directory cannot manufacture additional authority.
The state assumes a trusted workstation operator; it is not an independent audit
or a security boundary against station root.

## Permanent bench setup: next stages

The following are planned, not supplied by this helper:

1. **Recover the current attempt once.** Complete any outstanding authorized
   restoration and host automount cleanup before changing the bench topology.
2. **Keep the NVMe installed.** Prepare an exact signed boot-configuration change
   selecting management SD by default, with a reserved disposable NVMe partition.
   Stage and verify that partition from the Pi. Prove return to management with
   the drive present before retiring physical removal as the recovery route.
3. **Remote LUKS development.** Add a bounded storage helper after mailbox/HMAC
   behavior is established. Create/reopen only the reserved extent; keep backups
   and failure reconciliation independent of the test filesystem.
4. **Remote cold-power and isolation.** Select a controller for a single power
   source and every data/network path. Account for USB/PoE and UART back-power.
   Establish observable power-off and recovery behavior before counting automated
   cycles as cold/offline evidence. An SSH shutdown, reboot, network firewall or
   missing ping alone is insufficient.
5. **Frozen qualification candidate.** Sign after the implementation stabilizes,
   then run the offline create/reopen, lock, failure/recovery and comparable-board
   copied-media checks. A development shell remains outside the fleet profile.

SD-first and signed `tryboot` are supported bootloader mechanisms, but their
exact behavior and recovery on the selected topology still need testing.
`tryboot` is a reboot mechanism; do not assume it selects the same image across
complete power removal. See the [official bootloader documentation](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#fail-safe-os-updates-tryboot).
No EEPROM/OTP change, power-controller installation, disk repartitioning, or
physical test is performed by these software packages.
