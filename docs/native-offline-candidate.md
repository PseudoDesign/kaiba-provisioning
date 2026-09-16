# Native offline engineering candidate

This implements the unsigned-image portion of [Slice B](implementation-staging.md).
It is an engineering candidate for the already-owned development Pi 5, not a
fleet profile or a completed physical qualification. Signing, media writes,
EEPROM changes and OTP operations are not performed by these builds.

## Composition and outputs

The candidate uses the pinned Raspberry Pi platform and generic native
signed-boot/verity constructors. Normal boot and the verified ext4 root reside
on NVMe. SD remains the separate provisioner/recovery medium. Existing
host-bound media selectors and the development EEPROM policy are unchanged.
The candidate does not use the online verifier or kexec path.

The generic artifact manifest retains its historical rollback-policy label
for contract compatibility. That label does not add a first-fleet prerequisite:
the [active admission policy](fleet-admission-policy.md) does not require
offline rejection of older correctly signed images.

The signed boot ramdisk will bind the kernel, initramfs, DTB, boot arguments,
root hash and two fixed NVMe GPT partition GUIDs. The unsigned artifacts are
`unsigned/boot.img`, `nvme/root-data.img`, and `nvme/root-hash.img`. The inner
FAT boot ramdisk is not an outer boot partition: do not write it directly to
a boot partition. The [native handoff](native-offline-handoff.md) supplies the separate signing and media package; actual signing and physical execution remain pending.

Mutable state is tmpfs only. There is no encrypted persistent-state volume or
device identity. Development SSH/USB networking, DHCP, network-manager and
network-time services are disabled. UART remains the development observation
channel. No new EEPROM boot-order or debug-lock setting is applied.

On a clean commit, build on a native ARM64 builder:

```console
nix build --no-link --print-out-paths \
  .#kaiba-rpi5-native-offline-unsigned \
  .#kaiba-rpi5-native-offline-review
```

These packages are deliberately absent from dirty/path flake package exports
and from x86 package exports. Native ARM checks build the actual candidate;
x86 evaluation checks do not create a second Pi artifact lineage.

The review output retains source/platform pins, the lock file, artifact
bindings, the expected resolved `/etc/os-release` digest, the late-read probe
digest, and a corruption plan. Its status remains unsigned, not ready for
physical staging, and hardware-unobserved. The repository's EEPROM pin and
firmware bundle are not proof of the board's installed EEPROM identity.

## Local action and integrity observations

After the existing signed-boot evidence service succeeds, the candidate
checks that `/` is the read-only `/dev/mapper/root` backed by a verity target.
It reads `/etc/os-release` and compares its digest with its build-time input.
The resulting `KAIBA_NATIVE_OFFLINE` UART line is a local-action observation;
combine it with the exact boot-image observation and independent media
readback. It is not remote attestation or fleet admission.

Only after that action does it first read `/kaiba-offline-read-probe`. The
review output selects an allocated ext4 data block belonging to that regular
file. Altering that block before boot while retaining the original verity tree
tests enforcement on a read after mounting without a previous good cached
read. A second case alters the first verity block containing the ext4
superblock to exercise startup rejection.

Require pristine controls and explicit kernel verity-corruption diagnostics
for negative results. A timeout, ordinary boot failure, read-only mount, or
`read_failed` marker alone does not establish enforcement. A missing UART
result is inconclusive. Never count a fallback boot as the intended candidate.

## Software checks and physical follow-up

```console
nix develop --command scripts/check.sh contracts native-offline-eval
nix develop --command scripts/check.sh contracts native-offline-verity-vm
```

The VM check is x86-native and uses small synthetic ext4/verity disks with no
network device or time service. It demonstrates pristine reads, startup
corruption rejection and failure of a designated read after mounting. It does
not boot a Pi or qualify its firmware. The `native-offline-artifacts` check on
ARM builds and verifies the real candidate's artifact hashes and verity tree.

Before a physical attempt, prepare an explicitly scoped native boot signing
plan, verified outer boot filesystem and exact media-write/readback package.
Existing verifier/provisioner signing scopes do not cover this candidate.
Reuse signatures only for identical bytes and compatible lineage. Keep a
reviewed restoration route and stop on mismatched inputs or uncertain writes.

The physical procedure must demonstrate a cold boot with every network path
unavailable, no network-time dependency, the expected local action, and both
integrity cases. Record the actual board/EEPROM/kernel identities, source and
image bindings, media readback, corruption offsets/digests, UART capture
reference and outcome. Raw observations stay outside Git; no hardware result
is supplied by this PR. Firmware-HMAC feasibility proceeds independently.
