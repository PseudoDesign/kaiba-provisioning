# Raspberry Pi 5 target-media staging contracts

Kaiba has two deliberately separate media paths:

- `lib.mkRpi5MediaStagingFixture` builds a synthetic regular-file rehearsal
  from an already verified unfused capsule; and
- `lib.mkRpi5ProductionMedia` derives a complete GPT/FAT/dm-verity plan, a
  plan-specialized whole-device writer, and an independently built read-only
  verifier from an already verified signed release.

The fixture is regression coverage, not permission to write a device. The
production-media path defines the software contract intended for a separately
approved physical staging ceremony. Its build-time check still has no block
device, cold-power, Raspberry Pi, EEPROM, OTP, or secure-boot-enforcement
authority.

This standalone repository exports the lower-level factories. It intentionally
does not export a preconfigured `production-media` package: a deployment must
supply its own typed, already verified release, transaction, station hardware
configuration, and observed media geometry.

## Synthetic fixture boundary

`lib.mkRpi5MediaStagingFixture` accepts only a typed output from
`mkRpi5VerifiedUnfusedCapsule`. It constructs a deterministic regular-file GPT
target and an outer FAT filesystem containing exactly:

```text
config.txt
boot.img
boot.sig
```

`config.txt` contains only `boot_ramdisk=1`; the image and signature remain
byte-for-byte bound to the verified capsule. The fixture exercises source
digest checks, exact extent writes, `fsync`, close/reopen behavior, GPT and FAT
inspection, complete partition digests, and dm-verity verification without
opening anything under `/dev`.

Run the repository's supported regression contract with:

```console
nix --accept-flake-config build \
  .#checks.x86_64-linux.media-staging-fixture \
  --no-link -L
```

The legacy mixed `kaiba-provision-media-stager` contains both fixture and old
block-device modes, so it is not exposed as a top-level package. Its old
three-extent plan does not authorize the production GPT, canonical four-file
FAT, zero regions, signed-release binding, or final whole-media digest. Do not
reconstruct a device command from the fixture test or use that legacy binary
for physical staging.

A fixture receipt can prove that a regular file was reopened and matched the
expected bytes. It must retain false values for claims it cannot establish:

```json
{
  "hardware_observed": false,
  "cold_power_cycle_observed": false,
  "security_enforced": false,
  "mutation_eligible": false,
  "one_time_settings_changed": false
}
```

## Production-media construction

`lib.mkRpi5ProductionMedia` accepts only a store-backed output from
`lib.mkRpi5VerifiedSignedRelease`. That upstream release must already have
passed the exact 18-role publication contract, signature and receipt-lineage
verification, and deterministic EEPROM and owned-recovery replay.

The media factory additionally requires:

- one canonical transaction ID;
- one versioned hardware configuration;
- the exact capacity observed for this run; and
- a 512-byte logical sector size.

Capacity and sector size make the generated layout compatible with the current
target. They are not a persistent hardware identity or boot trust input.

A consumer flake can expose the result and its two capability-separated
binaries as follows. In this fragment, `verifiedSignedRelease` is already in
scope and must be the typed output of the lower-level verified-release
construction; it is not a directory selected by an operator at runtime.
Checked-in files under `releases/` are public inputs, not by themselves that
typed result.

```nix
let
  system = "x86_64-linux";
  productionMedia = kaiba-provisioning.lib.mkRpi5ProductionMedia {
    inherit system verifiedSignedRelease;
    transactionID = "transaction:rpi5-sacrificial-001:1";
    hardwareConfiguration =
      kaiba-provisioning.lib.hardwareConfigurations.malakRaspberryPi5SacrificialDevelopmentUsbSd;
    target = {
      sizeBytes = 0; # Replace with the exact observed capacity before evaluation.
      logicalSectorSizeBytes = 512;
    };
  };
in
{
  packages.${system} = {
    production-media = productionMedia;
    production-media-device-stager =
      productionMedia.kaibaRpi5ProductionMedia.deviceStager;
    production-media-device-verifier =
      productionMedia.kaibaRpi5ProductionMedia.deviceVerifier;
  };
}
```

The `0` above is deliberately invalid. Replace it with a freshly observed,
reviewed byte capacity; never copy an example capacity into a destructive
configuration.

The standalone repository contains two explicitly sacrificial development
hardware configurations under [`config/hardware/`](../config/hardware/):

- `malakRaspberryPi5SacrificialDevelopmentUsbSd` is hostname-bound to `malak`,
  selects its fixed USB-reader topology through `/dev/disk/by-path`, and
  protects `/dev/nvme0n1`; and
- `raspberryPi5SacrificialDevelopmentPiLocalNvme` is hostname-bound to
  `kaiba-rpi5-provisioner` and selects `/dev/nvme0n1` only while that Pi is
  booted from separate media.

These are local operational wiring, not generic profiles. A different station
must add and review its own versioned hardware configuration. Do not substitute
a runtime path argument.

The repository's pure production contract is exercised by:

```console
nix --accept-flake-config build \
  .#checks.x86_64-linux.production-media-staging \
  --no-link -L
```

That check uses a regular file. Passing it does not mean a physical device was
written or cold-read.

## Canonical whole-device layout

The production plan covers every byte from offset zero through the exact target
capacity with six consecutive regions:

1. the complete primary GPT area;
2. one canonical FAT32 boot filesystem;
3. the root-data image followed only by zero alignment padding;
4. the dm-verity hash-tree image followed only by zero alignment padding;
5. a zero-filled tail; and
6. the complete backup GPT area.

The GPT has exactly three partitions: `kaiba-boot`, `kaiba-root`, and
`kaiba-root-verity`. Partition GUIDs, type GUIDs, offsets, sizes, used lengths,
padded-partition digests, and the disk GUID are plan-bound. Root-data and
root-hash PARTUUIDs must match the values already authenticated through the
signed boot and root-integrity lineage.

The FAT filesystem has one canonical serialization and exactly four files:

```text
boot.img
boot.sig
config.txt
kaiba-media-binding.json
```

`config.txt` contains only `boot_ramdisk=1`. The non-circular media binding
connects the transaction, release manifest, capsule, boot and root payloads,
root-integrity record, dm-verity root hash, and all three partition GUIDs.
Reserved sectors, both FAT copies, directory entries, allocation chains, file
slack, free clusters, zero padding, and trailing bytes also have one accepted
representation. The plan binds every region digest and the final whole-device
digest.

## Media identity and overwrite safety

The canonical plan and receipts deliberately omit the medium's model, serial,
WWID, physical sector size, persistent path, and initial-content digest.
`/dev/disk/by-id` is not accepted as either identity or selector. Such values
are normally spoofable and must not silently become boot trust inputs.

The hardware configuration linker-fixes:

- the expected execution hostname;
- one whole-device node or `/dev/disk/by-path` selector;
- the protected-device set; and
- the hardware-configuration ID.

The operational preflight records those local facts plus the resolved device,
current boot ID, disk sequence, and geometry. They are overwrite-safety and
intra-operation continuity evidence. They do not appear in the canonical media
plan or in the stage, verification, cold-observation, and final receipt chain.

The writer rejects a partition, mounted device, root/system device, swap,
holders, slaves, incorrect capacity, and non-512-byte logical sectors. It locks
and pins the current attachment while it operates. It does not appraise or
preserve initial contents. The caller must decide out of band that destruction
of the selected medium is authorized.

## Physical staging sequence

The following procedure applies only to packages produced together by one
reviewed consumer-flake evaluation. Resolve the result links but do not copy or
edit the plan:

```console
nix build .#production-media \
  --out-link result-production-media
nix build .#production-media-device-stager \
  --out-link result-production-media-device-stager
nix build .#production-media-device-verifier \
  --out-link result-production-media-device-verifier
nix build .#kaiba-provision-media-contract \
  --out-link result-media-contract

plan="$(readlink -e result-production-media/plan.json)"
stager="$(readlink -e result-production-media-device-stager)"
verifier="$(readlink -e result-production-media-device-verifier)"
contract="$(readlink -e result-media-contract)"
```

Create a new root-owned evidence directory beneath a trusted path. No component
may be a symlink or writable by group or other users, and none of the receipt
names may already exist:

```console
evidence=/var/lib/kaiba-provisioning/evidence/transaction-rpi5-sacrificial-001
sudo install -d -o root -g root -m 0700 "$evidence"
preflight="$evidence/device-preflight.json"
```

Run the read-only operational preflight:

```console
sudo "$stager/bin/kaiba-provision-media-device-stager" dry-run \
  --plan "$plan" \
  --preflight "$preflight"

sudo jq '{
  hardware_configuration_id,
  execution_hostname,
  requested_device_selector,
  resolved_device_path,
  attachment_boot_id,
  attachment_sequence,
  target,
  sources_verified,
  target_usage_clear,
  target_locked,
  write_performed
}' "$preflight"
```

Review the compiled hardware configuration, resolved attachment, exact
geometry, sources, and `write_performed: false` against the approved
transaction. The reviewed preflight plus a separately authorized invocation of
`stage` is the destructive boundary. The next command overwrites the selected
whole device:

```console
sudo "$stager/bin/kaiba-provision-media-device-stager" stage \
  --plan "$plan" \
  --preflight "$preflight" \
  --receipt "$evidence/stage.json"
```

There is no runtime target override, force flag, fixture mode, or automatic
retry. A reboot, reattachment, selector change, or disk-sequence change
invalidates the preflight and requires a new review. If mutation occurs but
receipt publication fails, quarantine the selected device and reconcile; do
not repeat the write automatically.

The writer invalidates both GPT copies and syncs, zeroes and writes all payload
regions and syncs, writes and syncs the backup GPT, then writes and syncs the
primary GPT. It closes, reopens, and hashes the complete result before
publishing a new immutable receipt.

Next perform a real physical boundary: remove all power from the media, record
that fact under the approved operator procedure, and reattach it. The kernel
attachment tuple must differ from staging. Then use the independently built,
read-only verifier:

```console
sudo "$verifier/bin/kaiba-provision-media-device-verifier" verify \
  --plan "$plan" \
  --stage-receipt "$evidence/stage.json" \
  --receipt "$evidence/verification.json"
```

The verifier independently checks target safety and geometry, GPT CRCs and
semantics, canonical FAT bytes, all four payloads, signed-release and receipt
lineage, every used and padded partition digest, the zero tail, final device
digest, and `veritysetup verify` over read-only partition descriptors. It does
not import or trust the writer implementation.

Close the content-correlation chain only after a separately reviewed canonical
manual cold-power observation has been placed at
`$evidence/cold-power-observation.json`. It must conform to
[`rpi5-media-cold-power-observation-v1alpha2.schema.json`](../schemas/rpi5-media-cold-power-observation-v1alpha2.schema.json),
bind the exact plan plus stage and verification receipt digests, bind the
distinct before/after attachment tuples, record complete power removal, and
retain both `capture_authenticated: false` and `freshness_established: false`.
No authenticated power-boundary collector is implemented here.

Finalize the chain without replacing an existing receipt:

```console
cold_observation="$evidence/cold-power-observation.json"
final_pending="$evidence/final.pending.json"
final_receipt="$evidence/final.json"
set -euo pipefail
sudo test ! -e "$final_pending"
sudo test ! -e "$final_receipt"
if sudo "$contract/bin/kaiba-provision-media-contract" finalize \
    --plan "$plan" \
    --stage-receipt "$evidence/stage.json" \
    --verification-receipt "$evidence/verification.json" \
    --cold-observation "$cold_observation" \
    | sudo tee "$final_pending" >/dev/null; then
  sudo chmod 0600 "$final_pending"
  sudo ln "$final_pending" "$final_receipt"
  sudo unlink "$final_pending"
else
  echo "media receipt finalization failed; preserve pending evidence for review" >&2
  exit 1
fi
sudo jq . "$evidence/final.json"
```

Treat a failed pipeline or an unexpectedly existing output as an evidence
reconciliation case; do not overwrite a receipt. The final receipt correlates
the media content and operation records, but intentionally retains
`hardware_observed: false`, `security_enforced: false`, `mutation_eligible:
false`, and `one_time_settings_changed: false`.

## Claim boundary

A successful cold readback proves that the freshly attached, operationally
selected medium contains the expected bytes. It does not prove that it is the
same physical medium used during staging, because no authenticated media
identity is collected. It also does not prove that a Pi bootloader executed the
bytes or enforced secure boot.

Until a separately authenticated collector and physical campaign establish
more, all correlated media evidence must retain:

```text
hardware_observed=false
security_enforced=false
mutation_eligible=false
one_time_settings_changed=false
```

Media staging is therefore a prerequisite to the later lane transaction, not
authority to program EEPROM, OTP, JTAG, or any other one-time setting. Offline
signature verification, deterministic layout construction, a successful
write, and a cold readback must never be collapsed into a claim that the target
booted the release.
