# Stable-campaign recovery and staging sandbox

The sandbox implements the recovery/write sequence on private regular-file
copies. It consumes the same fixed campaign staging plan and v1alpha2 recovery
requirements as the preparation tools, and exercises real file I/O, fsync,
approval binding, execution journaling, and independent reopened readback.
It creates no physical qualification evidence.

## What the sandbox does

`prepare` first validates the staging plan against the separately supplied SD
and NVMe envelopes and recovery requirements. It derives the final GPT bytes
from the typed layout and checks their hashes against the plan. It then creates
a new private directory containing:

- sparse regular-file disks holding the exact captured recovery ranges;
- one durable backup file for every required range, verified through a new
  read-only descriptor after synchronization;
- verified snapshots of each complete planned partition, including zero
  padding, and the generated final GPT regions;
- a prepared record binding the input contracts, generated files, their local
  inode identities, and the synthetic preview digest.

The input disks and payloads must be regular files. Symlinks, special files,
hard-linked files, and reused input inodes are rejected. All writes target
newly created sandbox files. Only the listed recovery ranges are copied from
the original disk fixtures; unlisted bytes are sparse zeroes. These copies
must not be described as complete backups of the original devices.

`approve` binds a synthetic reviewer identifier to the exact preview. This is
an explicit rehearsal acknowledgement, not authenticated operator identity or
a grant from the live provisioning authority. The local operator controls the
sandbox and its public digest-sealed records; those records do not authenticate
file-creation provenance against that same operator.

`execute` reloads and revalidates the complete contracts, checks the synthetic
file attachments, and verifies all backup, preimage, and source bytes. Before
the first write it durably records `execution-started.json`. It writes complete
partition payloads before the backup GPT and primary GPT, synchronizes the
writes, and independently reopens the outputs for readback. A completed run
retains `execution-complete.json` and emits a synthetic completion report.

The sandbox requires Linux `/proc/self/fd`, `O_PATH`, and a filesystem that
supports regular-file hole punching. Zero chunks replace old bytes with holes
that read as zero, retaining the synthetic disks' sparse allocation. Unsupported
filesystems fail the operation; a failure after the started marker still
consumes the attempt.

The started marker permanently consumes that sandbox's attempt. Interruption,
partial writes, cancellation, changed attachments, or a failed readback must
not lead to a blind retry. Preserve the directory for diagnosis, including its
backups and journal. The tool has no automatic restore or journal-reset action.

## Run with regular-file fixtures

The input fixtures must contain bytes matching their canonical contracts.
The small JSON fixtures used by the recovery-requirements unit tests have
synthetic payload hashes and are not suitable disk images for this command.
For an entirely generated end-to-end exercise, use the integration check below.

For independently prepared fixtures, choose an existing protected parent
directory and a fresh child name. All CLI paths must be canonical absolute
paths. Example:

```console
fixture_dir=/absolute/protected/fixtures
work_dir=/absolute/protected/rehearsal

nix run .#kaiba-rpi5-stable-campaign-sandbox -- prepare \
  --directory "$work_dir/disks" \
  --staging-plan "$fixture_dir/staging-plan.json" \
  --requirements "$fixture_dir/requirements.json" \
  --sd-envelope "$fixture_dir/sd-envelope.json" \
  --nvme-envelope "$fixture_dir/nvme-envelope.json" \
  --sd-image "$fixture_dir/sd.img" \
  --nvme-image "$fixture_dir/nvme.img" \
  --boot-filesystem "$fixture_dir/boot.fat" \
  --root-data "$fixture_dir/root.img" \
  --root-hash "$fixture_dir/root-hash.img" \
  --release-filesystem "$fixture_dir/release.img" \
  > "$work_dir/preview.json"
```

Check that preparation exited successfully and review the exact preview before
creating the synthetic acknowledgement:

```console
nix run .#kaiba-rpi5-stable-campaign-sandbox -- approve \
  --preview "$work_dir/preview.json" --reviewer development-rehearsal \
  > "$work_dir/approval.json"

nix run .#kaiba-rpi5-stable-campaign-sandbox -- execute \
  --directory "$work_dir/disks" --approval "$work_dir/approval.json"
```

Successful output requires independent complete-range readback. A broken
stdout after execution does not mean that writing failed: inspect the retained
journal and completion file, and never rerun a consumed attempt.

## Software checks

```console
scripts/check.sh go ./internal/provisioning/campaignsandbox \
  ./cmd/kaiba-rpi5-stable-campaign-sandbox
scripts/check.sh contracts stable-campaign-sandbox \
  stable-campaign-sandbox-integration
```

The default Go tests use small regular files to exercise real backup and
staging I/O, source and backup tampering, attachment replacement, interruption,
and retry refusal. The dedicated integration check generates fixed-capacity
sparse SD/NVMe fixtures with the selected and legacy physical-end SD lineages
and aligned NVMe prestate, derives actual GPT captures and requirements from
those synthetic bytes, and runs the public preparation and execution APIs.
It hashes the complete planned partition ranges and independently reinspects
the final GPTs, so it needs more time than the small tests. It can also run
directly inside `nix develop`:

```console
KAIBA_CAMPAIGN_SANDBOX_INTEGRATION=1 CGO_ENABLED=0 \
  go test ./internal/provisioning/campaignsandbox \
  -run '^TestPublicCampaignSandboxIntegration$' -count=1
```

These checks run on Linux development hosts or CI VMs without a Pi, signing
token, loop device, or privileged device access. The full integration check is
separate from the normal Go suite and is included in the native Nix checks.

## Physical work still required

Synthetic approval and reports cannot satisfy the live campaign's backup,
attachment, approval, or writer requirements. Physical staging still needs a
reviewed adapter bound to the actual SD/NVMe selectors, current recovery-byte
capture, independently validated readback and attachment observations, and
live operator approval. Real media durability, disconnects, power loss, cold
readback, and Pi boot behavior require hardware qualification. The
[first physical baseline](first-physical-baseline.md) remains the next hardware
milestone.
