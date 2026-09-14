# Candidate campaign device staging

The per-leg staging candidate implements recovery capture, explicit local
operator acknowledgement, execute-once staging and independent reopened
readback. It operates on SD on `malak` or NVMe on
`kaiba-rpi5-provisioner`; the two devices are never assumed to be attached to
one host. Its Linux block-device adapter is exercised on disposable virtual
disks. Real attachment behavior, media durability and the Pi boot path still
require physical validation.

## Build a bound candidate

`kaiba-rpi5-stable-campaign-stage` is deliberately unconfigured. Device
operations fail before reading caller inputs until a reviewed consumer uses
`lib.mkRpi5StableCampaignStaging` to pin the exact staging plan and complete
partition payloads. There is no runtime device, host, source, force or
configuration override.

For the SD leg, a consumer can expose:

```nix
kaiba.lib.mkRpi5StableCampaignStaging {
  system = "x86_64-linux";
  leg = "malak-sd";
  stagingPlan = reviewedStagingPlan;
  payloads = {
    boot-filesystem = "${reviewedRun}/sd/boot-filesystem.img";
    root-data = "${reviewedRun}/sd/root-data.img";
    root-hash = "${reviewedRun}/sd/root-hash.img";
  };
}
```

Here `reviewedRun` is the reviewed campaign materialization, and
`reviewedStagingPlan` is the immutable store path to the separately prepared
staging-plan JSON. The materialization does not generate that plan. The NVMe
candidate uses `system = "aarch64-linux"`, `leg = "pi-local-nvme"` and exactly
the `release-filesystem` payload at
`"${reviewedRun}/nvme/release-filesystem.img"`. Build it natively or obtain it
from a trusted native ARM builder. All plan and payload paths must be immutable store paths;
the tool revalidates their typed contracts, exact sizes, hashes and zero tails.
The [packet checker](stable-campaign-packet.md) ties those inputs to the first
two selected campaign runs.

The SD candidate protects `malak`'s `/dev/nvme0n1` system disk in addition to
the normal inactive-device inventory. The NVMe candidate must run on the Pi
booted from separate media: it refuses a mounted, root, swap, held or composite
target. Hostname equality and Linux boot ID/disk sequence constrain local
operation; they do not authenticate a board or physical storage identity.

## Prepare and review each leg

Keep raw captures and recovery bytes in an existing root-owned protected
directory outside Git and the Nix store. Every ancestor must be root-owned
and not writable by other users; root-owned sticky ancestors such as `/tmp`
are permitted. An operator-owned home directory is rejected even under sudo.
Run the examples in a root shell with `umask 077` so redirected reports also
remain private. Use the independent v1alpha2 SD and NVMe
envelopes and [recovery requirements](stable-campaign-recovery.md) matching
the exact pinned staging plan. The selected device must still match every
captured preimage byte.

The following is the operator interface for a separately reviewed physical
ceremony. Developing or building this candidate does not execute these steps.

```console
sudo -i
umask 077
stage=/nix/store/REVIEWED-CANDIDATE/bin/kaiba-rpi5-stable-campaign-stage
evidence=/absolute/protected/campaign

"$stage" prepare --directory "$evidence/sd-attempt-1" \
  --requirements "$evidence/requirements.json" \
  --sd-envelope "$evidence/sd-envelope.json" \
  --nvme-envelope "$evidence/nvme-envelope.json" \
  > "$evidence/sd-preview.json"
```

Preparation creates a fresh private directory, captures every selected-leg
recovery range, synchronizes and independently reopens each backup, snapshots
all payloads and generated final GPT bytes, and binds the preview to the
current attachment and file identities. It opens the device read-only. The
backups preserve all required ranges, including both SD GPT lineages; they
are not a complete copy of every disk byte.

Check the successful exit status and review the plan, leg, device attachment,
backup extents and final writes. Supply the reviewed digest explicitly:

```console
"$stage" approve --preview "$evidence/sd-preview.json" \
  --expected-preview-digest sha256:REVIEWED_PREVIEW_DIGEST \
  --reviewer OPERATOR_ID > "$evidence/sd-approval.json"
```

This acknowledgement is a local operator assertion. The reviewer label and
public digest are not a signature or live authority grant. The administrative
operator controls the files and process; they cannot use these records to
authenticate their own observation or close a campaign claim. Apply the
existing human review and explicit physical execution authorization before
invoking `execute`.

## Execute once and verify independently

```console
"$stage" execute --directory "$evidence/sd-attempt-1" \
  --approval "$evidence/sd-approval.json" \
  --requirements "$evidence/requirements.json" \
  --sd-envelope "$evidence/sd-envelope.json" \
  --nvme-envelope "$evidence/nvme-envelope.json" \
  > "$evidence/sd-staging-report.json"

"$stage" verify \
  --requirements "$evidence/requirements.json" \
  --sd-envelope "$evidence/sd-envelope.json" \
  --nvme-envelope "$evidence/nvme-envelope.json" \
  > "$evidence/sd-independent-readback.json"
```

Execution rechecks the independent contracts, all backups, complete snapshots
and target preimages before durably recording the attempt. It writes complete
partition payloads, then backup GPT, then primary GPT and PMBR, synchronizing
the writes and revalidating the attachment. Zero tails are actually written
to the device. It closes the writable attachment and opens it read-only for
complete planned-range hashing before recording completion. `verify` performs
a separate read-only observation of those final ranges and can run after
reattachment; it does not require the old preimage to remain on the device.

Closing the writer can trigger a brief
[udev probe with a shared device lock](https://systemd.io/BLOCK_DEVICE_LOCKING/).
Only execution's final read-only acquisition waits for lock contention, for
at most ten seconds and subject to cancellation. Each acquisition repeats the
full device checks against the original attachment and revalidates the evidence
directory. Other open failures, changed attachments and readback failures stop
immediately. Preparation, preflight, writable opens and standalone `verify`
retain immediate refusal on a busy device. No writes are repeated while waiting.

Repeat the workflow separately on the NVMe host with its configured candidate
and fresh evidence directory. Both legs must be independently verified before
the first baseline boot. Reports describe local mechanical consistency; all
hardware-qualification and campaign-claim flags remain false.

An attempt marker consumes the directory permanently, including after a
partial write, failed synchronization, changed attachment, cancellation or
failed readback. Preserve the journal, backups and last error for manual
reconciliation. A lost stdout or missing completion report is not permission
to rerun. There is no automatic restore or journal reset.

## Software and physical validation

```console
scripts/check.sh go ./internal/provisioning/campaignstaging \
  ./cmd/kaiba-rpi5-stable-campaign-stage
scripts/check.sh contracts stable-campaign-staging stable-campaign-staging-vm
```

The VM check runs only on x86 Linux and uses disposable virtual block devices;
native ARM checks cover the library and package. Unit tests inject interrupted
writes, sync failures and changed attachments. These establish software
behavior, including refusal to retry an ambiguous attempt. Real SD/NVMe
disconnects, power loss, cold readback and the signed-verifier-to-released-OS
transition remain the [physical baseline](first-physical-baseline.md).
