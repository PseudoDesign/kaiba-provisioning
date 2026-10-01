# Ace disposable NVMe qualification kit

This is a synthetic test installation, not a replacement for Ace's pilot.
Prepare a spare NVMe on Malak; keep Ace's original NVMe disconnected and intact
through the whole physical campaign. Plan two swaps: install the spare, then
restore the original. An unbootable test disk requires an additional reflash
round trip. Do not change EEPROM, OTP, LUKS, the pilot deadline, or Mako.

The image has a read-only ext4 system underneath a temporary RAM overlay, a
read-only firmware partition, and a 4 GiB writable ext4 test partition. The
recovery system and the test data share one physical controller: this reduces
reflashing but cannot guarantee survival of a power cut. Local console root
login is automatic. SSH permits only the two reviewed Malak public keys; host
keys are created on the writable test partition. Confirm their fingerprint at
the console before first SSH. Do not reuse the pilot's known-hosts entry.

SPIRE is pinned to 1.15.2 and Fleet to
`0bd55c576536c29825aada2f7ce6fa052a877402`. The board/kernel inputs match the
reviewed Ace host pin. The trust domain is `nvme-qualification.kaiba.test`.
No pilot private state, real grants, or production configuration enter this
image. Test services bind loopback; only SSH is exposed. The Fleet device
fixture deliberately substitutes its storage observation; the production
client must continue rejecting plaintext storage.

## Build and write later

Build `path:./deploy/nvme-qualification#default` on a native ARM64 builder.
Keep the resulting bundle on Malak. The bundle contains `qualification.img`,
`manifest.json`, this runbook and `host.py`; the manifest includes byte length,
SHA-256, system closure and the scope of the artifact.

On Malak, with the spare attached, first run this read-only command:

```sh
python3 host.py plan --bundle /path/to/bundle \
  --device /dev/disk/by-id/EXACT-SPARE-WHOLE-DISK --out /tmp/nvme-write-plan.json
```

Review model, serial, size, existing partitions and the erase authorization for
that exact drive. Planning never erases. The separate privileged command is:

```sh
sudo python3 host.py write --plan /tmp/nvme-write-plan.json \
  --confirm-plan-sha256 REVIEWED-PLAN-DIGEST \
  --confirm-erase-serial REVIEWED-SPARE-SERIAL --receipt /tmp/nvme-write-receipt.json
```

Mounted disks, swap, device-mapper/RAID, LUKS/LVM and the pilot's partition labels
are rejected. Plans are bound to host, boot, current topology, serial and image.
Writing records an intent before modifying the disk, verifies every image byte
on readback, and never reboots or swaps a device. Preserve the receipt on Malak.

## Attended sequence

1. Save current nonsecret pilot health/identity evidence and confirm the
   original drive can be returned unchanged. Do not copy live database files.
   Any live-pilot backup/export is a separate, encrypted, writer-quiesced
   operation; this image does not export real authority secrets.
2. Cleanly halt Ace, confirm completion locally, remove PoE power, disconnect
   its original NVMe and fit the prepared test NVMe. Reconnect PoE.
3. At the console run `kaiba-qualify status`. Confirm the test hostname, mounted
   test partition and SSH host-key fingerprint. Find the DHCP address with
   `ip -br address`; use a separate strict known-hosts file for the test image.
4. With synchronized time, run `kaiba-qualify identity-init`, then
   `kaiba-qualify identity-check`. Initialize once only. Existing partial state
   is evidence, not permission to silently initialize again.
5. Create a fresh named Fleet case with `kaiba-qualify case prepare CASE`.
   Run checks and the selected crash boundary as described below. Each case
   keeps its own state; commands refuse to overwrite an existing case.
6. Capture each boundary event on Malak and wait for its durable receipt before
   cutting PoE. After power returns, collect status and check that same case.
   Do not infer an acknowledged commit solely from state on the test disk.
7. Run the offline cold-start case only with local-console access. Select
   `kaiba-qualify offline-arm`, cleanly shut down, then cycle PoE. Network
   traffic is blocked before normal network startup, including NTP; PoE stays
   available. Run `kaiba-qualify offline-check` at the console. With no trusted
   time, protected services must refuse startup. This is software isolation,
   not a physical air gap or proof of autonomous offline issuance.
8. Run `kaiba-qualify offline-disarm` locally, then cleanly reboot to restore
   networking. Collect evidence, shut down, remove power and reinstall the
   original NVMe. Verify the pilot's generation, retained identity and service
   health before closing the maintenance window. No deadline is extended.

## Fleet boundaries and independent receipts

Run each case within its freshly created one-hour synthetic admission window.
Expired fixtures are inconclusive; create a new case rather than extending or
editing existing grants. Keep a healthy second synthetic member as a control,
so expired TLS or a total authority outage cannot be mistaken for revocation.

```sh
kaiba-qualify case prepare before
kaiba-qualify case backup before
kaiba-qualify case prepare acknowledged
kaiba-qualify case backup acknowledged
```

Copy the synthetic backup files and their printed SHA-256 receipts to a private
directory on Malak before physical cuts. The only copies must not remain on the
disk being tested. These files contain synthetic private keys and are not public
qualification evidence. Use the separately retained digest for restore.

On Malak, use the separately pinned SSH host key and capture every event before
displaying it. `host.py capture` fsyncs the receipt before printing the event:

```sh
set -o pipefail
ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=./test-known-hosts \
  root@TEST-IP 'kaiba-qualify case before-commit before' \
  | python3 host.py capture --out ./before-cut.jsonl
```

Cut PoE only after `ready-before-commit` appears, within its 20-second window.
If `cut-window-expired` appears or timing is uncertain, preserve the case as
inconclusive and use a new case. After boot, with NTP synchronized:

```sh
kaiba-qualify case check before --expected active
```

For the second case, substitute `case after-ack acknowledged` in the SSH command
and a new receipt file. Wait for `ready-after-ack`, cut PoE, then check:

```sh
kaiba-qualify case check acknowledged --expected revoked
```

Compare case ID, distinct pre/post boot IDs, expected state, retained key hash,
certificate count and successful control-member access against Malak's receipt.
Capture all check outputs on Malak too. The before-commit operation intentionally
holds a real PostgreSQL transaction with a test-only trigger. The after-ack case
uses a completed real Fleet API response. Neither is an arbitrary disk write.

Commands refuse to arm the same case twice. After a crash they reconstruct only
the retained fixture, never `initdb`, new keys or fresh enrollment. A check starts
the existing fixture services and cleanly stops them afterward. Failure means
preserve state and logs; do not substitute a new case for the failed result.

`kaiba-qualify case rehearsal software` runs the pinned lifecycle and same-key
recovery/cutover suite with real services, simulated faults and an isolated
database restore. Its results are software evidence only. The internal
`--simulate-interruption` switch kills test processes for build-time checks; it
never claims a physical power cut.

## Restore rehearsals

Before physical cuts, rehearse a current synthetic case backup:

```sh
kaiba-qualify case restore before --backup-sha256 RETAINED-BACKUP-SHA256
kaiba-qualify case check before --expected active
```

The original case is renamed and retained; restore does not start services.
Restoring an old pre-revocation backup of `acknowledged` must fail a check with
`--expected revoked`. This test profile has no hardware monotonic anchor:
detecting a stale restore through independent evidence is NOT offline rollback
prevention. Never restore such a backup into the live pilot.

SPIRE state has a separate stopped-service backup/restore path:

```sh
kaiba-qualify identity-backup
kaiba-qualify identity-restore /srv/qualification/backups/PRINTED-ARCHIVE.tar RETAINED-SHA256
kaiba-qualify identity-check
```

Copy the synthetic archive to Malak first. Restore preserves the previous tree,
retains original service ownership, and leaves daemons stopped until the explicit
check. Compare the identity manifest hash and workload ID with the original
baseline; certificate rotation may change the leaf serial. This is a current
backup rehearsal, not authorization to resurrect consumed bootstrap grants.

## Scope and recovery

Never run abrupt-loss cases with the pilot NVMe connected. Keep independent
evidence and backup copies on Malak, not solely on the disk being cut. The image
retains no real customer secrets; synthetic backup artifacts still stay private.
No root shell helper automatically runs fsck repair, reformats a partition,
restores an obsolete authority, or retries an ambiguous enrollment operation.

If the writable partition cannot mount, use the local recovery console to
collect `lsblk`, `dmesg` and `kaiba-qualify data-check` with the partition unmounted. Preserve
the damaged image on Malak before repair or reflash. If the boot/system area is
damaged, reprogram the spare on Malak from the retained verified bundle.

Results describe only this exact spare-NVMe profile. All full offline hardware
qualification gates remain open: original-NVMe durability, secure boot,
anti-rollback, hardware-bound keys and trusted offline time are not proven.

## CI boundary

The completed physical campaign retains provisioning revision
`36c104d05949ad54163c6f9a575209331ca58512` and the Fleet revision already recorded
in this directory's lock file. Do not update those historical pins for deployment.
The full synthetic campaign needs the private Fleet source, so it runs in Fleet's
`historical-nvme-campaign` CI job with that repository's read-only token. Public
provisioning CI runs disk-guard unit tests and explicitly reports that it does not
run this private integration. A green public workflow alone is insufficient:
LAN closeout must link a successful Fleet campaign result for this exact pin.
Changes to this campaign require a new reviewed pin and corresponding private
validation; they do not retroactively change the completed physical observations.
