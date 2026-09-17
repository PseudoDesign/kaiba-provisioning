# Native offline positive observation, 2026-09-16

One approved pristine native cold boot completed on the existing owned development
Pi 5, followed by a verified return to the separate inspection SD. The expected
signed image reached its read-only verity root, completed the `/etc/os-release`
check, and read the pristine late-read probe under operator-confirmed network
isolation. **Slice B remains incomplete**: physical corruption enforcement and
firmware-HMAC feasibility remain open. Fleet admission is unevaluated.

The [public observation manifest](2026-09-16-native-offline-positive.json) retains
selected results, exact bindings and SHA-256 references to private evidence. It
is a reviewed engineering report, not a new executable schema, a
`kaiba-provision qualify` result, independent attestation, or operation authority.
The reserved [hardware-qualification evidence](../../tests/evidence/README.md)
and canonical development posture are unchanged.

## Inputs and scope

The candidate source is
[`27a73ea3e06c11608911a270f8e7f7f706da792c`](https://github.com/PseudoDesign/kaiba-provisioning/commit/27a73ea3e06c11608911a270f8e7f7f706da792c),
not this report's commit. The platform was Pi 5 Model B Rev 1.1 (`a04171`),
Linux `6.18.34`, with installed bootloader revision
`086b83e3332dfc8927c56762771d082f3077a1ae` (2026-05-26 16:01:25 UTC).
The bootloader's native UART revision matched the public version read after
returning to SD. Full board/media identifiers and SSH fingerprints stay private;
the manifest binds their inventory records by digest.

The boot-image SHA-256 is
`b6ff9cf9f3e6ce925f0ed2ffb91bebf8f08c4c7c1299279f8f13d812cf91a7bd`;
the signed root digest is
`162d93bff118b3de09e92b6d92299f842875ef557c7b52c9d24060c10066a1c5`.
The manifest also records root/tree hashes, both signed root PARTUUIDs, expected
local-action/probe hashes, and the pinned configuration-source hashes.

A fresh read-only enclosure check before this attempt matched all five staged
spans: primary GPT, outer boot FAT, root data, root tree and secondary GPT,
totaling **1,177,204,224 bytes**. The independent readback finished at
2026-09-16 23:07:07 UTC. The native boot and SD return reused the existing signed,
staged bytes; this bounded attempt performed no new signing, storage writes,
EEPROM changes or OTP/secret operations. Earlier staging/signing are separate
operations, not implied to be write-free.

## Observations

| Case | Retained result | Limit |
| --- | --- | --- |
| Cold boot offline | NVMe boot with the exact signed-image marker, read-only verity root and expected OS digest; no SD fallback observed | Physical cable/power isolation is operator-reported; the host independently observed no Pi USB gadget. This is the bounded local action, not full fleet-application qualification. |
| Unavailable network time | The same boot and local action succeeded. RTC began at 1970-01-01 00:00:20 UTC; systemd advanced to its built-in epoch, 2026-03-17 19:55:52 UTC | This is a local epoch adjustment, not network-supplied time or a test of every clock condition. |
| Pristine probe read | The first explicit late-read probe produced the expected digest after the local OS check | A successful pristine read does not demonstrate tamper rejection. |
| Return to inspection SD | NVMe was physically removed; expected SD/board inventory, fresh UART-matched SSH host key, read-only root and valid verity status were verified | The enclosure route replaces the failed boot-menu approach. Returning to SD does not restore the old NVMe filesystem. |
| Host cleanup | Temporary USB profile removed; original inspection network active; disk-management service restored with enclosure disconnected | A future enclosure attachment requires its own guard and fresh attachment check. |

The operator reported using only the separate USB-C power supply for the native
boot, with Ethernet/PoE, USB management and other USB storage/network adapters
disconnected. The exact candidate disables wireless configuration and network-time
clients. Its missing regulatory database diagnostic agrees with that pinned
configuration; it is recorded in the manifest.

Both UART captures ran for their full 180-second collection windows, with final
hash verification and serial settings restored. Capture times include setup and
idle time; they are not measurements of boot duration.

| Private capture reference | Bytes | SHA-256 |
| --- | ---: | --- |
| `uart-capture.9vvfnxz2/uart.raw.log` — native positive | 69,333 | `7a369e6b54643a84aa7f765cc3ba606e1bb6db7f40113eb193955d67a74d99c9` |
| `uart-capture.oy5hxpjc/uart.raw.log` — return to SD | 71,317 | `90cb21f925cc06d7b676949bd2fa251293d1b2367428854f245a591e0d521ca4` |

## Retention and missing material

Raw captures, operational records and full identifiers remain privately retained
on the station, following the [handoff's evidence boundary](../native-offline-handoff.md#bounded-physical-experiment).
A private station-local archive was read back and all 63 file digests verified.
Its digest is in the manifest. At the operator's request, no off-host raw archive
was created. This Git record preserves the public report and hashes; **it is not
a backup of the raw captures**, and hashes cannot reconstruct their contents.

A host restart had removed the earlier `/tmp` captures and the five original
pre-staging NVMe backup spans. Those original bytes remain unavailable. Fresh
post-restart readback and the two complete captures above establish the stated
observations; earlier lost logs are not counted as retained evidence. The signed
candidate can supply pristine candidate bytes, not the overwritten original
filesystem. Keep this distinction explicit in any subsequent restoration plan.

## Remaining gates

- Run the separately authorized startup-root and late-read corruption cases,
  requiring explicit kernel verity rejection. Restore/read back pristine bytes
  and repeat the positive control afterward.
- Complete firmware-HMAC feasibility and the mechanism-specific secret/lock
  observations; preserve a supported path or a specific failed assumption.
- Implement and qualify protected persistent state, including the later
  original-board/comparable-board copied-media demonstration.

This observation does not close FA-02 or FA-03 in full, waive any
[fleet admission condition](../fleet-admission-policy.md), change the offline
rollback decision, or promote the old online-verifier campaign. Continue with
[Slice B](../implementation-staging.md#b-native-offline-boot-and-protected-storage-feasibility)
under the existing execution boundaries.
