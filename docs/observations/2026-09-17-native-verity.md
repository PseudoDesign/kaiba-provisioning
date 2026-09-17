# Native verity observations, 2026-09-17

The existing owned development Pi rejected both deliberately altered root
blocks, then completed an isolated native boot after the pristine bytes were
restored. A final return to the inspection SD verified management access and
healthy root verity. These are scoped physical observations for the selected
native candidate. **Slice B remains incomplete:** firmware-HMAC feasibility and
its secret/lock checks remain open; fleet admission is unevaluated.

The [public observation manifest](2026-09-17-native-verity.json) binds exact
inputs, readbacks, results and private-evidence hashes. This is an engineering
report, not an executable evidence schema, independent attestation, an update
to the canonical development posture, or authority for another operation.
The [earlier positive observation](2026-09-16-native-offline-positive.md) remains
the historical record of the first pristine offline boot and network-time check.

## Candidate and bounded procedure

The reused signed candidate was built from
[`27a73ea3e06c11608911a270f8e7f7f706da792c`](https://github.com/PseudoDesign/kaiba-provisioning/commit/27a73ea3e06c11608911a270f8e7f7f706da792c).
Its boot-image SHA-256 is
`b6ff9cf9f3e6ce925f0ed2ffb91bebf8f08c4c7c1299279f8f13d812cf91a7bd`;
the signed root digest is
`162d93bff118b3de09e92b6d92299f842875ef557c7b52c9d24060c10066a1c5`.
The platform was Pi 5 Model B Rev 1.1 (`a04171`), Linux `6.18.34`, with
bootloader revision `086b83e3332dfc8927c56762771d082f3077a1ae`.
The manifest retains the root/tree/image bindings and source configuration hashes.

The separately approved procedure made four one-shot 4 KiB writes: startup
corruption, startup restoration, probe corruption and probe restoration,
**16,384 logical bytes total**. Fresh root-owned backups retained the two pristine
candidate blocks. Each mutation and restoration verified all five spans before
and after the write, using a fresh read-only descriptor and cache invalidation
for readback. The executor restored the kernel read-only guard and rejected
repeated or out-of-order actions. Its 22 software tests used regular-file
fixtures; the hardware results below come from the physical procedure.

| Case | Device byte offset | Change |
| --- | ---: | --- |
| Startup root | 135266304 | XOR bit 0 at byte 1024 of the 4096-byte block, then restore its exact preimage. |
| Explicit late read | 156061696 | XOR bit 0 at byte 0 of the 4096-byte block, then restore its exact preimage. |

The boot filesystem, original verity tree and both GPT regions matched their
expected hashes throughout. Final readback matched all five pristine spans,
**1,177,204,224 bytes**, before the restored positive control. No new signing,
EEPROM, OTP, key-content or HMAC operation occurred in this procedure.

## Physical results

| Case | Retained observation | Interpretation |
| --- | --- | --- |
| Startup corruption | Native NVMe image/root bindings matched; kernel dm-verity reported data block **0** corrupted. Successful local-action and probe markers were absent. | Explicit rejection of the altered startup root block; absence of a success marker alone was not counted as a pass. |
| Late-read corruption | Secure-boot marker matched; the recorded local action completed, then the explicit probe returned an I/O error and its failure marker. Kernel dm-verity reported data block **5077** corrupted. | The altered probe read was rejected. Console interleaving required the explicit review below. |
| Restored positive control | All three exact success markers appeared in order, including the pristine probe digest; no verity corruption was observed. | Pristine restoration recovered the same candidate's offline boot and bounded local action. |
| Return to inspection SD | NVMe removed; expected SD image, fresh UART-matched SSH key, board/SD inventory, read-only root and valid verity status verified. | Management recovery completed. The enclosure remains unplugged; the host disk-management service is restored and the original USB network profile is active. |

For each native case the operator reported separate USB-C power only, with
Ethernet/PoE, host USB data and other USB storage/network devices disconnected.
The host observed no Pi USB network interface or attached enclosure. The pinned
candidate disables wireless configuration and network-time services. The
restored positive again began with RTC time in 1970 and advanced to systemd's
built-in epoch; the local action did not depend on network-supplied time.
The final SD management session was network-connected and is not an offline test.

### Late-read console interleaving

The original byte-order parser returned **inconclusive** because two kernel
records interrupted the local-action record, including splitting `schema=v1`.
That result and the unchanged raw capture are retained.

The separate capture-specific review recovered the exact expected record by
removing only those two fully retained kernel records from the interrupted
record. No missing marker bytes were supplied. The local-action record carries
time **10.440971**, the probe I/O error **10.444418**, kernel corruption records
**10.449295** and **10.449948**, and the probe failure marker **10.500077**.
The pinned program emits the successful local-action record before opening the
probe. These event timestamps, exact recovered text and program order support
the observed late-read sequence despite asynchronous console byte ordering.

The reviewed result is a scoped engineering interpretation, not an unqualified
pass from the original parser. The manifest preserves both outcomes, the exact
insertion offsets, the review/source hashes and the derived-view digest. The
boot was not repeated and the original UART bytes were not rewritten.

## Retained evidence and limits

All four boot captures completed their full 180-second collection windows and
restored the UART settings. Windows include setup and idle time; they do not
measure boot duration. One earlier probe capture window expired before any
power instruction; it is retained but is not counted as a boot test.

| Private raw capture | Bytes | SHA-256 |
| --- | ---: | --- |
| Startup negative | 67,928 | `9f72b4a94e4c7bf73732db332ac47ef05dc44aee75e2ac2e2a96c72be4d9a323` |
| Late-read negative | 69,521 | `e427fb10d7eb88f31e3e9404edb23767231b5a4ddcf7b6bf5d2bae51c4835de0` |
| Restored positive | 69,111 | `e8b0b3762238751e1a26ec8fb49133efc18b5a54c2fe3a05258d81d02f67b4b3` |
| Final SD return | 70,596 | `a00729eabf3b7e7ec3a1f71bbac98f29a6b80c06aa46314bafe22e3818382bf7` |

Raw captures, full identifiers, operational records and the two candidate-block
preimages remain private on the station. A station-local archive was read back
and all 69 regular-file digests verified; its hash is in the manifest. At the
operator's request there is no off-host raw backup. Git preserves this report
and hashes, which cannot reconstruct the raw evidence.

The original pre-staging filesystem backup spans lost in the earlier host
restart remain unavailable. The fresh backups and restorations here recover
the candidate's blocks, **not the overwritten original NVMe filesystem**.

These results establish the two selected altered-block cases for this candidate.
They do not qualify every boot, update or recovery path, change the development
posture or [fleet admission conditions](../fleet-admission-policy.md), or close
FA-02/FA-03 in full. Firmware-HMAC feasibility, secret/lock checks, protected
persistent state and the later copied-media demonstration remain pending.
Continue with [Slice B](../implementation-staging.md#b-native-offline-boot-and-protected-storage-feasibility)
under its existing execution boundaries; the old online-verifier campaign is
unchanged.
