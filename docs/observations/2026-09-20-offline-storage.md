# Original-device offline storage observation, 2026-09-20

The owned development Pi created an encrypted private test record without network
access, then reopened and authenticated that same record after the guided cold-power
cycle. It returned successfully to the inspection SD. This establishes the selected
original-device persistence case; **lock rejection, copied-media confidentiality and
fleet admission remain unqualified**.

The [public manifest](2026-09-20-offline-storage.json) records candidate bindings,
scoped results and private-evidence hashes. It is an engineering observation, not
independent attestation, an admission record or permission for another operation.

## Candidate and procedure

The signed candidate came from [PR #48](https://github.com/PseudoDesign/kaiba-provisioning/pull/48),
source `ccea2906c4ba0582132abb8827a354531fb5e017`, whose tree matches merged main
`b4b23cd91c0338702a35cbf064d41968ee8b41d4`. The manifest binds its exact signed boot
image and dm-verity root. All artifact signatures and authenticated signing receipts
were verified before staging; the signing gate was stopped and its PIN source removed.

Six bounded spans totaling 1,376,802,304 bytes were staged after fresh private backups.
Full readback matched the expected image, root, verity tree, disposable test partition
and GPT spans. The earlier remote experiment partition was preserved. The new root
and hash tree occupy separate extents; the new disposable partition has its own
one-use journal. No OTP programming or EEPROM change occurred in this experiment.

NVMe stayed installed. With the Pi fully unpowered, the operator removed the
inspection SD for the native boots, then reinserted it for management return.
For each cold boot, the guide required disconnecting PoE, USB data, the separate
supply and the probe's host USB cable, confirming LEDs off and waiting ten seconds.
The probe was reconnected before passive UART capture; only the separate USB-C
supply powered the offline test. Network and other USB storage paths remained
operator-confirmed disconnected. These physical conditions are separate operator
evidence, not facts proved by UART, a boot ID or the assessor.

## Results and recovery

| Case | Recorded result |
| --- | --- |
| Offline create | Firmware-HMAC-derived LUKS creation and private-record verification completed; storage closed, journal completed and runtime lock closure reported. |
| Offline cold reopen | A distinct boot reopened the same volume and authenticated the same private test record using the expected signed image and verity root; cleanup completed. |
| Inspection SD return | UART-bound SSH authentication passed; the expected inspection SD root reported healthy verity (`V`). NVMe remained installed and all its partitions were unmounted. |

The production capture assessor independently reprocessed both saved UART captures
and matched the recorded pair assessment. Its qualification and physical-verification
flags remain false by design. No raw key, HMAC output or private record is included
in this public report.

An initial whole-image RAM-upload preparation stopped before upload or any media
write because inspection RAM was insufficient. The reviewed bounded streaming
continuation made the one actual staging attempt. The first guided boot session
later completed inspection shutdown but timed out before its first physical-off
acknowledgement; it recorded no experiment boot. Its evidence was preserved.
After confirmation that power cabling and media were unchanged, a separate
continuation completed the two native boots and management return. No completed
experiment was retried or original result overwritten.

Raw captures, identifiers, operation records and recovery backups remain private
on malak, as requested. Git preserves this report and hashes, which cannot restore
the raw evidence. The candidate remains staged and its create/reopen journal is
consumed: another boot is not permission to repeat the experiment.

## Remaining work

This closes the scoped original-device offline create/reopen demonstration in
[Slice B](../implementation-staging.md). It does not establish behavioral rejection
of locked operations, resistance to clearing locks, confidentiality on a functioning
comparable board, or protection of an enrolled fleet identity. Continue with the
[lock-rejection evidence work](../device-secret-rejection-evidence.md) and the
copied-media demonstration under their applicable execution authority. The
[fleet admission policy](../fleet-admission-policy.md) and development posture are
unchanged.
