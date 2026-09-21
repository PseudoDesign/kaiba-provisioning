# Remaining lock-rejection observations — 2026-09-20

The bounded development sequence completed on the owned Raspberry Pi 5. Its
read-only assessor reported `matched-target-and-kernel-observations`. This is a
scoped engineering observation, not a strict qualification-harness pass or fleet
admission. The companion JSON binds the retained private evidence by hash.

The exact helper source was `0f3038ba9bcbd887866b73a472de67c66c37650a`.
The inspection system used kernel 6.18.34 and firmware prefix `a8698392`. One
normal authenticated inspection reboot preceded the sequence; this was not an
offline cold-power test. No media, EEPROM, OTP or usage programming occurred.

| Check | Observation |
| --- | --- |
| HMAC control | Succeeded. |
| Signing control | Passed the development-only DER compatibility rule for a 40-byte advertised count. Canonical P-256 structure was checked; the signature was not cryptographically verified. |
| Crypto private read | Original Linux EINVAL retained; paired kernel observation showed a structurally valid marked error response with unchanged-or-zero payload. |
| Legacy private reads | The helper's pinned legacy-read exception passed; the observer does not inspect legacy payloads. |
| Signing after closure | Original Linux EINVAL retained; paired kernel observation showed a structurally valid marked error response with unchanged-or-zero payload. |
| Attempt to clear locks | Returned EINVAL. Immediate successful status readback showed all locks set **before** cleanup, establishing retention for this attempt. |
| Cleanup and final state | Locks closed; authenticated return remained on the same inspection boot with root dm-verity V. |

The failed raw-read, closed-signing and clearing calls remain failed operations
in the records. Their errors are not relabeled successful calls. Separate
last-error queries for crypto read and signing returned KEY_LOCKED, but those
global values are not transaction-correlated. The kernel observations provide
the paired error/payload evidence for those two calls; clearing retention rests
on its immediate status readback, not on errno or final cleanup status.

This completes the selected development observation sequence. Generation and
usage protection was observed only as lock bits; irreversible writes were not
tested. The strict qualification harness remains unchanged, hardware qualification
is false, copied-media confidentiality awaits a functioning comparable-board
test, and fleet admission remains unevaluated. No independent identity proof or
independent audit verification is claimed.

Raw UART and tool captures remain private on malak. This public candidate excludes
device serials, boot IDs, SSH details, key/signature bytes and raw captures. Hashes
bind retained bytes and cannot restore them or provide independent attestation.
This report grants no execution authority.
