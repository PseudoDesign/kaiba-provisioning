# Firmware HMAC rejection observation, 2026-09-20

The existing development Pi completed three positive HMAC comparisons, closed
its runtime locks, then rejected the fourth HMAC call. A passive eBPF observer
captured a structurally valid, response-marked operation-error tag with no new
payload bytes before Linux discarded that buffer and returned `EINVAL`.

This resolves the missing-payload observation for this exact call. It does not
turn the original helper failure into a pass or complete lock qualification.
The [manifest](2026-09-20-hmac-lock-rejection.json) records the separate findings
and hashes of private evidence. It grants no execution or admission authority.

## Method and results

The observer came from [PR #50](https://github.com/PseudoDesign/kaiba-provisioning/pull/50),
commit `ef66ce160bd0e38943825afbd27d829666368785`. Required CI passed at that head.
Its inert preflight loaded and attached both probes on the existing inspection
kernel, then detached without selecting a process or issuing a firmware call.
The separately approved one-shot packet then observed the unchanged development
helper. No new image, kernel build, signing ceremony, drive move or reboot was
needed. Raw buffers were not exported.

| Step | Observation |
| --- | --- |
| Positive HMAC controls | Control, repeated-input and changed-input comparisons succeeded; three complete observer records agreed with the helper. |
| Runtime closure | The helper applied all five runtime lock bits and read back closure. |
| Post-closure HMAC | Linux returned `-22` (`EINVAL`). The corresponding kernel-buffer observation had valid request/reply structure, a response marker, an operation-error bit and an unchanged-or-zero payload. |
| Separate error query | The helper immediately read `KEY_LOCKED`; this is separate metadata, not proof of transaction correlation or freshness. |
| Cleanup and final state | The observer detached and exited normally. Read-only checks confirmed the same inspection boot, all five runtime lock bits still set and healthy root verity (`V`). |

Exactly four HMAC calls and two volatile lock writes occurred in the bounded
helper sequence. There were no raw-key reads, signing operations, OTP programming,
media writes or power operations. The observer reported all four expected calls,
with no rejected observations or failed copies. No unexpected stderr was recorded.

The helper retained **exit 3 and `passed=false`**: its existing user-space transport
cannot validate a response discarded by `vcio`. The separate assessment records
`tagged-error-no-new-payload`; both qualification flags remain false. Neither the
original stdout nor its result was rewritten, and the failed operation was not
retried.

## Interpretation and remaining work

Previously, the [Linux-boundary assessment](../device-secret-rejection-evidence.md)
could establish only an API error with an immediate `KEY_LOCKED` query. This
observation adds evidence about the failed call's actual returned tag and payload:
the tag was marked as an error and contained no new payload bytes. It does not
reveal the mailbox's top-level response code or bind the global last-error value
to that transaction.

Adopting observer-backed results in the qualification harness still requires a
reviewed evidence contract and acceptance decision. Crypto/legacy raw-read denial,
signing closure, resistance to clearing locks and final protection-profile
qualification are not established by this HMAC-only run. Generation and usage
locks were observed as status bits; irreversible writes were not attempted.
Copied-media confidentiality still needs a functioning comparable board.

Private captures, exact boot/connection identifiers and execution records remain
on malak. Public hashes cannot reconstruct those records. The Pi remains on the
inspection SD with the development slot's runtime operations closed; this report
does not authorize another invocation or a reboot to clear them. The
[fleet admission policy](../fleet-admission-policy.md) is unchanged.
