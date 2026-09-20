# HMAC rejection evidence at the Linux boundary

Assess saved development results before scheduling another firmware experiment.
The development assessment distinguishes successful HMAC comparisons, lock-status
readback and a Linux API failure from validation of the firmware's error payload.
It does not change the qualification harness's acceptance conditions or convert a
failed attempt into a pass.

## Why the error payload can be unavailable

The pinned Raspberry Pi Linux 6.18.34 source is revision
`c8c7494100e99ee05b11aaa4f0588a223a63d1af`. Its
[firmware property driver](https://github.com/raspberrypi/linux/blob/c8c7494100e99ee05b11aaa4f0588a223a63d1af/drivers/firmware/raspberrypi.c)
copies the returned tags into a kernel buffer, but returns `-EINVAL` when a
completed mailbox transaction has an unsuccessful top-level response. Its
[`vcio` driver](https://github.com/raspberrypi/linux/blob/c8c7494100e99ee05b11aaa4f0588a223a63d1af/drivers/char/broadcom/vcio.c)
then frees that buffer and returns the error before `copy_to_user`. Other invalid
requests can also produce `EINVAL`.

Consequently, a user-space helper receiving that error cannot inspect the
firmware's returned payload. The helper's cleared output buffer does not establish
what the firmware or kernel buffer contained. Repeating the same call through the
same driver cannot resolve this observability limit.

The pinned [firmware-crypto header](https://github.com/raspberrypi/utils/blob/292dbe7e35296e556d839a0b9ae2ca957ac8c961/rpifwcrypto/rpifwcrypto.h)
defines `KEY_LOCKED` as error 4. The development helper's immediate last-error query
is a separate mailbox call. Its ordering improves the diagnostic value, but does
not bind that metadata to the failed transaction or establish that it is fresh.
The source analysis explains a possible failure path; it does not prove which
path a particular hardware request took.

## Decision for development evidence

Keep these claims separate:

| Recorded sequence | Supported interpretation | Still unestablished |
| --- | --- | --- |
| Successful control, repeated-input and changed-input HMAC comparisons | The helper observed repeatability and input separation in that boot | Cold-boot repeatability, LUKS persistence and copied-media protection |
| Successful closure followed by all five runtime lock bits set | The helper observed lock-status closure | Behavioral protection of every read, signing or write path |
| Those controls and closure, followed by HMAC `EINVAL` and an immediate successful `KEY_LOCKED` query | Linux rejected the operation; the sequence is consistent with lock rejection | A transaction-correlated firmware error, a validated error payload or a qualified protection check |
| Those controls and closure, followed by the helper's validated locked response | The helper validated the response according to its existing checks | Complete hardware qualification or other untested operations |

The third row is useful development evidence, while its operation and session
remain failed. An unexpected errno, missing control, intervening query, failed
cleanup or contradictory record cannot establish that sequence. The assessment
does not generalize the dedicated legacy-read exception to HMAC, signing or
crypto private-key reads.

## Assess a saved attempt

```console
kaiba-device-secret-development-session assess-hmac \
  --state /absolute/private/existing-session --attempt 0002
```

This command reads the existing session, intent, stdout, stderr and result. It
checks the session binding, boot/slot/usage, stdout digest, recorded result and
exact ordered steps. It acquires the existing local session lock without creating
one; it never contacts SSH/UART, loads a helper onto the Pi or changes evidence.
Failed and expired sessions can be assessed. Keep the output private alongside
the original evidence until its public projection is separately reviewed.

The output schema is `kaiba.device-secret-hmac-assessment/v1alpha1`. `source`
records the attempt, session/helper digests, and result/stdout digests. Claims use
the following values:

| Field | Values |
| --- | --- |
| `hmac_controls`, `runtime_lock_closure` | `observed` or `not-established` |
| `post_closure_rejection` | `linux-error-with-immediate-key-locked`, `helper-validated-locked-response` or `not-established` |
| `firmware_error_payload` | `unavailable`, `validated-by-helper` or `not-established` |
| `lock_cause` | `consistent-with-lock-rejection` for the Linux-error sequence; otherwise `not-assessed` |

`recorded_result` preserves the original pass/fail value. `hardware_qualified`,
`execution_authority` and `session_continuation_authorized` are always false.
Exit status zero means the assessment was produced, including when the recorded
test failed. Invalid or inconsistent evidence rejects assessment. File hashes
provide traceability, not independent authentication against the trusted station
operator. An assessment is not permission to repeat an operation, reboot, or
continue a failed session.

## Remaining qualification decision

The [mechanism acceptance cases](device-secret-feasibility.md#bounded-mechanism-experiment)
and [target harness](device-secret-target-harness.md#firmware-checks-and-evidence-limits)
remain authoritative. A future change must select and review one of these paths
before treating this Linux error as satisfying operation closure:

| Planned path | Resolving work | Decision it blocks |
| --- | --- | --- |
| Qualify the Linux API boundary | Define the profile's denial claim explicitly, test unrelated/malformed failures and stale last-error metadata, and review how controls and closure establish the claim without assuming a firmware payload | Adopting Linux-level rejection as sufficient evidence in the selected profile and harness |
| Observe the firmware response inside the kernel | Review a narrowly scoped observation mechanism that emits public booleans/status only, excludes secret-buffer export, and distinguishes malformed/transport failures; test and deploy it under separate authority | Retaining a requirement to validate the firmware error payload on this driver path |

Neither path is implemented or approved by this assessment. Both require their
own software review; any new signing, deployment or physical experiment also
needs its applicable execution authority. No kernel change or repeat hardware
run is needed to classify the evidence already saved.
