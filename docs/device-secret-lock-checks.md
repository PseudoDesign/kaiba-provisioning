# Remaining device-secret lock checks

This development-only sequence pairs the passive kernel observer with a bounded
helper to test crypto and legacy read denial, signing closure, and resistance to
clearing runtime locks. Software checks use synthetic firmware. Physical execution
and final qualification remain pending; no execution authority is built into the
helper, observer or assessor.

## One fresh inspection boot

The separately built `kaiba-device-secret-lock-checks` accepts only `locks` and the
existing slot/usage/boot-ID arguments. The ordinary development helper's commands
and contracts remain unchanged. Neither binary can generate a key or write OTP or
usage fields. The observer requires explicit `--lock-checks` selection; its default
continues to run only the previous HMAC experiment.

The helper refuses an already HMAC/signing-closed slot. After checking identity,
metadata, locked memory and disabled swap/core dumps, it executes this fixed order:

1. Apply READ/GEN/USAGE restrictions and verify status.
2. Perform one HMAC control and one signing control using fixed public inputs.
   A signing control validates the API response shape; it is not an independently
   verified signature or an enrolled-identity proof. No output is exported.
3. Probe crypto private-key read denial, then the two pinned legacy read paths.
4. Close all runtime operations and verify all five lock bits.
5. Probe signing denial with the same fixed public input used by the control.
6. Request clearing the runtime locks and verify that all lock bits remain set.
7. Always attempt final closure and readback after any runtime mutation, including
   after failure or interruption. Stop; never retry, power-cycle or continue a
   failed sequence automatically.

Bounds are **one HMAC call, two signing calls, three read probes and four volatile
lock writes**, including the clearing request and final cleanup. The read probes
could materialize key bytes in process/kernel memory if protection fails; bytes
are wiped and never emitted. Unexpected read/sign success stops the sequence.
A successful clearing request is judged by status, not its return code: cleared
bits fail the check and trigger final closure. A failure after mutation may leave
state uncertain and requires reconciliation.

A concrete execution packet must authorize those operations on the exact owned
development slot and bind the boot, artifacts and one-shot intent. A fresh normal
inspection reboot and authenticated UART/SSH return need explicit inclusion if
required. No new image, kernel, signing ceremony, media write or drive move is
needed for this software. No reboot or secret operation is implied by a build.

## Preserve failures and assess the paired evidence

The helper emits `kaiba.device-secret-lock-checks/v1alpha1` with `completed`,
`cleanup_locks_closed`, ordered step records and `hardware_qualified=false`.
`completed=true` means the bounded observation sequence finished, not that every
operation succeeded or hardware qualified. Exit 0 means completed; exit 3 means
stopped. Each negative crypto operation retains its original result. An `EINVAL`
step remains `passed=false`, outcome transport failure and errno 22. An immediate
successful `KEY_LOCKED` query permits observation to continue, but never by itself
validates denial. Other errnos or error-query failures stop and clean up.

The read-only assessor consumes exactly two lines: the helper JSON, then the line
prefixed `KAIBA_FIRMWARE_OBSERVER=`. Its closed plan contains `schema_version:
kaiba.device-secret-lock-checks-plan/v1alpha1`, `boot_id`, `slot_id` and
`expected_usage`, from the reviewed packet:

```console
nix run .#kaiba-device-secret-lock-assess -- \
  --plan /absolute/private/lock-plan.json \
  --capture /absolute/private/lock-capture.txt
```

It requires all metadata, positive controls, ordered lock/cleanup records and four
complete kernel observations: HMAC control, signing control, crypto read denial,
and signing denial. Both negative records must show structurally valid marked
error responses with unchanged-or-zero payloads. Errnos must agree with the helper.
Missing, extra, malformed, copied/mismatched or contradictory records reject the
assessment. Unexpected payload bytes reject it even with `KEY_LOCKED` metadata.
The legacy-read result still uses the existing dedicated helper validation;
legacy payloads are not observed by this eBPF program.

Success is `matched-target-and-kernel-observations`. Claims explicitly distinguish
observed crypto/signing rejection, the helper-validated legacy exception, retained
lock status after the clearing request, and generation/usage status bits that
were **not** tested with irreversible writes. Original failed-operation names remain
in the assessment. The global last-error value is still not transaction-correlated.
`hardware_qualified` and `execution_authority` remain false. Hashes bind retained
bytes, not independent attestation against a privileged station operator.

This is a separate development evidence contract. It does not change the
[qualification harness](device-secret-target-harness.md), the
[fleet admission policy](fleet-admission-policy.md), or qualify copied-media
confidentiality. Adopting these observations in a final protection profile remains
a reviewed decision.

## Software verification

```console
nix build .#checks.x86_64-linux.device-secret-development \
  .#checks.x86_64-linux.firmware-rejection-observer
```

Native ARM CI builds the same checks. Synthetic tests exercise exact operation
bounds/order, stopped controls, unexpected disclosure/success, transport failures,
stale/contradictory metadata, interruption, clearing failures with side effects,
cleanup and strict pairing of helper and observer records. Neither these tests nor
a successful build establish physical lock behavior.

## Response-validation diagnostics

A malformed reply still fails the operation and triggers the existing cleanup.
The development helper additionally writes a fixed `KAIBA_RESPONSE_VALIDATION`
line to stderr at the failed step, before cleanup can replace the diagnostic.
Its `step` and `reason` are program literals; no response bytes, signature, key,
raw status word or numeric response lengths are emitted. The JSON contract and
assessor acceptance rules are unchanged. Executors must retain stderr alongside
stdout; these diagnostics do not issue another mailbox call.

Reasons distinguish message framing, tag metadata, completion marking, nonzero
operation status, output length bounds, output extending beyond the reported
response, changed error payload, and failure of the existing error query. They
identify which validation predicate rejected a reply, not whether firmware or
the helper's ABI assumption is wrong. Software tests exercise these cases and
verify that later cleanup cannot erase the emitted reason. Physical diagnosis
still requires a separately authorized experiment; no validation is relaxed.
