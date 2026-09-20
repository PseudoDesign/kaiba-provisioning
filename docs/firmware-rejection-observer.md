# Passive firmware rejection observer

The experimental observer inspects the pinned Linux firmware driver's tag buffer
at function return, before `/dev/vcio` discards it on error. It reports only
structural and non-disclosure booleans. It never supplies a mailbox request,
changes the return value or exports response bytes. This implements the diagnostic
part of the [kernel-observation path](device-secret-rejection-evidence.md#remaining-qualification-decision).
It is **not a qualified lock test** or a change to the target harness's acceptance
rules. Hardware validation remains pending.

## Existing kernel, bounded helper

`kaiba-firmware-rejection-observer` contains a static ARM-capable launcher and an
eBPF object for the AArch64 register ABI. It uses the inspection kernel's existing
kprobe/BPF support; it needs no kernel rebuild, module installation, boot-image
change or signature. The launcher refuses another architecture. Build and check:

```console
nix build .#packages.aarch64-linux.kaiba-firmware-rejection-observer
nix build .#checks.x86_64-linux.firmware-rejection-observer
```

A separately reviewed execution packet supplies exact object/helper hashes, the
inspection boot ID, slot and usage, and a one-attempt record. The launcher is not
an authorization service. Do not invoke it outside that packet.

A `--verify-only OBJECT` preflight loads and attaches the probes with no selected
process, then immediately detaches; it never starts a helper or issues a firmware
request. It validates kernel acceptance only.

Before releasing a child process, the launcher loads both entry/return probes and
sets their filter to that child's PID. The child runs only the existing development
helper's `hmac` mode: three positive comparison calls, bounded volatile lock closure,
and one negative HMAC call. It has no raw-read, signing, key-generation, media-write
or reboot selection. The helper keeps its original result and exit status.

The observer detaches before reaping the child, so its PID cannot be recycled
while the filter is active. It bounds observation to 45 seconds, requests helper
termination on interruption/timeout, allows five seconds for cleanup, then kills
if necessary. Failed attachment never releases the child. An interrupted helper
or unconfirmed closure requires reconciliation, not an automatic retry. Process
exit releases unpinned BPF resources; no persistent service is installed.

## What is recorded

The BPF programs inspect only the selected child's HMAC, crypto-read and signing
shapes supported by the shared classifier; the launcher selects HMAC only.
Metadata requests are ignored. Invalid requests, concurrent pending calls and
event overflow are counted as rejected observations. There is one pending call
and at most 32 result slots. Missing return callbacks leave incomplete events;
missing entry callbacks are detected by comparing the exact expected four HMAC
calls with the helper's ordered records. A complete launcher run alone does not
prove complete observation.

The line prefixed `KAIBA_FIRMWARE_OBSERVER=` has schema
`kaiba.firmware-rejection-observation/v1alpha1`, launcher completion, original
helper exit status, rejected-observation count and ordered events:

- Original tag, kernel return code and whether copying/classification completed.
- Whether request and returned tag/capacity/length/padding satisfy the bounded ABI.
- Whether the response bit and operation-error bit are present.
- Whether all returned data after the operation-status word remained the original
  request or was entirely zero. Any new byte makes this false.

No returned payload byte is emitted, even for successful HMACs, malformed replies
or apparent disclosure. Request snapshots and temporary response copies stay in
kernel maps and are explicitly cleared after classification. This does not claim
protection from privileged map access, kernel compromise, RAM inspection, or
zeroization of the firmware driver's own buffers. The observer process disables
core dumps; the existing helper still enforces locked memory and disabled swap.

## Interpret results conservatively

Retain the raw private helper and observer output together. Check exact packet,
boot/slot/usage, four ordered HMAC events, successful pre-closure controls and
cleanup, and no rejected, incomplete or failed-copy events. Compare each event's
return code with the helper's recorded call. A stale last-error query cannot make
an unrelated errno or malformed response into a pass.

A valid tagged operation-error response with unchanged/zero payload supplies new
non-disclosure evidence for that exact failed call. It does not expose the mailbox's
top-level response code, prove freshness of a separate last-error query, establish
that locks cannot be cleared, or change a failed helper result into a successful
qualification run. An unchanged request with no response marker remains
inconclusive about the firmware reply. Keep unexpected or contradictory results
as failures and resolve the specific assumption before another experiment.

The next physical packet must be reviewed for the exact existing development key,
four HMAC calls and at most two volatile lock writes (including closure). No OTP
programming, lock-clearing attempt, raw-key read, signing, media modification or
power cycle is included. Other lock checks need their own bounded packet; the
[fleet admission policy](fleet-admission-policy.md) is unchanged.
