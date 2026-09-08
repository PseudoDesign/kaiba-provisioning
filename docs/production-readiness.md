# Production readiness

## Current decision

This repository is **not production-ready**. The canonical posture is
`approved-development-only`, covers one sacrificial development unit, sets
`production_ready` to `false`, and keeps `enrollment_ready` false. The presence
of signed inputs, passing software contracts, or a terminal
`security_applied` record does not change that decision.

This assessment follows the status language in the [documentation
index](README.md): implemented, tested, evidenced, and planned are distinct
claims.

## What is established

| Area | Status | Repository evidence | Scope limit |
| --- | --- | --- | --- |
| Device-class preflight | Evidenced | `tests/evidence/sacrificial-pi-5.json` records two matching live RPIBOOT observations and a passed reversible qualification | The record says `mutation_eligible: false`, does not establish the full unprovisioned state, and is correlation rather than attestation |
| Public release lineage | Implemented, tested, evidenced | Versioned schemas and finalizers plus the public `releases/rpi5-v0.1.6/` signed inputs | Public cryptographic material does not prove live target state or authorize a mutation |
| Development signer identity | Implemented, tested, evidenced | Public key and `signers/development-prototype/independent-review-2026-08-27.json` | Review is for the sacrificial signer; it does not prove present token custody or issue a grant |
| Signing gate and receipts | Implemented, tested | Exact grants, durable anti-replay state, artifact signatures, and signed receipt attestations have software and deployment tests | Dedicated-host root remains trusted; the workflow is development-only and live token use is outside automated tests |
| Control and audit authority | Implemented, tested | mTLS services, role checks, compare-and-swap state transitions, fence epochs, and hash-chained audit receipts | The included PKI generator and fixed deployment are explicitly development PKI |
| Seven-operation lane | Implemented, tested | Compiler-owned operation sequence, authority bridge, execute-once journal, and reconciliation tests | Target-facing GPIO, USB, UART, power, and mutation paths are simulated in the automated contracts |
| Media construction | Implemented, tested | Deterministic GPT/FAT/root/verity plans, host-bound selectors, writer/readback, and independent verification contracts | No checked-in qualification proves a complete live production-media and cold-power cycle |
| Read-only root design | Implemented, tested | `secure-boot-target.nix` requires `/dev/mapper/root`, dm-verity, tmpfs mutable state, no swap, volatile journal, and no core dumps | The posture explicitly records physical enforcement as unqualified |

## Explicit production blockers

The canonical development posture names the following blockers. They are
requirements, not optional hardening ideas.

### Boot policy

**Planned / blocked.** The current EEPROM configuration uses
`BOOT_ORDER=0xf216`, evaluated as NVMe, SD, network TFTP, then restart. The
production boot-order value remains undecided and requires qualification.
`BOOT_UART=1` is an existing development setting whose production policy has
not been reviewed.

### Debug restrictions

**Planned / blocked.** VideoCore JTAG is deliberately unlocked in the
development posture. The probe's `JTAG_LOCKED` observation is limited to
VideoCore and does not establish the state of every processor or physical
debug path. A production debug policy and evidence method are still required.

### EEPROM write protection and update policy

**Partly implemented / blocked.** The initial EEPROM update is constrained to
a transaction-bound, signed, one-shot fresh-board RPIBOOT operation with
prestate, readback, and reconciliation requirements. Effective EEPROM write
protection remains unlocked for development, and its production value is
undecided.

### Recovery

**Implemented as a development contract / blocked for production.** Recovery
is narrow, customer-signed, prebuilt before ownership, and permitted only after
owned state. Stock, unsigned, wrong-key, and altered recovery inputs are
rejected by the contract. The posture nevertheless marks recovery as not
production-qualified.

### Automatic self-update

**Implemented development setting / blocked.** `ENABLE_SELF_UPDATE=0` disables
the automatic SD/USB/TFTP scan in the approved development EEPROM input.
RPIBOOT EEPROM writes remain possible, and the production self-update policy is
undecided.

### Root integrity and persistent state

**Implemented and tested in software / blocked on physical qualification.** The
target uses a read-only dm-verity root bound to a signed root hash and
PARTUUID. Mutable state is tmpfs-only; swap, persistent journal, core dumps, and
persistent device secrets are disabled. The missing claim is live physical
enforcement across the complete production boot path.

### Anti-rollback

**Not implemented / blocking.** Older correctly signed images may boot. Runtime
evidence reports `rollback=unimplemented`, control terminalization requires
`rollback_unimplemented`, and the posture blocks enrollment-ready status.

### Lane power and topology

**Partly implemented / blocked on qualification.** Relay mode is fail-closed in
software and binds GPIO, USB, UART, release, and power mode. Production still
requires qualified normally-off electrical behavior and the reviewed USB power
topology under load. Manual power is development-only and cannot satisfy this
control.

### Production authority and key management

**Planned.** The checked-in Ubuntu authority and signing-host bundles exercise
strong isolation properties, but their identities, fixed network, generated
PKI, and signer profile are scoped to the sacrificial campaign. Production
requires an approved PKI lifecycle, signer custody/recovery policy, independent
role authentication, host recovery procedure, monitoring, and retained
ceremony evidence.

## Meaning of terminal states

`security_applied` means the control plane accepted the exact seven durable
operation records and a terminal evidence digest under the approved
development contract. It records release classification `development_asset`
and rollback status `rollback_unimplemented`. It does not mean that production
policy is complete, that secrets have been enrolled, or that the target is
approved for service.

An uncertain operation remains a reconciliation case. New mutation authority
must never be used to retry an old ambiguous outcome. Unknown target state,
unproven safe-off, authority mismatch, or journal incompatibility requires
quarantine and external review.

## Path to a production decision

The actionable control plan is maintained in
[Raspberry Pi 5 production security follow-on](raspberry-pi-5-production-security-follow-on.md).
At minimum, a production decision must resolve every canonical blocker, bind
the resulting policy into release and lane contracts, and collect independent
evidence for the real signer, authority hosts, power path, media path, target
boot path, recovery path, and rollback behavior. Documentation or software-only
tests alone cannot close those gates.

