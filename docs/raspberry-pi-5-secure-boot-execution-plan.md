# Raspberry Pi 5 secure-boot execution plan

This plan organizes the sacrificial development campaign into gates that must
close in order. It adapts the original monorepo execution plan to the current
standalone repository and intentionally distinguishes software completion from
live evidence.

> [!DANGER]
> SB-08 is an irreversible ownership ceremony. Nothing in this document grants
> authority to perform it. SB-08 remains blocked until SB-01 through SB-07 have
> independently passed for one frozen revision, release, rig, and target.

The development campaign can end only at `security_applied`; anti-rollback and
the other production controls remain follow-on work.

## Objective and boundary

Move one read-only-qualified, apparently fresh Raspberry Pi 5 through a single
transaction-bound customer-key and EEPROM commit, then demonstrate the signed
boot, owned recovery, negative-boot, and dm-verity properties of that exact
release.

“Apparently fresh” is deliberately narrow. The probe observes an all-zero
customer-key hash and unlocked VideoCore JTAG, plus the profile's stable board
facts. It does not prove supply-chain provenance, every OTP row, EEPROM
authenticity, all debug paths, storage authorization, or absence of all prior
state.

## Gate status

This table is a repository assessment, not a fresh campaign result.

| Gate | Deliverable | Current repository status |
| --- | --- | --- |
| SB-00 | Read-only hardware qualification | **Evidenced.** A redacted two-observation record is checked in; it remains non-mutating and `mutation_eligible: false`. |
| SB-01 | Baseline and documentation closeout | **In progress.** Public policy and docs exist; exact-board, frozen-revision, current CI, inventory, storage authorization, and deferred prestate review remain ceremony inputs. |
| SB-02 | Development signing root | **Software implemented; live gate not closed here.** Public signer review and v0.1.6 signed inputs exist, but the repository does not establish present custody or a newly completed live-token ceremony. |
| SB-03 | Complete signed release | **In progress.** Constructors, finalizers, schemas, checks, and public v0.1.6 inputs exist; a new standalone end-to-end composition is not exported. |
| SB-04 | Target-media staging | **Software implemented; physical gate open.** Production plan, writer, verifier, and fixture tests exist; no checked-in live cold-readback campaign closes the gate. |
| SB-05 | Enforced transaction plan | **Complete as a software gate.** Control, audit, bridge, compiler, lane guard, proposals, receipts, and reconciliation are tested without claiming hardware qualification. |
| SB-06 | Qualified physical lane | **In progress.** Software and simulation boundaries exist; GPIO/relay or manual-power rig, USB power, UART, boot selection, and safe-off need combined live qualification. |
| SB-07 | Rehearsal and failure campaign | **In progress.** Automated fault coverage exists; the non-OTP physical failure-mechanics campaign is not evidenced here. |
| SB-08 | Sacrificial ownership ceremony | **Blocked by SB-01 through SB-07.** |
| SB-09 | Owned-state acceptance | **Blocked by SB-08.** |
| SB-10 | Production readiness | **Explicitly deferred.** See the production follow-on. |

## Safety invariants

Every gate must preserve these invariants:

1. Private signing keys and PINs stay outside Git, the Nix store, CI, station
   images, target images, and evidence exports.
2. Public release approval never implies device execution authority.
3. The physical target and media path come only from reviewed, host-bound
   configuration; runtime callers cannot supply an arbitrary block device.
4. The seven operation names, order, classifications, and boot modes are
   compiler-owned.
5. Approval, current claim, fence epoch, per-operation intent, release, target,
   lane, power mode, payload, and deadline must all agree at dispatch.
6. The journal records start before the physical action and reloads terminal
   state before publishing evidence.
7. A command's exit code is not an authoritative physical postcondition.
8. A timeout, crash, target disappearance, lost response, or incomplete
   journal is never permission to retry an irreversible action.
9. Recovery artifacts exist and verify before ownership.
10. Software tests, regular-file fixtures, unfused boots, and simulations are
    labelled at their real assurance level.

## SB-00: read-only qualification

Use the [probe runbook](raspberry-pi-5-provisioning-probe.md) to obtain two
independent live observations separated by complete power removal and RPIBOOT
re-entry, then repeat the same known-good normal-boot criterion. Raw results
remain private; only the deterministic whitelist-redacted record may enter
[`tests/evidence/`](../tests/evidence/).

Exit criteria:

- both observations use the exact profile, probe bundle, tool, adapter, and
  station system;
- mandatory stable fields match and optional absent fields are consistently
  absent;
- the customer-key hash is all zero and VideoCore JTAG is unlocked;
- pre- and post-probe normal boot is unchanged;
- no mutation result is reported; and
- reviewers accept the record's explicit nonclaims.

## SB-01: freeze the candidate

Freeze one clean revision after all supported Go and Nix checks pass. Bind:

- the exact target fingerprint and SB-00 evidence digest;
- inventory ownership and absence of an unresolved transaction;
- expected fresh OTP and EEPROM preconditions not proved by SB-00;
- exact storage device authorization and overwrite safety;
- the signer, customer-key hash, release, recovery, and test bundles;
- development boot-order, UART, JTAG, self-update, write-protection, and
  anti-rollback decisions; and
- the selected relay or manual power mode and its qualified physical topology.

Any source, policy, signer, target, release, hardware configuration, or rig
change reopens the affected gates.

## SB-02: establish the development signing root

Verify the YubiKey-generated RSA-2048 public key, canonical SPKI fingerprint,
Raspberry Pi customer-key hash, device-generated key attestation, fixed PIV
slot `9c`, PIN/touch policies, signer/cohort IDs, and independent review.

Install the dedicated signing host through the inert deployment boundary,
exercise positive and negative host preflights, and prove that an incomplete
grant cannot invoke the key again. Production keys are out of scope; the
development key must never be promoted.

## SB-03: assemble a complete release

Follow the [signed-boot workflow](raspberry-pi-5-signed-boot-workflow.md). The
release must have one intent, five signing inputs and grants, five artifact
signatures, five receipt-attestation signatures, an authenticated receipt
export, six exact RPIBOOT trees, and one content-addressed 18-role publication.

Exit criteria include independent offline verification, reproducible public
artifacts, exact source lineage, no private material, and a reviewed manifest
digest suitable for the later per-device plan.

The current standalone composition gap must be resolved before using the
[signing ceremony](ubuntu-rpi5-development-signing-ceremony.md) for a new
release.

## SB-04: stage target media

Use only a plan-specialized writer and its separately built read-only verifier
from `mkRpi5ProductionMedia`. The current run must bind exact capacity,
512-byte logical-sector geometry, hardware configuration, execution hostname,
selector, resolved raw whole device, boot ID, and disk sequence.

After the reviewed preflight, stage once, remove all power, detach and reattach
the medium, then cold-read and verify GPT, the canonical FAT, every payload and
padding region, the complete media digest, release lineage, and dm-verity tree.
See [target-media staging](target-media-staging-prototype.md).

Any ambiguous write or receipt publication result quarantines the selected
medium; it is not automatically restaged.

## SB-05: enforce the transaction

The control service must own one target claim and fence epoch. The authority-free
draft is reviewed before approval. Each next operation follows the proposal,
apply, current-authority refresh, acknowledgement, one-shot execution, durable
receipt, evidence proposal, and evidence apply sequence.

Exit criteria are software-level positive, negative, expiry, idempotency,
role-separation, lost-response, stale-fence, and journal recovery tests. Passing
these tests cannot close SB-06 or SB-07.

## SB-06: qualify the physical lane

Qualify the exact host, USB controller/path, power source, cable, target port,
UART device, GPIO chip/line, relay, and normal/RPIBOOT transition method.

Relay mode must prove normally-off behavior at boot, unit failure, process
crash, cancellation, and host restart. Manual mode must prove the authenticated
prompt and USB-observation sequence but remains a development deviation and
cannot claim automatic fail-off.

The powered USB path must pass load testing without undervoltage, resets, or
unexpected disappearance. Back-power and alternate target power sources are
stop conditions.

## SB-07: rehearsal and failure campaign

Run the complete campaign with non-OTP fixtures and all mutation primitives
disabled. Inject failures before and after every durable transition, including:

- stale claim, approval, intent, proposal, fence, or release binding;
- control/audit disagreement or lost response;
- operator rejection and acknowledgement timeout;
- relay/power, USB, UART, RPIBOOT, and target re-identification failure;
- process kill before dispatch, during hardware wait, and before terminal
  publication;
- terminal journal and receipt publication failure; and
- host restart with each possible journal state.

The expected result is always a known clean abort, an exact republish, or a
read-only reconciliation/quarantine path—never a second mutation.

## SB-08: sacrificial ownership ceremony

SB-08 requires a separately generated, immutable ceremony packet binding every
closed gate and the final go/no-go approval. Use the fixed seven-operation
sequence in [live provisioning](raspberry-pi-5-live-provisioning.md).

Once `AttemptStarted` is durable for the first operation, the board must be
treated as potentially owned until direct observation proves otherwise. An
unexpected or unknown customer-key/EEPROM result removes it permanently from
the fresh-device path.

## SB-09: owned-state acceptance

After the commit, require all of the following on the exact target:

- cold boot of the approved signed image;
- target-emitted signed boot-image digest matching the release;
- customer-key and EEPROM readback matching the transaction;
- customer-signed owned recovery success;
- unsigned, wrong-key, altered, and stock-recovery image rejection across each
  enabled source;
- dm-verity corruption preventing root activation;
- repeated owned-state readback after recovery and negative tests;
- exact evidence reconciliation with control and audit; and
- no secret material in any export.

The result is `security_applied`, never `enrollment_ready`.
Rejection of an older image that is still correctly signed by the fused
customer key is not an SB-09 acceptance condition: the development design has
no anti-rollback mechanism. The production freshness campaign under SB-10 must
establish that rejection before any production claim.

## Terminal outcomes

### Clean abort

No irreversible attempt started, the target remains demonstrably fresh and
powered off, and the claim closes with an audited abort.

### Security applied

All seven exact operations and evidence records succeeded. The record retains
the `development_asset` classification and `rollback_unimplemented` status.

### Reconciliation required

A physical action may have started or its terminal evidence is unavailable.
Preserve the journal and use only separately authorized direct observation.

### Owned quarantined

The board is owned or possibly owned but does not satisfy the approved release,
recovery, or evidence state. It cannot return to the fresh-device workflow.

## SB-10: production follow-on

Production requires a new customer key and fresh board plus the stable
verifier, delegated release keys, online monotonic freshness decision,
encrypted mutable state, qualified bootstrap identity, A/B updater, hardened
final posture, narrow recovery, and fleet lifecycle described in the
[production security follow-on](raspberry-pi-5-production-security-follow-on.md).
