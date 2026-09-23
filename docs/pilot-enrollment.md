# Ace and Mako pilot enrollment

Status: **selected two-device pilot; software lifecycle tested, real deployment pending**.
Ace and Mako are the initial pilot cohort. Malak supplies the reviewed CLI
procedure and initial fleet authority. Selecting a device for this cohort does
not enroll it. This document defines the real-device milestone. The
original rehearsal contracts remain separate. Pilot runtime contracts and
software support are described in [the pilot client guide](pilot-device-client.md).

The pilot exercises real device identity, durable enrollment, restart recovery
and membership enforcement while recording incomplete hardware qualification.
Full qualification remains a separate milestone under
[FA-01–FA-08](fleet-admission-policy.md). A pilot member must never be reported
as satisfying that policy merely because its enrollment succeeded.

## Devices and roles

| Participant | Pilot role | Per-device work |
| --- | --- | --- |
| Ace | First enrollment, followed by the proposed future fleet-service host role. | Authenticate and bind its own target/storage, inspect the installed unlock path, record custody and qualification gaps, then generate its own operational identity. |
| Mako | Second independent enrollment, exercising isolation and continued operation of its existing services. | Repeat target authentication and inventory for Mako; establish its own custody, storage, service-impact and gap records. Ace's observations or exception cannot substitute for these. |
| Malak | CLI station and initial pilot authorities. | Dedicated durable stores, authenticated station/operator identities, scoped pilot issuer and private report retention. Keep signer, issuer, operator and device roles separate. |

The hosts share a [Pi 5/LUKS source configuration](https://github.com/PseudoDesign/nix-pseudo-design/blob/82c39216c933a038058de0024b7e5dc085b31d63/modules/hardware/rpi5-luks.nix).
That does not establish identical running releases, OTP history, LUKS derivation,
recovery credentials or effective protections. The
[Mako configuration](https://github.com/PseudoDesign/nix-pseudo-design/blob/82c39216c933a038058de0024b7e5dc085b31d63/hosts/mako/default.nix)
also declares web/application services. Inventory and preserve those workloads;
their fleet privileges do not increase because the host joins the pilot.

Retain the installed OS, storage and unlock configuration for the initial pilot.
Enrollment needs a reviewed credential directory on the existing encrypted
filesystem, not a destructive reinstall or automatic migration to another
derivation. Verify the actual backing storage and secret-handling configuration
before writing credentials. No change to the shared hardware module may silently
migrate either host. Any required storage change gets its own recovery plan.

## Pilot admission policy

The pilot contract and separate runtime use `rpi5-existing-luks-pilot-v1`.
It does not enable pilot credentials on the rehearsal API. Before execution, bind a
reviewed policy revision to exactly two authenticated target records. Hostnames
are operator labels, not identity proofs or an unrestricted allowlist.

| Gate | Required before pilot activation |
| --- | --- |
| Target and adoption | Authenticated inventory and station endorsement bind the actual device, storage and selected source record. Keep an explicit existing-secret custody/history review for each device. Do not invent a fresh OTP-programming or customer-root operation. |
| Identity and custody | Generate a distinct operational key on each target, persist it in the verified encrypted filesystem with a dedicated restricted directory, and keep it out of logs, exports, build outputs and transferable pilot fixtures. Approve issuer custody and recovery; retain CA, signing and station-administrator keys outside the devices. |
| Enrollment proof | Authenticate the pilot authority and issuer, bind fresh proofs to the exact target, enrollment, public key, audience, policy and source revision, and verify the installed credential after client restart. Process restart is sufficient for this initial pilot test and must be reported as such; it is not an offline cold-boot result. |
| Durable membership | Pending access is denied. Activation is atomic and idempotent; lost replies and restarts reconcile the same tuple. Revocation or quarantine denies later requests, including requests on an existing connection. |
| Explicit gaps and permissions | The authority verifies the exact accepted-gap record and pilot policy revision. Each device receives only the pilot permissions below. Unknown policy, altered or expired approval, wrong-target evidence and unresolved physical mutations block activation. |

The existing `ACE-EX-01` proposal concerns Ace only. Prepare a separate
`MAKO-EX-01` review if Mako's existing-secret history is adopted. Each decision
binds its target, observed prestate, scope, custody statement, unknowns, approver,
validity and invalidation conditions. Neither proposed identifier is approval.
Known conflicting ownership or unresolved key exposure cannot be hidden in a
generic qualification gap.

The initial pilot may explicitly accept incomplete full qualification of boot
ownership, signed boot/dm-verity, offline cold boot, firmware-HMAC migration and
locks, copied-storage/identity rejection, final debug/EEPROM settings, and signed
recovery. Record each applicable FA outcome and the accepted limitation separately.
An unperformed check stays unperformed; accepting it for the pilot does not mark
it passed. The encrypted-volume observation required above does not establish
FA-04's complete physical protection claim.

Pilot admission must not depend on labelling a real device as synthetic, changing
a development record's readiness booleans, or accepting an unsigned JSON override.
The current exporter and consumer do not support this adoption path. Implement
versioned semantics and independent source verification before live enrollment.

## Credential and service boundary

Use a dedicated pilot issuer/trust configuration and audience, isolated from
disposable rehearsal PKI and any later qualified fleet trust. Choose exact values
and custody in the deployment packet; do not reuse the fixture issuer. A device
credential permits authenticated access to its own pilot identity/status and
submission of its own bounded diagnostic-result references. It grants no access
to the other device's records, fleet administration, enrollment approval, remote
command execution, or signing/issuance authority.

The fleet service enforces membership and those permissions on each request.
An installed certificate alone is insufficient. Local applications keep running
if the fleet authority is unavailable; membership changes wait for authoritative
state, and fleet access fails closed. Existing application credentials remain
separate from pilot device credentials.

Keep the initial authority on malak through both enrollments and the isolation,
restart and revocation tests. The [later transfer to Ace](ace-adoption-plan.md#bootstrap-and-transfer-to-ace)
is a separate milestone with service credentials, protected state, backup/restore
and single-writer cutover. Pilot membership does not authorize that transfer or
grant Ace an administrator identity. Mako remains an independent pilot member.

Promotion to the fully qualified fleet requires all applicable FA evidence and a
new reviewed admission decision under that policy. A pilot credential cannot
gain qualified permissions by changing a label, audience or hostname. Define the
credential transition and retirement of obsolete pilot authority explicitly.

## Implementation slices

| Slice | Deliverable and owner | Completion check |
| --- | --- | --- |
| 1. Per-device records | Provisioning retains separately authenticated inventory, data/workload constraints, existing-secret review, selected policy and accepted-gap references for Ace and Mako. `nix-pseudo-design` owns host-specific deployment composition. | Both records are independently bound; private observations and key material are not put into public fixtures. Missing Mako evidence remains missing. |
| 2. Versioned pilot handoff | `kaiba-contracts` defines adoption, pilot eligibility and qualification as separate semantics, with rejection fixtures. Provisioning produces actual adoption records; `kaiba-fleet` independently verifies the sources and approved policy/gap decisions. | Matching producer/consumer pins; unsupported versions, stale decisions, cross-device substitutions and rehearsal-to-pilot promotion fail closed. Current closed schemas are not extended ad hoc. |
| 3. Real pilot client and authority | Provisioning adds explicit pilot client mode and malak CLI orchestration; fleet adds pilot policy enforcement and an approved issuer integration. Preserve development/rehearsal restrictions. | Packaged real-service tests pass with disposable test PKI. Dedicated pilot deployment, persistent stores, key custody, access limits and recovery are reviewed before issuance on the hosts. |
| 4. Enroll and report | Enroll Ace first and Mako second, using distinct credentials and durable transactions, then exercise the two-device cases below. | Both are active only in the pilot policy; reports retain remaining FA gaps. No additional device is eligible through the same two-target approval. |

The first three slices can be implemented and rehearsed without a kernel build,
token signing, drive move, reboot or OTP write. Actual credential creation,
deployment and service changes use the reviewed execution packet. A GUI and a
development-Pi station remain deferred; a controlled physical lane is required
only when the selected operation needs it.

## Automated acceptance and retained report

Extend the existing packaged producer/consumer/client rehearsal with two distinct
device fixtures. Test policy and contract code with synthetic observations and
disposable PKI; those fixtures do not become hardware evidence.

| Scenario | Required result |
| --- | --- |
| Two enrollments | Ace and Mako receive different keys, server-assigned identities and exact credential bindings. A retry preserves each original identity. |
| Cross-device substitution | Swapping target endorsements, source records, gap/exception approvals, challenges, proofs or certificates is rejected. One device cannot read or update the other's records. |
| Independent denial | Pending access is denied. Quarantining or revoking one member denies it immediately on subsequent requests while the other retains its permitted access. |
| Restart and lost replies | Client and authority process restarts, issuer/activation response loss and reconnects preserve committed state without duplicate identities or repeated physical operations. |
| Policy isolation | Rehearsal candidates, development readiness, unknown targets, an unapproved third host, changed/expired decisions and pilot credentials at a qualified endpoint are rejected. |
| Authority outage | Normal local services remain independent of fleet availability; new activation waits and fleet access fails closed. Last-known reporting never grants new authority. |
| Truthful qualification | A report can show pilot membership active while individual FA conditions remain blocked or not evaluated. No test flips `production_ready` or manufactures a hardware result. |

Keep one report per device and a cohort summary. Bind source and policy revisions,
target authentication, public key/credential references, approved history/gaps,
membership state, timestamps, restart type and evidence references. Report
readiness to join the pilot separately from readiness for full qualification.
Machine-readable labels for these distinctions are part of the pilot contract
family; the original rehearsal API does not accept pilot bindings.

This milestone completes when both real devices have completed the selected
pilot lifecycle and the retained report shows the remaining qualification work.
Adding them to this document or passing software fixtures does not complete it.

The first runtime handoff boundary is described in
[pilot handoff preflight](pilot-handoff-preflight.md). It exports reviewed
observations for independent fleet checks. The separate
[pilot client](pilot-device-client.md) and fleet lifecycle implement key proofs
and activation with synthetic test coverage. Real issuance and enrollment remain
pending deployment review. Neither a preflight report nor merging this
implementation enrolls Ace or Mako.
