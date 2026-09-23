# Enrollment implementation handoff

Status: producer implemented; isolated consumer rehearsal in review. Contract
adoption review and fleet authorization remain separate.

The [authenticated producer](fleet-export.md) implements the provisioning side.
The isolated consumer rehearsal is in
[fleet PR #1](https://github.com/PseudoDesign/kaiba-fleet/pull/1), with shared
integration obligations in
[contracts PR #7](https://github.com/pd-codex/kaiba-contracts/pull/7).
Hardware qualification continues independently. Production activation still
requires [FA-01–FA-08](fleet-admission-policy.md).
The current station remains read-only and the development Pi remains ineligible
for production enrollment.

The [development device client](device-enrollment-client.md) implements local
management-key creation, certificate installation and restarted installed-key
proof for the rehearsal service. It is separate from the station UI. Its
software tests do not establish encrypted-storage protection or physical
qualification; actual target execution remains a campaign task.

## Shared baseline

Use `pd-codex/kaiba-contracts` at commit
`9ebf773d5d07d61d8cb522aea66160d37562e6b1`, wire version
`0.1.0-draft.1`. This is a proposed baseline, not an adopted runtime API.

- [ProvisioningRecord](https://github.com/pd-codex/kaiba-contracts/blob/9ebf773d5d07d61d8cb522aea66160d37562e6b1/contracts/provisioning-record.md): provisioning produces secret-free candidate/completion evidence; consumers independently authenticate and verify it.
- [DeviceBinding](https://github.com/pd-codex/kaiba-contracts/blob/9ebf773d5d07d61d8cb522aea66160d37562e6b1/contracts/device-binding.md): identity inventory owns exact credential tuples, staged issuance, activation, replacement and revocation.
- [Adoption checklist](https://github.com/pd-codex/kaiba-contracts/blob/9ebf773d5d07d61d8cb522aea66160d37562e6b1/docs/adoption.md): transport, evidence envelopes, policy freshness and component ownership still need agreement.
- [Conformance scenarios](https://github.com/pd-codex/kaiba-contracts/blob/9ebf773d5d07d61d8cb522aea66160d37562e6b1/docs/conformance.md): schema validation is separate from authenticated runtime integration and physical qualification.

The contracts source review predates the selected first-fleet offline policy.
Preserve raw source facts such as `rollback_unimplemented`, but do not turn that
fact or archived online-unlock requirements into new first-fleet prerequisites.
The current admission policy governs platform eligibility.

## Provisioning producer adapter

Owner: this repository. The read-only adapter uses a pinned, offline contract
bundle and explicit source mapping. Copied-media testing remains a separate gate.

Deliverables and acceptance:

1. Pin the exact shared schemas and their provenance; enforce closed shapes and
   the shared canonical digest rules. Keep original evidence-byte digests
   distinct from canonical record digests.
2. Map authenticated control state and independently retained audit evidence
   into `ProvisioningRecord`. Preserve transaction ID and exact source state;
   `security_applied` stays `candidate_evidence`, with both readiness flags
   false and explicit reasons. Keep quarantine, uncertainty and reconciliation
   requirements visible. Do not manufacture a completed workflow.
3. Establish trusted inputs for authority, tenant, security domain, cohort,
   profile, posture and release. Missing required audit or source bindings must
   produce a typed blocked result, not placeholder evidence or a valid-looking
   export. The station observer snapshot is not independently verified audit.
4. Define durable immutable revision assignment: identical retries return the
   same bytes and digest; a changed source observation creates a new revision.
   Do not infer export revisions from control resource versions without an
   explicit mapping covering audit and other bound inputs.
5. Test the mapping with synthetic evidence and real disposable control/audit
   services. Exercise wrong authority, mismatched audit digest, stale source,
   missing evidence, development readiness upgrades and repeated exports.
   Record the producer's coverage of INT-PR-01/02; admission-side rejection
   remains a consumer integration obligation.

The first PR does not issue credentials, alter transactions, perform hardware
operations or expose a production enrollment endpoint. Its completion is an
adapter plus repeatable tests and a source-mapping document, not admission.

## Consumer handoff: enrollment rehearsal

Owner: [PseudoDesign/kaiba-fleet](https://github.com/PseudoDesign/kaiba-fleet),
the fleet inventory and enrollment implementation repository. The rehearsal
selects Go, PostgreSQL, HTTPS/mTLS and a separate disposable test CA. The following
boundaries govern implementation and adoption review; production CA integration
and deployment qualification remain open:

| Decision | Concrete deliverable | Blocks |
| --- | --- | --- |
| Durable inventory and RA/CA arrangement | PostgreSQL transactions and a separate idempotent test issuer; select production CA custody/integration later | Production enrollment API |
| Evidence resolver and authority authentication | Scoped mTLS reads, pinned exact artifacts and current control/audit/control observations | Reliance on exported records |
| Bootstrap and operational-key proof | Bound, expiring challenges and a restarted software client's installed-key proof | Rehearsal issuance and pending verification; hardware identity remains unqualified |
| Atomic activation and authorization freshness | One inventory transaction plus per-request exact tuple checks; lost-response reconciliation | Rehearsal activation; cross-authority production coordination remains open |
| Contract adoption | Producer/consumer records pinning schemas, supported versions, tests, compatibility and review | Compatibility claim |

The isolated rehearsal covers this sequence:

1. Accept and verify candidate evidence, assign canonical identity at the RA,
   and reject client-selected identity, scope or role.
2. Authenticate bootstrap and fresh operational-key proof; issue only a staged
   tuple. Routine fleet services must reject staged credentials.
3. Prove the installed key after a simulated restart, then atomically activate
   exactly the verifier-approved tuple. A lost response reconciles the existing
   tuple without duplicate issuance or activation.
4. Exercise replay, substituted key, wrong audience, expiry, revocation,
   quarantine with cached sessions, and replacement/prior-instance rejection
   against INT-DB-01–04. Use disposable PKI and synthetic production candidates
   in an isolated test domain; real development records must fail production
   admission.
5. Return authoritative status for station integration. The observer stays
   read-only. The separate [guided campaign](guided-station-campaign.md) supplies
   authenticated fixed-packet actions and durable recovery; real-device wrappers
   and isolated development fleet eligibility remain to be integrated and
   reviewed before it performs enrollment. The fleet authority continues to own
   eligibility, identity assignment and activation.

Candidate evidence may precede identity activation. Final completion evidence
follows required identity and audit outcomes; do not make completion evidence a
circular prerequisite for the activation it needs.

## Parallel physical gate

Continue the comparable-board copied-media experiment, production encrypted
state/credential lifecycle, permitted-image and recovery boundary, and final
boot/debug/EEPROM qualification separately. No experiment authorization is
conferred by this handoff. A functioning second Pi is available; availability
alone is not copied-media evidence.

The release milestone is one eligible device completing real enrollment and
interrupted-transaction recovery through the station, with all FA conditions
established. Neither a schema-valid record nor a passing isolated rehearsal
permits production activation.
