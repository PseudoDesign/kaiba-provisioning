# Current delivery scope

Agreed on 2026-09-15. Implementation baseline:
`93183ee2b13e4633be9e2568007d3d3f87d6c787` (PR #22 merged to `main`).

Freeze the existing implementation and retain its artifacts and evidence as
the starting point. Further implementation must directly complete or fix one
of the following three outcomes. This baseline is not a claim that CI or
physical qualification has passed.

## The product we are delivering

| Outcome | Done means | Current baseline |
| --- | --- | --- |
| Apply the agreed hardware security configuration | The selected real device completes the existing ordered procedure and required readback/acceptance checks for its approved profile. | Hardware tools, ordered workflow, signing and audit components exist. Complete physical execution remains open. |
| Enroll known-good devices in a fleet | An authenticated device identity is durably bound to its verified provisioning result and fleet membership. Failed or uncertain devices are not admitted. Membership can be retrieved after restart and enrollment retries cannot create conflicting identities. | Provisioning transactions persist, but fleet enrollment is not implemented. `security_applied` is not fleet membership. |
| Guide the operator through a simple UI | The UI identifies the device, shows the current step and outcome, requests the next necessary human action, and confirms actual fleet enrollment. Backend services perform the handshakes and retain progress. | A simulation and a live-interface foundation exist; the live backend is disabled. |

For the Ace and Mako pilot, the selected interface is a reviewed CLI procedure
on malak. Touchscreen/GUI provisioning and a development-Pi station are deferred
until later. The pilot exercises limited enrollment and retains unresolved
qualification in its report; it does not complete the hardware-security outcome.
The UI remains a later deliverable, not a prerequisite or a condition claimed
complete by CLI execution.

The operator flow is: connect and identify the device, apply and verify its
approved security configuration, enroll it, then show its fleet status.
Physical instructions and meaningful approvals belong in that flow. Normal
GUI operation must not require copying digests, moving JSON between tools, or
running ceremony helper commands; backend components own those exchanges.
Detailed evidence remains available for diagnosis.

## Reuse the agreed procedure and boundaries

The [existing hardware sequence](raspberry-pi-5-live-provisioning.md) is:
customer-key/EEPROM commit, signed cold boot, owned-state readback, signed owned
recovery, repeated readback, negative boot/recovery tests, and root-integrity
testing. Preserve its required qualification and approval preconditions.
The already-owned sacrificial Pi must not repeat a fresh-device ownership
operation; its current role is testing the owned boot path.

Reuse the existing claim, approval, intent, execute-once acknowledgement,
receipt and audit components underneath the UI. Uncertain physical outcomes
retain their reconciliation/quarantine behavior. Neither simplifying the UI
nor freezing scope authorizes hardware writes or another signing attempt.

Fleet admission must mean compliance with the selected, explicitly approved
security profile. The current development policy stops at `security_applied`
and blocks enrollment while anti-rollback is unimplemented. On 2026-09-16 the
user explicitly selected a fleet profile that does not require rejection of
older, correctly signed software while offline. Carry that decision into the
fleet policy without relabeling development success as production security or
clearing unrelated blockers. The existing [readiness assessment](production-readiness.md)
still describes the implemented development boundary.

The [fleet admission draft](fleet-admission-policy.md) records the concrete
acceptance proposal and the user's subsequent requirements for offline normal
operation and protection against copied storage, with offline rollback
prevention explicitly not required. The earlier online-only production
proposal must be reconciled with those choices before implementing fleet
admission; the draft does not itself change the approved hardware policy.

## Next milestone and limits

The selected initial cohort is **Ace and Mako**, following the
[pilot enrollment plan](pilot-enrollment.md). Use malak's CLI and initial
authorities, preserve each host's current storage and workloads, and keep
separate identities, adoption decisions and qualification reports. Shared source
configuration does not establish matching effective state or secret history.

Implement the versioned pilot handoff and limited admission policy before live
activation; the current development/rehearsal path cannot enroll these hosts by
renaming them. The fleet repository owns enrollment/inventory, with PostgreSQL
and a separate issuer interface in the rehearsal. Pilot issuer/trust custody,
deployment and contract adoption remain gates.

The [Ace adoption and bootstrap plan](ace-adoption-plan.md) retains the later
full-qualification and fleet-service transfer work. Pilot membership alone does
not authorize service transfer or satisfy FA-01–FA-08. The three delivery
outcomes and that full-qualification bar remain; the pilot is an intermediate
milestone with explicit gaps, not a claim of completed protection.

Follow the [implementation staging plan](implementation-staging.md) for the
first two parallel slices: real station status with restart recovery, and
native offline boot with protected-storage feasibility. Resolve provisional
choices at the operations they affect; the selected policy gates its own
admission, not every implementation step. Unmet pilot prerequisites block pilot
activation; missing FA conditions continue to block full qualification.

Retain completed signing, builds and evidence. Collect only missing evidence
or evidence invalidated by a relevant change. The retained campaign currently
has signed verifier artifacts and prepared media; recovery backups, physical
staging/readback and campaign execution are still outstanding.

Defer additional hardware variants, replacement signing frameworks, generalized
station architecture and standalone build/cache optimization projects unless
a demonstrated blocker prevents this delivery. Existing broader design
documents remain reference material; they do not automatically add work to
this milestone. Preserve the selected security requirements and use focused
checks for each actual change.
