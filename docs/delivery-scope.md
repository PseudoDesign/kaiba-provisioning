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

The operator flow is: connect and identify the device, apply and verify its
approved security configuration, enroll it, then show its fleet status.
Physical instructions and meaningful approvals belong in that flow. Normal
operation must not require copying digests, moving JSON between tools, or
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
and blocks enrollment while anti-rollback is unimplemented. Resolve that
specific admission gap explicitly; do not relabel development success as
production security or silently remove an agreed requirement. The existing
[readiness assessment](production-readiness.md) remains applicable.

## Next milestone and limits

Deliver one real device through all three outcomes using the current
components. The remaining work is to finish the existing physical path,
implement the minimum fleet enrollment handoff, and connect the live UI.
Confirm the fleet's backing service and device-identity interface before
implementing enrollment; the current transaction store is not already a fleet.

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
