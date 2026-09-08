# Raspberry Pi 5 live provisioning foundation

This document describes the implemented components and contracts for a
fail-closed development lane: its authority services, capability boundaries,
fixed operation sequence, physical power model, durable evidence, and recovery
behavior. The standalone flake does not export a complete live composition.

> [!DANGER]
> This is an architecture and operator-boundary reference, not authorization
> for an irreversible run. The repository has read-only hardware qualification
> evidence, but no checked-in evidence of a completed EEPROM/OTP campaign. The
> standalone flake also lacks some deployment-specific composition outputs
> needed by the historical end-to-end procedure.

The normative development posture is
[`policies/raspberry-pi-5-development-posture-v1alpha1.json`](../policies/raspberry-pi-5-development-posture-v1alpha1.json).
It covers one sacrificial board and deliberately stops at `security_applied`.

## Goals

The lane is designed to ensure that:

- no browser or ordinary operator process directly selects or invokes a
  privileged hardware operation;
- public release approval is separate from one-device execution approval;
- one transaction owns one fresh target through a claim and fence epoch;
- the operation list, classifications, boot modes, release, target, station,
  lane, and deadlines are immutable before execution;
- each physical action requires a fresh current intent and explicit display of
  the server-selected action;
- the privileged adapter executes at most once for a journal identity;
- a command response is not accepted as proof of physical postconditions; and
- an ambiguous one-way result enters reconciliation or quarantine, never an
  automatic mutation retry.

## Topology and authority

```text
independent approver
  -> control service (transactions, claims, approval, intent, terminal state)
  -> independent audit service (secret-free hash chain)
               ^
               | mutually authenticated TLS
               v
station authority bridge
  -> root-owned private Unix socket
  -> one-shot lane guard
       -> acknowledgement-only operator client
       -> fixed physical adapter / RPIBOOT / GPIO boundary
       -> execute-once journal and immutable receipts
               |
               v
        one sacrificial Raspberry Pi 5
```

The Ubuntu authority bundle installs control and audit as separate services
with different server trust roots. The station and approver use exact,
role-separated client identities. The default development listeners are fixed
at `192.168.8.249:8091` and `192.168.8.249:8092`; installation neither opens a
firewall nor starts the services. See the
[authority deployment guide](../deploy/ubuntu-provisioning-authority/README.md).

### Control service

The control service owns transaction lifecycle, device claims, fence epochs,
target binding, approval, per-operation intent, evidence admission,
reconciliation, quarantine, clean abort, and the terminal `security_applied`
record. Updates are compare-and-swap operations against the current resource
version and idempotency identity.

### Audit service

The audit service maintains an independent, secret-free hash chain. A control
mutation is not considered complete merely because one service responded; the
workflow reconciles control and audit results and preserves ambiguous cases.

### Authority bridge

The station bridge authenticates both services with mTLS, fetches only the
current closed plan/request, and exposes it through a private Unix socket. It
does not let the lane process choose a different operation, target, boot mode,
payload, or hardware path.

### Lane workflow

`kaiba-provision-lane-workflow` compiles the fixed draft and creates narrowly
typed proposal/apply transitions for approval, intent, evidence,
reconciliation, and terminalization. Proposal files are immutable snapshots;
later renewal or state changes invalidate them.

### Lane guard and operator

The lane guard is the root-only, one-shot physical adapter. It refreshes
authority, records `AttemptStarted` durably, asks the constrained operator
client to acknowledge the exact displayed action, executes the fixed adapter,
records a terminal result, and publishes an immutable receipt from the durable
journal.

`kaiba-provision-lane-operator` has acknowledgement authority only. It cannot
select an operation, target, path, payload, boot mode, or recovery action.

## Release and target prerequisites

Before a draft can be approved, the release must already be complete and
independently verified as described in the
[signed-boot workflow](raspberry-pi-5-signed-boot-workflow.md). The plan binds
the final release manifest, expected customer-key hash, expected EEPROM digest,
and all test and recovery bundles.

The target must be:

- the exact board from an accepted two-observation qualification record;
- apparently fresh at the observable boundary, with its customer-key hash
  observed as all zero;
- in the compiler's `fresh` state;
- completely powered off;
- free of an earlier active transaction or unresolved mutation; and
- connected through the reviewed lane topology.

The expected customer-key hash in the release must be nonzero. An unexpected
nonzero target hash is foreign ownership and requires quarantine.

The qualifier record itself does not establish a completely unprovisioned
board and does not authorize mutation. Before a mutation proposal, separately
close the profile's deferred checks for relevant OTP state, installed EEPROM
and protection state, attached-storage authorization, inventory ownership, and
prior transactions. See the [probe runbook](raspberry-pi-5-provisioning-probe.md).

## Fixed seven-operation campaign

The compiler owns the complete sequence:

| # | Operation | Classification | Boot mode |
| ---: | --- | --- | --- |
| 1 | Program customer key and EEPROM | irreversible | RPIBOOT |
| 2 | Cold power cycle and approved signed boot | reversible | normal |
| 3 | Owned-state readback | read-only | RPIBOOT |
| 4 | Test customer-signed owned recovery | reversible | RPIBOOT |
| 5 | Post-recovery readback | read-only | RPIBOOT |
| 6 | Test negative boot/recovery paths | reversible | RPIBOOT |
| 7 | Test root-integrity enforcement | reversible | RPIBOOT |

No request can omit, reorder, duplicate, rename, or reclassify an operation.
Prestates and poststates form one chain. The guard additionally checks the
current target, claim, fence, approval, intent, payload, boot mode, hardware
configuration, and time windows immediately before recording the attempt.

## Physical lane

### Relay-backed mode

Relay control is the production-shaped development default. The reviewed
topology requires:

- normally-open relay contacts and a qualified normally-off electrical bias;
- one fixed USB topology and an intact power-and-data path;
- Raspberry Pi RP1 GPIO output persistence disabled;
- logical inactive asserted before service startup and after every exit; and
- absence of the normal Pi PSU during RPIBOOT operations.

Before any OTP-capable run, load-qualify the source recommended by the
Raspberry Pi `usbboot` guidance, such as a Raspberry Pi Powered USB Hub, or an
independently reviewed USB 3 source capable of at least 900 mA. Undervoltage,
USB reset, or unexpected target disappearance is a stop condition.

Software control does not replace physical qualification. Relay failure,
wiring error, back-power, or an unexpected alternate power path can invalidate
the claimed off state.

### Manual-power mode

Manual power is an explicit development-only deviation. The guard displays
authenticated connect/disconnect prompts and records operator-attributed
acknowledgements plus USB topology observations. It has no GPIO device access.

Manual mode does not prove an electrical edge, automatic fail-off, or a
production-qualified power boundary. There is no relay-to-manual runtime
fallback: the selected mode is part of the plan digest, approval, intent,
service configuration, and evidence. A persisted/configured mismatch uses
neither actuator and requires external inspection.

## Transaction workflow

The exact CLI arguments are deployment-generated and should come from the
reviewed immutable package. At the protocol level the workflow is:

1. Create a transaction and acquire the exclusive target claim.
2. Bind the qualified target and current fence epoch.
3. Compile and install the authority-free seven-operation draft.
4. Independently review a proposal, then apply the exact approval.
5. For the next compiler-selected operation, create and review an intent
   proposal.
6. Immediately before execution, renew only the pending intent if necessary;
   do not renew between proposal review and apply.
7. Invoke the no-argument, one-shot lane unit and acknowledge the exact action.
8. Reload and inspect the immutable journal-backed receipt.
9. Create and review the evidence proposal, then apply it to control and audit.
10. Repeat steps 5–9 for the next fixed operation.
11. Derive `security_applied` only after all seven durable evidence records are
    exact and current.
12. Release the terminal claim through the original idempotency identity.

The exported loopback live-interface foundation has a disabled backend and
cannot enable mutations; it does not currently display this transaction from a
configured authority. A deployment-specific integration may display authority
state and server-supported actions, but it is not itself the root execution
boundary and must never fall back to the in-browser simulation. See the
[station UI guide](provisioning-station-kiosk.md).

## Claims, leases, and proposals

Lease renewal is intentionally narrow:

- approval is never renewed;
- an expired claim cannot be revived;
- a proposal's resource version is immutable;
- renewal between proposal review and apply invalidates that proposal;
- a pending intent may be renewed only in its exact compiler-derived state
  immediately before the one-shot unit starts;
- a ready campaign may be renewed only while preserving the exact successful
  prefix; and
- terminal evidence from an on-time operation may be recorded after approval
  expiry only while the exact mutation claim remains current.

Immediately before hardware dispatch, the guard refreshes the authenticated
binding and requires server-confirmed minimum authority windows. This closes
the gap between an earlier proposal and a delayed physical observation.

## Execute-once journal

The journal identity binds the plan, operation, target, authority, and attempt.
Ordering is:

```text
verify current authority and physical preconditions
  -> persist AttemptStarted
  -> dispatch at most one physical action
  -> persist terminal result
  -> reload terminal record
  -> publish immutable receipt without replacement
```

An exact rerun that finds the terminal record may verify or republish that
receipt while current publication authority remains valid. It cannot call the
hardware adapter again.

Journal schema changes are not silently migrated. A nonempty incompatible
journal removes the lane from service until the target is resolved externally.
Only a journal positively known to be empty and never used for a live operation
may be replaced as deployment maintenance.

## Failure and reconciliation

| Observation | Permitted response |
| --- | --- |
| Failure before `AttemptStarted` | Correct the non-hardware condition and create a new reviewed proposal if state changed |
| Durable terminal receipt exists but publication failed | Re-enter through current authority and republish the exact durable receipt |
| `AttemptStarted` exists without a durable terminal result | Preserve state; do not execute again; enter reconciliation |
| Hardware may have mutated but claim or approval expired | Acquire only the reviewed read-only reconciliation authority; never new mutation authority for the old result |
| Customer-key or EEPROM state is unexpected | Quarantine |
| Target identity or fence changed | Stop; reject the proposal and re-establish inventory state |
| Safe-off cannot be established | Record `unproven`, isolate the lane, and require external inspection |

Reconciliation is observation-only. It may establish which terminal state
already exists; it cannot replay the original operation. If observation cannot
prove a safe and authorized state, the target becomes `owned_quarantined` or
otherwise unavailable to the fresh-device path.

## Evidence boundary

Retain secret-free, immutable records for:

- qualification and target binding;
- complete signed-release and publication digests;
- transaction, claim, fence, draft, approval, and intent;
- journal start and terminal records;
- physical boot/power transition observations and their limitations;
- operation receipts and control/audit admission;
- reconciliation or quarantine decisions; and
- final claim release.

Never include private keys, PINs, OTP secrets, raw device-private keys,
derived storage secrets, active credentials, or unrestricted raw probe data.

`security_applied` means only that this development campaign's seven records
were accepted. It does not prove production anti-rollback, device enrollment,
or production readiness. Those are defined in the
[production follow-on](raspberry-pi-5-production-security-follow-on.md).
