# Production provisioning-station architecture

## Status and scope

This document proposes the architecture for a dedicated production
provisioning station. It adapts the platform-neutral station goals from the
earlier Kaiba design to this standalone repository and connects them to the
current Raspberry Pi 5 development foundations.

> [!IMPORTANT]
> This is a target architecture, not an implemented production station or an
> authorization to provision a device. The repository currently provides a
> read-only hardware probe, development control and audit services, an
> authority bridge, a fail-closed lane guard, release and media contracts, and
> operator-interface foundations. It does not provide a production inventory,
> registration authority, certificate-activation service, pending-credential
> verifier, or qualified production station.
>
> The exported `kaiba-provision-station` package is a loopback-only interface
> foundation with no installed hardware orchestration backend. It rejects a
> request to enable mutation. The separate `kaiba-provision-station-demo` and
> static Pages output are simulations. None of these programs grants live
> provisioning authority.

The current implementation and its authority boundaries are described in
[Architecture and trust boundaries](architecture-and-trust-boundaries.md),
[Live provisioning](raspberry-pi-5-live-provisioning.md), and
[Production readiness](production-readiness.md). The device enrollment and
credential model used here is the proposed
[device identity lifecycle](device-identity.md).

## Why production uses a dedicated station

Provisioning combines physical target access, bootstrap authority, sensitive
inventory context, and potentially irreversible security changes. Keeping that
intersection off general-purpose operator and development machines makes its
software, identities, network paths, physical custody, and audit behavior small
enough to qualify as one controlled boundary.

A production station is a managed appliance. It is not used for source
development, builds, email, general web browsing, arbitrary removable media, or
ordinary administration. It begins with one station, one physically labelled
lane, and one attached target. Parallel lanes are a later qualification step,
not a throughput shortcut.

The station is not a fleet root of trust. Its purpose is to coordinate one
approved transaction and operate one physical lane while stronger authorities
retain fleet-wide decisions. A fully compromised station can still damage or
misconfigure the target physically connected to it and can misuse authority
already issued to it. The design limits that exposure through short-lived,
transaction-bound capability, independent approval, central activation,
fencing, and externally retained audit evidence; it does not claim that host
hardening makes physical compromise harmless.

## Core invariants

A production implementation must preserve all of these rules:

- One station lane processes exactly one centrally claimed target at a time.
- Every reversible validation completes before the first irreversible effect.
- The operation sequence, classifications, expected prestates and
  postconditions, device profile, artifacts, station, lane, target, transaction,
  fence epoch, and deadlines are immutable before execution.
- Public release authorization is never interpreted as per-device execution
  authorization. See the
  [signed-boot workflow](raspberry-pi-5-signed-boot-workflow.md).
- A configured hardware selector identifies where an authorized action may be
  attempted; it is not device authentication or attestation.
- The station requests enrollment, issuance, verification, and activation, but
  no station-local action can assign an identity, issue a certificate, or make
  a credential active.
- Target private keys are generated or derived inside their final protection
  boundary wherever the device profile supports that claim.
- Every mutation records intent before dispatch and is followed by direct,
  profile-defined postcondition observation.
- An uncertain one-way result enters read-only reconciliation or quarantine. It
  never becomes permission to repeat the mutation.
- The station journal and external audit contain structured, secret-free
  evidence. Loss of the station cannot erase fleet provenance.
- Production and development stations use different credentials, inventories,
  issuers, policies, artifacts, and trust domains.

## Authority ownership

The station coordinates these authorities but does not replace any of them:

| State or decision | Authoritative component | Station capability |
| --- | --- | --- |
| Physical target state | Target, established through profile-defined observation and readback | Operate one claimed lane and report bounded observations |
| Transaction and asset binding | Provisioning coordinator | Request transitions using the current claim and resource version |
| Logical device identity and instance | Inventory and registration policy | Present the claimed asset and evidence; never choose an identity from target input |
| Claim lease and fence epoch | Provisioning coordinator | Acquire or renew a scoped claim; carry the epoch on every action |
| Irreversible commit approval | Independent approval authority | Present an immutable plan digest and consume the resulting narrow approval |
| Approved artifacts and policy | Artifact and policy authority | Resolve immutable contents by digest and verify them locally |
| Bootstrap authentication and enrollment authorization | Registration authority (RA) | Relay a transaction-bound challenge, response, and proof of possession |
| Certificate issuance and serial ledger | Certification authority (CA) | Submit the RA-authorized request and validate the public result |
| Credential generation and lifecycle state | Inventory | Stage a new tuple and request compare-and-set transitions |
| Pending credential proof | Pending-credential verifier | Ask the target to prove the installed key against a fresh challenge |
| Credential activation | Inventory, gated by RA policy and a valid verifier receipt | Request activation of one exact staged tuple; never activate locally |
| In-flight intent and local observations | Crash-safe station journal | Persist bounded recovery state and an audit outbox |
| Immutable provisioning provenance | Independent audit service | Append events and retain returned receipts; no arbitrary history rewrite |

The RA assigns the canonical logical identity. It ignores or replaces
identity-bearing CSR fields, hostnames, serials, MAC addresses, and target
request fields. The CA signs only the profile authorized by the RA. A
certificate's existence and X.509 validity do not activate it.

Activation is an atomic inventory operation over the exact logical device,
logical instance, credential slot, key generation, issuer, serial, public-key
fingerprint, and verifier receipt. If the station loses the activation
response, it reads authoritative inventory state and completes the audit
record. It does not issue a second certificate or invent a local rollback.

## Logical topology

```text
named operator                 independent approver
      |                                 |
      v                                 v
+---------------------- production station ----------------------+
| loopback operator UI -> orchestrator -> crash-safe journal      |
|                              |                 +-> audit outbox  |
| verified artifact cache      v                                  |
|                        sandboxed adapter                         |
| station identity broker      |                                  |
|                        privileged lane guard                    |
+-------------------------------|---------------------------------+
                                |
                         isolated target lane
                                |
                                v
                         exactly one target

station management network, mutually authenticated and scoped
                                |
                                v
+---------------------- control authorities ----------------------+
| coordinator | inventory | approval | artifact/policy | RA -> CA |
| pending verifier | independent append-only audit                 |
+-----------------------------------------------------------------+

offline roots, issuing keys, customer boot roots, release-signing
keys, and fleet-wide administrator credentials remain elsewhere
```

Roles may share infrastructure only when their identities, credentials,
authorization decisions, state, and audit records remain logically separate.
Co-location must not silently turn a station credential into inventory, RA, CA,
artifact-signing, or activation authority.

## Network zoning

The management interface and target-facing lane occupy separate security zones.
The station must not bridge, route, proxy, or perform network address
translation between them.

The management zone permits only mutually authenticated access to the exact
coordinator, inventory, approval, artifact, RA, pending-verifier, audit, time,
monitoring, and update endpoints required by policy. Destination identity,
audience, protocol, and port are fixed. General Internet egress, discovery,
wildcard service identities, and unauthenticated fallback are prohibited.

The target lane permits only the device-specific bootstrap transports and any
explicitly required enrollment, update, time, or recovery endpoints. A target
cannot use the station as a path to the management network, production
services, inventory administration, the CA, or arbitrary egress. A malicious
target and every byte it sends are untrusted input to a bounded parser.

The initial production design is online and fails closed. If a required
authority, trusted-time source, or external audit receipt is unavailable, the
station does not begin an irreversible operation. Loss before commit pauses or
cleanly aborts after proving a reusable baseline. Loss after commit stops new
mutation and enters reconciliation; it never enables disconnected continuation.

An offline irreversible mode would require separate signed grants, expiry,
quotas, monotonic replay protection, local activation rules, and an explicitly
lower-assurance review. It is outside this architecture. The proposed
Raspberry Pi production design also requires a fresh server policy decision
before protected state or services become available; see the
[production security follow-on](raspberry-pi-5-production-security-follow-on.md).

## Station components

### Health and fence agent

Before transaction admission and continuously during work, the station checks:

- approved boot, operating-system, package, configuration, and policy identity;
- station and workload credentials, service audiences, and revocation state;
- trusted time and minimum remaining credential lifetime;
- disk, journal, audit-outbox, memory, swap, and secret-bearing crash policy;
- network-zone and firewall configuration;
- physical lane, USB, UART, power, and target-presence state; and
- central station, lane, and maintenance authorization.

Configuration drift is an authorization failure, not merely an alert. The agent
prevents new admission if the station or lane is fenced, in maintenance,
outside its approved posture, near credential expiry, or unable to export audit
events. A station-wide posture failure fences every lane.

### Station identity broker

Each station has a unique, revocable bootstrap identity established during a
controlled station-enrollment ceremony. A protected, non-exportable key is
preferred. The bootstrap identity is used only for station lifecycle and for
obtaining short-lived, audience-restricted workload credentials.

The broker exposes narrow authentication or signing operations to named local
services. It does not expose raw key bytes or a generic signing oracle to the
orchestrator. Reimaging or replacing a station normally creates a new station
identity; restoring a disk image never restores transaction authority by
itself.

### Operator interface and orchestrator

Routine operators use a constrained loopback interface rather than a privileged
shell. Before commit it displays the station and lane, intended asset and
logical identity, target-binding observations and limitations, profile,
artifacts, policy, ordered operations, expected postconditions, point of no
return, approval, fence epoch, and transaction digest.

The interface sends only typed actions with the current state revision. It
cannot accept arbitrary commands, executable or payload paths, device nodes,
profiles, certificate names, or key selectors. Browser content never receives
raw device access. The simulation and live-interface foundations described in
the [station-interface guide](provisioning-station-kiosk.md) remain separate;
the static transition graph is never fallback behavior for a live station.

The orchestrator validates station admission, resolves the approved plan,
coordinates external authorities, checks the claim and approval, and invokes
one typed adapter operation. It never infers progress solely from a local stage
marker, certificate file, or successful command exit.

### Artifact resolver and platform adapter

The resolver accepts content only by immutable digest and revalidates the signed
manifest, expiry, revocation, dependency closure, source lineage, device-class
compatibility, rollback policy, and operation classifications for every
transaction. Mutable tags, implicit latest versions, unsigned local overrides,
and unreviewed cache entries fail closed.

The platform adapter and target protocol parser run with the least privilege
needed for one lane. They have no CA, inventory-administration, artifact-signing,
audit-read, or arbitrary network authority. Inputs and outputs use bounded,
versioned schemas, sizes, and deadlines. The adapter receives one typed target
handle and one declarative operation, never shell text.

### Privileged lane guard

The lane guard exclusively owns the physical target handle. It permits a
mutation only when the station and lane, transaction, target fingerprint,
current claim, fence epoch, approved plan, operation, expected prestate,
preceding postconditions, payload, boot mode, authority, and remaining time all
match.

It rejects multiple eligible targets, replacement or disappearance, an
unexpected device class, stale authority, out-of-order work, and any plan
change. The current repository's fixed development campaign and execute-once
journal demonstrate part of this shape; they do not qualify the proposed
production station. See [Live provisioning](raspberry-pi-5-live-provisioning.md).

### Journal and audit exporter

Every mutation follows this ordering:

```text
validate exact preconditions
  -> durably record and export intent
  -> receive the required independent audit receipt
  -> execute once
  -> directly observe the postcondition
  -> durably record and export evidence and result
```

The journal records only canonical digests, resource versions, claim and fence
state, actor and authorization references, bounded observations, external
receipts, and terminal results. It is a recovery replica and audit outbox, not
an alternative inventory, CA ledger, or audit authority.

An incompatible nonempty journal is not auto-migrated. It removes the lane from
service until the target is reconciled or quarantined. Station wall-clock time
is supporting evidence; the independent audit service assigns authoritative
ordering and returns a durable receipt.

## Claims, approval, and fencing

A provisioning claim is a renewable lease plus a monotonic fence epoch:

1. Acquisition reserves one transaction and physical asset for one station and
   lane and increments the epoch.
2. Renewal may extend expiry without changing the approved state or epoch.
3. Reacquisition or transfer increments the epoch and invalidates approval for
   the previous epoch.
4. Every central transition and physical dispatch carries the current epoch.
5. The lane requires enough remaining lease and approval time for the
   operation's worst-case duration plus a safety margin.
6. Lease loss blocks new dispatch immediately. An action already sent may have
   completed, so its result remains unknown until direct reconciliation.
7. A read-only reconciliation claim may observe state but cannot become mutation
   authority.
8. A claim is released only after completion, a proved clean abort, or recorded
   quarantine.

Fencing is independently enforceable at three levels:

- **Device quarantine** denies production use and routine renewal while
  permitting only explicitly approved recovery or retirement.
- **Lane fencing** prevents new work through one physical attachment.
- **Station revocation** prevents the host from acquiring or renewing any
  transaction authority.

Named operator, administrator, approver, artifact publisher, and audit reviewer
roles use distinct credentials. Production commit approval is issued outside
the potentially compromised station interface and binds the exact transaction,
station, lane, target, epoch, plan, artifact and policy digests, operation set,
and expiry.

## Credential and activation flow

The station may relay the proposed enrollment lifecycle, but each decisive step
belongs to another authority:

1. The target produces a bootstrap response and fresh operational-key proof of
   possession bound to the transaction digest and RA audience.
2. The RA authenticates the bootstrap evidence, assigns the inventory-owned
   logical identity, constrains the requested certificate profile, and
   authorizes issuance.
3. The CA records and returns one idempotent certificate result.
4. Inventory records the exact device, instance, slot, key-generation,
   public-key, issuer, and serial tuple as staged.
5. The station validates and atomically installs the public certificate, trust
   bundle, and policy metadata on the target.
6. The pending verifier challenges the installed private key and returns a
   signed receipt bound to the exact staged tuple and transaction.
7. The station may submit that receipt and request activation.
8. Inventory performs a compare-and-set activation only if every current policy
   and lifecycle precondition still holds.
9. A relying service proves production authentication and checks current
   inventory authorization before physical release is allowed.

Issuance, installation, pending verification, or a station-local success screen
is not activation. A CA-valid certificate for a quarantined, retired,
superseded, or inactive tuple remains production-denied.

## Secret and sensitive-material handling

The station may hold only its protected station identity, short-lived workload
credentials, action-bound operator assertions, expiring transaction
capabilities, read-only artifact authorization, append-only audit authorization,
and narrowly scoped pending-verifier access.

It must not hold:

- offline-root, issuing-CA, Pi customer-root, release-policy, delegated-release,
  or artifact-signing private keys;
- fleet-wide RA, inventory, or activation administrator credentials;
- credentials for another station, lane, target, or transaction;
- persistent fleet-wide bearer or bootstrap tokens;
- a target's root secret, private authentication key, OTP secret, LUKS key, or
  derived unlock value; or
- a credential capable of activating an arbitrary inventory tuple.

Target keys should be generated or derived inside the target boundary, with
only public keys, endorsements, fingerprints, and proofs returned. A profile
that cannot avoid secret injection uses a separately reviewed lower-assurance
path: a protected broker delivers one target-bound encrypted envelope directly
to the adapter or target boundary. The generic orchestrator, browser, journal,
logs, packet captures, audit service, and backups never receive plaintext.

Per-device workspaces are encrypted or memory-only, never reused, and cleared
before another target is admitted. Secrets are prohibited from command
arguments, broad environment variables, shell history, swap, logs, telemetry,
packet captures, crash dumps, the Nix store, public evidence, support bundles,
and ordinary station backups.

## Failure, retry, and quarantine

- Before the first irreversible effect, abort is allowed only after proving the
  target returned to an approved reusable baseline, erasing transient
  authorization, releasing the claim, and recording the result centrally.
- At or after that boundary, an unknown result, unverifiable postcondition,
  changed target, lease loss during mutation, restart mismatch, or missing audit
  evidence quarantines the device.
- A timeout or lost response causes direct observation and authoritative
  reconciliation. It never authorizes blind repetition of a mutation,
  enrollment request, or certificate issuance.
- An issued but unverified certificate remains staged and follows bounded expiry
  or explicit revocation. It is never silently activated.
- A public-key collision, failed proof of possession, out-of-profile
  certificate, policy-violating issuance, suspected secret exposure, invalid
  artifact, or audit-integrity failure also fences the affected lane or station.
- A changed target, key, logical identity, artifact, adapter, policy, approval,
  tool revision, or fence epoch cannot be repaired inside the original
  transaction.

If a station restarts or is restored, it queries the central authorities and
directly re-observes every incomplete target. A local success marker never
activates a device or authorizes continued mutation.

## Station lifecycle and operations

```text
unenrolled -> enrolled -> qualified -> active <-> maintenance
                                      |             |
                                      +-> fenced <--+
                                            |
                                            v
                                         retired
```

### Build, enroll, and qualify

Install an authenticated, pinned, reproducible station baseline with verified
boot, rollback controls, encrypted state, a production debug policy, minimal
services, and a protected unique station identity. Register the asset, owner,
location, hardware and software profile, lane, and configuration digests.

Qualification uses test-only trust domains and sacrificial targets. It covers
every mutation boundary, reconnect, reboot, timeout, lost response, stale fence,
wrong target, negative test, reconciliation, quarantine, and audit path.
Production promotion is an independent decision that grants bounded production
roles; it never copies test credentials or history.

### Updates and maintenance

An update drains active work, fences admission, enters maintenance, installs an
approved signed and rollback-constrained generation, reboots when required,
checks effective posture, and reruns the applicable qualification suite before
returning to active service.

Changes to orchestration, adapters, cryptography, kernel or device drivers,
firmware, trust bundles, journal or audit schemas, networking, or security
policy require stronger requalification than a data-only change. Routine
operators cannot approve station software or policy updates. Emergency in-place
changes do not become a supported baseline until incorporated through the
reviewed build and release process.

### Backup and recovery

Backups contain declarative configuration, public trust material, immutable
artifact references, central transaction references, and only the encrypted
journal or audit outbox needed for reconciliation. They exclude target secrets,
production signing keys, broad bearer tokens, live credentials, and unbounded
diagnostics. Backups are encrypted under separate custody, authenticated,
versioned, and restore-tested.

Replacement hardware normally requires a new station identity, fresh
qualification, explicit claim transfer, target rebinding, and new approval for
any remaining destructive work. External HSM and signer recovery follows its
own split-custody procedure; it is not part of a station backup.

### Monitoring and incident response

Monitor station posture and drift; authentication; target connection and lane
assignment; claim and fence changes; artifact, expiry, revocation, and rollback
decisions; every intent, operation, readback, issuance, verification,
activation request, and audit receipt; abnormal rates and repeated failures;
credential expiry; clock quality; disk and journal health; and audit-export
gaps.

On suspected compromise, fence the station and every lane, revoke station
workload credentials, invalidate unexpired capabilities and approvals, stop
related issuance and activation, preserve independent evidence, determine the
exposure window, and review every affected device. Rebuild from the approved
baseline under a new station identity and requalify. Do not trust in-place
cleanup of a compromised production station.

### Decommissioning

Drain, transfer, reconcile, or quarantine every incomplete transaction. Revoke
station and lane credentials and remove coordinator, RA, verifier, artifact,
and signer authorization. Export the final audit record, sanitize local
credentials, tokens, journals, caches, encryption keys, and storage under the
approved media policy, and retire the asset. Station and lane identifiers are
not reassigned.

## Production acceptance gates

A production implementation must demonstrate, with evidence from the exact
station build and physical lane, that:

- more than one eligible target, target replacement, or changed target binding
  prevents mutation;
- no write occurs without a current transaction, claim, fence epoch, approved
  immutable plan, and legal state transition;
- no irreversible operation occurs without externally retained intent, exact
  independent approval, and sufficient remaining authority time;
- crashes and lost responses before, during, and after every mutation reconcile
  without blind redispatch;
- stale station credentials, claims, approvals, fence epochs, and resource
  versions fail at both the control and lane boundaries;
- a malicious target or CSR cannot choose another identity, SAN, key usage,
  certificate profile, credential slot, or key generation;
- repeated issuance with identical idempotency inputs returns the authoritative
  original result while changed key or transaction context fails;
- station credentials cannot issue certificates, publish artifacts, alter
  unrelated inventory, activate arbitrary credentials, or operate another
  station, lane, or transaction;
- target roots and private keys never appear in station memory outside an
  explicitly reviewed narrow boundary, persistent storage, swap, logs, audit,
  packet capture, crash output, support bundles, or backups;
- a staged certificate works only at the pending verifier and remains denied by
  production before central activation;
- activation changes only the exact tuple named by a valid verifier receipt and
  a current inventory compare-and-set;
- audit loss, evidence mismatch, failed post-restart proof, or an unknown
  irreversible outcome prevents completion and invokes quarantine or fencing;
- device quarantine, lane fencing, and station revocation work independently;
- a partially provisioned or quarantined target can never re-enter the
  unprovisioned path;
- management and target zones cannot route, bridge, proxy, or NAT traffic to one
  another, including during maintenance and failure;
- service loss before commit pauses or safely aborts, while loss after commit
  stops mutation and reconciles rather than continuing offline;
- update, restore, reimage, and replacement cannot revive stale transaction,
  issuance, approval, or activation authority; and
- decommissioning closes every incomplete transaction, revokes authority,
  exports final audit evidence, and sanitizes station state.

Only after the single-lane station passes these gates should additional lanes
be considered. Each lane then requires its own permanent identifier, physical
mapping, target transport or network namespace, executor boundary, claim and
fence epoch, journal, workspace, and cross-lane negative tests.

## Current standalone boundary

This repository currently supplies useful development pieces of the proposed
shape:

- strict, versioned contracts and a read-only
  [Raspberry Pi 5 probe](raspberry-pi-5-provisioning-probe.md);
- development control, audit, authority-bridge, workflow, and lane-guard
  implementations;
- an inert
  [Ubuntu authority deployment](../deploy/ubuntu-provisioning-authority/README.md)
  using development PKI;
- public signed-release construction and verification boundaries;
- plan-specialized [target-media](target-media-staging-prototype.md) writer and
  verifier factories; and
- separate live-interface foundations and authority-free browser simulations.

It does not yet supply the production station identity broker, health/fence
agent, inventory and exact-tuple activation service, RA/CA integration,
pending-credential verifier, production artifact authority, qualified network
zones, complete production orchestrator, or station lifecycle automation. The
current development policy still stops at `security_applied` and sets
`enrollment_ready` to false. Those gaps must remain explicit until the
production acceptance campaign closes them.
