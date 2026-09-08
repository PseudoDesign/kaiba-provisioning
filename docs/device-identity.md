# Device identity and credential lifecycle

## Status and scope

This document defines the target production contract for provisioning,
enrolling, operating, rotating, recovering, and retiring Kaiba device
credentials. It is platform-neutral where possible and specializes the
Raspberry Pi 5 bootstrap requirements described in the
[production security follow-on](raspberry-pi-5-production-security-follow-on.md).

> [!IMPORTANT]
> This lifecycle is not implemented by the current repository. The current
> Raspberry Pi 5 development posture creates no production device identity,
> issues no production certificate, and cannot enter `enrollment_ready`.
> Test PKI, file-backed fixtures, public development signer metadata, and a
> successfully verified boot artifact do not establish an enrolled device.

An implementation may use a hardware security module, secure element, firmware
key service, isolated operating-system signer, or protected software key. Its
assurance claim must name the attacker boundary actually provided by that
mechanism.

## Security objective

When a service accepts a device, it needs evidence that:

1. the peer currently possesses the private key for the presented credential;
2. the registration authority assigned that key exactly one canonical logical
   device identity; and
3. the device, credential role, key generation, certificate instance, issuer,
   release authorization, and lifecycle state remain allowed by current policy.

The registration authority, not a device-supplied hostname, serial number,
MAC address, common name, or request field, assigns the canonical identity. A
deployment may represent it as a URI such as
`spiffe://kaiba.network/device/001`; the concrete namespace is policy, while
the rule that the device cannot choose another identity is mandatory.

Authentication and attestation are distinct:

- **Authentication** proves possession of a credential authorized for an
  identity.
- **Attestation** supplies fresh, appraisable evidence about the environment
  holding or using a credential.

A valid mutual-TLS connection is authentication, not proof of the complete
boot or runtime state. A device-signed version report is not trustworthy
attestation unless an independent verifier can establish protected collection,
freshness, endorsements, reference values, and appraisal policy.

## Identity and key roles

- **Logical device ID**: stable operator-assigned inventory identity. It is not
  itself a hardware authentication factor.
- **Logical device instance**: one enrollment of hardware and storage. A
  destructive storage replacement creates a new instance even when the board
  stays the same.
- **Device root secret**: device-lifetime secret or private key anchoring
  stronger derivations. It is not the PKI root-CA key and is never a general
  network credential.
- **Bootstrap identity**: narrowly accepted for enrollment, recovery, and
  pre-release authorization. It is not used for routine application traffic.
- **Operational identity**: replaceable key and certificate used by one
  deployed workload or protocol.
- **Attestation identity**: restricted key used only to authenticate structured
  evidence, when the platform can support the claimed boundary.
- **Credential slot**: one operational role for one logical device, such as an
  outbound management client or inbound application service.
- **Key generation**: monotonically increasing private-key generation within a
  credential slot.
- **Certificate instance**: issuer-and-serial certificate for a key generation.
  Same-key renewal changes the instance, not the generation.
- **Proof of possession (PoP)**: fresh cryptographic proof that the requester
  controls the private key corresponding to the enrolled public key.
- **Validation bundle**: public trust anchors and intermediates used to
  authenticate the enrollment and relying services.

One key has one purpose. Pi customer-root signing, release-policy signing,
delegated release signing, LUKS unlock, bootstrap authentication, operational
authentication, inbound service authentication, attestation, storage
encryption, and CA issuance use separate keys or reviewed, strongly
domain-separated derivations.

For the proposed no-TPM Pi design, the preferred pre-unlock bootstrap identity
is a separate hardware key or a strongly domain-separated child key. Direct
HMAC/ECDSA dual use of the BCM2712 device-private OTP key is not an assumed
capability. A software key created inside LUKS may serve as a lower-assurance
operational key after unlock, but cannot satisfy the stable verifier's
pre-unlock bootstrap requirement.

## Device-resident material

| Material | Secret? | Required treatment |
| --- | --- | --- |
| Device root or bootstrap private key | Yes | Device-unique, non-exportable where claimed, accepted only at narrow bootstrap/recovery services |
| Operational private key | Yes | Unique per device, slot, and generation; available only through its intended signer boundary |
| Operational certificate | No | Integrity-critical; atomically installed and tracked by issuer, serial, slot, and generation |
| Validation bundle | No | Integrity- and rollback-sensitive; updated through an authenticated path |
| Attestation private key | Yes | Restricted to structured evidence; never exposed as a generic TLS key |
| LUKS and data-encryption material | Yes | Separate from identity and signing roles; never included in audit evidence |
| One-boot private key | Yes | Generated for one authorized boot, held in volatile memory, then destroyed |
| Enrollment/recovery token | Yes | Single device, transaction, audience, and use; short-lived and erased afterward |
| Hardware identifiers | Usually no | Inventory correlation only; not proof of possession |
| Transaction and idempotency state | No | Durable and integrity-protected because it prevents replay and unsafe retry |

A deployed device must not contain:

- root or issuing CA private keys;
- Pi customer-root or routine release-signing private keys;
- provisioning-station administrator credentials;
- another device's secrets;
- broad infrastructure-provider credentials; or
- a fleet-shared symmetric bootstrap secret.

Secrets must not enter command arguments, environment dumps, logs, crash
reports, telemetry, packet captures, build outputs, the Nix store, public
evidence, or support bundles.

## Threat and assurance boundary

Each device profile must state whether it is intended to resist:

- copied, removed, or modified storage;
- hostile networks and replayed enrollment traffic;
- compromise of an unprivileged application;
- compromise of the network-facing agent;
- administrator or kernel compromise;
- debug access and non-invasive physical access;
- invasive extraction, fault injection, or side channels; and
- provisioning-station or supply-chain compromise.

File permissions plus LUKS protect against offline storage theft, but a running
privileged process can normally use or copy decrypted software keys. An
isolated signer narrows operations but inherits the OS privilege boundary. A
hardware non-exportable signer may prevent key extraction, but compromised
authorized software may still use it as a signing oracle. Documentation must
not collapse those different assurances into the phrase "hardware-backed."

## Production requirements

### Key and identity requirements

- Every device-authentication key is unique; no image, backup, or batch may
  clone it.
- Generate private keys within their final protection boundary using a
  qualified random source. If injection is unavoidable, use an authenticated,
  target-bound confidential channel and prove transient erasure.
- Obtain fresh PoP for every new asymmetric key before authorization.
- The registration authority assigns canonical identity and ignores or
  replaces identity-bearing CSR fields.
- Certificates constrain intended usage through basic constraints, key usage,
  extended key usage, SAN policy, algorithms, and issuer policy.
- Algorithm, key-size, certificate-profile, and signer-interface changes do
  not rename the logical device.

### Access requirements

- Network-facing code receives only a constrained signing interface for its
  own operational slot, not raw bootstrap, storage, attestation, or unrelated
  application keys.
- Signer access is restricted by service identity, operation, key identifier,
  algorithm, rate, audience, and input size where supported.
- Verified boot, rollback, debug lifecycle, update authorization, and operation
  locks match the claimed key boundary.
- An unavailable signer, expired certificate, stale trust bundle, or failed
  policy check fails closed; there is no unprotected fallback key.

### Fleet and service requirements

- Inventory binds logical ID, logical instance, bootstrap public identity,
  storage generation, credential slots, key generations, certificate
  instances, release authorization, lifecycle, and provisioning history.
- Relying services check both PKI validity and current inventory authorization.
  A CA-valid certificate for a quarantined, retired, superseded, or otherwise
  inactive tuple is insufficient.
- Production, development, staging, device, station, enrollment, and test roles
  use separate issuers or equivalently strict trust and issuance policies.
- The offline trust root does not perform routine issuance.
- Lifecycle operations are authenticated, authorized, idempotent, and
  attributable to a service or human identity.
- Recovery, revocation, CA compromise, ownership transfer, and retirement are
  designed and tested before the first production device is enrolled.

## Provisioning and enrollment roles

- **Device** generates or contains keys and proves possession.
- **Provisioning station** controls physical/bootstrap access and executes a
  reviewed transaction without owning fleet roots.
- **Registration authority (RA)** authenticates bootstrap evidence, assigns
  logical identity from policy, and authorizes issuance.
- **Certification authority (CA)** signs constrained certificates after RA
  authorization.
- **Inventory** owns identity bindings, states, generations, and activation.
- **Pending verifier** tests staged credentials without granting production
  access.
- **Relying service** authenticates the operational certificate and checks
  current inventory policy.
- **Attestation verifier**, if used, appraises evidence independently of the
  relying service.

Roles may be hosted together, but their credentials, authorization, and audit
records remain logically separate. The station never holds the offline CA root,
and the CA never infers device identity from untrusted CSR fields.

## Enrollment transaction

Bootstrap authentication and operational-key PoP are separate checks. Both
must be bound to one canonical transaction digest containing the nonce,
logical identity assigned by policy, device instance, storage generation,
operational SPKI, credential slot, key generation, certificate profile,
release authorization, policy version, and intended RA/audience.

A signed CSR proves possession of its CSR key when correctly validated. It
does not by itself authenticate a bootstrap identity, authorize requested
names, or bind all surrounding transaction state.

Provisioning is a durable state machine, not a script that infers progress from
whatever certificate or target state it happens to observe:

1. **Create transaction.** Reserve the logical ID and asset; bind device class,
   operator, approver, nonce, expiry, policy, exact artifacts, and idempotency
   key. Acquire an exclusive claim and monotonic fence epoch.
2. **Bind target.** Observe exactly one candidate and bind stable public
   observations to the transaction. Physical identifiers correlate inventory;
   they do not replace cryptographic PoP.
3. **Validate baseline.** Establish that ownership, boot, rollback, debug,
   recovery, storage, entropy, clock, key slots, and prior transaction state
   match the signed device-class policy. Unknown state fails.
4. **Approve exact plan.** Resolve ordered operations and postconditions. Bind
   independent approval to transaction digest, target, fence, artifacts,
   policy, and operation list. Any change invalidates approval.
5. **Establish mutual initial trust.** The RA authenticates and authorizes the
   candidate's bootstrap evidence; the device authenticates and authorizes the
   intended enrollment domain. Physical custody alone supplies neither
   direction automatically.
6. **Apply security foundation.** Establish verified boot, fresh-release gate,
   storage, debug, update, recovery, and operation-lock posture. Record intent
   before each irreversible action and verify direct postconditions.
7. **Create device-unique material.** Generate or derive keys in their final
   boundaries. Export only public keys, endorsements, and fingerprints. Check
   uniqueness and obtain fresh PoP.
8. **Authorize and stage credential.** Bind bootstrap authentication and PoP to
   the same fresh transaction. Inventory records a pending generation; the RA
   assigns identity; the CA issues a constrained staged certificate.
9. **Validate and install.** Check issuer, path, SPKI, SAN, algorithms,
   constraints, usage, validity, profile, and transaction binding. Atomically
   install certificate, validation bundle, and policy metadata in LUKS.
10. **Finalize and restart.** Erase bootstrap tokens and transient secrets;
    apply final key, debug, boot, recovery, and storage locks; cold restart and
    read back effective state. Production still rejects the staged credential.
11. **Verify and activate.** Prove the installed key to the pending verifier;
    run replay, key-substitution, alternate-identity, and untrusted-issuer
    negative tests. Atomically activate the exact device/slot/generation/
    certificate tuple, then prove production authentication.
12. **Complete.** Export the secret-free audit record, reconcile authoritative
    RA and inventory state, clear station workspaces, release the claim, and
    only then release the physical device.

Issuance alone is not completion. A successful terminal transaction has an
active exact tuple, production authentication proof, and confirmed independent
audit export.

## State and retry model

```text
transaction:
  created -> target_bound -> preflight_passed -> commit_approved
  -> trust_established -> security_applied -> identity_ready
  -> credentials_staged -> installed -> verified -> activated -> complete

terminal exceptions: aborted | quarantined

device: staged -> active <-> quarantined -> retired
key generation: pending | active | superseded | revoked
certificate: staged | active | superseded | revoked | expired
```

Every stage has durable input and output digests and direct postconditions, but
no secrets. Every mutation follows:

```text
check exact preconditions -> record intent -> execute once
-> observe authoritative state -> record evidence and result
```

Before the first irreversible effect, abort is allowed only after proving the
reusable baseline and absence of pending credentials or unique secrets. At or
after that boundary, an unknown, mismatched, or partial result becomes
quarantined and can never be presented as unprovisioned.

An exact idempotent retry returns the recorded result or resumes only after
reconciling observed and authoritative state. A timeout or lost response does
not authorize repetition. A different target, key, logical ID, policy,
artifact, approval, tool version, or fence epoch stops the transaction.

If certificate activation succeeded but the station lost the response,
inventory is authoritative: read it and finish the audit record. Do not issue a
second certificate or invent a rollback.

## Steady-state authentication

For each full transport authentication, the relying service must:

1. enforce the approved TLS version and mutual authentication where required;
2. validate path, issuer, validity, algorithms, constraints, usage, and EKU;
3. validate the canonical identity SAN/profile and ignore common name or
   application request fields for identity selection; and
4. enforce revocation and session-resumption policy.

For application authorization, or within a short cache invalidated by
quarantine events, it must map the certificate to the canonical device and
confirm that the device instance, credential slot, key generation, and exact
certificate instance are active. Apply a fresh attestation result separately
when policy requires it.

Different protocols use different credential slots. An outbound management
client and an inbound application service do not share a private key merely
because they run on the same device.

## Renewal, rotation, and trust rollover

Certificate renewal retains a key and creates a new certificate instance.
Operational rekey creates generation `N+1`. These are not interchangeable;
routine risk-limiting rotation should replace the key.

Routine operational rekey:

1. starts before expiry with fleet jitter and an offline-device margin;
2. generates `N+1` in its final protection boundary;
3. authenticates with the current credential and separately proves possession
   of `N+1`;
4. records `N+1` pending while `N` remains active for a bounded window;
5. proves `N+1` to the pending verifier;
6. atomically activates `N+1` and supersedes `N`; and
7. revokes or expires `N`, then destroys its private key after any approved
   rollback window.

If `N` may be compromised, possession of `N` cannot authorize its replacement.
Use the stronger bootstrap/recovery path and operator policy.

Device-side server trust and service-side device trust roll independently.
Validation-bundle rollover first installs overlapping old and new trust,
confirms adoption, changes the serving or issuing chain, waits through the
offline recovery window, and finally removes old trust. Bundle versions must
be monotonic or otherwise rollback-protected. Compromise of the old root needs
an independent recovery trust path rather than ordinary overlap.

## Revocation and quarantine

On suspected loss or compromise:

1. quarantine at the narrowest safe scope: certificate instance, slot
   generation, logical instance, entire device, cohort, or issuer;
2. deny production use and routine renewal while preserving only explicitly
   authorized recovery;
3. revoke affected certificates and publish the configured status information;
4. determine the earliest plausible exposure and affected descendants; and
5. use a stronger bootstrap/recovery path for replacement.

Compromise scope matters. An operational-key compromise normally requires a
new generation. Bootstrap/root compromise invalidates trust in the physical
identity and is not repaired by a child certificate. Issuer compromise requires
issuer replacement and affected credential reissuance. Storage-key compromise
requires rewrapping or re-encryption; identity rotation does not restore data
confidentiality. Station or RA compromise requires reviewing every transaction
in the exposure window.

## Recovery, replacement, transfer, and retirement

Recovery must not depend solely on the lost, expired, or compromised
operational key. Acceptable factors include a protected bootstrap identity,
controlled physical custody, single-device recovery authorization, independent
operator approval, and fresh appraised evidence.

Authentication and attestation private keys normally are not escrowed. Loss of
a non-exportable key triggers re-enrollment. Recoverable data-encryption keys
are a different design decision; this Raspberry Pi roadmap deliberately adopts
no escrow and destructive storage replacement.

Replacement storage on the same Pi creates a new storage generation and logical
device instance. The previous instance is quarantined or retired before the new
one can activate. Board replacement normally creates a new hardware/bootstrap
identity and instance; it does not silently inherit an immutable secret.

A factory reset or ownership transfer within the same approved customer-root
and ownership domain must:

1. quarantine the previous identity before clearing the device;
2. revoke every owner-domain certificate and enrollment grant;
3. erase operational, application, network, wrapping, cached credentials, old
   trust anchors, and owner data;
4. preserve or explicitly retire immutable hardware identity according to
   policy; and
5. require fresh ownership authorization before another enrollment.

An in-place transfer to a different customer-root or ownership domain is not
supported for a Raspberry Pi 5 fused to the previous customer's immutable
secure-boot root. Permanently retire or destroy that board according to policy;
do not preserve its hardware identity and re-enroll it under the new owner.

Retirement disables the device, all slots, key generations, and certificate
instances; revokes remaining credentials; destroys recoverable secrets;
sanitizes storage under the applicable policy; and closes the audit record. An
immutable root that cannot be erased remains deny-listed. Physical destruction
may be required when residual hardware secrets exceed the disposal threat
model.

## Audit record

The final record is secret-free but access-controlled. It includes:

- transaction, logical device, instance, asset, and device-class identifiers;
- bootstrap public-key and operational SPKI fingerprints;
- storage generation, credential slot, key generation, issuer, serial,
  profile, and validity;
- exact artifact, firmware, configuration, policy, and tool digests;
- observed boot, release, rollback, debug, signer, and storage-protection state;
- validation-bundle version and release authorization;
- station, operator, RA, CA, approver, and verifier identities;
- timestamps and all positive and negative results; and
- terminal transaction, device, key, and certificate states.

Private keys, OTP roots, HMAC results, LUKS passphrases, enrollment tokens,
PINs, and administrator credentials never enter the record. Events are
append-only or signed and exported independently so station failure cannot
erase fleet provenance.

## Production acceptance gates

A production implementation must demonstrate that:

- filesystem copying cannot create a second accepted device when the profile
  claims hardware binding; lower-assurance profiles explicitly disclaim it;
- no image, log, evidence, crash artifact, station output, or unintended store
  contains recoverable private-key material;
- a CSR or request cannot select another logical identity, SAN, slot, profile,
  usage, or generation;
- key substitution and replayed enrollment transcripts fail;
- exact retries are idempotent and changed device/key/context retries stop;
- only the active exact device/instance/slot/generation/certificate tuple is
  accepted, even if another presented certificate is CA-valid;
- a staged credential works only at the pending verifier and is production-
  denied before activation;
- activation changes only the exact tuple named by a valid verifier receipt;
- routine rekey performs a bounded, atomic cutover without identity change;
- trust-anchor rollover does not admit an unauthorized root;
- loss of the operational key enters the documented recovery path;
- revocation and quarantine invalidate cached application authorization;
- replacement storage leaves the prior instance retired;
- reset, transfer, and retirement remove prior authorization and close audit;
- unknown irreversible results and audit gaps prevent completion; and
- production release authorization was freshly enforced before protected
  storage and credentials became usable.

Until all applicable gates pass on production hardware, the repository must
continue to describe device identity and `enrollment_ready` as future work.

## References

- [RFC 5280: Internet X.509 PKI certificate and CRL profile](https://www.rfc-editor.org/rfc/rfc5280.html)
- [RFC 7030: Enrollment over Secure Transport](https://www.rfc-editor.org/rfc/rfc7030.html)
- [RFC 8995: Bootstrapping Remote Secure Key Infrastructure](https://www.rfc-editor.org/rfc/rfc8995.html)
- [RFC 9334: Remote ATtestation procedureS architecture](https://www.rfc-editor.org/rfc/rfc9334.html)
- [SPIFFE X.509-SVID specification](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/)
- [NIST IR 8350: Trusted network-layer onboarding](https://csrc.nist.gov/pubs/ir/8350/final)
- [NIST SP 800-57 Part 1 Rev. 5: Key management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [NIST SP 800-88 Rev. 2: Media sanitization](https://csrc.nist.gov/pubs/sp/800/88/r2/final)
