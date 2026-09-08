# Ubuntu development signing ceremony

This document preserves the separation-of-duties, key-handling, and evidence
requirements for signing a Raspberry Pi 5 development release on the dedicated
Ubuntu 24.04 signing host.

> [!CAUTION]
> This is not currently an executable end-to-end runbook from the standalone
> root flake. The ceremony helper's `prepare-public` phase expects six
> configured outputs that the root flake does not export. Do not start a live
> token ceremony until the integration gate below is closed by a reviewed
> composition. The checked-in v0.1.6 public inputs are not authorization to
> repeat their signing requests.

This ceremony is development-only. It does not write media, boot a target, run
RPIBOOT, change EEPROM or OTP, or authorize a device transaction.

## Current integration gate

The helper at
[`scripts/signing-ceremony/kaiba-provision-signing-ceremony.sh`](../scripts/signing-ceremony/kaiba-provision-signing-ceremony.sh)
expects these configured package outputs:

```text
development-signing
rpi5-prototype-unsigned-artifacts
rpi5-prototype-release-intent
rpi5-prototype-signing-plan
rpi5-prototype-eeprom-signing-plan
rpi5-prototype-release-review
```

They are not exported by the current [`flake.nix`](../flake.nix). The
standalone repository instead exposes lower-level `mkRpi5*` constructors that
a release-specific consumer flake can compose. Before a ceremony is runnable,
that composition must:

- pin the exact repository revision and source epoch;
- expose all six outputs under the names the helper validates, or update and
  test the helper and runbook together;
- fix the development signer, cohort, token serial, PIV slot, public key,
  signer-policy digest, and expected customer-key hash;
- bind the target artifacts, release intent, boot and EEPROM plans, and release
  review to one source revision;
- pass `go test ./...` and the complete flake checks on supported systems; and
- receive independent review before the signing host reads a PIN or contacts a
  token.

Until then, this document is a protocol specification and recovery guide, not
a copy-and-paste command sequence.

## Roles

Use separate people or independently controlled accounts:

| Role | Authority |
| --- | --- |
| Release preparer | Builds and inspects public unsigned inputs; cannot author the approval or use the key |
| Independent reviewer | Reproduces the public review and authors the exact approval and five grants |
| Signing operator | Installs the independently delivered registry and performs token touches; cannot change the approved inputs |
| Offline verifier | Authenticates the handoff, receipts, signatures, and final 18-role publication |

The v1alpha1 approval is reviewer-attributed but not cryptographically signed
by the reviewer. Separation of duties is therefore procedural: independently
communicated approval, registry, and manifest digests are mandatory controls.
A signing-host root user remains trusted and could replace local policy.

## Ceremony invariants

- Work from one clean, immutable commit and a new reserved release identity.
- Build public inputs independently for every role; do not share a mutable
  working session.
- The approval covers one exact release intent and expires within 24 hours.
- The registry contains exactly five role- and digest-bound grants.
- Every output directory is absent before its authority-bearing operation.
- Each successful grant uses the private key exactly twice in order: artifact
  signature, then canonical receipt-attestation signature.
- A failure-free five-grant ceremony therefore requires at least ten explicit
  private-key operations and, under the reviewed always-touch policy, at least
  ten touches.
- “At least ten” is not permission to retry. An incomplete intent permanently
  blocks that grant.
- PIN, PUK, management-key, private-key, or active systemd credential material
  never enters Git, the Nix store, command arguments, environment variables,
  logs, or public handoff directories.
- A complete signed release is cohort authorization only. It is not authority
  to stage a medium or mutate a Pi.

## Host boundary

Follow the
[Ubuntu signing-gate deployment guide](../deploy/ubuntu-signing-gate/README.md)
for the immutable host package, locked service identity, PC/SC policy, tmpfs
PIN source, durable anti-replay state, receipt export directory, preflight, and
service shutdown.

Installation is inert: it must not enable or start the gate, read the PIN, or
enumerate a smartcard. The service package fixes all signer selectors and the
gate accepts only the reviewed root-managed registry. The host remains
swap-free while the PIN exists.

The prototype trust anchor and independent review are under
[`signers/development-prototype/`](../signers/development-prototype/). That
review can be reused only while the token, slot, key, signer/cohort IDs, public
fingerprint, customer-key hash, and signer policy remain exact. It never
replaces release-specific approval.

## Protocol phases

### 1. Freeze the release

All roles independently obtain and verify the same clean commit. Record the
commit, proposed release ID, source epoch, repository remote, and successful CI
run. Reserve a new release identity; never move or reuse a release tag after an
authority-bearing result exists.

### 2. Build public inputs

The preparer, reviewer, operator, and verifier each build the configured
unsigned artifacts, release intent, signing plans, signing package, and public
review from their own clean checkout. An x86 host needs a reviewed AArch64
builder or emulation for target artifacts.

This phase must not use `sudo`, read a PIN, enumerate PC/SC, or contact the
YubiKey. Review at least:

- the unsigned-artifact manifest and dm-verity binding;
- release-intent digest, exact five inputs, and exact 18 required roles;
- boot, EEPROM, and owned-recovery plan inputs;
- reviewed public PEM, SPKI fingerprint, and Raspberry Pi customer-key hash;
- canonical signer-policy JSON and digest; and
- source revision and reproducible artifact inventory.

### 3. Author approval and grants

The independent reviewer uses `kaiba-provision-signing-approval` to author one
new approval directory and validates it from a separate checkout. The output
contains the approval plus a registry of exactly five grants. No release
preparer or signing operator edits expiry or identity fields.

Deliver the approval packet through an authenticated channel. Communicate its
manifest digest and the exact grant-registry **file SHA-256** through an
independent channel. The registry file SHA-256 is the lowercase 64-hex digest
reported by `sha256sum`, not merely a digest value asserted inside the packet.
At every handoff, verify exact file names, ownership/modes, `SHA256SUMS`, and
the independently communicated digests.

### 4. Install the inert gate boundary

Install the exact reviewed signing and deployment outputs as described in the
deployment guide and run static preflight. Then follow its complete
[root-owned registry staging and verification
flow](../deploy/ubuntu-signing-gate/README.md#ceremony-preparation): copy the
input into a new ACL-free, non-symlink directory beneath `/root`, verify the
staged file against the independently communicated registry file SHA-256,
install it root-owned and readable only by the signing service, and verify the
installed file's SHA-256 again.

Do not provision the PIN or start the service until the operator's public
review matches the reviewer packet exactly and the post-install registry
SHA-256 equals the independently approved value. A mismatch or pre-existing
staging path is a stop condition; preserve both copies for review rather than
editing, deleting, recopying, or reusing either one.

### 5. Provision the runtime PIN

From a controlling terminal, disable swap and use the fixed root helper. It
prompts without echo and atomically writes only the root-owned tmpfs source.
Run full preflight before and after explicitly starting the gate.

The service sees the systemd credential copy, not the source file. Never move
the source to persistent storage or supply the PIN through `Environment=`,
`EnvironmentFile=`, `SetCredential=`, argv, or an exported shell value.

### 6. Complete the first four requests

Submit the normal boot image and the three fresh-EEPROM inputs in canonical
role order. For each request:

1. confirm the plan, release-intent, role, digest, grant, and expiry;
2. perform the artifact-signature touch;
3. perform the receipt-attestation touch;
4. preserve the no-replace public result; and
5. record the gate receipt digest independently.

Do not submit the next request until the previous result is durable and its
identity has been checked.

### 7. Derive and sign owned recovery

Derive the owned-recovery plan only from the four verified earlier results and
the same release intent. Submit its fifth grant once. Owned-recovery replay may
reuse verified fresh EEPROM signatures; it does not authorize new signatures
for those inputs.

### 8. Export authenticated receipts

Export the exact five root-managed gate receipts through
`kaiba-provision-signing-receipts`. The export must contain five unique receipt
digests, one backend identity, five artifact signatures, and five canonical
attestation signatures. A client-created summary is not a substitute.

### 9. Close the signing boundary

Stop the gate before deleting the tmpfs PIN source. Confirm the runtime socket
and systemd credential mount disappeared, the PIN source directory is empty,
and static preflight still validates the inert installation. Durable anti-replay
state remains and must be preserved.

### 10. Authenticate the public handoff

Transfer only public results, registry, receipt export, release intent, and
their manifests. The offline verifier checks exact file sets, modes, checksums,
independently communicated digests, all five artifact signatures, all five
receipt attestations, grant expiry, and common release lineage.

### 11. Assemble and verify the release

Only after receipt verification succeeds may the public outputs enter the Nix
store for final assembly. The finalizer independently reconstructs the owned
recovery result and six RPIBOOT trees, then verifies and publishes exactly 18
roles without replacement.

Record the publication digest, Nix output/NAR identity, source revision,
release-intent digest, registry digest, five receipt digests, and independent
verification result. The publication remains software-only release evidence.

### 12. Handoff to a separate device plan

Media staging and the physical lane require new authority. The final release
manifest may become an input to a per-device plan, but the signing approval and
grants must never be interpreted as destructive authorization.

## Failure and recovery

On any error, ambiguous token result, missing terminal output, gate crash, or
receipt mismatch:

1. stop the gate;
2. preserve durable gate state, public outputs, logs allowed by policy, and all
   manifests;
3. remove the PIN source and re-establish the inert host boundary;
4. do not repeat the request or edit the registry;
5. determine whether a durable completed receipt exists; and
6. if the release still needs signatures, begin a wholly new independently
   approved attempt with five new grant identities.

Never combine a completed result from the abandoned registry with results from
the new attempt.

A defect confined to the public no-authority finalizer may permit a separately
reviewed recovery tool to reassemble the already authenticated original bytes.
That recovery must keep the original payload revision and signing evidence,
use a new verifier-owned directory, record both tool revisions, and never issue
a new signing request.

## Evidence retention

Retain at least:

- source revision, source epoch, release ID, and public review;
- public key, independent signer review, and signer-policy digest;
- approval, registry, and their independently communicated digests, including
  the staged and post-install registry file SHA-256 comparison;
- all five signing plans and no-replace public results;
- all five gate receipt digests and the authenticated export;
- offline receipt-verification record;
- final publication index and digest; and
- any failure or recovery record.

Do not retain PINs, private keys, systemd credential copies, or live secret
buffers in the evidence packet.
