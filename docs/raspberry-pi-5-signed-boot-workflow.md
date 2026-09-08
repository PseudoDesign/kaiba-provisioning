# Raspberry Pi 5 signed-boot and release workflow

This document describes how the repository separates public release
construction, approval-gated private-key use, offline verification, and
per-device execution authority.

> [!WARNING]
> The standalone flake exposes the low-level constructors and generic tools,
> but it does not currently expose all of the configured `rpi5-prototype-*`
> and `development-signing` outputs expected by the historical end-to-end
> ceremony helper. Do not copy commands from the former monorepo. The exact
> integration gap is listed under [Current standalone boundary](#current-standalone-boundary).

Nothing in this workflow writes target media, runs RPIBOOT, programs EEPROM or
OTP, or authorizes a physical device transaction.

## Authorization order

The release and device authorities deliberately form a one-way chain:

```text
unsigned reproducible artifacts
  -> release intent
  -> exact signing plans
  -> reviewer approval and five grants
  -> approval-gated artifact signatures and receipt attestations
  -> offline receipt and signature verification
  -> complete content-addressed signed release
  -> media plan and verified staging receipts
  -> one target-bound seven-operation lane plan
```

A release intent is cohort-scoped. It contains no station, lane, target,
transaction, claim, fence epoch, or execution expiry. A valid signature or
complete signed release therefore grants no authority to write a device. The
device plan is created only after the complete release manifest exists and can
bind its final digest.

## Exact signing inputs

`lib.mkRpi5ReleaseIntent` creates the public, pre-signature authorization
record. It authorizes exactly five immutable byte records in canonical order:

1. `rpi5.boot_image`
2. `rpi5.eeprom_bootcode`
3. `rpi5.eeprom_bootsys`
4. `rpi5.eeprom_config`
5. `rpi5.owned_recovery_bootcode`

The release intent binds the release and device class, clean source revision,
fixed source epoch, unsigned-artifact and EEPROM-release manifests, reviewed
public key and signer policy, expected customer-key hash, and every required
final role. Changing any input requires a new release intent and review.

## Complete release roles

The final signed-release manifest contains exactly 18 roles:

```text
boot_public_key
device_profile
platform_adapter
root_integrity
rpi5.boot_image
rpi5.boot_signature
rpi5.eeprom_bootsys
rpi5.eeprom_config
rpi5.fresh_commit_bundle
rpi5.fresh_readback_bundle
rpi5.negative_boot_bundle
rpi5.owned_readback_bundle
rpi5.owned_recovery_bootcode
rpi5.owned_recovery_bundle
rpi5.root_data_image
rpi5.root_hash_tree_image
rpi5.root_integrity_test_bundle
rpi5.signed_eeprom_image
```

`rpi5.eeprom_bootcode` is a signing-only intermediate. It is not a nineteenth
published role.

The final publication stores objects and directory trees at digest-derived
paths and records their lineage in an immutable index. The finalizer verifies
the complete staged tree before installing it without replacement, then
reopens the publication for verification.

## Capability boundaries

### Pure construction

These constructors consume public/store-backed inputs and have no signing or
hardware authority:

| Constructor | Purpose |
| --- | --- |
| `mkRpi5SecureBootArtifacts` | Construct unsigned boot and dm-verity artifacts from reviewed inputs |
| `mkRpi5EEPROMRelease` | Pin and describe EEPROM firmware/configuration inputs |
| `mkRpi5ReleaseIntent` | Authorize the exact cohort release lineage |
| `mkRpi5BootSigningPlan` | Bind the normal boot-image request |
| `mkRpi5EEPROMReleaseSigningInputs` | Derive the exact fresh EEPROM signing inputs |
| `mkRpi5EEPROMSigningPlan` | Bind the three fresh EEPROM requests |
| `mkRpi5OwnedRecoverySigningPlan` | Bind the owned-recovery bootcode request |

Nix evaluation and builds must never enumerate a YubiKey, read a PIN, or use a
private key.

### Approval-gated signing

`lib.mkDevelopmentYubiKeySigning` creates a configured runtime package. It
fixes the signer and cohort IDs, token serial, PIV slot `9c`, public key,
customer-key hash, signer policy, provider chain, gate socket, and registry
path. Runtime callers cannot substitute those selectors.

Each grant binds:

- the release-intent digest;
- one canonical artifact role and digest;
- a unique approval and grant identity;
- the reviewed signing backend and policy; and
- an expiry no more than 24 hours after approval.

The gate performs two ordered private-key operations for each successful
first attempt:

1. create the Raspberry Pi artifact signature; and
2. sign a domain-separated canonical receipt attestation.

The receipt attestation covers the full grant and request, request digest,
backend identity, artifact signature and digest, and the gate's `signed_at`
value. `signed_at` is an authenticated reading of the trusted signing-host
clock, not an external timestamp-authority assertion.

An incomplete durable intent permanently prevents the same grant from reaching
the backend again. There is no same-grant retry. Recovery requires a new
independently reviewed approval and five new grants; receipts from different
attempts must never be mixed.

### Offline admission

These constructors admit only public outputs back into the build graph:

| Constructor | Verification boundary |
| --- | --- |
| `mkRpi5VerifiedSignedBoot` | Reopens the boot plan/result, checks release lineage and signature, and emits the narrow signed-boot bundle |
| `mkRpi5VerifiedSignedEEPROM` | Replays and verifies the fresh EEPROM result |
| `mkRpi5VerifiedOwnedRecovery` | Replays and verifies owned recovery |
| `mkRpi5VerifiedSigningReceipts` | Authenticates the registry, five receipts, and five receipt-attestation signatures |
| `mkRpi5VerifiedRPIBootBundles` | Builds and validates the six canonical fresh/owned/test bundle trees |
| `mkRpi5VerifiedSignedRelease` | Cross-binds every role and lineage record into the complete publication |

The finalizer has no signer, smartcard, block-device, EEPROM, RPIBOOT, or OTP
capability. Its result means that the selected public artifact graph is
self-consistent and verifies under the reviewed key. It does not mean a live
ceremony happened unless the root-managed receipts and independent handoff
evidence are also reviewed.

## Raspberry Pi signature format

The canonical `boot.sig` is a three-line Raspberry Pi record containing the
image SHA-256 digest, a decimal timestamp, and an RSA-2048 signature. The RSA
signature authenticates the image digest. Release metadata, the fixed
timestamp, and the receipt digest are authenticated by the surrounding Kaiba
plans and receipt records, not by silently extending the vendor signature
format.

## Owned recovery and RPIBOOT bundles

The verified bundle set contains six closed directory trees:

```text
fresh-commit
fresh-readback
owned-readback
owned-recovery
negative-boot
root-integrity-test
```

The fresh commit is the only tree intended to cross the zero-to-owned customer
key boundary. Owned recovery is signed by the same customer key and is built
before ownership because stock or unsigned recovery must be rejected
afterward. Test bundles are narrowly constructed for specific readback and
negative checks; none should grow a generic shell, arbitrary storage browser,
or signing authority.

Building or verifying these directories does not execute `rpiboot` or report a
hardware result.

## Checked-in development release

[`releases/rpi5-v0.1.6/`](../releases/rpi5-v0.1.6/) contains public signed
inputs for the sacrificial development payload:

- boot, EEPROM, and owned-recovery signed results;
- the five-grant registry and authenticated receipt export;
- a fixed operational-payload manifest; and
- `SHA256SUMS` over the checked-in inventory.

It contains no private key, token credential, PIN, or signing provider. Its
presence is evidence of a public signed release lineage, not of target-media
staging or a completed board ceremony.

The current software contracts can be checked without a token or hardware:

```console
nix build .#checks.x86_64-linux.rpi5-signed-release --no-link -L
nix build .#checks.x86_64-linux.signing-receipts-integration --no-link -L
nix build .#checks.x86_64-linux.rpi5-rpiboot-bundles --no-link -L
```

Use the system matching the builder when selecting `checks.<system>`. These
checks verify software contracts only.

## Current standalone boundary

The root flake exports the constructors above, generic no-authority command
packages, the v0.1.6 public inputs, and software checks. It does **not** export
the former monorepo's ready-made composition under these names:

```text
development-signing
rpi5-prototype-unsigned-artifacts
rpi5-prototype-release-intent
rpi5-prototype-signing-plan
rpi5-prototype-eeprom-signing-plan
rpi5-prototype-release-review
```

The helper at
[`scripts/signing-ceremony/kaiba-provision-signing-ceremony.sh`](../scripts/signing-ceremony/kaiba-provision-signing-ceremony.sh)
still expects those outputs during `prepare-public`. Consequently the helper is
not an end-to-end supported entry point in this standalone repository today.
The generic `kaiba-provision-sign-boot` package has no signing backend. The
exported `kaiba-provision-sign-eeprom` package is a configured client of
`/run/kaiba-provision-signing/signing.sock`, pinned to the checked-in EEPROM
release inputs. It can submit an already authorized request to a running gate,
but it has no private key or direct hardware authority of its own. A configured
gate and an exact approval are therefore still required.

A consumer may compose the lower-level constructors into deployment-specific
outputs, but that consumer configuration becomes part of the reviewed release
boundary. It must fix every signer, key, policy, release, device-class, and
source input; publishing an arbitrary runtime selector would defeat the
capability design.

The [Ubuntu signing ceremony](ubuntu-rpi5-development-signing-ceremony.md)
therefore documents the human and evidence protocol while clearly identifying
this integration prerequisite.

## Review checklist

Before approving a new release composition, verify that:

- the source revision and source epoch are fixed and reproducible;
- all unsigned artifacts descend from the same target and dm-verity record;
- the reviewed public key, SPKI fingerprint, customer-key hash, signer policy,
  and independent signer review agree;
- exactly five grants cover the exact five roles and one release intent;
- every grant completed once with both artifact and receipt-attestation
  signatures;
- offline verification accepts all five receipt digests under one backend;
- EEPROM and owned-recovery replay reproduce the public signed results;
- the canonical six-tree bundle set is complete;
- the final publication contains exactly 18 roles and the expected lineage
  records; and
- no result is described as media, device, or OTP authorization.

Proceed to [target-media staging](target-media-staging-prototype.md) only after
the complete public release has passed independent verification and a separate
destructive authorization exists.
