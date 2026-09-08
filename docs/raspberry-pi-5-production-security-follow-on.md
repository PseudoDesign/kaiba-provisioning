# Raspberry Pi 5 production security follow-on

## Status and scope

This document proposes the path from the sacrificial Raspberry Pi 5 development foundation to a production appliance, preserving native secure boot and dm-verity while adding production key separation, encrypted state, release freshness, identity, updates, recovery, and operations.

> [!IMPORTANT]
> This is a proposal and roadmap, not a description of implemented production
> behavior. The checked-in evidence under [`tests/evidence/`](../tests/evidence/)
> records a read-only qualification of one sacrificial board. It does not show
> that an irreversible customer-key ceremony ran, that an owned board booted a
> signed release, or that the seven-operation mutation campaign completed.
>
> The machine-readable
> [development posture](../policies/raspberry-pi-5-development-posture-v1alpha1.json)
> remains authoritative for the implemented cohort. It terminates at
> `security_applied`, sets `enrollment_ready` to false, and does not authorize
> mutation. The public material under
> [`releases/rpi5-v0.1.6/`](../releases/rpi5-v0.1.6/) is a development release,
> not a production release.

The [secure-boot model](raspberry-pi-5-secure-boot.md) defines the existing
native boot boundary and the development campaign. This document begins at
that boundary and deliberately does not weaken it.

The design evaluated here does not add a TPM. It uses the BCM2712
device-private-key OTP region and Raspberry Pi firmware cryptography for an
automatic LUKS unlock, while giving device authentication a separate role. It
can provide verified boot, offline-storage confidentiality, and online-gated
release authorization. It cannot provide TPM-style measurement or quotes, and
its anti-rollback result depends on a fresh server decision enforced by a
stable verifier before protected state becomes available.

A production cohort must use a new production customer key and fresh boards.
A board fused to the development customer key permanently authorizes that key
and every native boot image validly signed by it; it cannot be converted into
the proposed production root merely by installing a newer release.

The storage design is intentionally no-escrow: application state must be
reconstructable or disposable because loss of a board, OTP secret, LUKS
header, or storage may make it permanently unavailable.

## Intended production chain

```text
immutable BCM2712 Boot ROM
  -> production-customer-signed EEPROM bootloader and configuration
  -> production-customer-signed stable verifier
  -> release-policy roots and rotatable delegated release keys
  -> fresh server policy bound to verifier, release digest, and epoch
  -> verifier authorization before protected material is available
  -> signed kernel, initramfs, DTB, overlays, command line, and manifest
  -> read-only dm-verity NixOS system root
  -> OTP-HMAC-derived unlock of LUKS mutable state
  -> separately scoped device authentication
  -> enrollment-ready service gate and restricted production networking
```

The completed campaign must prove the native root and hardened EEPROM, full
kernel-to-root authentication, a stable verifier with rotatable delegated
release keys, dm-verity plus OTP-unlocked LUKS, fresh server authorization,
qualified device authentication, safe A/B updates, destructive replacement,
narrow recovery, and final production hardware controls. The acceptance
campaign below turns those goals into observable tests.

## Security boundary without a TPM

After the full hardware campaign passes, the design may claim rejection of
unauthorized EEPROM, native boot, and delegated-release bytes; dm-verity
authentication of the system root; confidentiality of removed mutable storage;
board binding of automatic unlock; online rejection of obsolete releases; and
locking of raw-key export, bootstrap signing, and HMAC after approved use.

Binding to a particular storage device is a separate claim. It may be made
only if the exact storage identifier and read interface pass authenticity and
spoof-resistance qualification. Model, serial, WWID, and
`/dev/disk/by-id` values are normally operational identifiers, not trust
anchors.

Even after acceptance, it does not claim strong offline OS anti-rollback,
hardware measurement or TPM-style quotes, protection after authorized-kernel
compromise, recovery of unreplicated local data, in-place customer-root
replacement, or resistance to invasive extraction, fault injection, and side
channels.

An offline device cannot obtain a fresh monotonic release decision. It must
remain in a restricted recovery/update state without opening protected mutable
storage or starting protected functions. A requirement for indefinite
protected offline operation needs a TPM, secure element with monotonic state,
or another independently qualified counter.

Native Pi secure boot can accept an old image correctly signed by the fused
customer key. The production customer private key must therefore sign only the
stable verifier, approved EEPROM updates, and narrow recovery payloads. It must
not be the routine OS release-signing key.

## Production key hierarchy

```text
Pi customer root key
  -> signed EEPROM, stable verifier, and narrow recovery only

release-policy root keys
  -> signed delegation, threshold, revocation, and cohort policy

delegated release keys
  -> signed release manifests and boot bundles

per-device BCM2712 OTP key
  -> firmware HMAC for LUKS unlock

separate device-authentication role
  -> hardware key or strongly domain-separated child key
  -> one-boot keys and short-lived operational certificates
```

The Pi customer private key and release-policy private keys must remain outside
Git, the Nix store, CI runners, target images, and provisioning-station images.
Production signing uses an HSM interface, independent authorization, and
split-custody recovery. Public keys, policies, requests, receipts, manifests,
signatures, and verification results remain reproducible and independently
verifiable.

One key has one purpose. Direct use of the same BCM2712 OTP key for firmware
HMAC and ECDSA is an unresolved research option, not the default. It is allowed
only after vendor-intent, key-lifetime, lock-behavior, and cross-protocol review
explicitly approve the exception. Otherwise use another hardware slot or a
strongly domain-separated child-key design and record its assurance level.

Release-policy metadata binds the key role, identifier, threshold, validity,
delegation and revocation state; cohort and device generation; integer security
epoch and minimum verifier version; every boot-component and manifest digest;
dm-verity root and partition identifiers; update/recovery classification; and
source revision, reproducible inventory, SBOM, and provenance.

## Storage architecture

The immutable system and confidential mutable state use different mechanisms:

```text
boot/verifier
  customer-root-signed stable verifier

release slot A
  delegated-signed boot components
  dm-verity root-data A and root-hash A

release slot B
  delegated-signed boot components
  dm-verity root-data B and root-hash B

mutable state
  LUKS2 kaiba-state volume
```

The NixOS root is public but tamper-evident. LUKS holds operational identity
and certificate state, issued credentials, application data, and other
confidential mutable material. It does not hold the bootstrap private-key
boundary needed before unlock. Temporary files, journals, caches, core dumps,
and swap stay volatile unless a reviewed application requirement explicitly
permits persistence.

### OTP-HMAC LUKS derivation

Normal unlock must request a firmware HMAC operation rather than read the raw
OTP key:

```text
unlock_secret = HMAC-SHA-256(
  K_OTP,
  canonical_encode(
    "kaiba:luks:mutable-state:v1",
    qualified_storage_id_or_omitted,
    volume_nonce,
    storage_generation
  )
)
```

The encoding must be length-delimited and canonical, never ambiguous string
concatenation. `volume_nonce` is a newly generated public 256-bit value stored
with bounded LUKS metadata and replaced on every destructive initialization.
`storage_generation` is a monotonic control-plane record, not a hardware
counter.

The storage identifier is optional until its exact source, device scope, API,
authenticity, spoofing assumptions, and failure behavior are qualified. If no
identifier passes, omit it and narrow the claim to board binding plus
destructive reinitialization.

The HMAC output is a high-entropy LUKS keyslot passphrase, not the LUKS volume
master key. `cryptsetup luksFormat` creates a new random volume master key for
every initialization.

The signed initramfs must:

1. obtain and verify a fresh server authorization for the exact verifier,
   release-manifest digest, device instance, and security epoch;
2. reject an unauthorized or offline protected boot before release handoff or
   storage derivation;
3. verify the complete boot and dm-verity policy;
4. resolve exactly one expected block device and any qualified identifier;
5. validate bounded volume nonce and generation metadata;
6. request the firmware HMAC operation;
7. send the result to `cryptsetup` through a private pipe or socket, never
   argv, environment, disk, or logs;
8. clear temporary buffers after the volume opens;
9. lock further HMAC operations for the rest of the boot; and
10. mount only explicitly allowed mutable paths.

Every production boot image must set `lock_device_private_key=1` so raw key
export is disabled before userspace. Leaving HMAC available for the unlock
window does not authorize other firmware-crypto operations.

### No-escrow replacement behavior

Supported recovery is destructive replacement, not data recovery:

1. Boot an approved customer-signed recovery environment.
2. Verify the board's owned state and exact recovery authorization.
3. Identify replacement storage and prove the previous volume is not mounted.
4. Allocate a new nonce, LUKS UUID, storage generation, and logical instance.
5. Derive a new unlock secret and format a new LUKS2 volume.
6. Install the currently approved signed release.
7. Revoke the previous instance's certificates, leases, and credentials.
8. Re-enroll the hardware as the new logical device instance.

The board and OTP HMAC key do not change. A returning old volume may still
derive its passphrase, so the control plane must retire its instance and
credentials; local cryptographic rejection of every old volume is not claimed.

## Stable verifier and delegated boot

The first production milestone is a stable-verifier spike on the sacrificial
board. Two bounded candidates are acceptable:

- a minimal customer-root-signed Linux/initramfs verifier that validates a
  complete manifest and securely loads verified second-stage bytes; or
- a customer-root-signed U-Boot verified-boot image with required keys in its
  trusted control DTB and required signatures on selected FIT configurations.

The chosen verifier needs one non-interactive path, no unsigned or legacy
fallback, and authentication of every byte influencing kernel, initramfs, DTB,
overlays, command line, root hash, and slot.

The spike passes only when an approved release boots; altered components,
missing or wrong signatures, legacy formats, and revoked keys fail; and a
replacement delegated key boots without changing Pi OTP. Implementation,
policy roots, configuration, and script then become one reviewed root-signed
artifact.

## Release freshness

Every release carries a signed integer `security_epoch`. The control plane
holds independently monotonic minimum verifier and release epochs for each
cohort and logical device instance.

On each protected boot, the stable verifier uses only the restricted
enrollment/update network to request a fresh signed authorization. Request and
response bind:

- a fresh server nonce;
- logical device instance and storage generation;
- stable-verifier version;
- complete release-manifest digest;
- release security epoch;
- response expiry and intended audience; and
- a one-boot operational public key.

The verifier refuses handoff and LUKS derivation unless every value matches;
the server refuses values below either minimum. A release reporting its own
version is not remote attestation and cannot substitute for this decision.

Only the verifier may use the qualified bootstrap operation before lock.
Released OS code must be unable to reuse it, replay authorization for another
digest, or derive LUKS after rejection; otherwise `enrollment_ready` is blocked.

Short-lived credentials limit use after expiry. A highest-seen epoch in LUKS
is defense in depth because storage rollback rolls it back too. Server policy
is the independent monotonic state, so protected boot fails closed without it.

## Device identity and enrollment

The preferred bootstrap identity is separate from the LUKS role: a separate
hardware key or a strongly domain-separated child key whose public half is
bound during provisioning. A software identity generated inside LUKS may be an
acceptable lower-assurance operational identity after unlock, but it cannot
satisfy the verifier's pre-unlock bootstrap requirement.

Enrollment must:

1. bind the bootstrap public key to the provisioning transaction and hardware
   inventory;
2. require a fresh nonce and domain-separated proof of possession;
3. bind logical device instance and storage generation;
4. require verifier authorization for the exact verifier, release digest, and
   epoch;
5. issue a short-lived, purpose-constrained operational certificate;
6. place public certificate state and application credentials in LUKS; and
7. support renewal, revocation, retirement, replacement-storage enrollment,
   and board replacement.

This proves key control and one verifier-enforced fresh decision, not
hardware-rooted proof of all running software. See
[Device identity](device-identity.md).

## Signed A/B updates

Ordinary updates never replace the stable verifier:

1. Download a signed manifest and artifacts into a bounded staging area.
2. Verify policy, key status, epoch, sizes, hashes, and slot classification.
3. Write the inactive boot bundle and dm-verity data/hash pair.
4. Cold-read and verify every written byte.
5. Select the inactive slot for exactly one trial boot.
6. Require verifier, dm-verity, application-health, and server-epoch success.
7. Commit the slot only after all checks pass.
8. Fall back after incomplete write, power loss, or unsuccessful trial.

Raspberry Pi `tryboot` or an equivalently bounded slot selector can implement
the availability transition. It does not provide security anti-rollback.
Metadata must not enable an unsigned image, substitute a root hash, re-enable a
legacy path, or convert a data rollback into an accepted control generation.

A verifier update exceptionally requires offline root approval, HSM signing,
owned recovery, full negative testing, and a server minimum transition. Old
root-signed verifiers may remain native-bootable, so bypass flaws in them are an
explicit residual risk.

## Restricted network and service gate

Normal application networking is disabled until the stable verifier has
enforced a fresh release authorization and enrollment checks succeed.

The verifier and recovery environment permit only outbound access needed for
fixed enrollment, update, time, and revocation authorities. They expose no
inbound SSH, general administrative login, or unrestricted egress. Endpoint
policy and trust roots are part of the customer-root-signed verifier.

Application services depend on a local `kaiba-enrollment-ready.target`, or an
equivalent explicit gate, reached only after:

- secure-boot runtime state matches policy;
- the expected verifier and release digest are active;
- the one-boot server authorization is current;
- dm-verity is mounted read-only;
- LUKS mutable state is open;
- device authentication succeeds;
- the server accepts the release epoch; and
- current certificate and service lease are valid.

Failure before handoff leaves restricted update/recovery without LUKS. Expiry,
revocation, or lease failure stops protected services and restores restriction.

## Production hardware posture

Final EEPROM and OTP controls are applied only after update and owned-recovery
tests pass. The production profile must include:

- a reviewed `BOOT_ORDER` containing only required sources;
- network/TFTP and partition-walk fallback disabled unless they are an
  explicit, tested part of recovery;
- `BOOT_UART=0`;
- automatic EEPROM self-update disabled or constrained by approved signatures;
- VideoCore JTAG permanently locked;
- EEPROM hardware write protection enabled and physically qualified;
- raw device-private-key export locked before userspace;
- bootstrap signing locked before release handoff;
- HMAC locked immediately after approved derivations; and
- a prebuilt, independently verified customer-signed recovery bundle.

The development values `BOOT_ORDER=0xf216`, `BOOT_UART=1`, unlocked JTAG, and
unlocked EEPROM write protection are not production defaults.

Recovery may verify state, install an approved release, initialize replacement
storage, and re-enter enrollment. It must not contain a generic shell, private
fleet key, signer, unrestricted storage browser, or arbitrary OTP/EEPROM
mutation primitive.

## Engineering workstreams

### Workstream 1: policy and keys

- [ ] Define production posture, cohort, lifecycle, exception, release-policy,
      delegation, and revocation schemas.
- [ ] Generate the production Pi customer key in an HSM and establish split
      custody plus key-loss and compromise procedures.
- [ ] Extend grants, receipts, and independent verification to all roles.
- [ ] Prove private keys cannot enter Git, Nix, CI, station, or target closures.

### Workstream 2: stable verifier

- [ ] Build and test both bounded verifier candidates on the sacrificial Pi.
- [ ] Select one implementation and remove every alternative boot path.
- [ ] Implement delegated policy, threshold, revocation, and release checks.
- [ ] Bind every boot component, root selection, slot, and epoch, then enforce
      the fresh server exchange before handoff.
- [ ] Bind a one-boot key using a replaceable test bootstrap provider.
- [ ] Add mutate-every-field, wrong-key, revoked-key, and replay tests.
- [ ] Produce and independently verify the root-signed verifier artifact.

### Workstream 3: OTP-HMAC and LUKS

- [ ] Pin the firmware-crypto and cryptsetup-agent implementations.
- [ ] Add transaction-bound OTP provisioning with blank-prestate/readback and
      `lock_device_private_key=1` in every production boot image.
- [ ] Specify and test the canonical HMAC contract.
- [ ] Qualify the exact storage identifier or remove it from the derivation.
- [ ] Add LUKS2 and its mount policy, lock HMAC after unlock, prove raw export
      unavailable, and test destructive no-escrow replacement.

### Workstream 4: signed A/B releases

- [ ] Define a deterministic A/B disk layout and image builder.
- [ ] Add delegated-signed manifests and boot bundles.
- [ ] Implement inactive-slot write, cold verification, trial boot, health
      confirmation, commit, and fallback.
- [ ] Interrupt every persistent update transition in testing.
- [ ] Prove ordinary updates cannot replace the stable verifier.

### Workstream 5: identity and freshness

- [ ] Select the separate-key or domain-separated bootstrap design.
- [ ] Bind bootstrap public identity to evidence and inventory with a canonical
      nonce challenge and proof of possession.
- [ ] Lock bootstrap before handoff and prove released OS code cannot use it.
- [ ] Add logical instance and storage-generation records.
- [ ] Implement certificate lifecycle, cohort/device minimum epochs, and
      restricted networking.
- [ ] Prove old epochs cannot obtain new credentials or leases.

### Workstream 6: hardening and recovery

- [ ] Remove SSH, autologin, unused accounts, compilers, package managers, and
      unnecessary firmware interfaces from the production target.
- [ ] Disable unrestricted kexec, module loading, debugfs, core dumps, swap,
      and unnecessary kernel features.
- [ ] Apply service sandboxing and qualify boot order, UART, JTAG, self-update,
      and EEPROM write protection.
- [ ] Build and verify the narrow owned-recovery bundle.
- [ ] Test recovery before irreversible final hardening.

### Workstream 7: release and operations

- [ ] Make unsigned artifacts reproducible from pinned sources.
- [ ] Require independent signature and release-lineage verification.
- [ ] Publish image, checksum, manifest, SBOM, and provenance.
- [ ] Define canary, rollout, incident, revocation, retirement, and monitoring.
- [ ] Prove destructive re-enrollment leaves the previous instance retired.

## Hardware acceptance campaign

The sacrificial unit must pass the complete design before any production root
is used:

- approved delegated release boots through the stable verifier;
- altered, unsigned, wrong-key, and revoked release bundles fail;
- every enabled boot source enforces the same verification policy;
- dm-verity corruption prevents the system root from mounting;
- removed storage does not disclose mutable data;
- copied storage fails on another Pi;
- different-medium failure is required only after storage-ID qualification;
- raw OTP-key export fails before userspace;
- HMAC fails after approved unlock;
- released OS code cannot use the bootstrap signing operation;
- replacement storage creates a new nonce, LUKS key, storage generation, and
  logical device instance;
- old instance credentials and leases are rejected;
- an old correctly signed epoch is rejected before LUKS unlock and cannot
  obtain protected network service;
- A/B update recovers from power loss at every write and commit boundary;
- authorized recovery works and unauthorized recovery fails;
- final boot order, UART, JTAG, update, operation-lock, and EEPROM protection
  read back exactly; and
- no image or evidence export contains a signing key, OTP secret, derived LUKS
  passphrase, or active device credential.

After the sacrificial campaign passes, provision one fresh production canary
with the new production customer root and repeat the entire suite. Do not
expand the cohort until the canary evidence has passed independent review.

## Milestones

### Milestone 1: stable-verifier development spike

An unfused sacrificial candidate boots only an authorized delegated release,
rejects mutated inputs, enforces fresh server policy before handoff, and binds
a one-boot key using an explicitly non-production bootstrap identity. It makes
no firmware-backed identity or hardware-lock claim.

### Milestone 2: encrypted and updateable development appliance

After a separately approved irreversible development ceremony, firmware HMAC
opens LUKS only after verifier authorization and is then locked. Destructive
replacement, the bootstrap design, delegated A/B releases, revocation, and
interrupted-update recovery all pass.

### Milestone 3: enrolled appliance

The device authenticates with its qualified bootstrap identity, receives a
short-lived certificate bound to a one-boot key, and starts protected services
only after verifier-enforced server authorization.

### Milestone 4: hardened production canary

A fresh board uses the production customer root, HSM signing, final debug and
EEPROM posture, narrow recovery, and the complete production acceptance suite.

### Milestone 5: production release

The release pipeline publishes reproducible, independently verified artifacts
and evidence. Operations can update, revoke, quarantine, destructively
re-enroll, replace, and retire devices without weakening the trust chain.

## References

These links are non-normative discovery inputs. Pin an exact reviewed commit or
tag, record the review date, and turn the relevant behavior into a local test
before treating any external implementation as an engineering dependency. The
linked NixOS integration is an unmerged pull request, not a platform contract.

- [Raspberry Pi 5 secure-boot model](raspberry-pi-5-secure-boot.md)
- [Secure-boot execution plan](raspberry-pi-5-secure-boot-execution-plan.md)
- [Raspberry Pi secure-boot documentation](https://github.com/raspberrypi/usbboot/blob/master/docs/secure-boot.md)
- [Raspberry Pi firmware cryptography API](https://github.com/raspberrypi/utils/blob/master/rpifwcrypto/rpifwcrypto.h)
- [Raspberry Pi cryptsetup passphrase agent](https://github.com/raspberrypi/cryptsetup-passphrase-agent)
- [NixOS Raspberry Pi OTP-derived key integration proposal](https://github.com/nvmd/nixos-raspberrypi/pull/179)
- [Linux dm-verity documentation](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html)
- [U-Boot FIT signature verification](https://docs.u-boot.org/en/latest/usage/fit/signature.html)
