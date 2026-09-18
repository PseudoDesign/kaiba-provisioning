# Per-device boot roots and authorized firmware updates

## Status and decision

Planned, 2026-09-17. Use a unique Raspberry Pi customer boot root for each
production device. Investigate device-local signing of bootloader updates
authorized by a separately signed firmware bundle. Evaluate TPM 2.0 for the
next hardware revision before selecting a component.

This plan adds two qualification tracks: the current Pi 5 hardware and a future
TPM-equipped board. Neither track is implemented or production-qualified.
Writing this plan does not authorize OTP programming, EEPROM writes, or changes
to the existing sacrificial development campaign.

The archived [production follow-on](archive/raspberry-pi-5-production-security-follow-on.md)
describes an external root signer and no TPM. This plan proposes a replacement
for that root-custody model for future devices; it does not silently change the
[current secure-boot contracts](raspberry-pi-5-secure-boot.md).

The current [fleet admission policy](fleet-admission-policy.md) remains the
authority for the selected fleet: normal operation must work offline, copied
storage must protect private data and credentials, and offline rejection of
older correctly signed software is not required. This plan does not reinstate
the archived online-only boot design. Online authorization proposed below is
for new root-signing operations, not normal boot or local data access. Its
compromised-OS threat model is a stronger design goal than the first-fleet
admission scope, not a claim about the implemented device.

## Required security properties

- A root compromise on one device must not reveal another device's root.
- The normal OS must neither read the boot-root private key nor obtain a
  signature over arbitrary input, including through recovery or reboot paths.
- Every root operation must bind an independently authorized artifact role,
  exact bytes, device root identity, hardware applicability, and update policy.
- Bootloader configuration, embedded public key, recovery payloads, and stable
  verifier updates receive the same protection as executable bootloader bytes.
- Routine OS releases use delegated release keys, not the device boot root.
- Root keys, device identity keys, storage secrets, and update-authority keys
  have separate roles and access policies.
- Uncertain writes enter reconciliation or quarantine; they do not cause blind
  retries. Power loss must have a demonstrated recovery procedure.

Assume an attacker controls the running OS, mutable storage, update transport,
and submitted signing requests. Test reboot and recovery abuse as part of that
model. Invasive silicon attacks and fault injection need a separately stated
hardware assurance scope; merely adding a discrete TPM does not resolve them.

A shared firmware-update authority remains powerful across devices. Per-device
roots limit root-key compromise; they do not limit an authority that can approve
every device's firmware. Separate release approval from authorization issuance,
scope authorities by product or deployment, and specify rotation and revocation.

## Intended update flow

1. Build a reproducible firmware payload and manifest from pinned inputs.
2. Independently approve its exact content and sign the firmware bundle using
   the update authority. The ordinary OS may download and stage it.
3. Enter a qualified maintenance path. Verify bundle signatures, applicability,
   allowed configuration, predecessor state, and freshness before accessing any
   signing capability.
4. Derive the exact per-device artifacts, including the embedded customer public
   key. Bind their final digests to device-specific signing authorization.
5. Sign only those authorized artifact roles with the device root. Independently
   verify signatures and the complete resulting artifact graph before writing.
6. Persist transaction intent and recovery information, perform the qualified
   EEPROM update, and read back the result. Do not assume OS A/B partitions make
   an EEPROM write atomic or provide a second EEPROM bank.
7. Cold boot, verify the resulting state, and complete the transaction. Advance
   security state only according to the tested power-loss state machine.
8. Remove working secrets and signing access before normal OS execution.

The signed manifest must define all permitted per-device transformations.
Device-supplied digests alone are not evidence that those transformations were
correct. An authorization service must reconstruct or independently validate
the final signing inputs. Define precisely whether each interface receives
bytes or a digest to avoid double hashing or signing the wrong representation.

## Phase 1: Specify contracts and lifecycle

Deliver a reviewed design and software fixtures before hardware mutation.

| Contract | Required contents |
| --- | --- |
| Device-root record | Device ID, customer public key and Pi hash, key generation/custody profile, hardware revision, lifecycle state, TPM object identity when applicable |
| Firmware manifest | Payload and configuration digests, artifact roles, model/revision constraints, permitted personalization, security epoch, minimum updater version, recovery compatibility, provenance |
| Signing authorization | Device-root identity, manifest digest, final input digests, roles, algorithm, transaction, authority-policy version, freshness binding, TPM command binding when applicable |
| Update journal and receipt | Prestate, intent, authorized inputs, verified signatures, write/readback outcome, boot result, recovery disposition |

Reuse existing immutable plans, independent verification, and durable attempt
semantics. Version contracts that currently assume cohort-wide signed releases
or a fixed YubiKey backend; do not shoehorn per-device roots into those identities.
Keep a shared unsigned release plus independently verifiable device-specific
outputs so ordinary reproducible builds never receive private keys.

Decide before fusing production boards:

- Whether boot-root loss means board replacement or controlled recovery of the
  same key. A replacement root cannot be programmed into an already owned Pi.
- Whether device-local roots may have escrow copies. For a nonduplicable TPM
  key, TPM failure/clear or loss of necessary object material can end future
  signing capability. Backing up an opaque object blob is not automatically
  recovery onto another TPM. A recoverable design needs a separately qualified
  import/duplication and custody policy.
- Required offline operation. Initially propose online authorization for root
  updates; allow offline updates only after replay and revocation semantics are
  demonstrated. Loss of connectivity must not unlock signing.
- Who may approve firmware, issue device authorizations, recover a device,
  rotate an update authority, or retire hardware.

Existing images can remain bootable after loss of signing capability. Distinguish
that condition from a bricked device and from loss of application data.

Exit: approved contracts, explicit recovery/offline decisions, and fixtures for
two devices that cannot exchange authorizations or personalized artifacts.

## Phase 2A: Current Pi 5 feasibility

Prototype a minimal customer-signed maintenance environment on development
hardware. Prefer a cold-boot path that executes before the normal OS; do not
assume launching an updater from a compromised OS creates isolation.

Investigate and record:

1. How a unique RSA-2048 root is generated, initially protected, and used to
   construct the first signed EEPROM, verifier, and recovery set before OTP
   ownership. Account for interrupted provisioning and manufacturing logs.
2. Whether an encrypted root can be recovered only in the maintenance phase
   using a dedicated, domain-separated device-bound mechanism. The Pi OTP
   device secret is not itself the required RSA private key.
3. Exact firmware interfaces and lock behavior for raw secret access, HMAC,
   signing, and resets. Do not treat an encrypted root file as protection from
   an OS that can invoke its unwrap mechanism.
4. Whether all normal, alternate-media, recovery, warm-reset, and cold-reset
   paths prevent an attacker from recovering the root or abusing its signer.
5. Whether an older, validly signed updater can bypass current authorization
   policy. Freshness must be enforced before secrets are available, including
   under replay of storage and attempted network isolation.
6. Exposure of software key material in RAM, DMA, debug interfaces, crash
   handling, and the transition into the normal OS. Specify the actual claim
   supported by zeroization and access locks, rather than claiming physical
   non-extractability.

Exit: evidence that the normal OS cannot extract or misuse the root under the
stated threat model. If this fails, device-local signing on this hardware does
not pass. Preserve per-device roots using an external HSM signer as a fallback,
or defer deployment until the hardware revision. Document any weaker assurance
as a separate decision; do not label it equivalent to the TPM track.

## Phase 2B: TPM policy prototype and hardware selection

Start with a software TPM for policy tests, then reproduce the tests on candidate
hardware. Simulation proves policy logic, not resistance of a physical board.

Select candidates only after proving:

- RSA-2048 signing with PKCS#1 v1.5 and SHA-256 produces signatures accepted by
  the pinned Raspberry Pi tooling and actual boot chain for every required role.
- The root object has policy-only signing access, with no password or alternate
  authorization branch that permits arbitrary signatures. Review object
  attributes, signing restrictions/tickets, hierarchy administration, eviction,
  duplication, and clear behavior explicitly.
- Authorization binds the TPM signing command, object identity, digest, scheme,
  and relevant parameters. Prototype `PolicyCpHash` with signed authorization;
  determine the exact policy composition and command serialization in tests.
- The authority can issue authorization for final device-specific inputs.
  A signature over a generic firmware archive is not itself a TPM authorization.
- A session-bound online authorization cannot be reused for another session,
  input, object, or device. Define retry semantics; a TPM session nonce alone
  does not make the whole flash transaction execute once.
- Update-authority rotation and emergency revocation work without replacing the
  Pi root. Evaluate `PolicyAuthorize` and explicit policy versions, including
  replay of old authorizations and unintended alternate branches.
- Any PCR conditions rely on an authenticated early measurement path, with
  reviewed reset/locality behavior. Adding an SPI TPM does not automatically
  establish trustworthy Pi boot measurements. PCR matches do not establish
  absence of a runtime compromise; retain exact-input authorization.
- Protected NV state, if used, has defined administration, endurance, reset,
  rollback, and interruption behavior. Blocking a new signature for an old
  image does not stop the Pi ROM booting an already signed old image. If a future
  profile requires end-to-end rollback protection, every admitted boot path must
  enforce freshness; that is not a current fleet requirement.

Hardware review includes bus access and probing, reset/power sequencing,
authenticated TPM sessions where applicable, driver support, physical layout,
vendor lifecycle, and manufacturing provisioning. Treat availability attacks
through reset or clear separately from unauthorized signing.

Exit: tested policy transcripts, negative tests, candidate hardware results,
and a selected component with documented limits. Do not select a part on the
basis of non-exportable key storage alone.

## Phase 3: Provisioning and repository integration

Implement after the relevant feasibility track passes:

1. Add the versioned contracts from phase 1 and a verifier for personalized
   artifact graphs. Bind all results to the enrolled root and hardware profile.
2. Add a production signer interface and maintenance/TPM implementation, retaining
   the development YubiKey path as its existing, separate profile.
3. Build the maintenance environment through the existing Nix interfaces. Keep
   secrets out of derivations, images, Git, CI, logs, and public receipts.
4. Extend provisioning to generate/enroll the unique root, prove key possession
   and custody policy, prepare and verify all initial signed recovery artifacts,
   and independently match the target to its public-key hash before fusing.
5. Add the update authority workflow, final-input reconstruction, audit records,
   and scoped authorization service. Ordinary device credentials alone must not
   grant arbitrary firmware authorization.
6. Implement a journaled updater with explicit prepared, authorized, signed,
   write-started, readback-verified, boot-confirmed, and reconciled outcomes.
   Specify restart behavior at every boundary and counter/epoch transition.
7. Qualify EEPROM write protection and its maintenance transition, watchdog and
   power behavior, and externally assisted recovery where necessary. If the
   write mechanism cannot guarantee remote recovery, document that limitation.

Exit: two-device lab demonstration from provisioning through update and recovery,
with public, independently verifiable evidence and no secret leakage.

## Phase 4: Acceptance and rollout

| Test | Required result |
| --- | --- |
| Valid authorized bundle | Exact approved firmware installed, read back, and cold-booted |
| Modified firmware/configuration or wrong model | Refused before signing or writing |
| Device A authorization on device B | Refused by identity and cryptographic bindings |
| Compromised OS requests arbitrary signing or root export | Refused through every exposed interface |
| Input changed after approval | Refused; final bytes remain bound to authorization |
| Old bundle, authority policy, updater, or recovery image | Obsolete authorization cannot reopen root signing; already signed images may operate offline under the selected fleet policy, but must not expose or misuse the root |
| TPM bypass branch, object substitution, reset, clear | No unauthorized signature; documented availability/recovery outcome |
| Network unavailable or authorization replayed | No signing-authorization bypass; defer the update safely while preserving normal offline operation |
| Power cut at each write and epoch transition | Verified recovery or explicit quarantine; no guessed success or blind retry |
| Root material/TPM/storage lost | Demonstrated chosen recovery or replacement process |
| Update authority rotated/revoked | New authority works; revoked authority cannot authorize new root operations |
| Tampered measurements or normal-OS TPM access | Cannot satisfy signing policy for unapproved inputs |

Run software contract and policy tests first, then physical tests on sacrificial
boards with pinned firmware and tool versions. Record which properties are only
simulated. Commission an independent review of the signing-policy composition,
maintenance isolation, provisioning bootstrap, and recovery state machine before
production OTP ownership.

Roll out to a small canary set, then expand only after successful update,
interruption, recovery, and authority-rotation exercises. Track root identity,
custody profile, authorized/installed firmware, epoch, and recovery status per
device. Any acceptance failure blocks expansion of the affected hardware track.

## Mechanism references

Reviewed for planning on 2026-09-17. Pin implementation revisions during the
spikes; these references do not establish that this repository implements them.

- [Raspberry Pi secure boot](https://github.com/raspberrypi/usbboot/blob/master/docs/secure-boot.md): native signature chain and permanent customer-key binding.
- [TPM signed policy](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_policysigned.1/): authority signatures, command hashes, and session nonce binding.
- [TPM command parameter policy](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_policycphash.1.md): constraining the authorized command parameters.
- [TPM policy authorization](https://tpm2-tools.readthedocs.io/en/stable/man/tpm2_policyauthorize.1/): allowing authority-approved policy changes.
- [TPM PCR policy](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_policypcr.1/): measurement-conditioned authorization.
