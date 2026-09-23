# Fleet admission policy — draft

Drafted 2026-09-16 under the [frozen delivery scope](delivery-scope.md).
This defines the proposed acceptance bar for the first fleet profile, not a
claim that the current device satisfies it. It does not change the approved
development policy or authorize physical operations.

## Decisions and scope

The user has selected:

- **Offline operation:** an enrolled device must cold boot and perform its
  normal local functions without contacting a server. Losing connectivity
  alone must not force it into recovery or prevent access to its local data.
- **Copied-storage protection:** removing or copying SD/NVMe storage must not
  disclose device credentials or private application data, or enable another
  device to impersonate the original.
- **Offline rollback prevention is not required:** older software correctly
  signed under the device's authorized trust policy may run on the original
  device while offline. Its age alone is not an admission failure. This does
  not permit unsigned or altered software, waive copied-storage protection,
  or authorize revoked credentials to access fleet services.

The rest of this document is a concrete proposal for review. Initial enrollment
and changes to fleet membership require the fleet authority; normal offline
operation does not. No maximum offline duration is proposed. A server outage or
expiry of a network credential must not, by itself, disable local operation;
expired credentials still cannot authenticate to fleet services.

The scope covers substituted or modified boot/storage media, copied storage,
unauthorized enrollment, and replayed network requests. It trusts the approved
signers, provisioning authority, and authorized OS. It does not claim protection
after authorized-kernel compromise, invasive chip attacks, or compromise of
those authorities. Raspberry Pi's [secure-boot documentation](https://github.com/raspberrypi/usbboot/blob/master/docs/secure-boot.md)
distinguishes signed boot from disk encryption and explains the limits of OTP
key protection against privileged software.

## Required conditions

Admission is conjunctive: **all eight conditions below must pass for the
same device, profile version, and installed release.** Missing, unknown, stale,
or conflicting evidence is not a pass. A device awaiting a check remains
pending; an uncertain physical mutation requires reconciliation or quarantine.

| ID | Condition | Evidence required to pass |
| --- | --- | --- |
| FA-01 | **The device is eligible for one approved fleet profile.** The exact board class, ownership root, firmware, release, boot sources, debug settings, storage protection, rollback policy, and recovery policy are specified. No admission-critical field is undecided. | Target-bound inventory and readback match the approved profile; the hardware/release qualification is applicable; no unresolved previous operation or conflicting ownership exists. Serial numbers correlate observations but do not authenticate identity. |
| FA-02 | **Only authorized system software can execute.** Secure boot is permanently enabled under the approved fleet customer key. Authentication covers EEPROM/configuration, verifier, kernel, initramfs, device tree, boot arguments, and the persistent system root. Every enabled boot/recovery route preserves this boundary. | Customer-key and effective-state readback, exact image verification, successful cold boot, required negative boot/recovery tests, and physical root-integrity enforcement. A signature file or a read-only mount alone is insufficient. Tests must also show mutable startup scripts, plugins, modules, or configuration cannot introduce or select unauthorized system code or disable its security policy. |
| FA-03 | **Approved software works offline; offline rollback prevention is not required.** The installed release is approved at enrollment and supports normal protected operation after an offline cold boot. Older correctly signed software may run offline on the original device, subject to the other security conditions. | Release digest and policy binding; successful offline boot, data access, and local application operation. Qualification records behavior with older signed images and restored storage without requiring their rejection. Normal and recovery paths must still reject unauthorized or altered software. |
| FA-04 | **Stored secrets and private data are protected against removal and copying.** Persistent credentials and private data are encrypted; obtaining the storage alone does not provide the unlocking or authentication secrets. Each device has independent secret material. | Qualification shows copied media cannot be decrypted or used to authenticate on another board; per-device provisioning records and an offline cold boot show the intended protection was installed and works. No plaintext escape through swap, logs, crash dumps, backups, build outputs, or recovery. Public boot/system bytes need integrity, not confidentiality. |
| FA-05 | **The device has a unique, authorized fleet identity.** It proves control of its own key in a fresh enrollment transaction and authenticates the intended enrollment authority. The authority assigns the canonical identity; the device cannot choose another device's identity. | Fresh proof bound to the transaction, assigned identity, public key, intended authority, and provisioning result; uniqueness checks; replay and key-substitution rejection. No shared fleet credential, CA key, release-signing key, or station administrator credential is installed on the device. |
| FA-06 | **Development access and firmware mutation paths are closed according to the fleet profile.** Boot sources, debug interfaces, EEPROM write protection, and update authorization have explicit effective settings. | Final-state readback and observed behavior after cold restart match the settings below, including the scope of each hardware lock. Provisioning-only tokens and development access are removed. A configuration file alone is insufficient. |
| FA-07 | **Recovery preserves the security boundary.** Recovery and updates accept only authorized payloads and cannot bypass identity, storage, boot, or the selected rollback rule. | The required signed recovery, post-recovery readback, and rejection tests pass. There is no generic secret-exporting recovery shell or unrestricted storage interface. Storage/identity replacement retires the previous fleet instance and requires enrollment of the replacement. |
| FA-08 | **Enrollment is durably completed and access is conditional on membership.** Installing a certificate is not admission. Activation is one atomic, idempotent transition of the exact verified device/credential/profile/release/evidence record, conditional on all checks remaining valid and no conflicting claim or revocation. | After installation and final restart, the device proves its credential to the enrollment verifier while ordinary fleet access remains denied. Activation then permits a successful fleet authentication check. Evidence includes rejection while pending or revoked, restart/retry tests without duplicate or conflicting identities, and the retained secret-free audit result. |

Proposed Raspberry Pi 5 settings for FA-06 are:

- Normal local boot uses the approved NVMe/SD paths only; network boot and other
  unqualified fallback paths are disabled. The final profile records the exact
  order and configuration bytes.
- Boot UART and unauthenticated serial/debug consoles are disabled. Development
  USB-gadget root access and development login credentials are removed.
  Operational management access requires its own explicit authorization.
- VideoCore JTAG is locked. Evidence of that lock must not be described as
  proof that every processor debug interface is disabled; other accessible
  debug paths must be assessed against the stated storage/key boundary.
- Effective EEPROM write protection is enabled during normal operation;
  automatic EEPROM self-update is disabled. Maintenance that changes firmware
  requires an authorized, customer-signed operation and restoration/readback
  of the final protection state before release to service.

These are proposed production settings, not settings already approved or
qualified on the sacrificial development Pi. Unsupported or unobservable
settings block acceptance until resolved; documentation cannot substitute for
their enforcement.

Production identity and signing trust must be separate from development trust.
The current development-key-owned Pi remains a test device; installing a new
image does not change its fused customer root or make it eligible for a profile
requiring a different production root.

## Existing-device adoption

The [Ace adoption plan](ace-adoption-plan.md) selects an existing device as the
first production target. An existing OTP storage secret is separate from the
secure-boot customer root and the new operational fleet identity. Its presence
alone does not disqualify the device or establish that any FA condition passed.

The planned adoption path may accept externally created secret material through
an explicit, target/profile-bound reuse review. Record the creation history,
custody assessment, unknowns and approval scope without manufacturing a new
programming result. This accepts a historical process difference; it does not
waive FA-04, conceal conflicting ownership or turn unresolved exposure into
protection evidence. The proposed `ACE-EX-01` decision and its remaining gates
are described in the plan. Current runtime policies and contracts stay unchanged.

## Offline operation and continued fleet access

Offline cold boot, protected storage access, and normal local operation must be
tested with the network physically unavailable. Local enforcement cannot
depend on a fresh server token, certificate renewal, or network time. This
does not authorize expired certificates or weakened server authentication on
reconnection.

This profile does not require a monotonic hardware counter, a minimum-version
gate enforced while offline, or fresh server approval at each boot. Permitting
older signed software does not guarantee compatibility with every older
release or storage format. The release installed for initial admission must
still be approved at that time.

A disconnected device cannot learn a new server-side revocation or release
ban. Fleet services must enforce current membership and credential policy
when it reconnects, before granting access. Immediate remote shutdown of
offline functionality is not a guarantee of this profile.

Release-based denial on reconnection is not added as a requirement by the
offline rollback decision. If it is separately selected, the service needs
qualified evidence binding the running release to the current session. A
version string, ordinary signed report, or mTLS connection alone does not
prove boot state. Release-based denial must not be claimed merely because
credential revocation works. See the
[identity and attestation boundary](device-identity.md#security-objective).

Admission certifies the observed provisioning result and the defined ongoing
controls. It is not a permanent guarantee that a running device is
uncompromised.

## Evidence and completion

Qualify shared mechanisms on the exact supported hardware/release: boot and
root rejection, recovery, offline operation, copied-storage protection, the
selected rollback behavior, and enrollment failure/retry cases. Reuse that
evidence only within its recorded applicability; repeat checks invalidated by
relevant changes. Tests on a workstation do not prove hardware enforcement.

Every device must still complete its required individual procedure and
observations. For a fresh boot-root transition, preserve the
[existing seven-operation sequence](raspberry-pi-5-live-provisioning.md#fixed-seven-operation-campaign):
customer-key/EEPROM commit, signed cold boot, owned-state readback, signed
recovery, repeated readback, negative boot/recovery tests, and root-integrity
testing. Shared qualification does not waive those checks, their approvals,
or the final identity/storage checks. Already-owned development hardware must
not repeat a fresh-device ownership operation.

An already-owned production candidate requires an explicit adoption path that
verifies the approved root and retained ownership evidence without reprogramming
or claiming that a fresh commit occurred. Signed cold boot, owned-state readback,
recovery, repeated readback, negative boot/recovery and root-integrity checks
remain required. Storage-secret reuse alone does not select this boot-root path;
fresh authenticated inventory must determine the applicable prestate. This path
is planned, not an override of the current fresh-board control contract.

The backend evaluates these conditions and retains the evidence. The first Ace
campaign uses malak's reviewed CLI procedure and report; GUI provisioning is
deferred. Both interfaces must report pending, blocked, quarantined or enrolled
status, the exact failed condition and next necessary operator action. They may
report **enrolled** only after FA-08 completes. A later GUI should exchange
evidence references through the backend, without manual digest/JSON transfer.

## How to establish the conditions

This is the implementation and verification plan, not a report of completed
checks. It uses the existing provisioning lane and adds the storage, identity,
and fleet handoff it currently lacks.

The admission authority trusts an authenticated provisioning station to report
physical observations from its controlled lane. The station binds observations
to one target and transaction, compares them with approved artifacts, and
submits references to the retained results. Cryptographic device proof then
binds the enrolled public key to that transaction. A target saying "secure"
does not establish these facts, and its later TLS connection does not remotely
attest them. Station and authority compromise remain outside this assurance.

| Condition | Implementation and concrete verification | Reuse and remaining gap |
| --- | --- | --- |
| FA-01 | Express the selected profile as versioned machine-readable expected values and artifacts. The station compares board/ownership/firmware observations and inventory with those values before mutation and after final restart. Keep fresh-board preconditions separate from final owned-state requirements. Bind the profile, target, release, and transaction in the retained admission result. | Reuse [probe and evaluation](../cmd/kaiba-provision/main.go), target claims, and [device-class facts](../profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json). The current fresh-development profile and its deferred checks are not a final fleet profile; exact production values and missing observations still need closure. |
| FA-02 | Use native Pi secure boot to authenticate the boot image and its system-root hash; mount the system root through dm-verity. Verify the staged bytes and owned key state, then cold boot. Run the required wrong-key, unsigned, modified-boot, recovery, and root-corruption cases. Exercise modified root blocks, including reads after mounting; do not count a timeout or a read-only mount alone as successful rejection. Check that writable data cannot introduce executable system code. | Reuse [signed artifacts](../nix/secure-boot-artifacts.nix), [target configuration](../nix/modules/secure-boot-target.nix), media readback, and the [physical adapter](../internal/provisioning/physicalrpi5/adapter.go). Limited signed-boot observations exist; complete applicable physical acceptance remains open. |
| FA-03 | Cold boot the supported image with every network path unavailable, unlock its data, and exercise a defined local application action. Shared qualification also checks that server unavailability, unavailable network time, and an expired network credential do not disable local functions. Record older-image behavior without requiring rollback rejection or promising compatibility. | The native signed target provides an offline starting point. The [stable-verifier command](../cmd/kaiba-rpi5-stable-verifier/main.go) currently requests server authorization; its shipping composition and acceptance expectations must match the selected offline behavior. |
| FA-04 | Add a LUKS2 volume for credentials and private state, unlocked locally using a device-unique secret absent from removable storage. The candidate mechanism is OTP-backed firmware HMAC derivation inside the signed early-boot environment. Qualify that exact firmware/key/lock behavior first. In shared qualification, copy all storage to another comparable board: the original must unlock while the copy cannot decrypt a test record or answer a challenge using the original identity. Each device must record successful secret provisioning or approved existing-secret adoption, encrypted-volume setup, and offline reopen after cold restart. Adoption requires the history/custody review and unchanged protection checks above. | The current target has tmpfs state, not an implemented persistent-secret/LUKS path. Add the scoped unlock and secret-provisioning/adoption path; check every key slot and fallback, and keep secrets out of logs, store outputs, backups, and receipts. A generic decryption failure on a broken second board is not sufficient clone-protection evidence. |
| FA-05 | Generate an independent operational key on the trusted target and store it only in protected state. Bind its public key to the physical target and fresh enrollment transaction through the station's authenticated endorsement. The device authenticates the enrollment server and answers a fresh challenge bound to the transaction and public key. The authority assigns the identity and stages a constrained credential. Qualify rejection of replay, substituted keys, and another device's identity. | Reuse authenticated station/control channels and transaction bindings. Device key generation, bootstrap binding, issuance, and installation are [planned](device-identity.md), not implemented. A software key in LUKS can meet the selected copied-storage boundary; it is not a non-exportable hardware key. |
| FA-06 | After required recovery testing, apply the final approved locks and access configuration, cold restart, and verify effective state. Shared qualification tests the protected firmware-write and debug boundaries; each unit needs the corresponding hardware configuration/readback and absence of development access. Use a reviewed observation path that still works after UART/debug restrictions take effect. | Reuse owned-state observations and finalization plumbing. Current metadata explicitly does not establish effective EEPROM write protection or all processor debug paths. Final settings, their actuators, and evidence methods remain to be qualified. |
| FA-07 | Use one narrow signed recovery environment. On each device, run the required recovery and post-recovery readback plus negative recovery tests. Shared qualification checks that recovery preserves locks and secret protection, and that destructive storage replacement results in a new instance with the former fleet credentials retired. | Reuse [owned-recovery signing](../nix/owned-recovery-signing.nix) and the fixed physical sequence. Production recovery qualification and the storage/identity replacement handoff remain open. |
| FA-08 | Add a fleet registry and enrollment handoff: pending credential, installed-key proof after final restart, atomic activation of the verified record, then successful fleet authentication. Test failures before and after each durable transition, especially a lost activation response. Retry retrieves or completes the same authoritative result. Fleet services check current credential and membership authorization. | Reuse [control persistence](../internal/provisioning/controlplane/storage.go), idempotency, and audit receipts. The existing transaction store is not a fleet registry; its [terminal transition](../internal/provisioning/controlplane/workflow.go) stops at development `security_applied`. Implement the fleet record and activation interface, then connect the [live UI backend](../internal/provisioning/livestation/backend.go). |

For the storage candidate, Raspberry Pi documents [firmware HMAC and key-operation locks](https://github.com/raspberrypi/utils/tree/master/rpifwcrypto).
That establishes an upstream interface, not qualification of our pinned
firmware or proof of a secure enclave. Our proposed use must demonstrate
separate key purposes, raw-key read restrictions, and closure of unnecessary
key operations after early boot without disclosing the secret in evidence.
Derive the LUKS keyslot passphrase with an explicit purpose label and public
per-volume nonce; let LUKS generate its own independent volume key. Neither a
board serial nor a disk identifier is a secret or a substitute for this device
binding.

For initial identity binding, a concrete proposed path is to observe a public
endpoint-key fingerprint through the station's qualified direct connection,
pin that key for the encrypted exchange, and bind the operational public key
and fresh proof to the same target/session/transaction. The authenticated
station then endorses that binding to the enrollment authority. The signed
target image supplies trust in the intended enrollment domain. This is a
bootstrap protocol to implement and test, not permission to trust an arbitrary
network endpoint or a serial number. Offline unlock does not require a
separate online identity before the volume opens.

The retained result for each condition needs its expected and observed values,
test outcome, observer, target/transaction binding, profile and artifact
digests, and references to applicable shared qualification. Preserve the
underlying evidence; a hash without the referenced result is not enough.
Receipts contain no private keys, unlock material, or plaintext private data.

Use the [implementation staging plan](implementation-staging.md) to begin
bounded work before every final profile setting is resolved. Provisional
choices permit implementation; all eight conditions still gate admission.

1. Record the native signed-boot/verity candidate, existing SD/NVMe topology,
   acceptance criteria and specific decision gates. Start the two first slices
   in parallel: real read-only station status with restart recovery, and
   native offline boot with protected-storage feasibility. Final protection
   qualification does not block the read-only UI; fleet-service selection does
   not block offline-device work.
2. Close the coupled device-side gap: authenticated offline boot, local
   encrypted-state unlock, final locks, and copied-storage protection. Qualify
   any added OTP-secret operation under its own explicit plan and authority;
   do not hide it in or replay the existing ownership operation.
3. Confirm the actual fleet backing service and identity interface, then
   implement the minimal enrollment handoff and its transaction binding,
   installed-key proof, activation, retry, and revocation behavior. This work
   can proceed alongside remaining hardware qualification; real activation
   remains conditional on all admission checks.
4. Finalize and approve the exact fleet profile and close its required evidence.
   Demonstrate Ace through the required hardware sequence and enrollment using
   malak's reviewed CLI path, including offline operation and recovery from an
   interrupted transaction. Connect GUI actions to those real backend results
   in a later milestone; GUI completion does not gate this first admission.

Map qualification cases before the physical work they cover, preserving
applicable boot, root, recovery and handoff checks. Keep the old online-verifier
campaign intact for that candidate. If the fleet ships native boot, classify
its authority-offline-refusal case as inapplicable to that path and require a
separate offline-success case; do not invert a result or mark the old case
passed. A stable-verifier/kexec mechanism needs its associated tests if it
remains in the shipping path; the eight outcomes do not themselves require
that particular boot architecture. Unresolved settings block the operations
that depend on them and final admission, not unrelated implementation work.

## Effect on the current work

The existing [development posture](../policies/raspberry-pi-5-development-posture-v1alpha1.json)
still blocks fleet admission. Signed artifacts, the limited successful hardware
observations, and completed signing work remain useful evidence within their
scope; none establishes that all eight conditions pass.

The archived [production proposal](archive/raspberry-pi-5-production-security-follow-on.md)
requires fresh server permission before protected operation. Its offline
refusal behavior conflicts with the user's newly selected requirement and
cannot be the final fleet behavior unchanged. Mandatory offline rollback
prevention and a fresh server decision before every boot are outside the
selected first-fleet requirements; do not introduce new hardware or a new
service solely to provide them. Reuse verifier components where they support
the selected profile.
The existing 33-run/37-claim campaign is not silently waived or marked passed
by this draft; any changes to its acceptance criteria need an explicit mapping
to the selected profile.

The three choices above are resolved; the remaining proposed profile settings
are not approved by those choices alone. Map each condition to evidence already
held or the specific missing implementation or test. Broader roadmap items do
not become prerequisites merely by appearing in a design document. Carry the
explicit rollback decision into a future fleet policy without clearing the
other development blockers or claiming that qualification is complete.
