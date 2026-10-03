# Production management credentials and remote updates

Status: proposed implementation design, 2026-10-03. The operator selected remote
network updates and A/B system slots. No production credential, installed update
service, remote update execution, or hardware qualification is claimed.
This follows the [agreed provisioning plan](production-provisioning-plan.md).
Routine updates use the device's normal network. The first-fleet offline and
copied-storage requirements remain unchanged. This design is the next workstream
after documenting the provisioning procedure; it does not expand the hardware
qualification milestone into a new root-custody or rollback policy.

## Architecture

Use a device-initiated HTTPS update agent, a fleet-authorized offer service, and
a separate bounded privileged executor. The device needs no inbound update port,
development login, or general remote root shell. The updater is a separate
service from the existing kaiba-agent DNS address updater.

A production management credential authenticates the device to its intended
management authority. A signed, target/profile-bound update offer authorizes one
software transition. Independently verified release signatures authenticate the
installed bytes. None of these checks substitutes for another or constitutes
remote attestation of the running release.

Ordinary OS updates never reprogram the fused customer root. EEPROM maintenance
has separate authorization and restores/verifies the final protection state.
Device-local boot-root signing, TPMs, and the stronger autonomous-owner security
floors are outside this implementation.

## Credential boundary

Generate one P-256 operational management key on the trusted device after its
qualified encrypted credential volume is available. Persist it only in that
volume, with private ownership and no plaintext fallback. Do not export the key
or embed it in build artifacts, deployment packages, environments, or logs.

The fleet registration authority assigns the logical device and instance.
Initial enrollment binds a fresh proof to the provisioning result, authority,
assigned identity, public key, management slot, key generation and certificate
profile. Verify the issued certificate against explicitly configured production
issuer trust, the local key and the exact assigned identity. Installing a
certificate is not fleet activation.

The offer service checks current inventory authorization for the exact active
device/instance/slot/generation/certificate tuple on every protected request.
Pending, revoked, quarantined, expired, wrong-authority and replaced instances
remain denied on normal production routes. A certificate chain valid under the
CA is insufficient.

Before final activation, the same intended production credential may access only
a separate qualification route under an explicit, expiring campaign grant for
that exact tuple, board, profile and release transition. This permits the required
update demonstration without granting ordinary fleet membership. The grant does
not make a pending device active; production routes still deny it. Test both
boundaries. Qualification access, issuer integration and production admission
need explicit new support in fleet; existing rehearsal and pilot eligibility
cannot authorize this route by renaming their profiles.

Reuse existing proof, protected-storage, atomic state and reconciliation
patterns. Keep the existing development client and pilot profiles unchanged;
add an explicitly versioned production client/adapter path rather than removing
their development-only checks. Production issuer, origins, audiences and trust
must be configured from an approved installation profile, not development defaults.

Use the existing independent registration/issuer boundary. Support same-key
renewal with verified installation and authoritative reconciliation of lost
responses. Never generate a replacement identity merely because renewal failed.
Offline operation and local data access do not depend on credential renewal;
expired network credentials cannot obtain updates or fleet access. Retained-key
recovery requires a separately authorized recovery workflow. Define and test the
recovery authorization and client/server proof path before a credential can expire
in service. Recovery must neither depend solely on that expired certificate nor
issue a replacement identity automatically.

Private credential state must remain readable by both supported slots. Publish a
versioned state format and compatibility checks; stage migrations so the previous
slot can still open its own required state. An update must not make fallback lose
the retained key, reinitialize LUKS, or enroll a second instance. Qualification
includes reopening the same protected volume from each slot and each supported
release after cold power removal.

## Agent and privileged executor

Run the network agent as a dedicated service account. Use explicit server trust,
TLS 1.3/mTLS, bounded requests/responses, timeouts and configured origins. Do not
follow redirects or discover proxies/trust roots from the environment. Backoff
and request retry may obtain authoritative status; they may not dispatch another
uncertain physical operation.

The agent fetches only an offer assigned to its exact instance, installed-release
context and approved profile. Download artifacts from approved origins, verify
complete lengths/digests/signatures, and stage a complete local bundle before
requesting execution. No writable application configuration may choose the
update verifier, trusted keys, commands, target disk or security policy.

The privileged executor uses a root-owned local socket with exact caller-role
checks. Its deployment fixes device selectors, layout, tools and allowed actions.
The request identifies a reviewed signed offer and bundle; it supplies no shell
command, arbitrary path, offset, device or force/reset option. The executor
independently checks authorization, profile, current prestate and actual artifact
bytes before any write. Network-agent validation alone is insufficient.

Persist exclusive attempts, synchronize staged data and journal transitions,
and independently reopen/read back complete installed ranges. Preserve private
state and credentials across an authorized OS update. A candidate cannot erase,
format, recreate or adopt another credential volume as an implicit side effect.

Only a boot-confirmed, healthy, exact release completes the update record.
Interrupted or inconsistent execution enters reconciliation; repeating a request
retrieves the existing outcome rather than repeating writes. Public status and
receipts exclude private key, unlocking and plaintext application material.

## Selected A/B layout and recovery

Reserve two complete system slots on NVMe before provisioning the first device.
The proposed layout has a small boot-selection area, Slot A and Slot B, and one
shared LUKS2 private-state volume. Each system slot has a FAT boot filesystem,
root-data image, verity hash tree and complete public release metadata. Keep GPT
and the active slot unchanged during routine installation into the inactive slot.
Exact partition numbers, GUIDs, offsets, capacities and artifact limits belong to
the reviewed shipping profile; do not inherit development media geometry.

Build and sign a boot image for each slot with that slot's fixed root-data and
verity PARTUUIDs and root hash inside the authenticated image. The same release
can therefore have different boot-image bytes for A and B. Bind both variants and
their complete artifacts to one versioned release index. Existing one-image
signing grants do not authorize another image; obtain the exact signing scope for
each variant. Verify the firmware-HMAC unlock behavior for all permitted shipping,
previous, maintenance and recovery images, including both slot variants.

Raspberry Pi documents partition-level `tryboot_a_b` and a one-shot alternate
boot. Its [official example](https://www.raspberrypi.com/documentation/computers/config_txt.html#autoboot-txt)
uses an `autoboot.txt` selector, boots the candidate once and commits the selector
after health checks. The [signed-update example](https://github.com/raspberrypi/rpi-system-update/blob/master/README.md)
also combines alternate boot partitions with verified boot images. These are
candidate mechanisms, not evidence that our firmware, GPT layout, selector write
or watchdog behavior is qualified.

Treat the mutable slot selector as untrusted input: it may select only an
otherwise accepted signed image with authenticated root selectors. Changing it
must not enable unsigned code, change trust or introduce another boot source.
Qualify malformed selectors and attempts to select partitions outside the approved
layout against the exact signed firmware configuration.

Use this update sequence:

1. Obtain an authorized transition for the observed current release and inactive
   slot. Download and independently authenticate the complete bundle; durably
   record the attempt before dispatching any mutation.
2. Write only the inactive slot's reviewed extents. Independently reopen and hash
   complete boot, root, hash and release-metadata ranges. The existing active
   system and shared private volume remain usable if this step is interrupted.
3. Persist trial intent, verify the current selector and arm a bounded one-shot
   trial boot. Arrange a reset path for boot failures before relying on a userspace
   health service. A userspace timeout cannot recover a kernel that never starts.
4. Confirm the trial from live bootloader properties, authenticated boot-image
   identity, exact verity-root mapping and release metadata. Health requires local
   application operation, protected-volume reopen and usable retained credential
   state. Server availability and certificate renewal are not local health gates.
5. Commit only after those checks pass. Independently read back the boot selection
   and demonstrate an ordinary restart into the exact committed slot. Preserve
   the previous complete slot until a later authorized update reuses it.
6. On failed trial health or reset, retain the previous default. Reconcile observed
   boot and journals without rewriting the candidate automatically. Duplicate
   dispatch returns the same attempt; a fresh attempt requires fresh authority.

A/B image retention does not by itself prove recovery from interrupted selector
writes. FAT rename/fsync must not be assumed power-loss atomic. Qualify failures
before, during and after selector commit, including malformed or torn state,
cold power removal and watchdog reset, with positive controls. Select and pin a
boot-selection commit/recovery strategy that restores the approved slot without
routine fixture intervention. If the native selector cannot meet that promise,
resolve the mechanism before freezing the shipping profile or implementing a
real-disk writer; do not silently fall back to manual recovery.

A committed healthy release may later suffer storage damage. Define the bounded
recovery behavior for that case separately; the trial flag alone does not prove
fallback from every later failure. Keep narrow signed fixture recovery for
exceptional faults. A/B retention supplies availability recovery, not a hardware
minimum-version floor or a guarantee that every older release remains compatible.
The selected profile continues to allow older correctly signed software offline.

## Component ownership and proposed contracts

| Component | Owner and implementation boundary |
| --- | --- |
| Device credential client | Provisioning: protected key/state, bound proofs, installation, renewal and reconciliation; separate production configuration and version |
| Registration and membership | Fleet: target endorsement, identity assignment, staged issuance, installed-key verification, current tuple checks and atomic activation |
| Credential issuer | Independent issuer adapter and approved production custody; no CA private key on station clients or devices |
| Shared wire contracts | Contracts repository: reviewed versioned challenge, credential, transition-offer and receipt schemas with a shared conformance corpus |
| Release construction/signing | Provisioning and external signer: slot-specific boot variants, root/hash payloads and exact public signature/receipt closure |
| Remote offer service | Fleet: approved transition assignment, qualification-grant separation and current authorization on each protected request |
| Network agent and local executor | Provisioning: bounded transport/downloads, fixed local peer role, inactive-slot installation, durable trial/commit/reconciliation and health |
| Station fixture | Provisioning on malak: existing separate packet-authorized provisioning and exceptional signed recovery |

The proposed offer binds schema and audience, authority/key identity, unique
attempt identity, device/instance/storage generation, approved profile/layout,
current and target release, inactive slot, complete release-index digest,
artifact roles/lengths/digests, issuance/expiry and the applicable qualification
or active-membership decision. Use closed canonical JSON and an explicitly
configured signature suite/key set; settle the shared signature format before
adding a consumer. Content locations resolve through fixed approved origins,
never through arbitrary credential-bearing URLs or caller-selected files.

The executor independently checks the signed offer and local prestate. Require
current authorization at the agreed dispatch boundary and consume a durable
attempt identity before mutation. Define the authorization lease and revocation
race explicitly: a signed offer alone does not establish current membership,
and expiry during an already-started write does not authorize abandoning or
repeating it. Offline cold boot remains independent of this network operation.

Secret-free receipts bind the same attempt, exact releases/layout/slot, complete
readback digests, trial/normal boot observations, health outcome and durable
journal identity. Device status is an authenticated report from that device,
not independent hardware attestation or qualification evidence. Independently
collected physical witnesses remain necessary for hardware acceptance.

## Work sequence and acceptance

1. Freeze the selected A/B boot-selection recovery mechanism, shipping NVMe
   layout, offer/receipt protocol, credential authority configuration and component
   ownership. Keep shared contract changes explicit and versioned across
   provisioning and fleet. The recovery model choice is complete; the native
   mechanism and power-loss proof remain open.
2. Add the production credential client, corresponding fleet/issuer support and
   authorized HTTPS offer transport, with a disposable test issuer and registry
   fixtures. Cover staged qualification access and denial on ordinary routes.
   Fixtures never establish production issuance, enrollment or hardware protection.
3. Implement the local executor and boot-confirmation/recovery state machine
   against regular-file media and VM fixtures before hardware execution.
4. Integrate native ARM packaging and systemd services into the signed shipping
   image, then prepare an exact physical update packet and approval.
5. Demonstrate a real version-to-version update on the intended production Pi
   in both A-to-B and B-to-A directions, invalid-update rejection, preserved
   credential/private state, reboot health and the qualified interruption-recovery
   path. Use the existing development Pi for comparison/rehearsal; designate no
   additional new Pi sacrificial.

Tests cover wrong-device/profile/authority offers, unsigned or altered artifacts,
key substitution, expired credentials/offers, current membership rejection,
missing encrypted storage, interrupted renewal, lost responses, duplicate
executor requests, concurrent dispatch, failure at every durable transition,
reboot confirmation, recovery, and secret-free reports. Network/issuer outages
must leave normal offline functions available.

Do not remove provisioning-only access until the separately authorized production
management credential and update/recovery path work. Then remove those temporary
access paths, verify final state and repeat required acceptance on the exact
shipping release. Software tests or an installed updater never set
production_ready or enrollment_ready by themselves.

## Implementation starting point

Begin with the versioned production credential and transition-offer contracts,
then their producer/consumer conformance and disposable-PKI process tests. Reuse
patterns from the [development enrollment client](device-enrollment-client.md),
[enrollment handoff](enrollment-handoff.md) and [pilot lifecycle](pilot-enrollment.md)
without removing their scope restrictions. The current fleet rehearsal explicitly
rejects production profiles; a production route and authority adapter are new
implementation work.

The first code checkpoint must demonstrate durable on-target-key creation in a
verified protected mount, bound issuance/installation and same-key renewal,
current-tuple denial, staged qualification isolation and authenticated retrieval
of an exact signed offer. It has no disk writer and cannot claim an OS update.
The next checkpoint is the executor/trial/recovery state machine with fault
injection against regular-file media. Final native packages and real hardware
qualification follow those checks and a concrete execution approval.
