# First production hardware: provisioning and qualification plan

Status: agreed implementation direction, 2026-10-03. Physical execution,
signing, ownership, secret provisioning, and release to service remain subject
to their existing explicit authorization and evidence requirements.

## Outcome and selected policy

Qualify a repeatable provisioning procedure using the first intended production
Pi and the existing development Pi. No additional Pi is designated sacrificial.
The new Pi keeps its intended production configuration and remains a deployment
candidate throughout qualification. Every other new Pi is reserved for production.
A required check that fails leaves the candidate pending or quarantined; the
plan does not promise readiness before acceptance passes.

Use the existing [first-fleet admission profile](fleet-admission-policy.md):
normal local operation works offline, removed or copied storage does not disclose
private data or usable credentials, and older correctly signed software may run
offline. Production signing trust is separate from development trust. Use the
existing external signing pattern; device-local boot-root signing, per-device
root-custody redesign, TPM work, and the stronger autonomous-owner profile are
outside this milestone.

Normal boot is NVMe-only. Use narrow, customer-signed maintenance and recovery.
After one administrator installation and fixture wiring session, an approved
routine campaign must require no repeated sudo commands, cable moves, media
swaps, BOOTSEL presses, or manual power cycling. Independent review and bounded
execution approvals remain human decisions. Exceptional faults may require
inspection; automation must not conceal them or weaken acceptance.

This plan covers development closeout, profile selection, and shipping-release
qualification. Fleet activation, GUI integration, and production rollout remain
subsequent gates. An operational management credential and demonstrated update
path are nevertheless prerequisites for removing provisioning-only access and
releasing the first device.

## 1. Close the historical development work accurately

Preserve valid signed artifacts, receipts, observations, and campaign identities.
Record the original development-Pi ownership operation and terminal evidence as
missing from the bounded searched locations; global absence is not established.
End further discovery unless a concrete new source appears.

Revise task 1's administrative closeout criteria to permit a reviewed disposition
that distinguishes established results from unresolved history. Do not fabricate
a prior ceremony, infer a successful terminal transaction, or set
`security_applied` from that disposition. The existing terminal contract is
unchanged. Never repeat fresh-device ownership on the already-owned Pi.

Retain that Pi as the comparison and development board with its existing root.
Map development, Ace, and malak observations to their exact scope and input
bindings. Reuse valid evidence only within its applicability. The retained
online-verifier campaign's 33 runs and 37 claims stay associated with that
candidate; its authority-offline-refusal case is not a shipping-profile pass.
Create a distinct campaign for the offline shipping release.

## 2. Freeze the profile and qualification packet

Create a versioned, machine-readable profile and one immutable packet binding
actual board inventory, firmware, release, configuration, media geometry,
signing trust, recovery artifacts, tools, and independently derived acceptance
expectations. No admission-critical field may remain undecided at approval.

The profile requires native authenticated boot, dm-verity, NVMe-only normal boot,
and rejection of unauthorized software through every enabled boot/recovery route.
Disable network boot and unqualified fallback. Mutable state must not select
unauthorized executable system code or disable security policy.

Private state and credentials use LUKS2 unlocked locally by device-unique secret
material absent from removable storage. Qualify the existing firmware-HMAC
derivation and lock mechanism before accepting it. Unknown slot history,
unsupported locks, incomplete permitted-image coverage, or unproven protection
remain blockers. Storage loss uses destructive replacement and retirement of
the previous logical instance, followed by enrollment of its replacement.

Require disabled boot-UART logging and interactive debug consoles, absent
development login credentials and USB root access, locked VideoCore JTAG,
disabled automatic EEPROM self-update, and effective EEPROM write protection
in normal operation. Qualify the actual observation and maintenance-transition
methods; VideoCore locking is not proof that every debug path is closed.

Permit only reviewed signed normal, maintenance, and recovery images. Use the
production candidate's intended configuration. Do not sign unrestricted
inspection images under its production root. Recovery must preserve the secret
boundary and provide neither a generic root shell nor secret export.

Keep existing development schemas and terminal validation compatible. Add
profile-specific qualification records without upgrading development results
or changing their assurance limits.

## 3. Automate qualification and preserve the production candidate

### Install bounded privileged execution once

Install a root-owned systemd executor on malak with an authenticated client for
preparation, preflight, execution, status, and controlled evidence export. Accept
approved immutable packet identities and fixed operations only. Expose no
arbitrary-command, executable-path, disk, offset, or payload interface.

Reuse existing authorization, execute-once journals, staging, recovery, and
verification components. Automatically collect protected evidence, capture and
independently verify backups, stage the reviewed ranges, read back complete
ranges, and execute only separately approved restoration. Publish readable status
and explicitly selected public receipts so routine work needs no administrator
export commands. Do not expose private keys, plaintext, or raw secret responses.

Restart into observation and reconciliation mode. Never resume an uncertain
write, clear a consumed intent, or renew mutation authority automatically.
Preserve partial setup, attempts, journals, and backups. An absent or inconsistent
completion record is not permission to repeat an operation.

### Prepare a fixed controllable fixture

Fit the production Pi and NVMe once. Provide normally-off controllable power,
BOOTSEL selection, USB data isolation, and required maintenance/protection
transitions. Keep capture equipment independently powered. Observe actual power
removal and the cold interval; USB disappearance alone is insufficient.

Provide a bounded signed RAM maintenance environment for NVMe backup, staging,
readback, copying, and restoration without drive removal. It must preserve secret
restrictions and expose only packet-authorized operations. Qualify watchdog
shutdown, controller loss, host restart, back-power prevention, and load behavior
before unattended execution. Unsupported actuation blocks the campaign rather
than invoking a manual fallback. Reuse the existing development board's storage
and ownership; do not require another new board or erase its existing state.

### Execute production-preserving acceptance

Provision the new board's ownership and device secrets once under separately
scoped explicit authorization, preserving evidence from the first operation.
Keep the required fresh-device sequence: ownership/EEPROM commit, signed cold
boot, owned-state readback, signed recovery, repeated readback, negative
boot/recovery tests, and root-integrity testing.

Run pristine boot and protected-state reopen, a defined local data operation,
physically isolated offline cold boot, unavailable server/network-time cases,
and expired network-credential behavior. Losing connectivity or credential
expiry must not disable local operation. Observe older authorized software under
the selected rollback policy without requiring its rejection.

Exercise unsigned, wrong-key, altered boot/configuration, unauthorized recovery,
unauthorized mutable code, startup-root corruption, and late-read corruption.
Use bounded reversible media mutations and independently verify restoration plus
pristine controls. A timeout, broken comparison board, or unexplained failure
is not successful rejection.

Test interruption handling through simulations and reversible media operations.
Do not deliberately interrupt OTP programming or EEPROM writes, overwrite
immutable secrets, probe restrictions through irreversible negative writes, or
perform destructive hardware tests. Preserve uncertainty for reconciliation.
Apply final protections through the reviewed sequence, cold restart, and verify
the effective state through an observation path that remains usable afterwards.

### Compare copied storage using the existing development Pi

Verify its actual firmware, crypto support, slot usage, and local positive
controls without repeating ownership or secret programming. Do not assume it is
eligible merely because it is the same board model.

Transfer complete, hash-bound ciphertext and required public metadata through
a bounded maintenance channel. The original production board must open its
protected state while the functioning development board cannot decrypt the copy
or use the protected test credential. The current 65 MiB comparison fixture
alone does not qualify an entire shipping storage/credential layout; extend
coverage and authenticated evidence for that exact boundary.

Keep maintenance-channel observations separate from physically isolated
normal-boot evidence. Verify unchanged source bytes and successful cleanup.
Remove comparison material without changing the development Pi's ownership.

## Production management and update prerequisite

Development access is not the production management interface. Retain separately
authorized operational access and a bounded privileged update service after
provisioning-only credentials are removed. A valid management credential
identifies a peer; approved signed artifacts authorize the software change.
Do not expose a general root shell through the update interface.

The repositories contain signing, staging, readback, recovery, and development
enrollment components, but no completed, qualified update path for this locked
signed-boot profile has been established. Existing hosts' SSH/nixos-rebuild
procedure does not establish that path. The pilot kaiba-agent updates DNS
addresses; it is not an OS-update service.

Before releasing the first device, install and test the production management
credential and update path: a real version-to-version transition, verification
of the complete boot/root/verity set, invalid-update rejection, reboot health,
credential/state continuity, and demonstrated recovery from interruption.
EEPROM updates have a separate signed maintenance scope and must restore and
verify the final protection state. Ordinary OS updates do not reprogram the
fused customer root.

The next implementation work is the management-credential and update-service
contract and its tested producer/consumer path. Routine production updates use
the device's normal network, as selected by the operator. Specify authenticated
transport and the recovery mechanism before implementing writes; fixture staging
alone is not a remote updater.

## Evidence, completion, and remaining gates

Bind each attempt to the exact board, profile, release, packet, complete media
readback, capture, and independently reviewed witnesses. Derive expected results
independently of submissions. Reject missing, truncated, altered, replayed,
wrong-board, wrong-run, or expired evidence and duplicate dispatch. Preserve
collector/reviewer role separation and the assurance limits of existing tools.

Complete this milestone with a reviewed development disposition, approved
concrete profile, validated hardware-qualification report, and an approved
campaign demonstrated without routine sudo or hardware manipulation. Leave
the production Pi on independently verified baseline media with intended
protections applied and test credentials removed.

Hardware qualification, a certificate, or an updater does not establish fleet
membership. Final production readiness still requires all applicable FA-01
through FA-08 conditions, including durable enrollment and activation. Keep
`production_ready` and `enrollment_ready` false until their complete contracts
are satisfied. A failed required check keeps the candidate pending; it does not
authorize consuming another new Pi.
