# First-fleet implementation staging

This is the implementation plan under the [delivery scope](delivery-scope.md)
and [fleet admission policy](fleet-admission-policy.md). The three delivery
outcomes and FA-01 through FA-08 remain authoritative. Slice A now has a
read-only software implementation and repeatable real-service checks, described
in the [station runbook](provisioning-station-kiosk.md#read-only-live-station).
Slice B and the later milestones remain planned. This document records no new
hardware result or fleet approval.

## Starting decisions and planning exit

Start with the existing development Pi 5 SD/NVMe topology and its
[host-bound media selectors](../config/hardware/default.nix). Use the existing
native signed-boot and dm-verity components as the engineering candidate.
Normal operation must work offline, copied storage must protect private data
and credentials, and offline rejection of older correctly signed software is
not required. Native boot is a provisional implementation choice, not an
approved final fleet profile.

The initial planning step is complete when slices A and B have the
deliverables, acceptance criteria and dependencies below. They can then
proceed in parallel. Resolve each remaining decision before the operation or
milestone it blocks; final profile approval is not a prerequisite for all
software work. Unknown, missing or conflicting admission evidence still
blocks enrollment. The current development policy remains unchanged.

## A. Real station status and restart recovery

The implemented viewer selects one transaction through startup configuration,
keeps only a memory-resident last successful snapshot, and fetches fresh state
after restart. Its evidence consists of coordinator-recorded results and
references, without independent audit verification. The runbook describes the
configuration and software acceptance demonstration.

Connect the [live station interface](provisioning-station-kiosk.md) to existing
authenticated control-plane transaction reads and available read-only station
observations. Reuse the authoritative transaction and its station/lane access
checks. Display its bound device, actual progress, available results,
unresolved conditions and next necessary operator action.
Do not acquire or renew a claim merely to make a transaction readable.

Retain the selected transaction reference across station restart and reload
its authoritative state. A saved UI view cannot establish current progress or
authorization. When the authority is unavailable, show that state explicitly;
any retained results must be identified as last observed. Reconnection must
refresh the authoritative result before reporting current status.

This slice exposes no mutation or enrollment action and never substitutes the
simulation. Read-only observations must be applicable to the board's current
state: the already-owned development Pi must not enter fresh-board
qualification or repeat ownership programming. Missing observations remain
unknown rather than being inferred from attachment alone.

| Acceptance scenario | Required result |
| --- | --- |
| Retrieve a real authorized transaction | UI values agree with the control authority and available observations; absent evidence remains pending. |
| Restart the station | The selected transaction is restored and its current state reloaded without repeating an operation. |
| Lose and restore authority connectivity | UI reports unavailable/last-observed state, then refreshes from the authority; it never advances using cached or simulated success. |
| Request a transaction outside the station's authority | Access is rejected without exposing its device or transaction details. |
| Observe uncertain or quarantined work | UI preserves that outcome and shows the required reconciliation action without dispatching another operation. |

The dependencies are an authenticated control endpoint and an existing
transaction accessible to the station. Tests may create controlled fixtures;
the integration demonstration must use the real services. Fleet-service
selection, storage-secret feasibility and final lock qualification do not
block this slice. It does not require a new UI framework or fleet registry.

## B. Native offline boot and protected-storage feasibility

The [unsigned native candidate](native-offline-candidate.md) implements the
image composition and software-test preparation. Signing/media handoff,
physical demonstrations and device-secret feasibility remain separate gates.

Prepare the existing [signed-boot components](raspberry-pi-5-signed-boot-workflow.md)
and [verified-root target](../nix/modules/secure-boot-target.nix) for the selected
development board and SD/NVMe topology. Record the source revision, pinned
firmware, exact artifacts and applicable retained evidence. Reuse completed
builds and signing only where their inputs remain applicable; the retained
online-verifier image is not made offline-capable by relabeling it.

Prepare a bounded physical procedure with exact media, independent readback,
capture and stop conditions. Its local test action is to read `/etc/os-release`
from the intended verified root and compare its digest with the build record.
This establishes a small local action, not full fleet-application acceptance.

| Acceptance scenario | Required observation |
| --- | --- |
| Cold boot with every network path unavailable | The intended signed image reaches its verified root and completes the local test action without server authorization. |
| Boot without network time | Local boot and the same action succeed without obtaining network time. |
| Exercise verity enforcement | Altered root blocks are rejected, including reads after mounting; a read-only mount or timeout alone is not a pass. |
| Investigate the proposed device secret | Record supported firmware-HMAC operations on the pinned platform, derivation purposes, raw-secret exposure/read restrictions, required locks and evidence still missing. |
| Qualify the secret/lock mechanism | Use mechanism-specific positive and negative checks to establish the claimed boundary; a build, harness or upstream interface alone is insufficient. |

Investigate the [proposed OTP-backed firmware-HMAC unlock mechanism](fleet-admission-policy.md#how-to-establish-the-conditions)
before committing to the encrypted-state integration. The feasibility result
must identify either a supported implementation path with its evidence and
remaining checks, or a specific failed assumption and the decision it blocks.
A documented blocker completes the investigation report, not the hardware
qualification. Unperformed physical checks remain pending.
Qualification must cover purpose separation, raw-key read restrictions and
closure of unnecessary key operations after early boot.

Record the intended LUKS integration and secret handling, including key slots,
fallbacks, recovery and possible exposure through logs, build outputs or
backups. Copied-media confidentiality remains unproven until the later
original-board/comparable-board demonstration passes. Signing, storage writes
and OTP-secret operations require their existing or separately defined
execution authority. A new secret operation must not be hidden in or replay
the existing ownership procedure.

## Later milestones and decision gates

| Milestone | Completion demonstration | Decision or experiment that blocks it |
| --- | --- | --- |
| Protected persistent state | The original device cold boots offline and reopens a private test record; copied storage on a functioning comparable board cannot decrypt it or use the original identity. | Slice B must establish the device-secret mechanism and required protections. Qualify the complete encrypted-state and credential path, not just a decryption failure on the second board. |
| Fleet enrollment | Pending membership, fresh device-key proof, installed-key proof after restart, atomic activation, and retry/revocation behavior work against the selected service. | Confirm the fleet backing service and identity interface before implementation. This choice does not block slice A or B. Real activation still requires every admission condition. |
| Integrated admission | One eligible device completes the required hardware procedure and enrollment through the UI, including offline operation and interrupted-transaction recovery. | Approve the exact fleet profile and qualify final protections, recovery and applicable negative tests; retain all required evidence. The development-key-owned Pi is not eligible for a profile requiring a different customer root. |

Resolve these remaining decisions at their specific boundaries:

| Open decision | How to close it | What must wait |
| --- | --- | --- |
| Exact native candidate and applicable qualification cases | Bind the selected artifacts and media plan; map existing boot, root, recovery and any retained handoff tests to the candidate. | Its physical attempt and any qualification claim. |
| Device-secret provisioning, derivation and lock behavior | Run slice B's bounded investigation and authorized mechanism checks; record supported behavior or a concrete blocker. | Secret programming and protected-state integration that depend on those properties. |
| Final boot/debug/EEPROM protections and observation method | Select exact expected values, qualify their actuators and verify effective state after restart through an observation path that still works. | Applying those settings and admitting the device; read-only UI integration can continue. |
| Fleet service and identity interface | Identify the actual service and agree its device-proof, membership and activation interface. | Enrollment implementation; offline-device work can continue. |

Keep the existing online-verifier campaign intact for its candidate. Map
applicable evidence explicitly: native offline success is a separate case,
not a pass or inversion of the old authority-offline-refusal case. If the
shipping path retains stable-verifier/kexec components, retain their required
qualification. Archived plans do not add first-fleet prerequisites, and this
staging plan neither waives missing evidence nor grants hardware authority.
