# Kaiba provisioning documentation

Start with the selected delivery scope, the admission conditions, and the
current implementation status. Component references explain existing code;
archived proposals do not add requirements to the first fleet.

## Current plan and status

| Document | Purpose |
| --- | --- |
| [Delivery scope](delivery-scope.md) | The three outcomes: apply hardware security, enroll devices, and guide the operator through a simple live UI |
| [Fleet admission policy](fleet-admission-policy.md) | Eight acceptance conditions, implementation/evidence mapping, and the selected offline and copied-storage requirements; remaining profile settings are proposed |
| [Implementation staging](implementation-staging.md) | Parallel first slices for real station status and native offline boot/storage feasibility, with later admission gates |
| [Production readiness](production-readiness.md) | What exists, what has been observed, and what still prevents fleet admission |

Normal device operation must work offline. Copied storage must not disclose
private data or usable device credentials. Offline rejection of older correctly
signed software is not required. These choices do not waive authentication,
hardware protections, recovery checks, or current authority for provisioning
operations. The implemented development posture still has
[`production_ready: false`](../policies/raspberry-pi-5-development-posture-v1alpha1.json).

## Current component and development references

These guides describe reusable components and their limits, not a completed
production workflow. The identity document is a design reference; its
first-fleet applicability is determined by the admission policy.

| Document | Boundary |
| --- | --- |
| [Native offline handoff](native-offline-handoff.md) | One-image signing scope, verified FAT/GPT package and bounded physical procedure; full physical qualification pending |
| [Native offline candidate](native-offline-candidate.md) | Pi 5 NVMe boot/root candidate, explicit local action and integrity tests; pristine boot and scoped physical negatives observed; device-secret feasibility pending |
| [Native verity observations, 2026-09-17](observations/2026-09-17-native-verity.md) | Startup and late-read rejection, pristine restoration, positive control and SD return; includes the explicit console-interleaving review |
| [Native offline observation, 2026-09-16](observations/2026-09-16-native-offline-positive.md) | Reviewed positive boot, unavailable network-time operation, SD return and private-evidence hashes; Slice B remains incomplete |
| [Development workflow](development-workflow.md) | Focused tests and candidate validation |
| [Native-build policy](../README.md#native-build-policy) | Native builders, cache reuse, and narrow exceptions |
| [Architecture and trust boundaries](architecture-and-trust-boundaries.md) | Implemented authority, execution, audit, and UI boundaries |
| [Raspberry Pi 5 secure-boot model](raspberry-pi-5-secure-boot.md) | Native boot chain, supported claims, and required hardware evidence |
| [Contracts reference](contracts-reference.md) | JSON contracts, Go interfaces, Nix constructors, and modules |
| [Hardware qualification](raspberry-pi-5-provisioning-probe.md) | Read-only observations and their limitations |
| [Signed-boot workflow](raspberry-pi-5-signed-boot-workflow.md) | Full-release signing, verification, and publication |
| [Development signing ceremony](ubuntu-rpi5-development-signing-ceremony.md) | Five-input full-release integration reference and outstanding composition requirements |
| [Target-media staging](target-media-staging-prototype.md) | Exact-media plans, writer, and independent verification |
| [Live provisioning](raspberry-pi-5-live-provisioning.md) | Required seven-operation fresh-device sequence, approvals, and reconciliation |
| [Station interface](provisioning-station-kiosk.md) | Simulation and authenticated read-only transaction view; hardware actions and enrollment remain unavailable |
| [Development target access](raspberry-pi-5-development-target-access.md) | Optional root-equivalent development access; excluded from fleet images |
| [EEPROM crypto-lock update](rpi5-eeprom-crypto-update.md) | September firmware pin, public signing/recovery inputs and pending physical update |
| [Device-secret feasibility](device-secret-feasibility.md) | Pinned firmware-crypto package, non-secret capability probe and pending physical mechanism investigation |
| [Remote device-secret development](device-secret-development.md) | RAM-resident firmware checks and authenticated SSH/reboot runner; no new image signature for helper changes |
| [Device-secret experiment automation](device-secret-automation.md) | Staged plan, passive host capture runner and software rehearsal |
| [Device-secret execution packet](device-secret-execution-packet.md) | File-only packet, bounded staging/restore executor and private report projection; selected hardware session pending |
| [Device-secret target harness](device-secret-target-harness.md) | Experimental two-boot LUKS harness, secret/lock checks and unsigned image constructor; physical execution remains pending |
| [Device identity lifecycle](device-identity.md) | Proposed identity, enrollment, and credential lifecycle; not implemented |
| [Software-only rehearsals](software-rehearsals.md) | Simulation, durable rehearsal, unfused, and regular-file checks |
| [Public root literals](public-root-key-markers.md) | Implemented key-marker scanner exceptions and their exact scope |

## Existing online-verifier candidate references

Keep these to understand existing code, retained artifacts, and scoped hardware
observations. They describe the server-authorized stable-verifier/kexec
candidate, whose offline-refusal behavior is not the selected fleet behavior.
Their 33-run/37-claim qualification remains associated with that candidate.
Select applicable tests explicitly if reusing its components; a build or an
archived plan does not close a hardware gate. Native ARM compilation does not
mean that the resulting image uses the native Pi boot path without kexec.

| Document | Boundary |
| --- | --- |
| [Stable-verifier spike](stable-verifier-spike.md) | Existing verifier, handoff modes, narrow physical diagnostics, and unclosed candidate qualification |
| [Verifier-only signing](stable-verifier-signing.md) | One boot-image signing route and authenticated public handoff |
| [Release candidate exports](release-candidate-artifacts.md) | Existing provisioner/verifier export workflow and immutable provenance |
| [Public campaign preparation](stable-campaign-preparation.md) | File-only composition of the existing campaign |
| [Recovery preparation](stable-campaign-recovery.md) | Recovery-range descriptions; does not capture backup bytes |
| [Staging sandbox](stable-campaign-sandbox.md) | Synthetic recovery, write, interruption, and readback rehearsal |
| [Campaign device staging](stable-campaign-staging.md) | Fixed candidate device-leg contracts and native staging exports |
| [Preparation packet](stable-campaign-packet.md) | Public checks for the old candidate's first two runs |
| [Self-kexec diagnostic](../scripts/diagnostics/rpi5-self-kexec/README.md) | Retained file-handoff/SMP observations and their narrow limits |

## Archived plans

The [archive](archive/README.md) retains four superseded or deferred plans:
the online production roadmap, broad production-station architecture,
fresh-board execution-plan snapshot, and first online-verifier baseline.
Their old priority statements and online-only requirements are not current
instructions. Applicable physical safety, transaction, and evidence rules
remain in the active guides.

## Status and authority

- **Implemented** means code or configuration exists.
- **Tested** means the named software test exercises a contract; it does not
  mean that real hardware enforced it.
- **Observed/evidenced** means a scoped result was retained against exact
  inputs. Its limitations still apply; some raw evidence remains outside Git.
- **Proposed** means an approach or setting still needs selection,
  implementation, or qualification.

The scope and admission policy define the selected outcome. For actual
implementation and execution, [`policies/`](../policies/),
[`profiles/`](../profiles/), [`config/hardware/`](../config/hardware/),
[`schemas/`](../schemas/), and [`flake.nix`](../flake.nix) remain authoritative
versioned inputs. Inert deployment bundles live in [`deploy/`](../deploy/).
Public evidence, releases, and signer material live in
[`tests/evidence/`](../tests/evidence/), [`releases/`](../releases/), and
[`signers/`](../signers/); none grants new signing or hardware authority.

The documentation originated in
[`nixos-kaiba-network` at `ac26f61`](https://github.com/ams-tech/nixos-kaiba-network/tree/ac26f61b4a50cc1965ea6d56d0f865ac92781a4e/docs).
That origin explains the retained proposals; it does not supersede the current
scope. An uncertain physical outcome still requires reconciliation or
quarantine, and development `security_applied` is not fleet membership.
