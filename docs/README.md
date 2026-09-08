# Kaiba provisioning documentation

This directory describes the Raspberry Pi 5 secure-boot provisioning
components, contracts, evidence, and goals in this repository. The implemented
boundary is intentionally limited to a sacrificial development cohort and
reviewed hardware configurations. Nothing in these documents upgrades that
scope to a production approval.

## Status language

Documents use these terms narrowly:

- **Implemented** means code or declarative configuration exists in this
  repository.
- **Tested** means an automated Go, Nix, shell, or browser test exercises the
  stated contract. It does not mean the test was run on live production
  hardware.
- **Evidenced** means a review or observation artifact is checked in and bound
  to identifiable inputs. Its own disclaimers and scope still apply.
- **Planned** means a desired control, qualification, or workflow is described
  but is not established by the current implementation.

These labels describe repository claims, not the result of a fresh test run.
The canonical development posture remains
[`production_ready: false`](../policies/raspberry-pi-5-development-posture-v1alpha1.json).

## Start here

| Document | Purpose | Current basis |
| --- | --- | --- |
| [Architecture and trust boundaries](architecture-and-trust-boundaries.md) | Components, authority boundaries, fixed campaign, and failure behavior | Components/contracts implemented; configured composition and physical gates open |
| [Raspberry Pi 5 secure-boot model](raspberry-pi-5-secure-boot.md) | Native boot chain, ownership boundary, supported claims, and explicit non-claims | Design and software contracts implemented; physical enforcement not evidenced |
| [Secure-boot execution plan](raspberry-pi-5-secure-boot-execution-plan.md) | Ordered SB-00 through SB-10 gates and their current closure status | Development plan; irreversible gates remain blocked |
| [Production readiness](production-readiness.md) | What the repository establishes and what still blocks production | Implemented policy plus scoped evidence and planned work |
| [Contracts reference](contracts-reference.md) | JSON schemas, Go wire contracts, Nix constructors, modules, and exported packages | Implemented |
| [Production security follow-on](raspberry-pi-5-production-security-follow-on.md) | Security goals and the follow-on work needed to close them | Planned and tracked against current controls |
| [Device identity lifecycle](device-identity.md) | Proposed bootstrap, enrollment, rotation, revocation, recovery, and retirement model | Planned; not implemented by this repository |
| [Production-station architecture](provisioning-station-production.md) | Proposed host, authority, network, credential, and lifecycle boundaries | Planned; not implemented by this repository |

## Workflow guides

| Document | Boundary covered |
| --- | --- |
| [Hardware qualification](raspberry-pi-5-provisioning-probe.md) | Non-persistent RPIBOOT observations and the private-to-public evidence boundary |
| [Signed-boot workflow](raspberry-pi-5-signed-boot-workflow.md) | Unsigned artifacts, release intent, signing plans, verified results, and release publication |
| [Development signing ceremony](ubuntu-rpi5-development-signing-ceremony.md) | Human review, approval, dedicated Ubuntu signing gate, receipts, and closure |
| [Target-media staging](target-media-staging-prototype.md) | Deterministic media plans, host-bound device selection, staging, and independent verification |
| [Live provisioning](raspberry-pi-5-live-provisioning.md) | Authority, the seven-operation lane, execute-once evidence, and reconciliation |
| [Station kiosk](provisioning-station-kiosk.md) | Separation between the live station and the browser-only simulation |
| [Development target access](raspberry-pi-5-development-target-access.md) | Optional root-equivalent USB-gadget SSH and UART-bound recovery access |
| [Software-only rehearsals](software-rehearsals.md) | In-memory, durable, browser, unfused, and regular-file assurance levels |

## Source and adaptation

This set was reconstructed from the provisioning documentation in
[`nixos-kaiba-network` at `ac26f61`](https://github.com/ams-tech/nixos-kaiba-network/tree/ac26f61b4a50cc1965ea6d56d0f865ac92781a4e/docs),
with the
[production security follow-on](https://github.com/ams-tech/nixos-kaiba-network/blob/ac26f61b4a50cc1965ea6d56d0f865ac92781a4e/docs/raspberry-pi-5-production-security-follow-on.md)
as the primary goal statement. The material was re-audited against the
standalone layout and current root flake instead of copied verbatim.

DNS architecture, old monorepo report composition, and historical v0.1.13–15
station-image release instructions are intentionally not part of the supported
standalone documentation. Their outputs are not exported here. The source's
platform-neutral identity goals were retained as proposed future work, while
paths such as `provisioning/`, `nix/provisioning/`, and
`tests/provisioning/` were rebased to this repository's root layout.

The source's non-fusing, unfused-compatibility, and RPIBOOT-bundle material is
consolidated into the secure-boot, signed-boot, target-media, and software
rehearsal guides. Its station, station-image, and target-access material is
recast as separate interface-demo, proposed production-station, and explicit
development-access boundaries because this flake exports no ready-made station
or target image.

## Current sources of truth

Use prose as a guide and the following versioned inputs as the authority for an
actual build or review:

- [`policies/`](../policies/) defines the approved development posture and its
  explicit production blockers.
- [`profiles/`](../profiles/) defines the observable Raspberry Pi 5 device
  class and deferred checks.
- [`config/hardware/`](../config/hardware/) contains the only supported
  execution-host and media-device selectors.
- [`schemas/`](../schemas/) contains the public JSON contracts.
- [`flake.nix`](../flake.nix) is the source of truth for exported constructors,
  packages, checks, and NixOS modules.
- [`deploy/`](../deploy/) contains inert Ubuntu deployment bundles. Installation
  does not itself authorize or start a signing or provisioning service.
- [`tests/evidence/`](../tests/evidence/) is the checked-in boundary for
  whitelist-redacted hardware qualification evidence; raw probes stay outside
  the repository.
- [`releases/`](../releases/) and [`signers/`](../signers/) contain public
  release inputs and public signer-review material, never private keys or PINs.

## Safety baseline

The current workflow is fail-closed around immutable digests, exact roles,
fixed hardware selectors, explicit operator acknowledgements, and durable
attempt records. An uncertain physical result is a reconciliation or quarantine
case, not permission to retry a mutation. The terminal `security_applied` state
also records that rollback remains unimplemented; it is not an
`enrollment_ready` assertion.
