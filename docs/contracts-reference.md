# Contracts reference

This repository uses three contract layers:

1. JSON schemas define public artifacts exchanged between build, review,
   signing, media, and evidence workflows.
2. Go types and strict decoders define control, audit, bridge, lane, and
   operator wire protocols.
3. Nix constructors bind implementations to immutable inputs and expose
   authority and capability boundaries.

Always select interfaces from the current [`flake.nix`](../flake.nix). A name
found in a historical workflow or helper is not necessarily a currently
exported package.

## JSON schema groups

There are 57 versioned files under [`schemas/`](../schemas/). Several groups
retain older alpha revisions so checked inputs can be verified; revision
coexistence does not imply automatic migration.

| Group | Schemas | Principal producers and consumers |
| --- | --- | --- |
| Device and qualification | `device-profile-*`, `rpi5-development-posture-*`, `rpi5-hardware-qualification-*`, `rpi5-manual-lane-qualification-*` | `kaiba-provision`, profile/posture Nix checks, qualification evidence packaging |
| Unsigned release inputs | `unsigned-artifact-set-*`, `rpi5-release-intent-*`, `rpi5-platform-adapter-*`, `rpi5-eeprom-release-*` | Secure-boot artifact, release-intent, and EEPROM constructors; signing-plan builders |
| Signing plans and results | `rpi5-boot-signing-plan-*`, `rpi5-boot-signing-result-*`, `rpi5-eeprom-signing-plan-*`, `rpi5-eeprom-signing-result-*`, `rpi5-owned-recovery-signing-plan-*`, `rpi5-owned-recovery-signing-result-*` | Boot/EEPROM/recovery signing adapters and offline finalizers |
| Signing authorization | `signing-request-*`, `rpi5-signing-approval-*`, `signing-grant-registry-*`, `yubikey-signing-policy-*`, `signer-independent-review-*` | Approval authoring, gate registry loading, signer review, and the fixed development signing constructor |
| Signing receipts | `signing-gate-receipt-export-*`, `signing-gate-receipt-verification-*` | `kaiba-provision-signing-receipts`, signed-release finalization, independent receipt verification |
| RPIBOOT and boot bundles | `secure-boot-bundle-*`, `rpi5-rpiboot-bundle-set-*`, `rpi5-rpiboot-directory-tree-*` | RPIBOOT bundle constructor/verifier and the physical lane package |
| Signed release | `rpi5-signed-release-manifest-*`, `rpi5-signed-release-publication-*` | `mkRpi5VerifiedSignedRelease`, `kaiba-provision-finalize-release`, media and lane constructors |
| Stable-verifier spike | `rpi5-stable-verifier-policy-*`, `rpi5-delegated-release-manifest-*`, `rpi5-boot-authorization-*`, `rpi5-stable-verifier-event-*`, `rpi5-stable-verifier-spike-evidence-*` | Stable release verification, audience-bound non-production authorization, UART events, and software/hardware evidence packaging |
| Media plan and layout | `rpi5-device-media-layout-*`, `rpi5-media-binding-*`, `rpi5-media-staging-plan-*` | `mkRpi5ProductionMedia`, fixture staging, device-specific writer and verifier |
| Media execution evidence | `rpi5-media-device-preflight-*`, `rpi5-media-stage-receipt-*`, `rpi5-media-staging-receipt-*`, `rpi5-media-verification-receipt-*`, `rpi5-media-verification-report-*`, `rpi5-media-fixture-result-*`, `rpi5-media-cold-power-observation-*`, `rpi5-unfused-runtime-facts-*` | Media stagers/verifiers, contract finalizer, cold-power and unfused-runtime correlation |

The schema version is part of each canonical object. Consumers also enforce
semantic conditions that JSON Schema alone cannot express, including exact
role sets, canonical ordering, digest recomputation, file modes and trees,
expiry, release lineage, and correlation among receipts.

## Go-only service and lane contracts

Not every runtime protocol has a file under `schemas/`. The authoritative types
and version constants for these interfaces live with their strict decoders:

| Contract family | Source package | Key behavior |
| --- | --- | --- |
| Transactions, claims, approvals, intent, evidence, reconciliation, quarantine | `internal/provisioning/controlplane` | Resource versions, idempotency, fence epochs, exact active claims, and terminal-state validation |
| Audit events and receipts | `internal/provisioning/auditlog` | Secret-free structured events, service-assigned sequence/time, and previous-event hash chaining |
| Authority bridge | `internal/provisioning/authoritybridge` | Correlates stable control and audit reads before returning a typed local request |
| Lane plan, request, attempt, and boot transition | `internal/provisioning/laneguard` | Fixed operation vocabulary, plan digest, execute-once persistence, safe-off, and reconciliation |
| Operator prompt | `internal/provisioning/operatorprompt` | Unix peer authentication and exact server-selected acknowledgement phrases |
| Workflow proposals | `internal/provisioning/operatorworkflow` and `plancompiler` | Authority-free draft reconstruction and typed approval/intent/evidence transitions |
| Release binding | `internal/provisioning/releasebinding` | Exact equality over signed release, lane package, compiled artifacts, customer key, EEPROM, and boot image digests |
| Stable release verification and handoff | `internal/provisioning/stableverifier` and `stablehandoff` | Inline root/delegated signatures, exact release roles, retained descriptors, fixed credential archive, and kexec boundary |
| Non-production authorization and evidence | `internal/provisioning/releaseauthorization`, `verifierevents`, and `stableevidence` | TLS 1.3 with explicit roots, one-use challenge binding, structured UART events, and allowlisted spike evidence |
| Stable-verifier campaign media evidence | `internal/provisioning/campaignmedia` | v1alpha1 preserves its fail-closed physical-end-GPT rejection; explicitly selected v1alpha2 strictly parses and hashes the reviewed legacy-root-layout physical-end lineage with distinct disk/boot GUIDs and shared root-data/root-hash GUIDs while remaining read-only and ineligible for staging |
| Stable-campaign provisioner artifacts | `nix/rpi5-stable-campaign-provisioner-artifacts.nix`, `nix/rpi5-stable-campaign-provisioner-signed-boot-filesystem.nix`, and `schemas/rpi5-stable-campaign-provisioner-*` | Development-only inner signing input, dm-verity artifacts, and separately materialized signed 128 MiB FAT boot-partition image fixed to Pi SD partitions 1-3; the attached NVMe is read-only input and ordinary release/capsule consumers must reject these schemas |

Persisted runtime formats are versioned independently. In particular, a
nonempty lane journal is not a migration input: incompatible state must be
removed from service and resolved through reconciliation or quarantine, not
silently rewritten.

## Exported Nix library

The root flake exports these constructor families on supported Linux systems.
System-parametric constructors take `system`; the stable-campaign post-sign
constructor fixes its x86 build and AArch64 target platforms. Other arguments
are specific immutable inputs rather than general runtime selectors.

| Family | Exported attributes |
| --- | --- |
| Catalog and public assets | `assets`, `hardwareConfigurations` |
| Artifact and release construction | `mkRpi5SecureBootArtifacts`, `mkRpi5EEPROMRelease`, `mkRpi5EEPROMReleaseSigningInputs`, `mkRpi5ReleaseIntent`, `mkRpi5BootSigningPlan`, `mkRpi5EEPROMSigningPlan`, `mkRpi5OwnedRecoverySigningPlan` |
| Signing and receipt verification | `mkDevelopmentYubiKeySigning`, `mkRpi5VerifiedSignedBoot`, `mkRpi5VerifiedSignedEEPROM`, `mkRpi5VerifiedOwnedRecovery`, `mkRpi5VerifiedSigningReceipts` |
| Bundle and release verification | `mkRpi5VerifiedRPIBootBundles`, `mkRpi5VerifiedSignedRelease`, `mkRpi5VerifiedUnfusedCapsule`, `mkRpi5UnfusedVerifier` |
| Media | `mkRpi5MediaStagingFixture`, `mkRpi5ProductionMedia` |
| Stable-verifier spike | `mkRpi5StableVerifierUnsignedBoot`, `mkRpi5StableVerifierTestSD`, `mkRpi5DelegatedReleaseSpike`, `mkRpi5StableVerifierSpikeRig` |
| Stable-campaign provisioner | `mkRpi5StableCampaignProvisionerSignedBootFilesystem` (post-sign verification/materialization only; the revision-bearing unsigned package is a clean-Git flake package, not a public constructor) |
| Physical development lane | `mkRpi5PhysicalLaneGuard`, `mkRpi5DevelopmentSecureBootRunner`, `mkRpi5DevelopmentSecureBootOperationalPayload` |
| Deployment and ceremony | `mkDevelopmentSigningCeremony`, `mkUbuntuProvisioningAuthorityDeployment`, `mkUbuntuSigningGateDeployment` |

The constructors are the supported way to obtain configured hardware-facing or
signing programs. For example, the block-device media stager and independent
device verifier are outputs of `mkRpi5ProductionMedia`; they are not generic
root packages accepting an arbitrary device.

`mkRpi5SecureBootArtifacts` is fixed to the ordinary GPT-PARTUUID profile. Its
public API cannot select the dedicated stable-campaign SD binding; that binding
is reachable only through the clean-revision provisioner package. The
post-sign provisioner constructor also dumps and checks the dm-verity
superblock's format, algorithm, block sizes, data-block count, UUID, and salt
before accepting the signed SD artifacts.

## Exported NixOS modules

The root `nixosModules` set exports:

- `default`
- `provisioning-audit`
- `provisioning-authority-bridge`
- `provisioning-control`
- `provisioning-lane-guard`
- `provisioning-probe`
- `provisioning-signing-gate`
- `provisioning-station-demo`
- `secure-boot-target`
- `stable-verifier-spike`

Modules default to non-authoritative or disabled behavior. The lane guard, for
example, requires an explicit immutable package and defaults
`enableMutations = false`.

## Direct flake packages

The following package groups are exported for both `x86_64-linux` and
`aarch64-linux` unless noted otherwise.

| Group | Package attributes |
| --- | --- |
| Probe and services | `default`, `kaiba-provision`, `kaiba-provision-audit`, `kaiba-provision-authority-bridge`, `kaiba-provision-control`, `kaiba-provision-lane-guard`, `kaiba-provision-lane-operator`, `kaiba-provision-lane-workflow`, `kaiba-provision-station` |
| Rehearsal and UI | `kaiba-provision-rehearsal`, `kaiba-provision-integrated-rehearsal`, `kaiba-provision-station-demo`, `kaiba-provision-station-pages` |
| Public signing and release tools | `kaiba-provision-signing-approval`, `kaiba-provision-signing-receipts`, `kaiba-provision-sign-boot`, `kaiba-provision-sign-eeprom`, `kaiba-provision-rpiboot-bundles`, `kaiba-provision-finalize-release` |
| Media and unfused tools | `kaiba-provision-media-contract`, `kaiba-provision-unfused-compat`, `kaiba-provision-unfused-evidence`, `kaiba-provision-unfused-runtime-record` |
| Stable-verifier spike | `kaiba-rpi5-stable-verifier`, `kaiba-rpi5-verifier-test-authority`, `kaiba-rpi5-one-boot-prove` (development-only, static executables) |
| Stable-campaign provisioner | `kaiba-rpi5-stable-campaign-provisioner-unsigned`, `kaiba-rpi5-stable-campaign-provisioner-signing-plan`, and `kaiba-rpi5-stable-campaign-development-signing` (`x86_64-linux` only; exported only from a clean, revisioned Git flake; signing runtime uses the non-production prototype key) |
| Fail-closed foundations | `kaiba-provision-signer-foundation`, `kaiba-provision-signing-client-foundation`, `kaiba-provision-signing-gate-foundation`, `kaiba-provision-yubikey-wrapper-foundation` |
| Suites and immutable inputs | `provisioning-suite`, `provisioning-services`, `provisioning-test-result`, `rpi5-physical-lane-guard-fixture`, `rpi5-probe-bundle`, `rpi5-eeprom-release` |
| Deployment bundles | `ubuntu-provisioning-authority-deployment`, `ubuntu-signing-gate-deployment` |
| Ceremony helper | `kaiba-provision-signing-ceremony` (`x86_64-linux` only; placeholder-provenance package for checks) |

The foundation packages deliberately lack a complete live authority binding.
Likewise, prepared attributes such as the historical `development-signing` and
`rpi5-prototype-*` are not currently exported by the root flake. The dedicated
stable-campaign development-signing output above does not close that
five-artifact integration boundary. Do not copy
historical `nix build` commands for those names without first restoring and
reviewing the corresponding outputs. The workflow-specific guides call out
that integration boundary where it matters.

The direct ceremony-helper package is instantiated with an all-zero source
revision and `sourceTreeClean = false`, so its `prepare-public` path fails
closed. An operational helper must instead be created with
`mkDevelopmentSigningCeremony` from the reviewed clean source revision.

## Checks

`nix --accept-flake-config flake check -L` evaluates the schema/profile,
artifact, EEPROM, signing, receipt, RPIBOOT, signed-release, media,
stable-verifier spike, module, deployment, station UI, and Go-suite contracts
declared in `flake.nix`.
Most are deliberately software-only. Their descriptions in
`tests/report-input.json` state the authority and hardware claims they do not
make; those negative claims are part of the contract, not boilerplate.
