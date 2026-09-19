# Kaiba Provisioning

Kaiba Provisioning provides Go and Nix reference components and contracts for
a fail-closed Raspberry Pi 5 secure-boot provisioning lane. It covers hardware
qualification, approval-gated signing, deterministic release and media
construction, audited execution, and operator-facing workflows.

> [!WARNING]
> This repository targets a sacrificial development cohort and explicitly
> reviewed hardware configurations. It is not a general-purpose Raspberry Pi
> imager or a turnkey production provisioning system. Several operations can
> affect EEPROM, OTP, boot media, or signing state; use only the configured Nix
> outputs and reviewed deployment procedures.

## What is included

| Area | Purpose | Primary entry points |
| --- | --- | --- |
| Hardware qualification | Probe a Pi without persisting changes, compare repeated observations, and emit redacted evidence | `kaiba-provision probe`, `kaiba-provision qualify` |
| Control and audit | Manage transactions, claims, approvals, quarantine, and an independent hash-chained audit log | `kaiba-provision-control`, `kaiba-provision-audit`, `kaiba-provision-authority-bridge` |
| Lane execution | Compile the fixed operation sequence, collect explicit acknowledgement, and execute one bound physical action at a time | `kaiba-provision-lane-workflow`, `kaiba-provision-lane-operator`, `kaiba-provision-lane-guard` |
| Signing and releases | Gate YubiKey-backed signing behind immutable approvals and verify complete signed releases offline | `kaiba-provision-signing-gate`, `kaiba-provision-sign-boot`, `kaiba-provision-sign-eeprom`, `kaiba-provision-finalize-release` |
| Media construction | Bind a release to an exact storage layout, write it through a configured device-specific package, and verify it independently | `kaiba-provision-media-device-stager`, `kaiba-provision-media-device-verifier`, `kaiba-provision-media-contract` |
| Operator interfaces | Observe one authenticated transaction through a read-only loopback UI, or run the separate in-memory simulation | `kaiba-provision-station`, `kaiba-provision-station-demo` |

Generic hardware-facing binaries and `kaiba-provision-sign-boot` are
intentionally unconfigured and fail closed. The exported
`kaiba-provision-sign-eeprom` is different: it is pinned to the local
approval-gate socket and EEPROM release inputs, but has neither private-key nor
direct hardware authority. Flake constructors bind complete deployments to
reviewed inputs: `lib.mkRpi5PhysicalLaneGuard`,
`lib.mkDevelopmentYubiKeySigning`, and `lib.mkRpi5ProductionMedia`.

## Quick start

The supported development systems are `x86_64-linux` and `aarch64-linux`.
Build natively for the selected architecture; see the
[native-build policy](#native-build-policy) for remote builders and exceptions.
Nix supplies a Go toolchain compatible with the module's Go 1.24 requirement
and the other development tools:

```console
nix develop
scripts/check.sh go ./internal/provisioning/campaignmedia
```

Build the non-persistent probe package:

```console
nix build .#kaiba-provision
```

The resulting executable is `result/bin/kaiba-provision`; its pinned device
profile, schemas, and RPIBOOT probe bundle are under `result/share/kaiba/`.

### Run the station simulation

The demo is an in-memory simulation. It binds only to an explicit loopback
address and has no hardware, signing, or persistence authority.

```console
nix run .#kaiba-provision-station-demo -- --listen 127.0.0.1:8080
```

Open `http://127.0.0.1:8080` in a browser. The static version deployed to
GitHub Pages is built with:

```console
nix build .#kaiba-provision-station-pages
```

## Safety model

- Plans, approvals, requests, and receipts are canonical and digest-bound.
- Hardware selectors and execution-host bindings come from the versioned
  [hardware catalog](config/hardware/); callers cannot supply an arbitrary
  block device at runtime.
- The physical lane guard uses a durable execute-once journal. Ambiguous
  outcomes enter reconciliation or quarantine and never become blind retries.
- Signing keys and PINs are runtime-only. The repository contains public trust
  anchors and signed inputs, not private keys or credentials.
- The live station observes one configured transaction without submitting
  control commands or performing enrollment. Its unconfigured foundation keeps a disabled backend.
  Neither mode falls back to the browser simulation, and the simulation never
  calls a live backend.
- Raw device observations remain outside the repository. Only validated,
  whitelist-redacted qualification evidence belongs under
  [`tests/evidence/`](tests/evidence/).

The relay-backed lane is designed around normally-off power and a fixed,
reviewed USB topology. A development-only manual-power mode exists, but it does
not provide automated fail-off guarantees and is not a production-lane
qualification.

## Repository layout

| Path | Contents |
| --- | --- |
| [`cmd/`](cmd/) | CLI entry points |
| [`docs/`](docs/) | Security model, development runbooks, contract reference, and production roadmap |
| [`internal/provisioning/`](internal/provisioning/) | Control, signing, media, lane, and station implementation packages |
| [`nix/`](nix/) | Packages, constructors, NixOS modules, and pinned patches |
| [`config/hardware/`](config/hardware/) | Typed, host-bound hardware configurations |
| [`profiles/`](profiles/) and [`policies/`](policies/) | Device-class and development posture inputs |
| [`schemas/`](schemas/) | Versioned JSON contracts |
| [`deploy/`](deploy/) | Inert Ubuntu deployment bundles and preflight tooling |
| [`releases/`](releases/) | Public, signed release inputs |
| [`signers/`](signers/) | Public signer trust anchors and independent review records |
| [`tests/`](tests/) | Nix contracts, Go tests, deployment checks, fixtures, and UI tests |

## Documentation

The [current delivery scope](docs/delivery-scope.md) fixes the next milestone:
apply the agreed hardware security configuration, enroll the verified device
in a fleet, and guide the operator through a simple live UI.

Start with the [documentation index](docs/README.md). It defines the status
language used throughout the guides so that implemented code, software tests,
checked evidence, and proposed production controls are not conflated.

- [Architecture and trust boundaries](docs/architecture-and-trust-boundaries.md)
- [Fleet admission policy and verification plan](docs/fleet-admission-policy.md)
- [Raspberry Pi 5 secure-boot model](docs/raspberry-pi-5-secure-boot.md)
- [Production readiness](docs/production-readiness.md)
- [Contracts reference](docs/contracts-reference.md)

Superseded and deferred roadmaps are in the [documentation archive](docs/archive/README.md).
The existing online-verifier candidate is documented separately in the index;
its server-required boot policy is not the selected offline fleet behavior.

Operator workflows cover [hardware qualification](docs/raspberry-pi-5-provisioning-probe.md),
[release signing](docs/raspberry-pi-5-signed-boot-workflow.md),
[media staging](docs/target-media-staging-prototype.md), and the
[live development lane](docs/raspberry-pi-5-live-provisioning.md). The
[station interface](docs/provisioning-station-kiosk.md) and
[development target access](docs/raspberry-pi-5-development-target-access.md)
guides make their current non-production boundaries explicit. The signing
guides identify the configured flake outputs that still need to be restored or
supplied by a reviewed consumer before starting a new live ceremony.

### Deployment and evidence guides

- [Ubuntu development provisioning authority](deploy/ubuntu-provisioning-authority/README.md)
- [Ubuntu 24.04 signing-gate deployment](deploy/ubuntu-signing-gate/README.md)
- [Raspberry Pi 5 v0.1.6 public signed inputs](releases/rpi5-v0.1.6/README.md)
- [Development prototype signer](signers/development-prototype/README.md)
- [Hardware qualification evidence boundary](tests/evidence/README.md)

The deployment bundles are inert by design: installation does not enable or
start their services. Follow the linked preflight and operator steps before
crossing a hardware or signing boundary.

## Native-build policy

Avoid cross-compilation in Kaiba's Nix projects. Native builds are the default
for application packages, kernels, NixOS images, and signing artifacts. Use
`x86_64-linux` builders for x86 packages and `aarch64-linux` builders for ARM
packages, locally and in CI. Apply the same default to downstream projects
that consume this flake.

Nix supports cross-compilation, but cross-built derivations differ from native
ones and have more limited upstream binary-cache coverage. A small platform
override can therefore trigger builds of an entire compiler and userspace
closure. Native builds let us reuse the pinned Nixpkgs and Raspberry Pi caches
and share our own outputs through Cachix. See the
[Nix cross-compilation documentation](https://nix.dev/tutorials/cross-compilation.html).

- Keep `stdenv.buildPlatform` and `stdenv.hostPlatform` the same for normal
  package builds. Do not introduce `pkgsCross`, `crossSystem`, or an x86
  `nixpkgs.buildPlatform` for an ARM image as a convenience fallback.
- From an x86 workstation, obtain ARM outputs from a trusted binary cache or
  configure a native ARM remote builder. Selecting an `aarch64-linux` flake
  attribute does not make an x86 machine able to build missing ARM outputs.
  The x86 signing workstation can verify and package existing ARM artifacts
  without compiling ARM programs.
- Run checks that realize ARM programs or images on ARM runners. Keep x86
  configuration checks evaluation-only: interpolating a target store path
  into a test script can pull in its complete cross-built dependency graph,
  even inside a shell conditional. Exclude such references during Nix
  evaluation instead.
- Keep overlays scoped to the packages that need them so a target-specific
  change does not invalidate cached build tools on another architecture.

The existing exceptions are narrow: the Go `evidencefile` compile-only ARM
portability test, same-CPU glibc-to-musl `pkgsStatic` tools such as initramfs
BusyBox, and evaluation-only cross-platform fixtures that do not realize ARM
outputs on x86. QEMU VM execution is emulation, not cross-compilation. These
exceptions are not a precedent for cross-building full system images. Any new
exception needs an explicit rationale in the change, a dependency/cache-cost
assessment, and tests; prefer native coverage whenever it meets the need.

## CI, Cachix, and GitHub Pages

The [main CI workflow](.github/workflows/ci.yml) starts formatting and
deployment checks alongside native Nix checks for both supported
architectures. The x86 job runs the independent Go unit check first, and its
later Nix checks reuse that result. Static-mode contract tests share a separate
check and compiler cache. The formatting job does not repeat either suite.

The two older online-verifier Pi boot-image checks run in separate native ARM
jobs. On PRs, CI compares each check's complete Nix derivation against the PR
base and builds only changed variants. This includes transitive source, kernel,
configuration and toolchain changes; it does not rely on a file-path allowlist.
Every other ARM check still runs, as do the lightweight x86 verifier checks.
The required aggregate accepts a skipped image job only after a successful
comparison reports unchanged inputs. Missing or failed comparison blocks it.
`main` pushes and manual runs build both variants, and `scripts/check.sh full`
continues to run the complete native suite.

Pull requests consume binary caches but do not push to
them. Successful `main` pushes upload to the
[`kaiba-provisioning` cache](https://app.cachix.org/cache/kaiba-provisioning)
when `CACHIX_AUTH_TOKEN` grants write access; an explicit write-and-read-back
probe makes a broken cache token or cache name fail the workflow. Raspberry Pi
dependencies are pulled from `nixos-raspberrypi`. The dedicated verifier jobs
also upload their built kernels on trusted `main` pushes. A running `main`
workflow is allowed to finish its cache upload when a newer push arrives;
obsolete PR runs are still cancelled.

The same workflow publishes the static station simulation from `main`, reusing
the site already realized by the x86_64 Nix checks. Deployment waits for every
CI job to pass. Enable Pages once under **Settings > Pages** by selecting
**GitHub Actions** as the build and deployment source.

## Development checks

Run focused tests while editing, then the software checks before pushing:

```console
nix develop
scripts/check.sh go ./internal/provisioning/campaignmedia
scripts/check.sh fast
```

Run the complete Nix contract suite before merging changes that affect
packages, schemas, release inputs, or deployment boundaries:

```console
scripts/check.sh full
```

The [development workflow](docs/development-workflow.md) describes focused,
static-mode, contract, full-CI, and release-candidate validation.
