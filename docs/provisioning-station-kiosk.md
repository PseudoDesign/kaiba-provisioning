# Provisioning-station interface demo

`kaiba-provision-station-demo` is a deterministic, loopback-only interface for
reviewing the Raspberry Pi 5 operator workflow. The same interface assets can
also be built as a static browser simulation. Both forms are demonstrations;
neither is a provisioning authority.

The modeled workflow covers station admission, fresh-candidate qualification,
independent approval, one simulated irreversible ownership transition, owned
readback and recovery, negative boot tests, root-integrity and rollback gates,
final controls, evidence export, and the modeled `enrollment_ready` handoff.

The demo does not:

- invoke `kaiba-provision` or enumerate USB devices;
- upload RPIBOOT firmware or operate a physical lane;
- contact control, audit, inventory, enrollment, or signing services;
- handle private keys, PINs, credentials, or target secrets;
- stage media, update EEPROM, program OTP, or boot a target; or
- authenticate, attest, activate, or authorize a device.

The live probe, signing gate, media writer, authority bridge, and lane guard
remain separate processes and capabilities. A synthetic happy path is not
hardware evidence and grants no authority to perform the actions it depicts.

## Modeled safety behavior

Before the simulated point of no return, a reusable target may stop cleanly.
After it, an uncertain result, changed target, mismatched readback, missing
evidence, failed recovery, or failed acceptance test ends in
`owned_quarantined`. The demo never presents that target as fresh again.

Reaching the modeled `enrollment_ready` state does not generate a device key,
issue a certificate, activate a credential, or authorize production access.
The current development implementation has a stricter real boundary: it stops
at `security_applied` because independently monotonic anti-rollback is not yet
implemented. See the [secure-boot design](raspberry-pi-5-secure-boot.md) and
[architecture and trust boundaries](architecture-and-trust-boundaries.md).

## Run locally

From the standalone repository:

```console
nix --accept-flake-config run .#kaiba-provision-station-demo -- \
  --listen 127.0.0.1:8080 \
  --scenario happy-path
```

Open `http://127.0.0.1:8080/`. The server has no authentication layer and
accepts only an explicit IPv4 or IPv6 loopback listener. It must not be exposed
through a reverse proxy, port forward, container publish option, or non-loopback
network namespace.

The deterministic scenarios are:

- `happy-path`
- `class-mismatch`
- `baseline-failure`
- `multiple-targets`
- `acquisition-error`
- `target-replaced`
- `mutation-safety-violation`
- `boot-failure`
- `preparation-failure`
- `approval-failure`
- `trust-failure`
- `commit-uncertain`
- `commit-readback-mismatch`
- `signed-boot-failure`
- `owned-readback-mismatch`
- `recovery-failure`
- `negative-boot-failure`
- `root-integrity-failure`
- `rollback-failure`
- `finalization-failure`
- `final-retest-failure`
- `audit-failure`
- `deferred-baseline-failure`
- `precommit-target-replaced`
- `post-recovery-readback-mismatch`

Each scenario exercises display states only. Reloading the interface starts a
new synthetic run; it does not reset or reconcile a real target.

## NixOS service

Pin the standalone repository directly. There is no nested provisioning flake:

```nix
{
  inputs.kaiba-provisioning = {
    url = "github:PseudoDesign/kaiba-provisioning/<PINNED_REVISION>";
    inputs.nixpkgs.follows = "nixpkgs";
  };
}
```

When the surrounding `nixosSystem` passes `specialArgs = { inherit inputs; };`,
the service can be configured as:

```nix
{ inputs, pkgs, ... }:

{
  imports = [
    inputs.kaiba-provisioning.nixosModules.provisioning-station-demo
  ];

  services.kaiba-provisioning-station-demo = {
    enable = true;
    package =
      inputs.kaiba-provisioning.packages.${pkgs.stdenv.hostPlatform.system}.kaiba-provision-station-demo;
    listenAddress = "127.0.0.1";
    port = 8080;
    scenario = "happy-path";
  };
}
```

Keep the package assignment explicit so binary provenance is visible in the
host configuration. The module rejects non-loopback addresses. It runs under a
dynamically allocated unprivileged identity with a read-only system image,
private device namespace, closed device policy, empty capability set, and
network access restricted to localhost. It creates no operator group, installs
no udev rule, and grants no target-device access.

Build the two forms directly:

```console
nix --accept-flake-config build .#kaiba-provision-station-demo -L
nix --accept-flake-config build .#kaiba-provision-station-pages -L
```

## Static browser simulation

`kaiba-provision-station-pages` contains the same canonical `index.html`,
`styles.css`, `transport.js`, and `app.js` used by the loopback service, plus a
generated `workflow-graph.json` and an explicit runtime configuration.

Runtime selection is fail-closed:

- the loopback service selects HTTP mode and calls its local state/action
  endpoints; and
- the static package selects transition-graph mode and keeps the current node
  and monotonically increasing revision in browser memory.

There is no hostname detection, query-string switch, endpoint probing, or
fallback from the HTTP service to browser simulation. Missing or malformed
configuration remains an error instead of silently changing authority models.

The graph is generated by exploring the authoritative Go mock state machine,
not by maintaining a second JavaScript workflow. Tests traverse every edge,
compare browser and Go states, byte-compare the shared assets, and reject a
site that weakens the simulation boundary.

The repository's Pages workflow publishes the static package at the root of
the configured GitHub Pages site after a successful `main` build. If Pages is
enabled for the repository, the conventional project URL is
`https://pseudodesign.github.io/kaiba-provisioning/`. Treat that location as a
public, unauthenticated, per-tab simulation. It has no Go server, durable state,
WebUSB, device access, secret material, or provisioning capability.

## Local display session

The module does not configure a graphical session, display manager, browser,
automatic login, or touchscreen calibration. Those remain station-host policy.
After separately restricting the operator session and browser, a local display
may launch Chromium explicitly:

```console
chromium \
  --kiosk \
  --app=http://127.0.0.1:8080/ \
  --no-first-run \
  --disable-session-crashed-bubble
```

Chromium's kiosk switch removes ordinary browser chrome; it is not a security
boundary. A real station must separately restrict the account, browser policy,
navigation, downloads, extensions, developer tools, keyboard escape paths,
shell access, and remote debugging. Displaying this interface is never a reason
to grant the operator raw USB, GPIO, UART, signing, bridge-socket, or lane-guard
access.

## Path to a live interface

The exported `kaiba-provision-station` is a live-interface foundation, not a
configured live station. It binds only to an explicit loopback address, uses a
`DisabledBackend`, and rejects `--enable-mutations`. It therefore cannot read
the control plane, submit authority transitions, or invoke hardware in its
current form. The static demo is a separate in-memory program.

Do not evolve the HTTP demo into a process with direct hardware privileges. A
live UI should submit narrowly typed actions to a separate orchestrator and
privileged lane guard. Those components, not browser content, must own:

- target and lane binding;
- transaction continuity, claims, and fence epochs;
- plan and approval validation;
- intent journaling and audit export;
- fixed artifact and hardware selectors;
- one-shot execution and postcondition observation; and
- reconciliation, quarantine, and terminal disposition.

The UI should receive only structured, secret-free state and must never accept
arbitrary commands, executable paths, payload paths, profiles, device nodes, or
key selectors. The static graph must remain a public demonstration and must
never become fallback behavior for a live station.

The host, service, and network boundaries required before that integration can
be production-capable are defined in the proposed
[production-station architecture](provisioning-station-production.md).
