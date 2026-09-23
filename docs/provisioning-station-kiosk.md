# Provisioning-station interfaces

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
at `security_applied`, with an existing guard recording unimplemented
anti-rollback. That runtime guard and the demo's rollback scenario predate the
selected [fleet admission policy](fleet-admission-policy.md), which does not
require offline rollback prevention. Updating the real enrollment path and
its UI requires explicit integration; a demo transition is not an admission
decision. See [architecture and trust boundaries](architecture-and-trust-boundaries.md).

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

## Read-only live station

The exported `kaiba-provision-station` can observe one existing transaction
through the authenticated control service. Its browser listener remains
loopback-only. In observer mode it reads recorded state; it cannot submit authority
transitions, acquire or renew claims, invoke hardware, or enroll a device.
`--enable-mutations` remains rejected. The static demo is a separate program
and is never a fallback for live observation.

Configure all five observer inputs together: transaction ID, control HTTPS
origin, station client certificate, client private key, and exclusive control
server CA. Partial configuration is an error. Without observer inputs, the
original foundation with `DisabledBackend` remains available.

The following example uses placeholder service and transaction identities;
replace them with the station's configured values and runtime credential
paths. The certificate's canonical station/lane URI must match the two flags.
The authority still independently authenticates and authorizes each read.

```console
nix --accept-flake-config run .#kaiba-provision-station -- \
  --listen 127.0.0.1:8081 \
  --station-id station-1 \
  --lane-id lane-1 \
  --transaction-id transaction-reviewed-1 \
  --control-url https://control.example:8443 \
  --tls-cert /run/credentials/station.crt \
  --tls-key /run/credentials/station.key \
  --control-server-ca /run/credentials/control-ca.crt \
  --rpiboot-sysfs /sys/bus/usb/devices/1-1 \
  --uart /dev/serial/by-id/kaiba-target-uart
```

Open `http://127.0.0.1:8081/` from that host. Keep credentials outside Git and
the Nix store. The browser receives neither credential paths nor private keys.
The authority permits transaction reads to the active station/lane claimant
or, after release, the latest historical claimant. An unclaimed or inaccessible
transaction remains denied; the viewer does not obtain a claim to bypass that
rule. This slice adds no transaction picker or listing API.

Preserve the same startup configuration across service restarts. The configured
transaction ID restores the selection; a fresh authority read restores its
progress. No workflow is replayed and no transaction snapshot is saved to disk.
Before the first successful read, the view contains no transaction details.

The browser refreshes five seconds after the previous request finishes and
also offers manual refresh. Authority update time and the last successful
read time are separate. During an authority outage, the last successful
snapshot remains in memory with a stale warning. A browser-to-station failure
also marks the displayed view stale. Denied access, a missing transaction, or
an invalid response clears the details. Reconnection requires a new successful
read; restarting during an outage cannot restore the previous snapshot.

### What the view establishes

The seven operation rows reflect coordinator records, including missing,
pending-intent, failed, uncertain and reconciled outcomes. They do not infer
completion from a later UI phase. An intent without an outcome is not a reason
to retry; reconciliation and quarantine remain external reviewed procedures.

Recorded customer-key prestate is the observation at target binding, not the
current owned key. Expected key and image digests are intended bindings.
Receipt IDs and result digests are recorded references, not independent audit
verification. Current secure-boot, JTAG and EEPROM-protection state remain
unknown where the transaction supplies no direct observation. Development
`security_applied` does not establish fleet admission; offline rollback
prevention is not added as a fleet requirement by this view.

Local observations only inspect the configured USB sysfs presence/identifiers
and UART-node presence. They do not open the UART, run a probe, load RPIBOOT
code, change power or qualify a board. USB visibility cannot authenticate the
bound device. No RPIBOOT device during normal boot is not a qualification
failure, and the already-owned Pi never enters fresh-board qualification.

### Repeatable real-service check

Run on either supported native architecture:

```console
nix develop --command scripts/check.sh contracts station-observation-integration
```

The check starts the packaged control and station binaries on loopback using
temporary development mTLS credentials and a disposable durable control store.
Fixture setup creates, claims and binds a clearly labeled test transaction
through normal authenticated commands. Viewer interactions then demonstrate
transaction retrieval, station restart, authority outage/restart, stale-state
recovery, and rejection of workflow actions. The check compares authority-store
bytes and filesystem metadata to detect any viewer mutation. It cleans up its
processes and temporary credentials and never contacts a deployed authority.
These are real-service software results, not physical provisioning evidence.

## Guided development campaign

The same live station now supports a separate
[guided campaign mode](guided-station-campaign.md). Its touchscreen view shows
the current step, last recorded result, required input and allowed action;
diagnostics are exported separately. A mutually authenticated controller owns
the durable journal and invokes only fixed, reviewed packet wrappers.

This mode preserves the observer and foundation contracts. The packaged native
software demonstration uses disposable enrollment-client state. Real Pi
wrappers and isolated development fleet eligibility remain to be integrated;
finishing a development campaign does not establish any fleet-admission gate.

## Remaining live workflow integration

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

The current [architecture](architecture-and-trust-boundaries.md) and
[fleet admission mapping](fleet-admission-policy.md#how-to-establish-the-conditions)
define the integration work for this milestone. The broader
[production-station proposal](archive/provisioning-station-production.md) is
deferred reference material, not a requirement to build another station platform.
