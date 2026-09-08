# Software-only rehearsals

The repository provides safe ways to inspect the fixed seven-operation state
machine and its durable control/audit integration without a Raspberry Pi,
YubiKey, GPIO line, RPIBOOT device, serial port, or block device.

These rehearsals are development tools. They cannot close a physical
qualification gate, authorize a release, or produce evidence that secure boot
or dm-verity was enforced by hardware.

## Lightweight state-machine rehearsal

`kaiba-provision-rehearsal` runs the exact operation vocabulary through an
in-memory simulator and emits a JSON report:

```console
nix run .#kaiba-provision-rehearsal
```

Inject a synthetic failed or uncertain result at any operation from 1 through
7:

```console
nix run .#kaiba-provision-rehearsal -- \
  --inject-at 1 \
  --inject-outcome failed

nix run .#kaiba-provision-rehearsal -- \
  --inject-at 4 \
  --inject-outcome uncertain
```

Exit status is `0` for a passed rehearsal, `3` for the requested failed
outcome, and `4` for the requested uncertain outcome. Those nonzero statuses
are expected when testing failure behavior.

The report is synthetic. Its digests and identifiers are suitable for testing
canonical serialization, not for a live transaction.

## Integrated durable rehearsal

`kaiba-provision-integrated-rehearsal` exercises the real file-backed control
and audit stores, transaction orchestration, plan binding, and software
executor. It is packaged separately from the live lane guard so its runtime
closure does not gain the physical adapter, `rpiboot`, or GPIO tooling.

Provide a fresh absolute state directory:

```console
rehearsal_state="$(mktemp -d)"
nix run .#kaiba-provision-integrated-rehearsal -- \
  --state-dir "$rehearsal_state"
```

Failure injection uses the same sequence and outcome arguments:

```console
rehearsal_state="$(mktemp -d)"
nix run .#kaiba-provision-integrated-rehearsal -- \
  --state-dir "$rehearsal_state" \
  --inject-at 7 \
  --inject-outcome uncertain
```

Preserve the state directory when diagnosing restart and evidence behavior.
Do not relabel its files as live authority or hardware evidence.

## Browser simulation

The loopback demo renders the generated finite transition graph and serves an
in-memory API:

```console
nix run .#kaiba-provision-station-demo -- --listen 127.0.0.1:8080
```

The static Pages build is also authority-free:

```console
nix build .#kaiba-provision-station-pages
```

The UI may demonstrate states beyond the current live development ceiling so
operators can review the intended lifecycle. A simulated `enrollment_ready`
screen does not mean the live control service permits that transition. See the
[station guide](provisioning-station-kiosk.md).

## Unfused and media fixtures

The lower-level unfused and media contracts provide two more assurance layers:

- `mkRpi5VerifiedUnfusedCapsule` binds a signed boot image to its exact
  root-data and root-hash images and a signer-anchored verifier.
- `mkRpi5MediaStagingFixture` wraps verified inputs in a deterministic
  regular-file GPT/FAT/root/verity image and checks its complete byte layout.

`kaiba-provision-unfused-compat` verifies an offline fixture. The generic
direct package has no configured trusted signer; a signed verification path
must come from `mkRpi5UnfusedVerifier` with its expected signer fingerprint
fixed at build time.

`kaiba-provision-unfused-runtime-record` only validates a supplied facts object
against a media plan and serializes two bounded UART records. It does not
collect the facts, authenticate UART capture, or prove a real boot.

The media fixture is a regular file. It is not an inner `boot.img`, a flashable
production image, a block-device write, or cold-readback evidence. See
[target-media staging](target-media-staging-prototype.md).

## What each layer establishes

| Layer | Establishes | Does not establish |
| --- | --- | --- |
| State-machine rehearsal | Operation order and synthetic outcome behavior | Durable authority, signatures, or hardware |
| Integrated rehearsal | Real control/audit persistence with a software executor | Physical adapter or target behavior |
| Browser simulation | Operator workflow and UI state transitions | Live backend authority |
| Unfused capsule verification | Public signature, boot/root lineage, and fixture correlation | Native secure-boot enforcement |
| Regular-file media fixture | Deterministic complete-media bytes and verifier behavior | Correct device selection, power cycle, or Pi boot |

Use these layers to find defects before approaching a physical boundary, but
do not add their assurance levels together and call the result a hardware test.
The physical requirements remain in the
[execution plan](raspberry-pi-5-secure-boot-execution-plan.md).

