# Ace: dated native ARM64 SPIRE smoke profile

Status: **manual software experiment; no hardware qualification or persistent
SPIRE deployment**. This profile is tied to the observed Ace system and pinned
artifacts below. It is not an automatic CI hardware test or a general-purpose
device installer. The [2026-09-29 observation](observations/2026-09-29-ace-spire-smoke.md)
records a passing run and reported cleanup for these bounded software checks.

The experiment launches one temporary SPIRE Server and Agent as an existing
nonroot process, issues a synthetic workload identity, observes rotation,
restarts the agent without its consumed grant, and checks bounded credential
expiry after stopping the temporary authority. It exercises native ARM64
execution on the existing operating system. It does not test the real DNS
registry/controller path, production membership or any boot protection.

## Exact profile and software inputs

The [Ace inventory](observations/2026-09-29-ace-offline-inventory.md) records the
Pi 5 Model B Rev 1.1, kernel `6.18.42`, September 2026 firmware, writable
encrypted root and observed time service. The runner requires `aarch64`, the
expected host name, a nonroot effective user, and this exact running system:

```text
/nix/store/f4q82s6kzy6y4q943y9v9nsm64c9s0xp-nixos-system-ace-26.05.20260807.ee48b14
```

The dated software pins are:

| Input | Exact pin |
| --- | --- |
| Nixpkgs | `70ce234312134a463ba7728e94da2486a1d237ac` |
| SPIRE | nixpkgs `spire` version `1.15.2`, upstream `spiffe/spire` tag `v1.15.2` |
| SPIRE source SHA-256, base64 | `Mmjx4moERdYXbGqaGdtHs/uH3Gsm3E6dA50UST5HfRE=` |
| Go probe source | [fleet commit `4e1cc6717b0b987fe036fac1f94f76c0f554cb7d`](https://github.com/PseudoDesign/kaiba-fleet/tree/4e1cc6717b0b987fe036fac1f94f76c0f554cb7d) |
| Probe source archive | Exactly `identity/` and `vendor-contracts/SPIFFE-PIN.json`; SHA-256 `9782caef81902afc779cd2a86b0305f32851ae70d4e4d5ed7c302b48b8b140a5` |
| Probe vendor hash | `sha256-J2D2dPiRbymMkKd+W32bsj2PiSCSIY0PqQ1XGhctaXU=` |
| ARM64 probe binary SHA-256 | `aa904426645638e2a3c455230d047df971614e8cdf74842c6300e983328c91d0` |

The exact runtime paths are:

```text
SPIRE agent:
/nix/store/xprm29ibxp2g3s4j2p1n075gp18n21lv-spire-1.15.2-agent

SPIRE server:
/nix/store/amkjv23s9r9wjxy7kydahb3axi01ri80-spire-1.15.2-server

Python:
/nix/store/41m77i1296n33p6liin8ynr6wh3h6b7m-python3-3.14.6

Station-built probe:
/nix/store/7i9yjfgi3mkkj7mggcxnfax2942rxydh-kaiba-spiffe-probe-arm64-smoke-4e1cc671/bin/kaiba-spiffe-probe
```

SPIRE and Python closures came from the normal signature-checked Nix cache.
Those cache signatures are software-distribution checks, not evidence of the
Pi's secure boot. The probe was cross-compiled as pure Go on the x86 station
with `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=arm64`, `-trimpath`, and
`-ldflags='-s -w -buildid='`. Its source tests ran natively on the station;
ELF inspection checked ARM64 and static linkage. This does not claim a native
ARM build of the probe or rely on target emulation. The locally built probe
is a digest-checked temporary file on Ace, not an unsigned store import.

## Bounded manual execution

Use only the reviewed target connection and independently confirmed host key.
Connection credentials, trust-file locations and other private access details
are intentionally absent from this guide. A changed running-system closure
requires fresh inventory and review of this dated profile; do not bypass the
runner's check.

The executed Python payload is retained as
[`scripts/offline-qualification/ace-spire-smoke.py`](../scripts/offline-qualification/ace-spire-smoke.py).
The exact executed [staging wrapper](../scripts/offline-qualification/ace-spire-smoke-wrapper.sh)
is retained separately. Both files are deliberately excluded from `flake
check` and persistent NixOS services. Stage the payload as `run-remote.py`, the
wrapper as `run-on-ace.sh`, and the binary as `kaiba-spiffe-probe` in the same
new private directory. The wrapper requires an owned mode-0700 directory
matching `/tmp/kaiba-ace-smoke-stage.XXXXXXXX` and removes that exact directory
on exit.

After separately staging the pinned runtime closures and those three exact
files, set `smoke_stage` to the validated returned directory and invoke the
wrapper as the existing nonroot process:

```console
bash "$smoke_stage/run-on-ace.sh"
```

The wrapper supplies the pinned Python path and probe digest. Calling the
Python payload directly would omit the wrapper's staging cleanup.

The runner creates a new private temporary state directory. The temporary
authority binds an ephemeral IPv4 loopback port, and both API sockets remain
inside that directory. Port conflicts fail without stopping an existing
listener. A join token is generated at runtime, stored privately, consumed
and removed; it is not printed or placed in command arguments. The synthetic
domain is `ace-smoke.test`, with workload:

```text
spiffe://ace-smoke.test/device/ace-smoke/instance/temporary/workload/rotation-probe
```

This fixture selects the current Unix UID. It does not establish isolation
between services sharing that UID or grant production access.

The intended runtime checks are:

1. A live Go Workload API source observes two distinct short-lived SVID serials
   for the same identity in one process, while the server and agent stay alive.
2. Agent restart succeeds with temporary state retained and the consumed join
   token removed, without creating or replaying an enrollment grant.
3. After the temporary server stops and the credential expires, the live agent
   denies identity. A timeout alone is insufficient: the result needs either
   the probe's explicit expired-credential diagnostic or a fresh SPIRE
   no-identity diagnostic correlated to that probe process.

The runner has a 240-second watchdog. Normal/error exit and handled signals
terminate child processes and remove its private state. The reviewed staging
wrapper separately removes its own exact staging directory. A SIGKILL, host
failure or power loss cannot execute cleanup handlers; reconcile those cases
against the recorded directory rather than deleting broad temporary paths.
Added runtime store closures may remain available for ordinary future garbage
collection; this experiment performs no host-wide collection or profile switch.

## Evidence and limits

The JSON result contains public identity metadata, checks, pass/failure and
cleanup status. It exports no SPIRE logs, private keys, or join tokens. Preserve
the exact runner, result and their hashes with the private station evidence;
review a separate public observation. A successful process exit alone is not
the complete observation: checks and cleanup must also be recorded.

Temporary files can occupy the existing filesystem. Deleting them is not a
secure-erasure guarantee, and this experiment does not claim hardware-protected
keys. It does not change firmware, OTP, TPM, disk layouts, boot configuration,
system profiles or persistent services, and performs no reboot.

`hardware_qualified`, `boot_chain_authenticated`,
`offline_rollback_qualified`, and `clock_continuity_qualified` remain false;
fleet admission is unevaluated. Cold boot, protected persistent authority
state, independent provider domains, physical isolation, allowed old/recovery
images, monotonic state, secure time and recovery still require their own
[qualification evidence](https://github.com/PseudoDesign/kaiba-infra/blob/codex/spiffe-spire-next-steps/docs/offline-qualification.md).
