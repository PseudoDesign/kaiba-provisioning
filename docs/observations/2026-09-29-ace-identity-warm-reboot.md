# Ace persistent identity warm reboot: 2026-09-29

Ace completed a supervised warm reboot of the installed persistent identity
pilot. The [sanitized receipt](2026-09-29-ace-identity-warm-reboot.json) records
all eleven before/after checks passing. This is native software continuity
evidence for one short online reboot. It does not qualify cold power-on,
offline startup, rollback resistance, trusted time, or production admission.

The operator checked the installed boot kernel and initrd against the selected
system, then requested the reboot at `2026-09-29T06:42:40Z`. The
[read-only observer](../identity-reboot-observation.md), revision
`80edf573aadbca788df2c547dfaf3f96ad37e6a8`, captured the healthy baseline at
`06:40:48Z` and the ready post-reboot state at `06:44:11Z`. The latter reported
77.15 seconds of uptime. The collector did not request the reboot or start any
service. After the operator's reboot request, identity startup, time
synchronization and the probe were automatic; only read-only checks followed.

The current, persistent and newly booted system all resolved to generation 10:

```text
/nix/store/ylpbjk8jzr195l7yn7f713sgjfimicbs-nixos-system-ace-26.05.20260807.ee48b14
```

The boot ID and completed probe invocation changed. The registered workload
retained its exact identity:

```text
spiffe://pilot.kaiba.pseudo.design/device/ace/instance/ace-pilot-20260929/workload/identity-probe
```

The public trust bundle and canonical public enrollment-status digests were
unchanged. The comparison required a recent successful invocation from the
current boot, matching output metadata, an unexpired SVID, reported NTP
synchronization, an absent consumed grant, unchanged protected pilot metadata,
and no failed units. Hydra server, evaluator and queue runner, PostgreSQL, SSH,
SPIRE server/agent and the probe timer were active.

## Early observation was correctly rejected

An earlier post-reboot capture at `06:43:29Z`, reporting 35.24 seconds of uptime,
was not ready. SPIRE server/agent were not active and NTP synchronization was
not yet reported. The output file still contained a pre-reboot identity; no
fresh completed probe invocation backed it. The observer recorded these
failures instead of accepting that stale output. A later capture converged
automatically; no manual identity-service or clock start made the result pass.
The early transcript's digest is retained alongside the passing pair.

## Evidence and limits

The receipt binds the exact observer and transport-helper source digests, the
three private transcript digests, and the comparison digest. Re-projecting the
retained passing captures with that source reproduced all eleven checks.
Public files omit raw transcripts, trust keys, bootstrap/node records, private
paths, enrollment bodies, SSH anchors and access details. The same sanitized
receipt is retained with the host configuration.

The observer sees target self-report over authenticated SSH. The operator
record supplies the reboot action; a boot-ID change does not independently
attest physical hardware or the boot chain. The earlier installation receipt
correctly records that its own activation did not reboot Ace and remains
unchanged. This new receipt records the subsequent warm reboot separately.

There was no power removal or network isolation. Online time synchronization
and the existing one-hour agent credential lifetime remain dependencies.
No EEPROM, OTP, TPM, disk layout, unlock scheme, enrolled identity, DNS
publication or fleet-admission change was part of this observation. No
OFF-01 through OFF-12 physical/offline gate is closed by it.
