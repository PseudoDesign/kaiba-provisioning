# Ace native SPIRE smoke: 2026-09-29

The [dated manual profile](../ace-spire-smoke.md) passed its bounded software
checks on Ace's existing ARM64 operating system. The temporary SPIRE Server
and Agent ran as a nonroot process in private temporary state, using the
synthetic `ace-smoke.test` domain. This is real native execution with synthetic
identity, not production enrollment or hardware qualification.

The retained report records:

| Check | Observed result |
| --- | --- |
| Workload issuance and rotation | The same Go probe process observed two distinct X.509-SVID serials for the same workload identity while the server and agent remained alive |
| Agent restart | The agent restarted using its temporary persisted state after the consumed join-token file was removed; the workload identity remained unchanged |
| Authority outage and expiry | After the temporary server stopped, the workload credential expired and a subsequent fetch was denied while the agent stayed alive; the runner required an identity-specific diagnostic, not merely a timeout |
| Cleanup | The final payload report recorded all tracked child processes stopped and temporary state removed; the staging wrapper also completed its normal cleanup path |

The initial attempt stopped before starting identity services because the
version preflight inspected stdout while SPIRE writes its version to stderr.
It reported no completed checks and successful cleanup. The retained final
runner checks combined stdout/stderr against the exact pinned version; the
second attempt produced the passing result. No firmware or system change was
used to resolve that preflight error.

The software inputs are fully listed in the profile: Nixpkgs
`70ce234312134a463ba7728e94da2486a1d237ac`, SPIRE `1.15.2`, and the ARM64 probe
from fleet commit `4e1cc6717b0b987fe036fac1f94f76c0f554cb7d`. The runner required
the exact running-system closure from the earlier
[Ace inventory](2026-09-29-ace-offline-inventory.md). The probe binary was
digest-checked before execution.

The [public JSON projection](2026-09-29-ace-spire-smoke.json) binds the observed
checks and software inputs to retained evidence. Exact executed source and
public evidence hashes are:

```text
runner_sha256=sha256:d723ad8668154d00a57633f02bc723bb6a35d203e32c9c0f522aab6b6dc76604
wrapper_sha256=sha256:ec90521a395dcfd79444f3062077e3185c3e56e0f7dad71b464db13c4817f9aa
result_sha256=sha256:82d5429d3c6dd672b9888643e548b7f6c55ddde07da50f99ead22023596a356c
```

The runner and wrapper are retained under `scripts/offline-qualification/`;
the result and source archive remain in private station evidence. No private
keys, grant values, SPIRE logs, host keys, access credentials or private
connection details are published here. Hashes identify retained bytes and do
not attest the running boot chain.

The signature-checked SPIRE/Python store copies remain additive unrooted
artifacts eligible for ordinary future garbage collection. No system or user
profile was activated, persistent service installed, or firmware, boot, OTP,
TPM or disk layout changed. There was no reboot. The full fleet registry and
DNS stack was not deployed on Ace. Temporary file removal is not a
secure-erasure guarantee.

All hardware gates remain open. The same-UID workload selector establishes no
service-user isolation; temporary process restart establishes no cold-boot or
protected-state continuity. Credential expiry under the current running clock
establishes no offline clock trust. Native monotonic state, old signed boot
paths, state replay protection, hardware binding and recovery require their
separate physical qualification. `hardware_qualified`,
`boot_chain_authenticated`, `offline_rollback_qualified`, and
`clock_continuity_qualified` remain false; fleet admission is unevaluated.
