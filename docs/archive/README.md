# Archived and deferred plans

Archived on 2026-09-16 after reviewing the documentation against the selected
[first-fleet requirements](../fleet-admission-policy.md) and
[delivery scope](../delivery-scope.md). These documents retain their historical
content, with an archive notice and corrected relative links. Their status
tables are snapshots, not current device or project status.

| Document | Why it is outside the current plan |
| --- | --- |
| [Production security follow-on](raspberry-pi-5-production-security-follow-on.md) | Requires server approval before protected boot and refuses offline operation; superseded by the selected offline policy |
| [Production-station architecture](provisioning-station-production.md) | Broad, unimplemented station platform deferred by the scope freeze; also carries the older online-only device assumption |
| [Secure-boot execution plan](raspberry-pi-5-secure-boot-execution-plan.md) | Fresh-board development gate snapshot and older production roadmap; does not describe the already-owned development Pi or the current fleet requirements |
| [First physical verifier baseline](first-physical-baseline.md) | Earlier next-step plan for the online verifier and its offline-refusal test; not the first offline fleet milestone |

The [live-provisioning guide](../raspberry-pi-5-live-provisioning.md) retains the
required fresh-device sequence and execution boundaries. The already-owned Pi
must not repeat ownership programming. Signing, staging, recovery backups,
current transaction authority, and unknown-outcome reconciliation remain
required where the selected operation uses them.

Existing online-verifier [implementation and evidence](../stable-verifier-spike.md)
remain available as component references. Archiving a plan neither discards
artifacts nor marks its qualification passed. Its old test expectations remain
attached to that candidate; the offline fleet needs evidence for its own
selected path.
