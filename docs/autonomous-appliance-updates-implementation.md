# Autonomous appliance updates: implementation and release gates

Status: software reference implementation, 2026-10-03. **The approved plan is not
fully complete.** No production credential has been issued, updater installed,
physical update run, native selector qualified, or hardware readiness established.
This implements the protocol and transaction foundations of
[production management updates](production-management-updates.md).

## Implemented and tested

- Additive 0.7.0-draft.1 wire contract, pinned byte-identically from Contracts;
  strict JSON, purpose-separated P-256 signatures and exact certificate identity.
- Private LUKS2/ext4 volume checks; one-time P-256 key creation, durable same-key
  enrollment/renewal/recovery, idempotent installation reconciliation and refusal
  to regenerate missing keys. No change to development/pilot credential clients.
- Fixed HTTPS authority origin, TLS 1.3, explicit server trust, no redirects or
  environment proxies, bounded requests and content-addressed artifact downloads.
- Agent Tick/Run loop: local confirmation independent of authority connectivity,
  15-minute jittered polling, bounded exponential retry, deferred activation,
  seven-day overdue diagnostics, redacted fixed-code durable logs.
- Executor: independent release/authority trust, fresh current-certificate phase
  leases, monotonic exclusive attempts, protected-volume checks, durable intent,
  complete inactive-slot writes/readback, state compatibility, typed quiesce,
  trial and subsequent normal-boot confirmation, bounded fallback/reconciliation.
- Complete journal intents reconcile after restart; incomplete/ambiguous records
  remain preserved. Known interrupted cache downloads retry automatically; altered
  completed content remains refused. No uncertain media operation is redispatched.
- Regular-file driver rejects block devices, symlinks, hardlinks, target aliases,
  changed paths and size/digest differences. It establishes software behavior only.
- Root-owned fixed Unix socket, exact SO_PEERCRED caller UID and root-server
  authentication, bounded typed operations and serialized mutation dispatch.
- Native x86_64/aarch64 focused Nix checks and immutable wire-pin verification.

Tests use disposable keys, synthetic observations and regular files. They cover
altered/wrong-purpose signatures, identity/profile/layout/key substitutions,
expiry, wrong phases, repeated requests, interrupted writes, cold restart of
journals/credentials, busy applications, incomplete readback, lost acknowledgements,
failed trial, and lost selector-commit responses. They cannot prove firmware,
selector atomicity, LUKS secret custody, physical readback or independent acceptance.

## Required deployment adapters

These are explicit unfinished work, not hidden fallbacks:

1. Freeze the public installation profile: exact board/NVMe inventory, approved
   firmware/configuration, partition GUIDs/ranges/capacities, both signed release
   variants, recovery images, authority origin/audience and production issuer trust.
2. Qualify the native Pi selector/reset/watchdog and FAT commit recovery against
   that profile. Boot implementations must provide trustworthy Observe, one-shot
   Trial, independently reopened Default, bounded Restore/Commit and Restart.
   Inject power loss before/during/after selector mutation and pre-userspace hangs.
   If recovery fails, revise the design; do not ship a manual-repair fallback.
3. Implement and qualify the real fixed-range block writer and protected state
   reopening from both slots. Keep GPT, active slot and the shared private volume
   outside ordinary update writes. The regular-file driver cannot be substituted.
4. Integrate the production issuer's idempotent operation adapter and current
   inventory admission/approval boundaries. No test CA or pilot issuer grants
   production authorization. All terminal provisioning/acceptance review remains
   independent of update receipts.
5. Install the dedicated network service and bounded privileged executor with a
   tested root-owned local socket and exact SO_PEERCRED role checks. Agent uses
   LocalExecutor and can call IPCClient; no production process/service assembly
   has been installed. Bind immutable configuration, state
   ownership, health/quiesce adapters and default 02:00–04:00 UTC window.
6. Build the networked signed appliance image with no SSH, developer keys, USB root
   access, interactive debug console, remote Nix builder or arbitrary execution/file
   API. The retained offline candidate is unchanged and does not contain this agent.
7. Run VM process-boundary tests, native ARM packaging checks, the existing
   development-Pi comparison, then the intended first production unit under its
   exact expiring qualification grant. Prove a real version transition, offline
   operation, interrupted update recovery, renewal/expired recovery, state/key
   continuity and normal-route denial before admission. Obtain physical execution
   authorization through the existing approval process before real writes/power.

The native gate intentionally prevents implementing/deploying a shipping writer
on an assumed layout. Software changes can merge independently when reviewed;
production enrollment, security_applied and readiness remain unchanged.

## Operations and assurance

The network agent offers no inbound port or command interpreter. Offers contain
no URLs, paths, offsets or tool selection. Release and update authority keys are
separate. Native target selection and IPC deployment are trusted installation
inputs, never application configuration. The SandboxLifecycle interface supports
only signed built-in catalog health/quiesce and shared-state compatibility; service
catalog deployments, custom images, tenant hosting and DNS mutation are deferred.

Fleet approves a release once, freezes membership, runs canary → 10% → remainder,
requires 24 hours observation after confirmed health and recent healthy reports,
and pauses on failure, reconciliation or missing reports. Busy units remain
untouched; resuming a paused rollout is an explicit control-plane decision, never
an automatic force or repeated sudo operation. Operator-facing approval/admission
endpoints and final production service wiring remain deployment-adapter work.

Normal Fleet routes require the exact current active identity/certificate.
Qualification uses separate routes and an exact board/provisioning/transition
grant; installing a certificate or reporting an update never activates membership.
Expired recovery authenticates the retained registered key over server-authenticated
HTTPS, never by accepting an expired mTLS certificate or minting a new identity.
