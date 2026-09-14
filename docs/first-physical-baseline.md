# First physical stable-verifier baseline

The next engineering milestone is **run 1: `approved-release-boots`,
`positive-baseline`** on the already development-key-fused sacrificial
`a04171` Pi. Establish one complete signed-verifier-to-released-OS boot, then
the existing authority-offline rejection, before scheduling the rest of the
33-run qualification. The completed self-kexec/SMP diagnostic establishes only
its narrower transition; it does not supply this baseline.

This runbook prepares that handoff. It records no new hardware execution and
does not authorize signing, media writes, power operations, OTP, or EEPROM
changes. The current campaign remains paused after read-only capture.

## Close the staging prerequisites first

The [remaining hardware gate](stable-verifier-spike.md#remaining-hardware-gate)
identifies the immediate implementation work:

- Bind the current SD/NVMe `v1alpha2` GPT envelopes to the independently
  supplied staging plan using the [v1alpha2 recovery-requirements
  tool](stable-campaign-recovery.md). Its descriptive catalog retains both
  GPT lineages and every recovery range; it does not capture recovery bytes.
- Build the [per-leg staging candidate](stable-campaign-staging.md) against
  the reviewed plan and all four payloads. Its software path implements durable
  recovery capture, explicit local acknowledgement, execute-once writes and
  separate readback. The actual captures, independent attachment observations,
  execution approval and physical writer qualification must still be obtained
  on the selected devices. Keep the descriptive catalogs'
  `destructive_staging_ready=false`; do not repair GPTs to bypass that boundary.
- The [regular-file sandbox](stable-campaign-sandbox.md) rehearses those
  recovery and staging operations with synthetic copies. Its tested software
  behavior does not close the physical capture, attachment, approval, or
  writer-qualification requirements above.
- The separate development provisioner also lacks a writer. Its inner
  `boot.img` is not an SD partition image. Follow the
  [post-sign outer-boot boundary](raspberry-pi-5-development-target-access.md#compose-a-development-image)
  if that provisioner is needed for inspection.

Resolve these blockers before proposing a physical attempt. Completing this
document or assembling a packet does not close them.

## Prepare one operational packet

Use the existing campaign plan and artifact records; keep raw material in the
operator's protected evidence directory outside Git. Run the
[packet checker](stable-campaign-packet.md) to cross-check both selected runs,
their actual public inputs, all four payloads and the staging/recovery
contracts. Its source revision remains a caller assertion; it cannot replace
the following operator records. Record:

- The reviewed clean source commit, matching CI revision, native build
  platform, immutable artifact paths and digests. Pin the actual revision
  embedded in the artifacts; a PR merge-test revision can differ from its head.
- The signed verifier boot, public policy/trust bindings, delegated release,
  selected handoff mode and platform pins. For the file/live-FDT candidate,
  use `mkRpi5StableVerifierFileLiveFDTHardwareSystem` with its existing kernel
  policy. Retain the current signing review and approval boundaries.
- The sealed baseline media and the run-1 `manifest.json` and
  `materialization.json` from `mkRpi5StableVerifierCampaignRun`. Keep the full
  code-derived campaign plan intact while selecting `runIndex = 1`.
- The exact reviewed board, hardware configuration, SD/NVMe attachments,
  recovery bindings and four partition payloads: boot filesystem, root data,
  root hash and release filesystem. Do not inherit three partitions from an
  earlier boot-partition-only experiment.
- The authority configuration and public certificate validity interval,
  Pi RTC prerequisite, capture operator, fixed UART/power topology, capture
  duration/byte limits and approved stop/recovery procedure. Private keys and
  credentials remain in their existing runtime-only locations.

## Observe the positive boot

Once the staging prerequisites and explicit execution authorization exist:

1. Stage the approved complete media set through the reviewed writer, then
   independently read back every complete planned partition and compare its
   size and digest. A successful build or writer receipt alone is insufficient.
2. Start the bounded UART capture before power-on. Record complete cold-power
   removal and reapplication through the reviewed physical topology, alongside
   the independent media readback and authority audit. Preserve the complete
   capture; missing or truncated output is incomplete evidence.
3. Follow the [code-derived run trace](../internal/provisioning/stablecampaign/runs.go):
   release verification, bootstrap, fresh authorization, loaded handoff and
   execution. Then require an observable released OS on the expected root.
   `handoff-executing` alone does not establish entry into that OS.
4. Retain the raw capture digests, observed terminal boundary and outstanding
   witnesses. Run 1 carries five planned claims; command-line, live-FDT,
   one-boot-proof and bootstrap-replay witnesses remain distinct requirements.
   On timeout or failure, preserve the last observed boundary and stop for
   diagnosis/reconciliation before another physical attempt.

## Reuse the media for the first negative case

After the positive observation, select existing run 2,
`authorization-offline-rejected:authority-offline`. Its materialized partition
digests must equal the baseline. Use the approved authority-unavailability
condition and a new bounded capture; no media mutation or re-signing is needed.
The expected trace ends at `verifier-failed` with `challenge-request-failed`,
without handoff into the released OS, followed by the existing fail-closed
poweroff behavior. Retain an authority-unavailability observation and physical
power evidence; UART silence alone does not establish either.

## Hand off observations, then finish qualification

Report these attempts as engineering observations with exact inputs, evidence
locations, missing witnesses and the next blocking boundary. The
[witness requirements](../internal/provisioning/stablecampaign/witnesses.go)
and authenticated claim-closure implementation are still outstanding;
`RequirePlannedClaimClosure` deliberately fails closed. A consistent execution
envelope cannot be promoted to a campaign pass.

Keep the existing **33 physical runs and 37 planned claims**. After the initial
boot/refusal path is understood, complete that matrix and its authenticated
witness closure against the final candidate. Retain earlier observations only
where their exact inputs and evidence meet those requirements; changed inputs
or missing witnesses require new qualification evidence.
